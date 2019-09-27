<?php
/**
 * DokuWiki Plugin authclientcert (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Pawel Jasinski <pawel.jasinski@gmail.com>
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC')) {
    die();
}

class auth_plugin_authclientcert extends auth_plugin_authplain
{

    /**
     * Constructor
     */
    public function __construct() {
        parent::__construct(); // for compatibility
        $this->cando['addUser']     = false; // can Users be created?
        $this->cando['delUser']     = true;  // can Users be deleted?
        $this->cando['modLogin']    = false; // can login names be changed?
        $this->cando['modPass']     = false; // can passwords be changed?
        $this->cando['modName']     = false; // can real names be changed?
        $this->cando['modMail']     = false; // can emails be changed?
        $this->cando['modGroups']   = true;  // can groups be changed?
        $this->cando['getGroups']   = true;  // can a list of available groups be retrieved?
        $this->cando['external']    = true;  // does the module do external auth checking?
        $this->cando['logout']      = true;  // possible for user logged in with password
    }

    /**
     * Do all authentication [ OPTIONAL ]
     *
     * @param   string $user   Username
     * @param   string $pass   Cleartext Password
     * @param   bool   $sticky Cookie should not expire
     *
     * @return  bool             true on successful auth
     */
    public function trustExternal($user, $pass, $sticky=false) {
        global $USERINFO;
        $sticky ? $sticky = true : $sticky = false; //sanity check

        $header_name = $this->getConf('http_header_name');
        if (empty($header_name)) {
            $this->_debug("CLIENT CERT: http_header_name is empty", 0, __LINE__, __FILE__);
            return false;
        }
        $cert = $_SERVER[$header_name];
        if (empty($cert)) {
            $this->_debug("CLIENT CERT: missing http header ($header_name)", 0, __LINE__, __FILE__);
            return false;
        }
        $certUserInfo = $this->_extractUserInfoFromCert($cert);
        if (empty($certUserInfo)) {
            return false;
        }
        $remoteUser = $certUserInfo['user'];
        $userinfo = $this->_upsertUser($certUserInfo);
        if(empty($userinfo)) {
            return false;
        }
        $_SERVER['REMOTE_USER'] = $remoteUser;
        $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['auth']['info']['name'] = $userinfo['name'];
        $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'] = $userinfo['mail'];
        $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['auth']['info']['grps'] = $userinfo['grps'];
                            $_SESSION[DOKU_COOKIE]['auth']['info']['user'] = $remoteUser;
                            $_SESSION[DOKU_COOKIE]['auth']['user'] = $remoteUser;
        $this->cando['logout'] = false;  // not possible as long as certificate is provided
        return true;
    }

    protected function _upsertUser($certUserInfo) {
        $user = $certUserInfo['user'];
        $userInfo = $this->getUserData($user);
        if ($userInfo !== false) {
            // modify user?
            return $userInfo;
        }
        $group = $this->getConf('group');
        if (empty($group)) {
            $group = "user";
        }
        $group = $this->cleanGroup($group);
        if ($this->createUser($user, auth_pwgen().auth_pwgen(), $certUserInfo['name'], $certUserInfo['mail'], array($group))) {
            return $this->users[$user];
        }
        $this->_debug("CLIENT CERT: Unable to autocreate user", 0, __LINE__, __FILE__);
        return false;
    }

    protected function _formatCert($cert) {
        // restore BEGIN/END CERTIFICATE if missing
        $pattern = '/-----BEGIN CERTIFICATE-----(.*)-----END CERTIFICATE-----/msU';
        if (1 === preg_match($pattern, $cert, $matches)) {
           $cert = $matches[1];
           $replaceCharacters = array(" ", "\t", "\n", "\r", "\0" , "\x0B");
           $cert = str_replace($replaceCharacters, '', $cert);
        }
        return "-----BEGIN CERTIFICATE-----".PHP_EOL.$cert.PHP_EOL."-----END CERTIFICATE-----".PHP_EOL;
    }

    protected function _extractUserInfoFromCert($cert) {
        $cert = $this->_formatCert($cert);
        if (empty($cert)) {
            $this->_debug("CLIENT CERT: unable to locate user certificate", 0, __LINE__, __FILE__);
            return false;
        }
        $_SESSION['SSL_CLIENT_CERT'] = $cert;
        $client_cert_data = openssl_x509_parse($cert);
        if (empty($client_cert_data)) {
            $this->_debug("CLIENT CERT: unable to parse user certificate $client_cert_data", 0, __LINE__, __FILE__);
            return false;
        }

        // this could be anything like: givenName sn, sn givenName, uid, ...
        // [subject] => Array ( [C] => CH [O] => Admin [OU] => Array ( [0] => VBS [1] => V ) [UNDEF] => E1024143 [CN] => Pawel Jasinski )
        $name = $client_cert_data['subject']['CN'];
        if (empty($name)) {
            $this->_debugCert($client_cert_data, "CLIENT CERT: user certificate is missing subject.CN", 0, __LINE__, __FILE__);
            return false;
        }

        // go after email address in extension.subjectAltName
        // [extensions] => Array ( [subjectAltName] => email:Pawel.Jasinski@vtg.admin.ch, othername:  ...<snip/>
        $altName = $client_cert_data['extensions']['subjectAltName'];
        $mail = null;
        foreach (explode(",", $altName) as $part) {
            $nameval = explode(":", $part, 2);
            if (count($nameval) == 2 && $nameval[0] == "email") {
                $mail = trim($nameval[1]);
                break;
            }
        }
		// Also look for the email in the subject (openssl/easy-rsa seems to do things this way)
		if (empty($mail)) {
			$mail = $client_cert_data['subject']['emailAddress'];
		}
        if (empty($mail)) {
            $this->_debugCert($client_cert_data, "CLIENT CERT: user certificate is missing email address", 0, __LINE__, __FILE__);
            return false;
        }
		$user = $this->getUserByEmail($mail);
        return ['name' => $name, 'mail' => $mail, 'user' => $user ];
    }

	 /**
     * Find a user by his email address
     *
     * @param $mail
     * @return bool|string
     */
    protected function getUserByEmail($mail) {
        if($this->users === null) $this->_loadUserData();
        $mail = strtolower($mail);
        foreach($this->users as $user => $uinfo) {
            if(strtolower($uinfo['mail']) == $mail) return $user;
        }
        return false;
    }

    private function _getOID($OID, $name) {
        preg_match('/\/' . $OID  . '=([^\/]+)/', $name, $matches);
        return $matches[1];
    }

    /**
     * Wrapper around msg() but outputs only when debug is enabled
     *
     * @param string $message
     * @param int    $err
     * @param int    $line
     * @param string $file
     * @return void
     */
    protected function _debug($message, $err, $line, $file) {
        if(!$this->getConf('debug')) return;
        msg($message, $err, $line, $file);
    }

    protected function _debugCert($client_cert_data, $message, $err, $line, $file) {
        $cert_dump = print_r($client_cert_data, true);
        $this->_debug($message." ".$client_cert_data.$cert_dump, $err, $line, $file);
    }
}

