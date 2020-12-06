<?php

class rcube_dovecot_password
{
	/**
	* Update current user password
	*
	* @param string $curpass Current password
	* @param string $passwd  New password
	* @param string $username User login
	*
	* @return int Result
	*
	*
	* The following parameters must be set on password plugin config `config.inc.php`
	*
	* Dovecot Driver options
	* ---------------------
	* Command to use for changing password. (see "Sudo setup" in README)
	* $config['password_dovecot_bin'] = 'sudo systemd-run --machine mail --pipe /usr/local/bin/dovechpwd';
	*
	* Path to Dovecot password file on Dovecot server.
	* $config['password_dovecot_file'] = '/etc/dovecot/users';
	*
	* Password hashing/crypting algorithms.
	* Default: 'bcrypt'
	* Possible options: 'dovecot' equivalent to setting $config['password_algorithm'] = 'dovecot'
	* Possible options if $config['password_dovecot_hash'] is set to 'mkpasswd':
	*		 'sha-512', 'sha-256', 'md5', 'des'.
	* $config['password_dovecot_scheme'] = 'bcrypt';
	*
	* Optional : Used if scheme is not set to 'bcrypt' or 'dovecot'.
	* Default: '/usr/bin/mkpasswd'
	* //$config['password_dovecot_hash'] = '/usr/bin/mkpasswd';
	* 
	* 
	* Sudo setup
	* ----------
	* # ls -l /usr/local/bin/dovechpwd
	* -rwxr-xr-x 1 root root
	*
	* # cat >/etc/sudoers.d/roundcube << EOF
	* roundcube ALL=NOPASSWD:/usr/local/bin/dovechpw
	* #roundcube ALL=NOPASSWD:/usr/bin/systemd-run --machine=mail --pipe /usr/local/bin/dovechpwd *
	* EOF
	*
 	*/
	
    public function save($currpass, $newpass, $username)
    {
    	$rcmail = rcmail::get_instance();
        $bin = $rcmail->config->get('password_dovecot_bin');
		$pass_file = $rcmail->config->get('password_dovecot_file');
		$hash_bin = $rcmail->config->get('password_dovecot_hash', '/usr/bin/mkpasswd');
		$scheme = $rcmail->config->get('password_dovecot_scheme', 'bcrypt');

		$password = self::hash_password($newpass, $scheme, $hash_bin);
    	if ($password === false) {
			return PASSWORD_CRYPT_ERROR;
		}
			
		$cmd = implode(' ', [$bin, escapeshellarg($pass_file)]);

        $handle = popen($cmd, "w");
        if ($handle === false) {
        	return PASSWORD_CONNECT_ERROR;
        }

        fwrite($handle, $username.PHP_EOL);
        fwrite($handle, $password.PHP_EOL);

		$ret = pclose($handle);
        if ($ret == 0) {
            return PASSWORD_SUCCESS;
        }

//      This would log the output into logs/errors
//		rcube::write_log("errors", "Password plugin: Return code of $cmd : $ret");

        rcube::raise_error(array(
                'code' => 600,
                'type' => 'php',
                'file' => __FILE__, 'line' => __LINE__,
                'message' => "Password plugin: Unable to execute $cmd"
            ), true, false);

        return PASSWORD_ERROR;
    }
    
    public static function hash_password($passwd, $scheme, $bin)
    {
    	if ($scheme == "bcrypt") {
			$password = "{BLF-CRYPT}" . password_hash($passwd, PASSWORD_BCRYPT);
		} else if ($scheme == 'dovecot') {
			$password = password::hash_password($passwd, 'dovecot', true);
    	} else {
            $cmd = implode(' ', [$bin, '-m', escapeshellarg($scheme), '-s']);
            $spec = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('file', '/dev/null', 'a'));
            $handle = proc_open("$cmd", $spec, $pipes);
            
            if (!is_resource($handle)) {
                return false;
            }
            fwrite($pipes[0], $passwd.PHP_EOL);
            pclose($pipes[0]);
            $password =  "{CRYPT}" . trim(stream_get_contents($pipes[1]));
            pclose($pipes[1]);
            proc_close($handle);
		}
		return $password;
    }
}
