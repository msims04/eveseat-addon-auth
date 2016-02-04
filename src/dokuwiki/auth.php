<?php

/**
* @ignore
*/
if(!defined('DOKU_INC')) die();

class auth_plugin_authseat extends DokuWiki_Auth_Plugin
{
	/**
	 * Constructor.
	 */
	public function __construct()
	{
		parent::__construct();

		$this->cando['addUser'     ] = false;
		$this->cando['delUser'     ] = false;
		$this->cando['modLogin'    ] = false;
		$this->cando['modPass'     ] = false;
		$this->cando['modName'     ] = false;
		$this->cando['modMail'     ] = false;
		$this->cando['modGroups'   ] = false;
		$this->cando['getUsers'    ] = false;
		$this->cando['getUserCount'] = false;
		$this->cando['getGroups'   ] = false;
		$this->cando['external'    ] = true ;
		$this->cando['logout'      ] = true ;

		$this->success = true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function trustExternal($user, $pass, $sticky = false)
	{
		// Attempt to authenticate using the login credentials.
		if (!empty($user) && !empty($pass)) {
			if (is_integer($user = $this->authenticateUser($user, $pass))) {
				switch ($user) {
					case 1001: msg($this->getLang('LOGIN_ERROR_INVALID_CONNECTION'      )); break;
					case 1002: msg($this->getLang('LOGIN_ERROR_INVALID_CREDENTIALS'     )); break;
					case 1003: msg($this->getLang('LOGIN_ERROR_INVALID_MAIN_CHARACTER'  )); break;
					case 1005: msg($this->getLang('LOGIN_ERROR_INVALID_CHARACTER_ACCESS')); break;
					default:   msg($this->getLang('LOGIN_ERROR_UNKNOWN'                 )); break;
				};

				auth_logoff();
				return false; }

			$this->setSession($user['characterName'], $user['userEmail'], $user['userIsSuperuser']);
			return true; }

		// Do not continue if there is no session.
		if (!isset($_SESSION[DOKU_COOKIE]['auth']['info'])) {
			auth_logoff(); return false; }

		// Attempt to authenticate using the session.
		$character = $_SESSION[DOKU_COOKIE]['auth']['info']['name'];
		$email     = $_SESSION[DOKU_COOKIE]['auth']['info']['mail'];

		if (!empty($character) && !empty($email)) {
			if (is_integer($user = $this->authenticateSession($character, $email))) {
				switch ($user) {
					case 1001: msg($this->getLang('LOGIN_ERROR_INVALID_CONNECTION'      )); break;
					case 1002: msg($this->getLang('LOGIN_ERROR_INVALID_CREDENTIALS'     )); break;
					case 1003: msg($this->getLang('LOGIN_ERROR_INVALID_MAIN_CHARACTER'  )); break;
					case 1005: msg($this->getLang('LOGIN_ERROR_INVALID_CHARACTER_ACCESS')); break;
					default:   msg($this->getLang('LOGIN_ERROR_UNKNOWN'                 )); break;
				};

				auth_logoff();
				return false; }

			$this->setSession($user['characterName'], $user['userEmail'], $user['userIsSuperuser']);
			return true; }

		auth_logoff();
		return false;
	}

	/**
	 * {@inheritdoc}
	 */
	public function logoff()
	{
		global $USERINFO;

		unset($USERINFO);
		unset($_SERVER['REMOTE_USER']);
		unset($_SESSION[DOKU_COOKIE]['auth']['user']);
		unset($_SESSION[DOKU_COOKIE]['auth']['info']);
	}

	/**
	 * Sets the user's info into dokuwiki's login variables.
	 * @param string  $username
	 * @param string  $email
	 * @param boolean $isAdmin
	 */
	private function setSession($username, $email, $isAdmin = false)
	{
		global $USERINFO;

		// Set the user info.
		$USERINFO['name'] = $username;
		$USERINFO['mail'] = $email;
		$USERINFO['grps'] = $isAdmin ? ['admin', 'user'] : ['user'];

		// Set the session.
		$_SERVER['REMOTE_USER']                = $username;
		$_SESSION[DOKU_COOKIE]['auth']['user'] = $username;
		$_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
	}

	/**
	 * Authenticates a user with seat and returns the user's details or an error code.
	 * @param  string $username
	 * @param  string $password
	 * @return array|integer
	 */
	private function authenticateUser($username, $password)
	{
		global $conf; $settings = $conf['plugin']['authseat'];

		curl_setopt_array(($curl = curl_init()), [
			CURLOPT_URL            => "{$settings['seat_address']}/login",
			CURLOPT_HTTPHEADER     => [
				"X-Token: {$settings['seat_token']}",
				"service: dokuwiki",
				"username: {$username}",
				"password: {$password}",
			],
			CURLOPT_POST           => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_SSL_VERIFYHOST => $settings['seat_verify_ssl'] === 'on',
			CURLOPT_SSL_VERIFYPEER => $settings['seat_verify_ssl'] === 'on',
		]);

		$response = json_decode(curl_exec($curl), true);
		curl_close($curl);

		if (!$response          ) { return 1001; }
		if (!$response['result']) { return $response['errno']; }

		return $response['data'];
	}

	/**
	 * Authenticates that the logged in user is still valid.
	 * @param  string $character
	 * @param  string $email
	 * @return array|integer
	 */
	private function authenticateSession($character, $email)
	{
		global $conf; $settings = $conf['plugin']['authseat'];

		curl_setopt_array(($curl = curl_init()), [
			CURLOPT_URL            => "{$settings['seat_address']}/session-good",
			CURLOPT_HTTPHEADER     => [
				"X-Token: {$settings['seat_token']}",
				"service: dokuwiki",
				"character: {$character}",
				"email: {$email}",
			],
			CURLOPT_POST           => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_SSL_VERIFYHOST => $settings['seat_verify_ssl'] === 'on',
			CURLOPT_SSL_VERIFYPEER => $settings['seat_verify_ssl'] === 'on',
		]);

		$response = json_decode(curl_exec($curl), true);
		curl_close($curl);

		if (!$response          ) { return 1001; }
		if (!$response['result']) { return $response['errno']; }

		return $response['data'];
	}
}
