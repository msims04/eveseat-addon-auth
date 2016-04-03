<?php

namespace msims04\seatauth\auth\provider;

/**
* @ignore
*/
if (!defined('IN_PHPBB')) { exit; }

/**
 * SeAT authentication provider for phpBB3.
 *
 * @package auth
 */
class seat extends \phpbb\auth\provider\base
{
	/**
	 * The authentication provider constructor.
	 *
	 * @param \phpbb\config\config              $config
	 * @param \phpbb\db\driver\driver_interface $db
	 * @param \phpbb\user                       $user
	 */
	public function __construct(
		\phpbb\config\config              $config,
		\phpbb\db\driver\driver_interface $db,
		\phpbb\user                       $user
	) {
		$this->config = $config;
		$this->db     = $db;
		$this->user   = $user;

		$this->user->add_lang_ext('msims04/seatauth', 'common');
	}

	/**
	 * {@inheritdoc}
	 */
	public function login($username, $password)
	{
		ini_set('display_errors', 'On');
		error_reporting(E_ALL | E_STRICT);

		$sqlByUsername = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type, user_login_attempts FROM ' . USERS_TABLE . ' WHERE username = \'%s\'';
		$sqlByID       = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type, user_login_attempts FROM ' . USERS_TABLE . ' WHERE user_id = %d';
		$password      = trim($password);

		// Do not allow empty passwords.
		if (!$password) {
			return [
				'status'    => LOGIN_ERROR_PASSWORD,
				'error_msg' => 'NO_PASSWORD_SUPPLIED',
				'user_row'  => ['user_id' => ANONYMOUS],
			];
		}

		// Do not allow empty usernames.
		if (!$username) {
			return [
				'status'    => LOGIN_ERROR_USERNAME,
				'error_msg' => 'LOGIN_ERROR_USERNAME',
				'user_row'  => ['user_id' => ANONYMOUS],
			];
		}

		// Do not allow the default admin to log in.
		if ($username == 'admin') {
			return [
				'status'    => LOGIN_ERROR_USERNAME,
				'error_msg' => 'LOGIN_ERROR_ADMIN_USERNAME',
				'user_row'  => ['user_id' => ANONYMOUS],
			];
		}

		// Find a phpbb user incase someone is trying to login with their
		// character name. Use the user's email address instead to login.
		// This is needed in order to use the administration panel.
		$sth = $this->db->sql_query(sprintf($sqlByUsername, $this->db->sql_escape($username)));
		$phpbb_user = $this->db->sql_fetchrow($sth);
		$this->db->sql_freeresult($sth);

		if ($phpbb_user) {
			$username = $phpbb_user['user_email'];
		}

		// Get the user details from seat.
		$user = $this->authenticateUser($username, $password);

		if (is_integer($user)) {
			switch ($user) {
				case 1001: $error = 'LOGIN_ERROR_INVALID_CONNECTION';          break;
				case 1002: $error = 'LOGIN_ERROR_INVALID_CREDENTIALS';         break;
				case 1003: $error = 'LOGIN_ERROR_NO_MAIN_CHARACTER_SET';       break;
				case 1004: $error = 'LOGIN_ERROR_MAIN_CHARACTER_UNAUTHORIZED'; break;
				default:   $error = 'LOGIN_ERROR_UNKNOWN';                     break;
			};

			return [
				'status'    => LOGIN_ERROR_EXTERNAL_AUTH,
				'error_msg' => $error,
				'user_row'  => ['user_id' => ANONYMOUS],
			];
		}

		// Return the phpbb user if it was already found earlier.
		if ($phpbb_user) {
			return [
				'status'    => LOGIN_SUCCESS,
				'error_msg' => false,
				'user_row'  => $phpbb_user,
			];
		}

		// Find a phpbb user using the seat user's character name.
		$sth = $this->db->sql_query(sprintf($sqlByUsername, $this->db->sql_escape($user['characterName'])));
		$phpbb_user = $this->db->sql_fetchrow($sth);
		$this->db->sql_freeresult($sth);

		if ($phpbb_user) {
			return [
				'status'    => LOGIN_SUCCESS,
				'error_msg' => false,
				'user_row'  => $phpbb_user,
			];
		}

		// Create a new phpbb user if one wasn't found.
		$result = user_add([
			'username'      => $user['characterName'],
			'user_password' => phpbb_hash(openssl_random_pseudo_bytes(256)),
			'user_email'    => $user['userEmail'],
			'group_id'      => in_array('Superuser', $user['userRoles']) ? 5 : 2,
			'user_type'     => in_array('Superuser', $user['userRoles']) ? 3 : USER_NORMAL,
		]);

		// Return the newly created user.
		$sth = $this->db->sql_query(sprintf($sqlByID, $this->db->sql_escape($result)));
		$phpbb_user = $this->db->sql_fetchrow($sth);
		$this->db->sql_freeresult($sth);

		return [
			'status'    => LOGIN_SUCCESS,
			'error_msg' => false,
			'user_row'  => $phpbb_user
		];
	}

	/**
	 * {@inheritdoc}
	 */
	public function validate_session($user)
	{
		if ($user['username'] == 'Anonymous') { return true; }
		return $this->authenticateSession($user);
	}

	/**
	 * {@inheritdoc}
	 */
	public function acp()
	{
		// These are fields in the config for this auth provider.
		return [
			'seat_address',
			'seat_token',
			'seat_verify_ssl',
		];
	}

	/**
	 * {@inheritdoc}
	 */
	public function get_acp_template($config)
	{
		return [
			'TEMPLATE_FILE'	=> '@msims04_seatauth/auth_provider_seat.html',
			'TEMPLATE_VARS'	=> [
				'AUTH_SEAT_ADDRESS'    => $config['seat_address'   ],
				'AUTH_SEAT_TOKEN'      => $config['seat_token'     ],
				'AUTH_SEAT_VERIFY_SSL' => $config['seat_verify_ssl'],
			]];
	}

	/**
	 * Authenticates a user with seat and returns the user's details or an error code.
	 * @param  string $username
	 * @param  string $password
	 * @return array|integer
	 */
	private function authenticateUser($username, $password)
	{
		curl_setopt_array(($curl = curl_init()), [
			CURLOPT_URL            => "{$this->config['seat_address']}/login",
			CURLOPT_HTTPHEADER     => [
				"X-Token: {$this->config['seat_token']}",
				"service: phpbb",
				"username: {$username}",
				"password: {$password}",
			],
			CURLOPT_POST           => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_SSL_VERIFYHOST => $this->config['seat_verify_ssl'] === 'on' ? 2 : 0,
			CURLOPT_SSL_VERIFYPEER => $this->config['seat_verify_ssl'] === 'on' ? 1 : 0,
		]);

		$response = json_decode(curl_exec($curl), true);
		curl_close($curl);

		if (!$response          ) { return 1001; }
		if (!$response['result']) { return $response['errno']; }

		return $response['data'];
	}

	/**
	 * Authenticates that the logged in user is still valid.
	 * @param  array $user
	 * @return boolean
	 */
	private function authenticateSession($user)
	{
		curl_setopt_array(($curl = curl_init()), [
			CURLOPT_URL            => "{$this->config['seat_address']}/authorized",
			CURLOPT_HTTPHEADER     => [
				"X-Token: {$this->config['seat_token']}",
				"service: phpbb",
				"username: {$user['user_email']}",
				"character: {$user['username']}",
			],
			CURLOPT_POST           => true,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_SSL_VERIFYHOST => $this->config['seat_verify_ssl'] === 'on' ? 2 : 0,
			CURLOPT_SSL_VERIFYPEER => $this->config['seat_verify_ssl'] === 'on' ? 1 : 0,
		]);

		$response = json_decode(curl_exec($curl), true);
		curl_close($curl);

		if (!$response || !$response['result']) {
			return false;
		}

		return true;
	}

}
