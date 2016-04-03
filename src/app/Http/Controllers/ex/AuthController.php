<?php

namespace Seat\Addon\Auth\Http\Controllers\ex;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use Illuminate\Auth\Guard as Auth;
use Illuminate\Cache\Repository as Cache;
use Illuminate\Config\Repository as Config;
use Illuminate\Http\Request;
use Illuminate\Log\Writer as Log;
use Seat\Eveapi\Models\Character\CharacterSheet;
use Seat\Web\Models\User;

class AuthController extends Controller
{
	const ERRNO_INVALID_CONNECTION          = 1001;
	const ERRNO_INVALID_EXTERNAL_SERVICE    = 1002;
	const ERRNO_INVALID_CREDENTIALS         = 1002;
	const ERRNO_NO_MAIN_CHARACTER_SET       = 1003;
	const ERRNO_MAIN_CHARACTER_UNAUTHORIZED = 1004;
	const ERRNO_USER_NOT_FOUND              = 1005;
	const ERRNO_USER_CHARACTER_MISMATCH     = 1006;

	const ERROR_INVALID_CONNECTION          = '';
	const ERROR_INVALID_EXTERNAL_SERVICE    = 'The external service name is invalid.';
	const ERROR_INVALID_CREDENTIALS         = 'Your credentials are invalid.';
	const ERROR_NO_MAIN_CHARACTER_SET       = 'Your account does not have main character set.';
	const ERROR_MAIN_CHARACTER_UNAUTHORIZED = 'Your character is not authorized to use this service.';
	const ERROR_USER_NOT_FOUND              = 'That user does not exist.';
	const ERROR_USER_CHARACTER_MISMATCH     = 'Your account\'s character is different from your current main character.';

	/**
	 * @var \Illuminate\Auth\Guard
	 */
	private $auth;

	/**
	 * @var \Illuminate\Cache\Repository
	 */
	private $cache;

	/**
	 * @var \Carbon\Carbon
	 */
	private $carbon;

	/**
	 * @var \Illuminate\Config\Repository
	 */
	private $config;

	/**
	 * @var \Illuminate\Log\Writer
	 */
	private $log;

	/**
	 * @var \Illuminate\Http\Request
	 */
	private $request;

	/**
	 * @var \Seat\Eveapi\Models\Character\CharacterSheet
	 */
	private $character_sheets;

	/**
	 * @var \Seat\Web\Models\User
	 */
	private $users;

	/**
	 * Constructs the class.
	 *
	 * @param  \Illuminate\Auth\Guard                       $auth
	 * @param  \Illuminate\Cache\Repository                 $cache
	 * @param  \Carbon\Carbon                               $carbon
	 * @param  \Illuminate\Config\Repository                $config
	 * @param  \Illuminate\Log\Writer                       $log
	 * @param  \Illuminate\Http\Request                     $request
	 * @param  \Seat\Eveapi\Models\Character\CharacterSheet $character_sheets
	 * @param  \Seat\Web\Models\User                        $users
	 *
	 * @return void
	 */
	public function __construct(
		Auth           $auth,
		Cache          $cache,
		Carbon         $carbon,
		Config         $config,
		Log            $log,
		Request        $request,
		CharacterSheet $character_sheets,
		User           $users
	) {
		$this->auth             = $auth;
		$this->cache            = $cache;
		$this->carbon           = $carbon;
		$this->config           = $config;
		$this->log              = $log;
		$this->request          = $request;
		$this->character_sheets = $character_sheets;
		$this->users            = $users;
	}

	/**
	 * Returns the response for failed actions.
	 *
	 * @param  integer $errno
	 * @param  string  $message
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	private function failure($errno, $message)
	{
		return response()->json([
			'result' => false,
			'errno'  => $errno,
			'error'  => $message,
		]);
	}

	/**
	 * Returns the response for successful actions.
	 *
	 * @param  array $data
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	private function success(array $data)
	{
		return response()->json([
			'result' => true,
			'data'   => $data,
		]);
	}

	/**
	 * Attempts to login using either an email/password or a username/password combination.
	 *
	 * @param  string $username
	 * @param  string $password
	 *
	 * @return boolean
	 */
	private function login($username, $password)
	{
		$identifier = filter_var($username, FILTER_VALIDATE_EMAIL) ? 'email' : 'name';

		$authorized = $this->auth->once([
			$identifier => $username,
			'password'  => $password
		]);

		return $authorized == true;
	}

	/**
	 * Get all characters from a user that passes validation.
	 *
	 * @param  \Seat\Web\Models\User $user
	 * @param  string                $service
	 *
	 * @return \Illuminate\Support\Collection
	 */
	private function getValidCharacters(User $user, $service)
	{
		$characters = $user->keys

			// Gets all valid characters from the user's api keys.
			->transform(function ($item) use ($user, $service) {
				$min_access_mask        = $this->config->get("addon.auth.{$service}.min_access_mask");
				$allow_expiration_dates = $this->config->get("addon.auth.{$service}.allow_expiration_dates");

				// SeAT doesn't delete api keys properly so validate each key.
				if (!$item->info || !$item->characters) {
					$this->log->info("This api key cannot be read from the database.", [
						'key' => $item->key_id
					]);

					return;
				}

				// Do not allow characters on disabled keys to be used.
				if (!$item->enabled) {
					$this->log->info("This api key is disabled.", [
						'key_' => $item->key_id
					]);

					return;
				}

				// Do not allow characters on keys with expiration dates to be used.
				if (!$allow_expiration_dates && !!$item->info->expires)  {
					$this->log->info("This api key has an expiration date.", [
						'key' => $item->key_id
					]);

					return;
				}

				// Do not allow characters on keys without the minimum access mask to be used.
				if ($item->info->accessMask & $min_access_mask != $min_access_mask) {
					$this->log->info("This api key does not meet the minimum access mask requirements.", [
						'key' => $item->key_id
					]);

					return;
				}

				// Allow characters on this key to be used.
				return $item->characters;
			})

			// Remove null elements from the array.
			->filter(function ($item) { return $item != null; })

			// Merges characters from multiple arrays into one single array.
			->collapse();

		return $characters;
	}

	/**
	 * Gets a user's main character sheet.
	 *
	 * @param  \Seat\Web\Models\User $user
	 * @param  string                $service
	 *
	 * @return \Seat\Eveapi\Models\Character\CharacterSheet
	 */
	private function getMainCharacter(User $user, $service) {
		// Get the character id from the user's settings.
		$characterID = $user->settings->where('name', 'main_character_id')->first();
		$characterID = $characterID ? $characterID->value : false;

		// Get the character sheet of the main character if the character exists in $characters.
		$characters  = $this->getValidCharacters($user, $service);
		$character   = $characters->whereLoose('characterID', $characterID)->first();
		$character   = $character ? $this->character_sheets->where('characterID', $character->characterID)->first() : false;

		return $character;
	}

	/**
	 * Checks if a character is authorized to use an external service.
	 *
	 * @param  \Seat\Eveapi\Models\Character\CharacterSheet $character
	 * @param  string                                       $service
	 *
	 * @return boolean
	 */
	private function isCharacterAuthorized(CharacterSheet $character, $service)
	{
		$characters   = explode(',', $this->config->get("addon.auth.{$service}.characters"  ));
		$corporations = explode(',', $this->config->get("addon.auth.{$service}.corporations"));
		$alliances    = explode(',', $this->config->get("addon.auth.{$service}.alliances"   ));

		$character_details = [
			'character'   => $character->characterName,
			'corporation' => $character->corporationName,
			'alliance'    => $character->allianceName,
		];

		// Check if a character is blacklisted.
		if (in_array(-$character->characterID, $characters)) {
			$this->log->info('The character is blacklisted.', $character_details);
			return false;
		}

		if (in_array(-$character->characterID, $characters)) {
			$this->log->info('The character\'s corporation is blacklisted.', $character_details);
			return false;
		}

		if (in_array(-$character->characterID, $characters)) {
			$this->log->info('The character\'s alliance is blacklisted.', $character_details);
			return false;
		}

		// Check if a character is whitelisted.
		if (in_array($character->characterID  , $characters  )
		||  in_array($character->corporationID, $corporations)
		||  in_array($character->allianceID   , $alliances   )
		) {
			return true;
		}

		return false;
	}

	/**
	 * Converts the relevant values from the user and character models into one array.
	 *
	 * @param  \Seat\Web\Models\User                        $user
	 * @param  \Seat\Eveapi\Models\Character\CharacterSheet $character
	 *
	 * @return array
	 */
	private function getResponseValues(User $user, $character)
	{
		return [
			'userID'          => $user->id,
			'userName'        => $user->name,
			'userEmail'       => $user->email,
			'userRoles'       => $user->roles
				// Remove null elements from the array.
				->filter(function ($item) { return $item != null; })

				// Change the role model to the role title.
				->transform(function ($item) { return $item->title; }),

			'characterID'     => $character->characterID,
			'characterName'   => $character->name,
			'corporationID'   => $character->corporationID,
			'corporationName' => $character->corporationName,
			'allianceID'      => $character->allianceID,
			'allianceName'    => $character->allianceName,
		];
	}

	/**
	 * Checks if a user is authorized to use an external service.
	 *
	 * @param  \Seat\Web\Models\User $user
	 * @param  string                $service
	 * @param  string                $required_character_name
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	private function getLoginResult(User $user, $service, $required_character_name = null)
	{
		// Get the user's main character.
		$character = $this->getMainCharacter($user, $service);

		if (!$character) {
			$this->log->info(self::ERROR_NO_MAIN_CHARACTER_SET);

			return $this->failure(
				self::ERRNO_NO_MAIN_CHARACTER_SET,
				self::ERROR_NO_MAIN_CHARACTER_SET
			);
		}

		// Verify that the character name matches the required value (if not null).
		if ($required_character_name && $character->name != $required_character_name) {
			$this->log->info(self::ERROR_USER_CHARACTER_MISMATCH);

			return $this->failure(
				self::ERRNO_USER_CHARACTER_MISMATCH,
				self::ERROR_USER_CHARACTER_MISMATCH
			);
		}

		// Verify that the character is authorized.
		$allow_guests         = $this->config->get("addon.auth.{$service}.allow_guests");
		$character_authorized = $this->isCharacterAuthorized($character, $service);

		if (!$character_authorized && !$allow_guests) {
			$this->log->info(self::ERROR_MAIN_CHARACTER_UNAUTHORIZED);

			return $this->failure(
				self::ERRNO_MAIN_CHARACTER_UNAUTHORIZED,
				self::ERROR_MAIN_CHARACTER_UNAUTHORIZED
			);
		}

		// Prepare the response and add a flag if the user is a guest.
		$response_values = array_merge(
			$this->getResponseValues($user, $character),
			['guest' => !$character_authorized]
		);

		// Log whether the user was authenticated as a guest or an user.
		if (!$character_authorized && $allow_guests) {
			$this->log->info('The user authenticated successfully as a guest.', [
				'character' => $response_values['characterName'],
			]);
		}

		else {
			$this->log->info('The user authenticated successfully.');
		}

		return $this->success($response_values);
	}

	/**
	 * Handles authenticating a user.
	 *
	 * @param  \Illuminate\Http\Request $request
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function postLogin()
	{
		// Get the neccessary headers from the request.
		$service  = $this->request->header('service' , false);
		$username = $this->request->header('username', '');
		$password = $this->request->header('password', '');

		$this->log->info('A user is attemping to authenticate with an external service.', [
			'username' => $username,
			'service'  => $service,
		]);

		// Verify that the external service exists in the configuration.
		if (!$service || !$this->config->get("addon.auth.{$service}")) {
			$this->log->info(self::ERROR_INVALID_EXTERNAL_SERVICE, [
				'service' => $service
			]);

			return $this->failure(
				self::ERRNO_INVALID_EXTERNAL_SERVICE,
				self::ERROR_INVALID_EXTERNAL_SERVICE
			);
		}

		// Attempt to authenticate the user's credentials.
		if (!$this->login($username, $password)) {
			$this->log->info(self::ERROR_INVALID_CREDENTIALS);

			return $this->failure(
				self::ERRNO_INVALID_CREDENTIALS,
				self::ERROR_INVALID_CREDENTIALS
			);
		}

		return $this->getLoginResult($this->auth->user(), $service);
	}

	/**
	 * Handles authenticating that a user/character is still valid.
	 *
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function postAuthorized()
	{
		// Get the neccessary headers from the request.
		$service   = $this->request->header('service'  , false);
		$username  = $this->request->header('username' , '');
		$character = $this->request->header('character', '');

		$this->log->info('A service is attempting to validate a user.', [
			'username'  => $username,
			'character' => $character,
			'service'   => $service,
		]);

		// Verify that the external service exists in the configuration.
		if (!$service || !$this->config->get("addon.auth.{$service}")) {
			$this->log->info(self::ERROR_INVALID_EXTERNAL_SERVICE, [
				'service' => $service
			]);

			return $this->failure(
				self::ERRNO_INVALID_EXTERNAL_SERVICE,
				self::ERROR_INVALID_EXTERNAL_SERVICE
			);
		}

		// Check the cache first so the api isn't hammered too badly.
		$key = 'auth:session:' . sha1("{$service}:{$username}");

		if ($this->cache->has($key)) {
			$this->log->info('Returning the cached authorization result.');

			return $this->cache->get($key);
		}

		// Attempt to find the requested user.
		$identifier = filter_var($username, FILTER_VALIDATE_EMAIL) ? 'email' : 'name';
		$user       = $this->users->where($identifier, $username)->first() ?: false;

		if (!$user) {
			$this->log->info(self::ERROR_USER_NOT_FOUND);

			return $this->failure(
				self::ERRNO_USER_NOT_FOUND,
				self::ERROR_USER_NOT_FOUND
			);
		}

		// Get and cache the response for 15 minutes.
		$response = $this->getLoginResult($user, $service, $character);
		$this->cache->put($key, $response, $this->carbon->now()->addMinutes(15));

		return $response;
	}
}
