<?php

namespace Seat\Addon\Auth\Http\Controllers\ex;

use App\Http\Controllers\Controller;
use App\Http\Requests;
use Auth;
use Cache;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Seat\Eveapi\Models\Character\CharacterSheet;
use Seat\Web\Models\User;

class AuthController extends Controller
{
	const ERRNO_INVALID_CONNECTION         = 1001;
	const ERRNO_INVALID_CREDENTIALS        = 1002;
	const ERRNO_INVALID_MAIN_CHARACTER     = 1003;
	const ERRNO_INVALID_NOT_MAIN_CHARACTER = 1004;
	const ERRNO_INVALID_CHARACTER_ACCESS   = 1005;

	const ERROR_INVALID_CONNECTION         = '';
	const ERROR_INVALID_CREDENTIALS        = 'Those credentials are invalid.';
	const ERROR_INVALID_MAIN_CHARACTER     = 'That account does not have valid main character set.';
	const ERROR_INVALID_NOT_MAIN_CHARACTER = 'That character is not the main character of the account.';
	const ERROR_INVALID_CHARACTER_ACCESS   = 'That character is not authorized to use this service.';

	/**
	 * The service prefix for the configuration file.
	 * @var string
	 */
	private $service;

	/**
	 * Returns the response for failed actions.
	 * @param  integer $errno
	 * @param  string  $message
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
	 * @param  array $data
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
	 * @param  string $username
	 * @param  string $password
	 * @return boolean
	 */
	private function login($username, $password)
	{
		$identifier = filter_var($username, FILTER_VALIDATE_EMAIL) ? 'email' : 'name';
		return Auth::once([$identifier => $username, 'password' => $password]) == true;
	}

	/**
	 * Gets all of the characters registered to a user that have valid api keys.
	 * @param  Seat\Web\Models\User $user
	 * @return Illuminate\Support\Collection
	 */
	private function getCharacters(User $user)
	{
		return $user->keys->transform(function ($item) {
			$accessMask = config("addon.auth.{$this->service}_accessMask");

			if (!$item->enabled || !!$item->info->expires) { return; }
			if ($item->info->accessMask != $accessMask)    { return; }

			return $item->characters[0]; })
		->filter(function ($item) { return $item != null; });
	}

	/**
	 * Gets a user's main character sheet.
	 * @param  Seat\Web\Models\User $user
	 * @return Seat\Eveapi\Models\Character\CharacterSheet
	 */
	private function getMainCharacterSheet(User $user) {
		$characterID = $user->settings->where('name', 'main_character_id')->first();
		$characterID = $characterID ? $characterID->value : false;

		$characters  = $this->getCharacters($user);
		$character   = $characters->whereLoose('characterID', $characterID)->first();
		$character   = $character ? CharacterSheet::where('characterID', $character->characterID)->first() : false;

		return $character;
	}

	/**
	 * Checks if a character is authorized to use any external services.
	 * @param  Seat\Eveapi\Models\Character\CharacterSheet  $character [description]
	 * @return boolean
	 */
	private function isCharacterAuthorized(CharacterSheet $character)
	{
		if (in_array($character->allianceID   , config("addon.auth.{$this->service}_alliances"   ))) { return true; }
		if (in_array($character->corporationID, config("addon.auth.{$this->service}_corporations"))) { return true; }
		if (in_array($character->characterID  , config("addon.auth.{$this->service}_characters"  ))) { return true; }

		return false;
	}

	/**
	 * Converts the relavent values from the user and character models into one array.
	 * @param  Seat\Web\Models\User                        $user
	 * @param  Seat\Eveapi\Models\Character\CharacterSheet $character
	 * @return array
	 */
	private function getDetails($user, $character)
	{
		return [
			'userID'          => $user->id,
			'userName'        => $user->name,
			'userEmail'       => $user->email,
			'userIsSuperuser' => $user->roles->contains('title', 'Superuser'),
			'characterID'     => $character->characterID,
			'characterName'   => $character->name,
			'corporationID'   => $character->corporationID,
			'corporationName' => $character->corporationName,
			'allianceID'      => $character->allianceID,
			'allianceName'    => $character->allianceName,
		];
	}

	/**
	 * Handles authenticating a user.
	 * @param \Illuminate\Http\Request $request
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function postLogin(Request $request)
	{
		// Attempt to login.
		$this->service = $request->header('service' );
		$username      = $request->header('username');
		$password      = $request->header('password');

		if (!$this->login($username, $password)) {
			return $this->failure(AuthController::ERRNO_INVALID_CREDENTIALS, AuthController::ERROR_INVALID_CREDENTIALS); }

		// Get the main character.
		$user      = Auth::user();
		$character = $this->getMainCharacterSheet($user);

		if (!$character) {
			return $this->failure(AuthController::ERRNO_INVALID_MAIN_CHARACTER, AuthController::ERROR_INVALID_MAIN_CHARACTER); }

		// Verify that the character is authorized.
		if (!$this->isCharacterAuthorized($character)) {
			return $this->failure(AuthController::ERRNO_INVALID_CHARACTER_ACCESS, AuthController::ERROR_INVALID_CHARACTER_ACCESS); }

		// Success!
		return $this->success($this->getDetails($user, $character));
	}

	/**
	 * Handles authenticating that a user/character is still valid.
	 * @param \Illuminate\Http\Request $request
	 * @return \Illuminate\Http\JsonResponse
	 */
	public function postSessionGood(Request $request)
	{
		$email = $request->header('email');
		$name  = $request->header('character');
		$key   = 'auth:session:' . sha1("{$email}:{$name}");

		// Check the cache first so the api isn't hammered too badly.
		if (Cache::has($key)) { return $this->success(Cache::get($key)); }

		// Get the main character.
		$this->service = $request->header('service');
		$user          = User::where('email', $email)->first();
		$character     = $this->getMainCharacterSheet($user);

		if (!$character) {
			return $this->failure(AuthController::ERRNO_INVALID_MAIN_CHARACTER, AuthController::ERROR_INVALID_MAIN_CHARACTER); }

		// Registered character must be the main character.
		if (!$character->name == $name) {
			return $this->failure(AuthController::ERRNO_INVALID_NOT_MAIN_CHARACTER, AuthController::ERROR_INVALID_NOT_MAIN_CHARACTER); }

		// Verify that the character is authorized.
		if (!$this->isCharacterAuthorized($character)) {
			return $this->failure(AuthController::ERRNO_INVALID_CHARACTER_ACCESS, AuthController::ERROR_INVALID_CHARACTER_ACCESS); }

		// Success! Cache the result for 30 minutes.
		$details = $this->getDetails($user, $character);
		Cache::put($key, $details, Carbon::now()->addMinutes(30));
		return $this->success($details);
	}
}
