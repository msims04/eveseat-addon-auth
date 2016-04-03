<?php

return [

	'dokuwiki' => [
		'min_access_mask'        => env('AUTH_ADDON_DOKUWIKI_MIN_ACCESS_MASK'       , 1073741823),
		'allow_expiration_dates' => env('AUTH_ADDON_DOKUWIKI_ALLOW_EXPIRATION_DATES', false),
		'allow_guests'           => false,
		'characters'             => env('AUTH_ADDON_DOKUWIKI_CHARACTERS'            , ''),
		'corporations'           => env('AUTH_ADDON_DOKUWIKI_CORPORATIONS'          , ''),
		'alliances'              => env('AUTH_ADDON_DOKUWIKI_ALLIANCES'             , ''),
	],

	'intel' => [
		'min_access_mask'        => env('AUTH_ADDON_INTEL_MIN_ACCESS_MASK'       , 1073741823),
		'allow_expiration_dates' => env('AUTH_ADDON_INTEL_ALLOW_EXPIRATION_DATES', false),
		'allow_guests'           => false,
		'characters'             => env('AUTH_ADDON_INTEL_CHARACTERS'            , ''),
		'corporations'           => env('AUTH_ADDON_INTEL_CORPORATIONS'          , ''),
		'alliances'              => env('AUTH_ADDON_INTEL_ALLIANCES'             , ''),
	],

	'mumble' => [
		'min_access_mask'        => env('AUTH_ADDON_MUMBLE_MIN_ACCESS_MASK'       , 1073741823),
		'allow_expiration_dates' => env('AUTH_ADDON_MUMBLE_ALLOW_EXPIRATION_DATES', false),
		'allow_guests'           => env('AUTH_ADDON_MUMBLE_ALLOW_GUESTS'          , false),
		'characters'             => env('AUTH_ADDON_MUMBLE_CHARACTERS'            , ''),
		'corporations'           => env('AUTH_ADDON_MUMBLE_CORPORATIONS'          , ''),
		'alliances'              => env('AUTH_ADDON_MUMBLE_ALLIANCES'             , ''),
	],

	'phpbb' => [
		'min_access_mask'        => env('AUTH_ADDON_PHPBB_MIN_ACCESS_MASK'       , 1073741823),
		'allow_expiration_dates' => env('AUTH_ADDON_PHPBB_ALLOW_EXPIRATION_DATES', false),
		'allow_guests'           => false,
		'characters'             => env('AUTH_ADDON_PHPBB_CHARACTERS'            , ''),
		'corporations'           => env('AUTH_ADDON_PHPBB_CORPORATIONS'          , ''),
		'alliances'              => env('AUTH_ADDON_PHPBB_ALLIANCES'             , ''),
	],

];
