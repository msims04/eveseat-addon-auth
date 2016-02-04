<?php

Route::group([
	'namespace'  => 'Seat\Addon\Auth\Http\Controllers',
	'middleware' => 'api.auth',
	'prefix'     => 'api'
], function () {
	Route::group(['namespace' => 'ex', 'prefix' => 'ex'], function () {
		Route::controller('auth', 'AuthController');
	});
});
