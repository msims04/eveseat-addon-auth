<?php
/*
The MIT License (MIT)

Copyright (c) 2015 msims04

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
* DO NOT CHANGE
*/
if (empty($lang) || !is_array($lang)) { $lang = []; }

$lang = array_merge($lang, [
	'LOGIN_ERROR_UNKNOWN'                  => 'An unknown error has occured.',
	'LOGIN_ERROR_ADMIN_USERNAME'           => 'You cannot login using the admin username.',
	'LOGIN_ERROR_INVALID_CONNECTION'       => 'There was an error communicating with the SeAT server. Please try again later.',
	'LOGIN_ERROR_INVALID_CREDENTIALS'      => 'Those credentials are invalid.',
	'LOGIN_ERROR_INVALID_MAIN_CHARACTER'   => 'That account does not have valid main character set.',
	'LOGIN_ERROR_INVALID_CHARACTER_ACCESS' => 'You are not authorized to use this service.',

	'SEAT_CONFIG'                          => 'SeAT API Configuration',
	'SEAT_ADDRESS'                         => 'Address',
	'SEAT_ADDRESS_EXPLAIN'                 => 'The API application\'s auth address. (e.g. https://seat.example.com/api/ex/auth)',
	'SEAT_TOKEN'                           => 'Token',
	'SEAT_TOKEN_EXPLAIN'                   => 'The API application\'s authentication token.',
	'SEAT_VERIFY_SSL'                      => 'Verify SSL Certificate',
	'SEAT_VERIFY_SSL_EXPLAIN'              => 'Only turn this off if you are using a self-signed certificate.',
]);
