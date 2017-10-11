<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| This file is where you may define all of the routes that are handled
| by your application. Just tell Laravel the URIs it should respond
| to using a Closure or controller method. Build something great!
|
*/

Route::resource('/', 'HomeController');
Route::resource('/links', 'LinksController');
Route::resource('/monitors', 'MonitorsController');
Route::resource('/origins', 'OriginsController');
Route::resource('/asnames', 'AsnamesController');
Route::resource('/ipquery', 'IpqueryController');
Route::get('/test', function(){return view('test');});
Route::resource('whois', 'WhoisController');
Route::get('whois_api','WhoisController@whois_api');
Route::get('whois_file','WhoisController@whois_file');
Route::get('whois_file1','WhoisController@whois_file1');