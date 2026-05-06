<?php
// Laravel-style route file; exercises identifiers that are part of
// framework names but unrelated to RCE (e.g. system events, exec order).
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/status', function () {
    return ['ok' => true];
});
