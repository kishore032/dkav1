<?php

use App\Http\Controllers\RawmailController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

// Mailgun inbound webhook (exempt from CSRF in bootstrap/app.php)
Route::post('/webhook/mailgun', [RawmailController::class, 'receive']);
