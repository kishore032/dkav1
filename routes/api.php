<?php

use App\Http\Controllers\LookupController;
use App\Http\Controllers\SubmissionController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function () {
    // Public lookup (unauthenticated)
    Route::get('/lookup',    [LookupController::class, 'lookup']);
    Route::get('/selectors', [LookupController::class, 'selectors']);
    Route::get('/version',   [LookupController::class, 'version']);
    Route::get('/apis',      [LookupController::class, 'apis']);

    // Authenticated submission
    Route::post('/challenge', [SubmissionController::class, 'challenge']);
    Route::post('/submit',    [SubmissionController::class, 'submit']);
});
