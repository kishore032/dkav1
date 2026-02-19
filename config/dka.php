<?php

return [
    /*
    |--------------------------------------------------------------------------
    | DKA Identity
    |--------------------------------------------------------------------------
    */
    'username'      => env('DKA_USERNAME', 'dka'),
    'terse'         => env('DKA_TERSE', 'no-reply'),
    'domain'        => env('DKA_DOMAIN', 'dka.example.com'),
    'target_domain' => env('DKA_TARGET_DOMAIN', '*'),

    /*
    |--------------------------------------------------------------------------
    | DKA Behavior
    |--------------------------------------------------------------------------
    */
    'token_ttl'     => (int) env('DKA_TOKEN_TTL', 900),
    'unlock_delay'  => (int) env('DKA_UNLOCK_DELAY', 60),
    'version'       => (int) env('DKA_VERSION', 1),

    /*
    |--------------------------------------------------------------------------
    | Mailgun
    |--------------------------------------------------------------------------
    */
    'mg_signing_key' => env('MG_SIGNING_KEY'),
    'mg_domain'      => env('MG_DOMAIN'),
    'mg_secret'      => env('MG_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | Hidden selectors — never returned by lookup or selectors API
    |--------------------------------------------------------------------------
    */
    'hidden_selectors' => ['dka-status', 'api'],
];
