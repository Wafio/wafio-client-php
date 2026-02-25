<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Third Party Services
    |--------------------------------------------------------------------------
    |
    | This file is for storing the credentials for third party services such
    | as Mailgun, Postmark, AWS and more. This file provides the de facto
    | location for this type of information, allowing packages to have
    | a conventional file to locate the various service credentials.
    |
    */

    'postmark' => [
        'key' => env('POSTMARK_API_KEY'),
    ],

    'resend' => [
        'key' => env('RESEND_API_KEY'),
    ],

    'ses' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'region' => env('AWS_DEFAULT_REGION', 'us-east-1'),
    ],

    'slack' => [
        'notifications' => [
            'bot_user_oauth_token' => env('SLACK_BOT_USER_OAUTH_TOKEN'),
            'channel' => env('SLACK_BOT_USER_DEFAULT_CHANNEL'),
        ],
    ],

    'wafio' => [
        'credentials_file' => (function () {
            $p = env('WAFIO_CREDENTIALS_FILE') ?: base_path('../mtls-credentials.json');
            if ($p !== '' && !str_starts_with($p, '/') && (PHP_OS_FAMILY !== 'Windows' || !preg_match('#^[A-Za-z]:#', $p))) {
                $p = base_path($p);
            }
            return $p;
        })(),
        'host' => env('WAFIO_HOST', 'localhost'),
        'port' => env('WAFIO_PORT', 9089),
    ],

];
