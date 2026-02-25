# wafio-client-php

A production-ready **PHP client** for **Wafio** WAF over TCP mTLS.
Analyze incoming HTTP requests and check whether a client key is currently blocked.

**Works with:**
- ✅ PHP 8.1+
- ✅ Laravel, Symfony, and plain PHP
- ✅ Full type hints and PHPDoc

**Features:**
- **Fail-open by default** (circuit breaker behavior)
- **FPM-safe connection model** (connect per operation, then close)
- **mTLS authentication** with server verification
- **Framework-agnostic helpers** for request-to-analyze conversion
- **Feature parity** with TypeScript and Go clients (`analyze`, `checkBlock`, `getTierLimits`)

## Installation

```bash
composer require wafio/wafio-client-php
```

Monorepo local path example:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "packages/wafio-client-php"
    }
  ],
  "require": {
    "wafio/wafio-client-php": "*"
  }
}
```

Then run:

```bash
composer install
```

## Quick Start

### 1. Prepare mTLS credentials

Generate or download your project mTLS key from the Wafio dashboard and save it as JSON (for example `mtls-credentials.json`).

Expected fields:

```json
{
  "ca_pem": "-----BEGIN CERTIFICATE-----...",
  "client_cert_pem": "-----BEGIN CERTIFICATE-----...",
  "client_key_pem": "-----BEGIN PRIVATE KEY-----...",
  "tcp_url": "tcp.wafio.cloud:9443"
}
```

### 2. Create a client and analyze a request

```php
<?php

use Wafio\Client\WafioClient;

$client = new WafioClient([
  'credentials' => __DIR__ . '/mtls-credentials.json', // tcp_url dipakai otomatis
]);

$result = $client->analyze([
    'method' => 'POST',
    'uri' => '/api/login',
    'remote_addr' => '203.0.113.42',
    'host' => 'app.example.com',
    'headers' => [
        'content-type' => ['application/json'],
        'user-agent' => ['Mozilla/5.0'],
    ],
    'body' => '{"email":"alice@example.com"}',
]);

if (($result['action'] ?? 'allow') === 'block') {
    http_response_code(403);
    echo 'Request blocked: ' . ($result['message'] ?? 'Forbidden');
    exit;
}

echo 'Request allowed';
```

Laravel shortcut (no manual body/header mapping in middleware):

```php
$result = $client->analyzeFromLaravelRequest($request);
```

The client automatically handles:
- request header normalization
- real client IP resolution
- multipart preview body + `body_size`
- large body fallback to `body_b64`

### 3. Check block window

```php
$status = $client->checkBlock('203.0.113.42');

if (!empty($status['blocked'])) {
    http_response_code(403);
    echo 'Client is currently blocked';
    exit;
}
```

## Core Concepts

### `analyze()` vs `checkBlock()`

- **`analyze()`** performs full WAF inspection and returns decision metadata (`action`, `score`, `categories`, `message`).
- **`checkBlock()`** is a fast block-window lookup for a key (for example IP or user key).

### Fail-open behavior

By default, if Wafio is unavailable:

1. Request is allowed.
2. Failure counter increments.
3. After threshold is reached, cooldown is applied.
4. During cooldown, requests are immediately allowed (no network attempt).

This prevents your app from hard-failing when Wafio is temporarily down.

### PHP-FPM connection model

This client is intentionally optimized for PHP-FPM:

- Opens connection per operation (`analyze`, `checkBlock`, `getTierLimits`)
- Closes connection after response
- Avoids stale shared sockets across independent requests

## Request Helpers

Use `Helpers` to build analyze payloads consistently across frameworks.

```php
use Wafio\Client\Helpers;

$snapshot = [
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'url' => $_SERVER['REQUEST_URI'] ?? '/',
    'headers' => getallheaders() ?: [],
    'body' => file_get_contents('php://input') ?: '',
    'remoteAddress' => $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
    'host' => $_SERVER['HTTP_HOST'] ?? '',
    'requestId' => $_SERVER['HTTP_X_REQUEST_ID'] ?? '',
    'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
];

$analyzeReq = Helpers::buildAnalyzeRequest($snapshot);
```

Client IP resolution order:

1. `X-Forwarded-For` (first IP)
2. `X-Real-IP`
3. `Forwarded`
4. `remoteAddress`

## Configuration

```php
$client = new WafioClient([
    'credentials' => '/path/to/mtls-credentials.json',
]);
```

Required option:

- `credentials`: file path or PEM array containing `client_cert_pem`, `client_key_pem`, `ca_pem` (optional `tcp_url`)

Optional options:

- `host` (optional override; default from `tcp_url` if available, else `localhost`)
- `port` (optional override; default from `tcp_url` if available, else `9089`)

Built-in behavior values:

| Setting | Value |
|---|---|
| request timeout | 2000ms |
| connect timeout | 2000ms |
| failure threshold | 3 |
| cooldown | 60s |

## API Surface

Main class: `Wafio\Client\WafioClient`

- `connect(): void`
- `analyze(array $req): array`
- `analyzeFromLaravelRequest($request, array $overrides = []): array`
- `checkBlock(string $key): array`
- `getTierLimits(): ?int`
- `close(): void`

Helpers:

- `Wafio\Client\Helpers::buildAnalyzeRequest(array $snapshot): array`
- `Wafio\Client\Helpers::resolveClientIp(?array $headers, ?string $remoteAddress = null): string`
- `Wafio\Client\Credentials::loadFromFile(string $filePath): array`

## Examples

- `packages/wafio-client-php/examples/laravel-sample`
- `packages/wafio-client-php/examples/laravel-sample-alt`
- `packages/wafio-client-php/examples/form-example.php`

## Troubleshooting

- `credentials must include ca_pem` → ensure JSON includes `ca_pem`
- TLS/connect errors → check host/port and server certificates
- Requests always allowed when server is down → expected fail-open behavior

## License

MIT
