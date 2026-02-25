# Wafio Laravel sample

Example Laravel application that sends HTTP requests to **Wafio** for analysis. If Wafio returns **block**, the app responds with 403; if **allow**, the request continues to the route handler.

This sample follows the same concept as [wafio-client Node.js](../../../wafio-client) and the [Express web sample](../../../wafio-client/examples/web-sample): middleware calls Wafio and blocks with 403 when required.

## Prerequisites

1. **Wafio server** is running (TCP mTLS, default port 9089).
2. **mTLS credentials** are saved from `POST /api/projects/:id/mtls-keys` to a JSON file. Default path: `../mtls-credentials.json` (which resolves to `packages/wafio-client-php/examples/mtls-credentials.json`).

## Install & run

```bash
cd packages/wafio-client-php/examples/laravel-sample
composer install
cp .env.example .env
php artisan key:generate
```

Set Wafio environment values (optional, defaults are available):

```env
WAFIO_CREDENTIALS_FILE=../mtls-credentials.json
WAFIO_HOST=localhost
WAFIO_PORT=9089
```

Run the app:

```bash
php artisan serve
```

Open http://localhost:8000 and try:

- http://localhost:8000/safe
- http://localhost:8000/search?q=hello
- http://localhost:8000/search?q=1' OR '1'='1 (may be blocked)

## Environment

| Env | Default | Description |
|-----|---------|-------------|
| `WAFIO_CREDENTIALS_FILE` | `../mtls-credentials.json` | Path to mTLS credentials file |
| `WAFIO_HOST` | `localhost` | Wafio server host |
| `WAFIO_PORT` | `9089` | Wafio TCP port |

## PHP library

The **wafio/wafio-client-php** package lives in `packages/wafio-client-php` and is installed as a path repository in `composer.json`.

Key APIs:

- `WafioClient` – `connect()`, `analyze(array $req)`, `checkBlock(string $key)`, `getTierLimits()`, `close()`
- `WafioClient::analyzeFromLaravelRequest($request)` – one-call Laravel integration (no manual body/header shaping)
- `Helpers::buildAnalyzeRequest(array $snapshot)` – convert request snapshot to analyze payload (client IP resolution supports `X-Forwarded-For`, `X-Real-IP`, and `Forwarded`)

Middleware used by this sample: `App\Http\Middleware\WafioMiddleware` (registered in `bootstrap/app.php` for the `web` group).
