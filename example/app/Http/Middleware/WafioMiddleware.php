<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Wafio\Client\WafioClient;

/**
 * Wafio WAF middleware: sends every request to Wafio for analysis.
 * 
 * Simple single-connection design:
 * - 2000ms timeout per request (mTLS + WAF processing)
 * - 3 failures = 60 second cooldown (fail-open)
 * - Returns 403 when action=block
 * 
 * Env:
 *   WAFIO_CREDENTIALS_FILE  path to mtls-credentials.json
 *   WAFIO_HOST              Wafio server host (default: localhost)
 *   WAFIO_PORT              Wafio port (default: 9089)
 *   WAFIO_DISABLED          set 1/true/yes to disable Wafio
 */
class WafioMiddleware
{
    private static ?WafioClient $client = null;

    public function handle(Request $request, Closure $next): Response
    {
        // Check if Wafio is disabled
        if ($this->isWafioDisabled()) {
            return $next($request);
        }

        try {
            $client = $this->getClient();

            // Analyze request directly from Laravel Request object.
            $result = $client->analyzeFromLaravelRequest($request);

            // If blocked, return 403
            if (($result['action'] ?? '') === 'block') {
                $categories = $result['categories'] ?? [];
                $message = trim((string) ($result['message'] ?? ''));
                if ($message === '' && !empty($categories)) {
                    $message = 'Request blocked: ' . implode(', ', $categories) . '.';
                }
                if ($message === '') {
                    $message = 'Request blocked.';
                }

                return response()->view('errors.403', [
                    'message' => $message,
                    'categories' => $categories,
                ], 403);
            }

            // Request allowed; proceed
            return $next($request);
        } catch (\Throwable $e) {
            // Log the error
            if (config('app.debug')) {
                report($e);
            }

            // Fail-open: always allow on error (circuit breaker handles repeated failures)
            return $next($request);
        }
    }

    /**
     * Check if Wafio is disabled via environment variable.
     */
    private function isWafioDisabled(): bool
    {
        $disabled = getenv('WAFIO_DISABLED');
        return $disabled !== false && preg_match('/^(1|true|yes)$/i', $disabled) === 1;
    }

    /**
     * Get or initialize the single Wafio client (shared across requests).
     */
    private function getClient(): WafioClient
    {
        if (self::$client !== null) {
            return self::$client;
        }

        $credentialsFile = $this->findCredentialsFile();
        
        $host = getenv('WAFIO_HOST') ?: config('services.wafio.host', 'localhost');
        $port = (int) (getenv('WAFIO_PORT') ?: config('services.wafio.port', 9089));

        self::$client = new WafioClient([
            'host' => $host,
            'port' => $port,
            'credentials' => $credentialsFile,
        ]);

        return self::$client;
    }

    /**
     * Find credentials file from multiple possible locations.
     */
    private function findCredentialsFile(): string
    {
        $possiblePaths = [
            getenv('WAFIO_CREDENTIALS_FILE') ?: null,
            base_path('mtls-credentials.json'),
            base_path('../mtls-credentials.json'),
            dirname(base_path()) . '/mtls-credentials.json',
        ];

        foreach ($possiblePaths as $path) {
            if ($path && is_readable($path)) {
                return $path;
            }
        }

        return base_path('mtls-credentials.json');
    }
}

