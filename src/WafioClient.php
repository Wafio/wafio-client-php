<?php

declare(strict_types=1);

namespace Wafio\Client;

/**
 * Wafio TCP mTLS client. Simple, single-connection design for PHP.
 * 
 * Features:
 * - Instance-scoped connection (short-lived, connect on demand)
 * - 2000ms timeout per request (includes mTLS handshake + processing)
 * - Circuit breaker: 3 failures = 60s cooldown
 * - Fail-open: returns allow on timeout
 */
final class WafioClient
{
    private const TYPE_CHECK_BLOCK_REQ  = 0x01;
    private const TYPE_ANALYZE_REQ     = 0x02;
    private const TYPE_TIER_LIMITS_REQ  = 0x03;
    private const TYPE_CHECK_BLOCK_RESP = 0x81;
    private const TYPE_ANALYZE_RESP    = 0x82;
    private const TYPE_TIER_LIMITS_RESP = 0x83;

    // Simple config (hardcoded)
    private const TIMEOUT_MS = 2000;
    private const FAIL_THRESHOLD = 3;
    private const COOLDOWN_SECONDS = 60;

    // Circuit breaker state shared in worker process
    private static int $failCount = 0;
    private static int $cooldownUntil = 0;

    // Instance socket state (safe for PHP-FPM request lifecycle)
    private mixed $socket = null;
    private string $readBuffer = '';

    // Instance config
    private string $host;
    private int $port;
    /** @var array{client_cert_pem: string, client_key_pem: string, ca_pem: string} */
    private array $credentials;
    /** @var string[] Temp file paths for SSL context (deleted on close) */
    private array $tempFiles = [];


    /**
     * @param array{
     *   host?: string,
     *   port?: int,
     *   credentials: string|array{client_cert_pem: string, client_key_pem: string, ca_pem?: string, tcp_url?: string}
     * } $options
     */
    public function __construct(array $options)
    {
        $creds = $options['credentials'];
        $resolvedTcpUrl = null;
        if (is_string($creds)) {
            $loaded = Credentials::loadFromFile($creds);
            $resolvedTcpUrl = isset($loaded['tcp_url']) && is_string($loaded['tcp_url']) ? trim($loaded['tcp_url']) : null;
            $this->credentials = [
                'client_cert_pem' => $loaded['client_cert_pem'],
                'client_key_pem'  => $loaded['client_key_pem'],
                'ca_pem'          => $loaded['ca_pem'],
            ];
        } else {
            $resolvedTcpUrl = isset($creds['tcp_url']) && is_string($creds['tcp_url']) ? trim($creds['tcp_url']) : null;
            $this->credentials = [
                'client_cert_pem' => Credentials::normalizePem($creds['client_cert_pem'] ?? ''),
                'client_key_pem'  => Credentials::normalizePem($creds['client_key_pem'] ?? ''),
                'ca_pem'          => Credentials::normalizePem($creds['ca_pem'] ?? ''),
            ];
        }

        $parsedEndpoint = self::parseTcpEndpoint($resolvedTcpUrl);
        $this->host = $options['host'] ?? ($parsedEndpoint['host'] ?? 'localhost');
        $this->port = (int) ($options['port'] ?? ($parsedEndpoint['port'] ?? 9089));

        if ($this->credentials['ca_pem'] === '') {
            throw new \InvalidArgumentException('credentials must include ca_pem');
        }
    }

    /**
     * @return array{host: string, port: int}|null
     */
    private static function parseTcpEndpoint(?string $raw): ?array
    {
        if ($raw === null) {
            return null;
        }
        $endpoint = trim($raw);
        if ($endpoint === '') {
            return null;
        }
        $endpoint = preg_replace('#^(tls|tcp|https?)://#i', '', $endpoint) ?? $endpoint;
        $slashPos = strpos($endpoint, '/');
        if ($slashPos !== false) {
            $endpoint = substr($endpoint, 0, $slashPos);
        }
        if (str_starts_with($endpoint, ':')) {
            $endpoint = 'localhost' . $endpoint;
        }

        $parsed = parse_url('tcp://' . $endpoint);
        if (!is_array($parsed)) {
            return null;
        }

        $host = isset($parsed['host']) && is_string($parsed['host']) && $parsed['host'] !== ''
            ? $parsed['host']
            : 'localhost';
        $port = isset($parsed['port']) ? (int) $parsed['port'] : 9089;
        if ($port <= 0 || $port > 65535) {
            return null;
        }

        return ['host' => $host, 'port' => $port];
    }

    /**
     * Connect to the Wafio server (mTLS). Auto-called by analyze/checkBlock.
     * Uses 2 second timeout for initial connection (mTLS handshake).
     */
    public function connect(): void
    {
        if ($this->socket !== null && $this->isConnected()) {
            return;
        }
        
        $certFile = $this->writeTempFile('wafio-cert-', $this->credentials['client_cert_pem']);
        $keyFile  = $this->writeTempFile('wafio-key-', $this->credentials['client_key_pem']);
        $caFile   = $this->writeTempFile('wafio-ca-', $this->credentials['ca_pem']);
        $this->tempFiles = [$certFile, $keyFile, $caFile];

        $ctx = stream_context_create([
            'ssl' => [
                'local_cert'        => $certFile,
                'local_pk'          => $keyFile,
                'cafile'            => $caFile,
                'verify_peer'       => true,
                'verify_peer_name'  => true,
            ],
        ]);
        $target = 'tls://' . $this->host . ':' . $this->port;
        $errno = 0;
        $errstr = '';
        $timeout = 2.0; // 2 second timeout for initial connection
        $sock = @stream_socket_client(
            $target,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        
        if ($sock === false) {
            $this->deleteTempFiles();
            throw new \RuntimeException("Wafio connect failed: {$errstr} ({$errno})");
        }
        $this->socket = $sock;
        stream_set_blocking($this->socket, true);
        // Set 5000ms timeout for all streaming operations
        stream_set_timeout($this->socket, 0, self::TIMEOUT_MS * 1000);
    }

    public function isConnected(): bool
    {
        return $this->socket !== null && is_resource($this->socket) && !feof($this->socket);
    }

    /**
     * Get tier limits from server.
     * Returns max_tcp_connections or null on error.
     *
     * @return int|null
     */
    public function getTierLimits(): ?int
    {
        try {
            if (!$this->isConnected()) {
                $this->connect();
            }
            $frame = $this->sendFrame(self::TYPE_TIER_LIMITS_REQ, []);
            if ($frame['type'] === self::TYPE_TIER_LIMITS_RESP && is_array($frame['body'])) {
                return (int) ($frame['body']['max_tcp_connections'] ?? null);
            }
            return null;
        } catch (\Throwable $e) {
            return null;
        } finally {
            $this->disconnect();
        }
    }


    /**
     * Analyze a request. Returns allow/block and metadata.
     * 
     * Circuit breaker:
     * - 3 failures = 60 second cooldown
     * - During cooldown, returns allow with error
     * - After cooldown expires, tries to connect again
     *
     * @param array{method: string, uri: string, remote_addr: string, host?: string, headers?: array, body?: string, body_b64?: string, body_size?: int, user_agent?: string, request_id?: string} $req
     * @return array{action: string, score?: int, categories?: array|null, message?: string, error?: string}
     */
    public function analyze(array $req): array
    {
        // Check circuit breaker cooldown
        if (self::$cooldownUntil > 0 && time() < self::$cooldownUntil) {
            return ['action' => 'allow', 'error' => 'wafio unavailable (cooldown, try again in ' . (self::$cooldownUntil - time()) . 's)'];
        }
        // Reset fail count when cooldown expires
        if (self::$cooldownUntil > 0 && time() >= self::$cooldownUntil) {
            self::$failCount = 0;
            self::$cooldownUntil = 0;
        }

        try {
            if (!$this->isConnected()) {
                $this->connect();
            }

            $payload = [
                'method'      => $req['method'] ?? 'GET',
                'uri'         => $req['uri'] ?? '/',
                'remote_addr' => $req['remote_addr'] ?? '127.0.0.1',
                'host'        => $req['host'] ?? '',
                'headers'     => $req['headers'] ?? [],
                'body'        => $req['body'] ?? '',
                'body_b64'    => $req['body_b64'] ?? '',
                'user_agent'  => $req['user_agent'] ?? '',
                'request_id'  => $req['request_id'] ?? '',
            ];
            if (isset($req['body_size']) && (int) $req['body_size'] > 0) {
                $payload['body_size'] = (int) $req['body_size'];
            }
            $frame = $this->sendFrame(self::TYPE_ANALYZE_REQ, $payload);
            if ($frame['type'] !== self::TYPE_ANALYZE_RESP) {
                return ['action' => 'allow', 'error' => 'unexpected response type'];
            }
            // Success: reset fail counter
            self::$failCount = 0;
            return $frame['body'];
        } catch (\Throwable $e) {
            // Increment fail count and check threshold
            self::$failCount++;
            if (self::$failCount >= self::FAIL_THRESHOLD) {
                self::$cooldownUntil = time() + self::COOLDOWN_SECONDS;
                // Try to disconnect
                try {
                    $this->disconnect();
                } catch (\Throwable $e2) {
                    // ignore
                }
            }
            // Always fail-open
            return ['action' => 'allow', 'error' => 'timeout/unavailable (fail-open)'];
        } finally {
            $this->disconnect();
        }
    }

    /**
     * Analyze a Laravel request directly.
     *
     * @param mixed $request Illuminate\Http\Request-compatible object
     * @param array<string, mixed> $overrides Optional payload overrides
     * @return array{action: string, score?: int, categories?: array|null, message?: string, error?: string}
     */
    public function analyzeFromLaravelRequest($request, array $overrides = []): array
    {
        $payload = Helpers::buildAnalyzeRequestFromLaravel($request);
        if ($overrides !== []) {
            $payload = array_merge($payload, $overrides);
        }
        return $this->analyze($payload);
    }

    /**
     * Check if a key is currently in the block window.
     * On timeout/error: returns not blocked (fail-open).
     *
     * @return array{blocked: bool, error?: string}
     */
    public function checkBlock(string $key): array
    {
        // Check circuit breaker
        if (self::$cooldownUntil > 0 && time() < self::$cooldownUntil) {
            return ['blocked' => false, 'error' => 'cooldown'];
        }

        try {
            if (!$this->isConnected()) {
                $this->connect();
            }
            $frame = $this->sendFrame(self::TYPE_CHECK_BLOCK_REQ, ['key' => $key !== '' ? $key : 'unknown']);
            if ($frame['type'] !== self::TYPE_CHECK_BLOCK_RESP) {
                return ['blocked' => false, 'error' => 'unexpected response type'];
            }
            self::$failCount = 0;
            return $frame['body'];
        } catch (\Throwable $e) {
            self::$failCount++;
            if (self::$failCount >= self::FAIL_THRESHOLD) {
                self::$cooldownUntil = time() + self::COOLDOWN_SECONDS;
                try {
                    $this->disconnect();
                } catch (\Throwable $e2) {
                    // ignore
                }
            }
            return ['blocked' => false, 'error' => 'unavailable'];
        } finally {
            $this->disconnect();
        }
    }

    public function close(): void
    {
        $this->disconnect();
    }

    private function disconnect(): void
    {
        if ($this->socket !== null && is_resource($this->socket)) {
            @fclose($this->socket);
            $this->socket = null;
        }
        $this->readBuffer = '';
        $this->deleteTempFiles();
    }

    /**
     * Send a frame and wait for the matching response.
     *
     * @param array<string, mixed> $payload
     * @return array{type: int, body: array}
     */
    private function sendFrame(int $type, array $payload): array
    {
        if ($this->socket === null || !is_resource($this->socket)) {
            throw new \RuntimeException('Not connected. Call connect() first.');
        }
        $body = json_encode($payload, JSON_THROW_ON_ERROR);
        $bodyLen = strlen($body);
        $lenBe = pack('N', $bodyLen);
        $frame = chr($type) . $lenBe . $body;
        $written = @fwrite($this->socket, $frame);
        if ($written !== strlen($frame)) {
            throw new \RuntimeException('Write failed');
        }
        return $this->readFrame();
    }

    /**
     * @return array{type: int, body: array}
     */
    private function readFrame(): array
    {
        if ($this->socket === null) {
            throw new \RuntimeException('Not connected');
        }
        while (strlen($this->readBuffer) < 5) {
            $chunk = fread($this->socket, 8192);
            if ($chunk === false || $chunk === '') {
                throw new \RuntimeException('Read failed or connection closed');
            }
            $this->readBuffer .= $chunk;
        }
        $bodyLen = unpack('N', substr($this->readBuffer, 1, 4))[1];
        $need = 5 + $bodyLen;
        while (strlen($this->readBuffer) < $need) {
            $chunk = fread($this->socket, 8192);
            if ($chunk === false || $chunk === '') {
                throw new \RuntimeException('Read failed or connection closed');
            }
            $this->readBuffer .= $chunk;
        }
        $type = ord($this->readBuffer[0]);
        $bodyStr = substr($this->readBuffer, 5, $bodyLen);
        $this->readBuffer = substr($this->readBuffer, $need);
        $body = json_decode($bodyStr, true);
        if (!is_array($body)) {
            $body = ['error' => 'invalid json'];
        }
        return ['type' => $type, 'body' => $body];
    }

    private function writeTempFile(string $prefix, string $content): string
    {
        $f = tempnam(sys_get_temp_dir(), $prefix);
        if ($f === false) {
            throw new \RuntimeException('Failed to create temp file');
        }
        file_put_contents($f, $content);
        return $f;
    }

    private function deleteTempFiles(): void
    {
        foreach ($this->tempFiles as $path) {
            if (file_exists($path)) {
                @unlink($path);
            }
        }
        $this->tempFiles = [];
    }

    public function __destruct()
    {
        $this->close();
    }
}
