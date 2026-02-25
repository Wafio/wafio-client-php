<?php

declare(strict_types=1);

namespace Wafio\Client;

/**
 * Build AnalyzeRequest from request snapshot (framework-agnostic).
 * Client IP resolved from proxy headers (X-Forwarded-For, X-Real-IP, Forwarded).
 */
final class WafioRequest
{
    /**
     * Resolve client IP from snapshot: proxy headers then remoteAddress.
     *
     * @param array{headers?: array<string, string|string[]>, remoteAddress?: string} $snapshot
     */
    public static function resolveClientIp(array $snapshot): string
    {
        $headers = $snapshot['headers'] ?? [];
        $xff = self::getFirstHeader($headers, 'x-forwarded-for');
        if ($xff !== '') {
            $first = trim(explode(',', $xff)[0] ?? '');
            if ($first !== '') {
                return $first;
            }
        }
        $xri = self::getFirstHeader($headers, 'x-real-ip');
        if ($xri !== '') {
            return $xri;
        }
        $forwarded = self::getFirstHeader($headers, 'forwarded');
        if ($forwarded !== '' && preg_match("/for\\s*=\\s*[\"']?([^\"',;\\s]+)/i", $forwarded, $m) === 1) {
            return trim($m[1]);
        }
        return $snapshot['remoteAddress'] ?? '127.0.0.1';
    }

    /**
     * Normalize headers to array<string, string[]> (server format).
     *
     * @param array<string, string|string[]>|null $headers
     * @return array<string, string[]>
     */
    public static function normalizeHeaders(?array $headers): array
    {
        if ($headers === null || $headers === []) {
            return [];
        }
        $out = [];
        foreach ($headers as $k => $v) {
            if ($v === null || $v === '') {
                continue;
            }
            $out[$k] = is_array($v) ? $v : [$v];
        }
        return $out;
    }

    /**
     * Build AnalyzeRequest from snapshot (for WafioClient::analyze()).
     *
     * @param array{method?: string, url?: string, headers?: array, body?: string, remoteAddress?: string, host?: string, requestId?: string, userAgent?: string} $snapshot
     * @return array{method: string, uri: string, remote_addr: string, host: string, headers: array<string, string[]>, body: string, user_agent: string, request_id: string}
     */
    public static function buildAnalyzeRequest(array $snapshot): array
    {
        $headers = self::normalizeHeaders($snapshot['headers'] ?? null);
        $remote_addr = self::resolveClientIp($snapshot);
        $user_agent = $snapshot['userAgent'] ?? self::getFirstHeader($snapshot['headers'] ?? [], 'user-agent');
        return [
            'method'      => $snapshot['method'] ?? 'GET',
            'uri'        => $snapshot['url'] ?? '/',
            'remote_addr' => $remote_addr,
            'host'       => $snapshot['host'] ?? '',
            'headers'    => $headers,
            'body'       => $snapshot['body'] ?? '',
            'user_agent' => $user_agent,
            'request_id' => $snapshot['requestId'] ?? '',
        ];
    }

    /**
     * Build snapshot from Laravel Request (Illuminate\Http\Request).
     * Type hint mixed so the package does not require illuminate/http; pass Laravel request when using Laravel.
     *
     * @param mixed $request Laravel Request: getMethod(), getRequestUri(), ip(), header(), getContent()
     * @return array{method: string, url: string, headers: array, body?: string, remoteAddress?: string, host?: string, requestId?: string, userAgent?: string}
     */
    public static function fromRequest($request): array
    {
        $method = $request->getMethod();
        $url = $request->getRequestUri();
        $headers = $request->headers->all();
        $body = $request->getContent() ?: null;
        if ($body === '' && $request->getContentType() === 'application/json') {
            $body = json_encode($request->all());
        }
        $remoteAddress = $request->ip();
        $host = $request->getHost();
        return [
            'method'        => $method,
            'url'          => $url,
            'headers'      => $headers,
            'body'         => $body,
            'remoteAddress' => $remoteAddress,
            'host'         => $host,
            'requestId'    => $request->header('x-request-id'),
            'userAgent'    => $request->userAgent(),
        ];
    }

    /**
     * @param array<string, string|string[]> $headers
     */
    private static function getFirstHeader(array $headers, string $name): string
    {
        $lower = strtolower($name);
        foreach ($headers as $k => $v) {
            if (strtolower($k) === $lower && $v !== null && $v !== '') {
                $s = is_array($v) ? ($v[0] ?? '') : $v;
                return trim((string) $s);
            }
        }
        return '';
    }
}
