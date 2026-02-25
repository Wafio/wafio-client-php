<?php

declare(strict_types=1);

namespace Wafio\Client;

/**
 * Helpers to build AnalyzeRequest from request snapshot (framework-agnostic).
 * Same behaviour as wafio-client JS: buildAnalyzeRequest, normalizeHeaders, resolveClientIp.
 */
final class Helpers
{
    private const MAX_WAF_BODY_PREVIEW = 64 * 1024;

    /**
     * Resolve client IP from headers (X-Forwarded-For, X-Real-IP, Forwarded) then remoteAddress.
     *
     * @param array<string, string|string[]>|null $headers
     */
    public static function resolveClientIp(?array $headers, ?string $remoteAddress = null): string
    {
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
        if ($forwarded !== '' && preg_match("/for\\s*=\\s*[\"']?([^\"',;\\s]+)/i", $forwarded, $m)) {
            return trim($m[1]);
        }
        return $remoteAddress ?? '127.0.0.1';
    }

    /**
     * Normalize headers to array of string[] (server expects array per header).
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
     * Build AnalyzeRequest from request snapshot (method, url, headers, body, remoteAddress, etc.).
     *
     * @param array{method?: string, url?: string, headers?: array, body?: string, remoteAddress?: string, host?: string, requestId?: string, userAgent?: string} $snapshot
     * @return array<string, mixed> AnalyzeRequest shape for WafioClient::analyze()
     */
    public static function buildAnalyzeRequest(array $snapshot): array
    {
        $headers = self::normalizeHeaders($snapshot['headers'] ?? null);
        $remoteAddress = $snapshot['remoteAddress'] ?? null;
        $remote_addr = self::resolveClientIp($snapshot['headers'] ?? null, $remoteAddress);
        $user_agent = $snapshot['userAgent'] ?? self::getFirstHeader($snapshot['headers'] ?? null, 'user-agent');

        return [
            'method'      => $snapshot['method'] ?? 'GET',
            'uri'         => $snapshot['url'] ?? '/',
            'remote_addr' => $remote_addr,
            'host'        => $snapshot['host'] ?? '',
            'headers'     => $headers,
            'body'        => $snapshot['body'] ?? '',
            'user_agent'  => $user_agent ?? '',
            'request_id'  => $snapshot['requestId'] ?? '',
        ];
    }

    /**
     * Build AnalyzeRequest directly from Laravel Request object.
     *
     * This keeps middleware usage minimal while preserving body limit behavior:
     * - multipart: body uses a safe text preview, body_size uses Content-Length (or estimate)
     * - large non-multipart body: automatically moved to body_b64
     *
     * @param mixed $request Illuminate\Http\Request-compatible object
     * @return array<string, mixed>
     */
    public static function buildAnalyzeRequestFromLaravel($request): array
    {
        $headers = $request->headers->all();
        $contentType = strtolower(self::requestHeader($request, 'Content-Type', ''));
        $isMultipart = strpos($contentType, 'multipart/form-data') !== false;

        if ($isMultipart) {
            $body = self::multipartPreviewBody($request, self::MAX_WAF_BODY_PREVIEW);
            $bodySize = (int) self::requestHeader($request, 'Content-Length', '0');
            if ($bodySize <= 0) {
                $bodySize = self::estimateMultipartBodySize($request);
            }
        } else {
            $body = (string) $request->getContent();
            $bodySize = strlen($body);
        }

        $snapshot = [
            'method' => $request->getMethod(),
            'url' => $request->getRequestUri(),
            'headers' => $headers,
            'body' => $body,
            'remoteAddress' => $request->ip(),
            'host' => $request->getHost(),
            'requestId' => self::requestHeader($request, 'x-request-id', ''),
            'userAgent' => $request->userAgent(),
        ];

        $payload = self::buildAnalyzeRequest($snapshot);
        if ($bodySize > 0) {
            $payload['body_size'] = $bodySize;
        }

        if ($isMultipart) {
            $payload['body'] = $body;
            $payload['body_b64'] = '';
            return $payload;
        }

        if (strlen((string) ($payload['body'] ?? '')) > self::MAX_WAF_BODY_PREVIEW) {
            $realSize = strlen((string) $payload['body']);
            $payload['body_b64'] = base64_encode((string) $payload['body']);
            $payload['body'] = '';
            $payload['body_size'] = $realSize;
        }

        return $payload;
    }

    /**
     * Get first header value (case-insensitive).
     *
     * @param array<string, string|string[]>|null $headers
     */
    public static function getFirstHeader(?array $headers, string $name): string
    {
        if ($headers === null) {
            return '';
        }
        $lower = strtolower($name);
        foreach ($headers as $k => $v) {
            if (strtolower($k) === $lower && $v !== null && $v !== '') {
                $s = is_array($v) ? ($v[0] ?? '') : $v;
                return is_string($s) ? trim($s) : '';
            }
        }
        return '';
    }

    /**
     * @param mixed $request
     */
    private static function requestHeader($request, string $name, string $default): string
    {
        $value = $default;
        if (method_exists($request, 'header')) {
            $value = $request->header($name, $default);
        }
        if ($value === null) {
            return $default;
        }
        return (string) $value;
    }

    /**
     * @param mixed $request
     */
    private static function multipartPreviewBody($request, int $maxBytes): string
    {
        $parts = [];
        $remaining = $maxBytes;

        foreach ($request->request->all() as $key => $value) {
            $line = $key . '=' . (is_scalar($value) ? (string) $value : '');
            if ($remaining <= 0) {
                break;
            }
            if (strlen($line) > $remaining) {
                $line = substr($line, 0, $remaining);
            }
            $parts[] = $line;
            $remaining -= strlen($line);
        }

        if ($remaining > 0) {
            foreach (self::flattenFiles($request->allFiles()) as $fileMeta) {
                $line = 'file_' . $fileMeta['field'] . '=' . $fileMeta['name'];
                if (strlen($line) > $remaining) {
                    $line = substr($line, 0, $remaining);
                }
                $parts[] = $line;
                $remaining -= strlen($line);
                if ($remaining <= 0) {
                    break;
                }
            }
        }

        return implode("\n", $parts);
    }

    /**
     * @param mixed $request
     */
    private static function estimateMultipartBodySize($request): int
    {
        $size = 0;

        foreach ($request->request->all() as $key => $value) {
            $size += strlen((string) $key);
            if (is_scalar($value)) {
                $size += strlen((string) $value);
            }
        }

        foreach (self::flattenFiles($request->allFiles()) as $fileMeta) {
            $size += (int) $fileMeta['size'];
            $size += strlen((string) $fileMeta['name']);
        }

        return $size;
    }

    /**
     * @param array<string, mixed> $files
     * @return array<int, array{field: string, name: string, size: int}>
     */
    private static function flattenFiles(array $files, string $prefix = ''): array
    {
        $out = [];
        foreach ($files as $name => $value) {
            $field = $prefix === '' ? (string) $name : $prefix . '.' . (string) $name;

            if (is_object($value)
                && method_exists($value, 'getClientOriginalName')
                && method_exists($value, 'getSize')) {
                $out[] = [
                    'field' => $field,
                    'name' => (string) ($value->getClientOriginalName() ?: $field),
                    'size' => (int) $value->getSize(),
                ];
                continue;
            }

            if (is_array($value)) {
                $out = array_merge($out, self::flattenFiles($value, $field));
            }
        }

        return $out;
    }
}
