<?php

declare(strict_types=1);

namespace Wafio\Client;

/**
 * Load and normalize mTLS credentials (same format as wafio-client JS).
 * JSON file from Wafio API: POST /api/projects/:id/mtls-keys → save as mtls-credentials.json.
 */
final class Credentials
{
    /**
     * Load credentials from JSON file (client_cert_pem, client_key_pem, ca_pem).
     *
     * @param string $filePath Path to mtls-credentials.json
     * @return array{client_cert_pem: string, client_key_pem: string, ca_pem: string}
     */
    public static function loadFromFile(string $filePath): array
    {
        if (!is_readable($filePath)) {
            throw new \RuntimeException("Credentials file not readable: {$filePath}");
        }
        $raw = file_get_contents($filePath);
        $data = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException('Invalid JSON in credentials file');
        }
        if (empty($data['client_cert_pem']) || empty($data['client_key_pem'])) {
            throw new \RuntimeException('JSON file must contain client_cert_pem and client_key_pem');
        }
        if (empty($data['ca_pem'])) {
            throw new \RuntimeException('JSON file must contain ca_pem');
        }
        return [
            'client_cert_pem' => self::normalizePem((string) $data['client_cert_pem']),
            'client_key_pem'  => self::normalizePem((string) $data['client_key_pem']),
            'ca_pem'          => self::normalizePem((string) $data['ca_pem']),
        ];
    }

    /**
     * Normalize PEM string (unescape \n, ensure trailing newline).
     */
    public static function normalizePem(string $pem): string
    {
        $s = str_replace(["\\n", "\r\n"], ["\n", "\n"], trim($pem));
        return $s === '' ? '' : rtrim($s) . "\n";
    }
}
