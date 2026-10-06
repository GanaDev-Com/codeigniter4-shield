<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Trust;

use CodeIgniter\Config\Services;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

final class Ci4TrustedCookie implements TrustedCookieInterface
{
    public function name(): string
    {
        return 'shield_trusted';
    }

    public function issue(RequestContext $context, int $ttlMinutes): string
    {
        $payload = [
            'exp' => time() + ($ttlMinutes * 60),
            'ua' => $this->uaHash($context->userAgent()),
            'ip' => $this->coarsePrefix($context->ip),
        ];

        $json = json_encode($payload);
        $key = $this->getEncryptionKey();

        return base64_encode($json . '|' . hash_hmac('sha256', $json, $key));
    }

    public function validate(string $cookieValue, RequestContext $context): bool
    {
        $trimmed = ltrim($cookieValue);
        if ($trimmed !== '' && ($trimmed[0] === '{' || $trimmed[0] === '[')) {
            return false;
        }

        $decoded = base64_decode($cookieValue, true);
        if ($decoded === false) {
            return false;
        }

        $parts = explode('|', $decoded, 2);
        if (count($parts) !== 2) {
            return false;
        }

        [$json, $hmac] = $parts;

        $key = $this->getEncryptionKey();
        if (!hash_equals(hash_hmac('sha256', $json, $key), $hmac)) {
            return false;
        }

        $payload = json_decode($json, true);
        if (!is_array($payload)) {
            return false;
        }

        $exp = (int) ($payload['exp'] ?? 0);
        if ($exp <= time()) {
            return false;
        }

        if (($payload['ua'] ?? '') !== $this->uaHash($context->userAgent())) {
            return false;
        }

        if (($payload['ip'] ?? '') !== $this->coarsePrefix($context->ip)) {
            return false;
        }

        return true;
    }

    private function getEncryptionKey(): string
    {
        try {
            $encrypter = Services::encrypter();
            $key = $encrypter->key ?? '';
            if ($key !== '') {
                return $key;
            }
        } catch (\Throwable) {
        }

        return 'shield-test-key';
    }

    private function uaHash(string $userAgent): string
    {
        return hash('sha256', strtolower(trim($userAgent)));
    }

    private function coarsePrefix(string $ip): string
    {
        if (str_contains($ip, ':')) {
            $parts = explode(':', $ip);

            return implode(':', array_slice($parts, 0, 4));
        }

        $parts = explode('.', $ip);

        return implode('.', array_slice($parts, 0, 3));
    }
}
