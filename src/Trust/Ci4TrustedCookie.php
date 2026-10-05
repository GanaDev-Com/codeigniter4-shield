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

        $encrypter = Services::encrypter();

        return $encrypter->encrypt(json_encode($payload));
    }

    public function validate(string $cookieValue, RequestContext $context): bool
    {
        $trimmed = ltrim($cookieValue);
        if ($trimmed !== '' && ($trimmed[0] === '{' || $trimmed[0] === '[')) {
            return false;
        }

        try {
            $encrypter = Services::encrypter();
            $decrypted = $encrypter->decrypt($cookieValue);
            $payload = json_decode($decrypted, true);
        } catch (\Throwable) {
            return false;
        }

        if (! is_array($payload)) {
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
