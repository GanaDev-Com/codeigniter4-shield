<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Support;

final class TrustedProxyInspector
{
    public static function hasConfiguredProxies(): bool
    {
        $config = config('App');

        return ! empty($config->proxyIPs);
    }

    public static function looksDeployedBehindProxy(string $baseURL): bool
    {
        $host = parse_url($baseURL, PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            return false;
        }

        return ! in_array(strtolower($host), ['localhost', '127.0.0.1', '::1', '0.0.0.0'], true);
    }

    public static function forwardedHeaderSeen(array $server): bool
    {
        foreach ['HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $key) {
            if (($server[$key] ?? '') !== '') {
                return true;
            }
        }

        return false;
    }
}
