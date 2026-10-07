<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use Ganadev\Shield\Codeigniter\Support\TrustedProxyInspector;

it('detects configured trusted proxy ips', function () {
    $config = config('App');

    $config->proxyIPs = [];
    expect(TrustedProxyInspector::hasConfiguredProxies())->toBeFalse();

    $config->proxyIPs = ['203.0.113.10'];
    expect(TrustedProxyInspector::hasConfiguredProxies())->toBeTrue();
});

it('detects deployments behind a public host', function () {
    expect(TrustedProxyInspector::looksDeployedBehindProxy('https://example.com/'))->toBeTrue()
        ->and(TrustedProxyInspector::looksDeployedBehindProxy('https://app.example.co.uk'))->toBeTrue()
        ->and(TrustedProxyInspector::looksDeployedBehindProxy('http://localhost:8080/'))->toBeFalse()
        ->and(TrustedProxyInspector::looksDeployedBehindProxy('http://127.0.0.1/'))->toBeFalse()
        ->and(TrustedProxyInspector::looksDeployedBehindProxy('http://[::1]/'))->toBeFalse()
        ->and(TrustedProxyInspector::looksDeployedBehindProxy('not-a-url'))->toBeFalse()
        ->and(TrustedProxyInspector::looksDeployedBehindProxy(''))->toBeFalse();
});

it('detects forwarded headers in the server array', function () {
    expect(TrustedProxyInspector::forwardedHeaderSeen([]))->toBeFalse()
        ->and(TrustedProxyInspector::forwardedHeaderSeen(['HTTP_X_FORWARDED_FOR' => '']))->toBeFalse()
        ->and(TrustedProxyInspector::forwardedHeaderSeen(['HTTP_X_FORWARDED_FOR' => '198.51.100.4']))->toBeTrue()
        ->and(TrustedProxyInspector::forwardedHeaderSeen(['HTTP_FORWARDED' => 'for=198.51.100.4']))->toBeTrue()
        ->and(TrustedProxyInspector::forwardedHeaderSeen(['HTTP_CF_CONNECTING_IP' => '198.51.100.4']))->toBeTrue()
        ->and(TrustedProxyInspector::forwardedHeaderSeen(['HTTP_X_REAL_IP' => '198.51.100.4']))->toBeTrue();
});
