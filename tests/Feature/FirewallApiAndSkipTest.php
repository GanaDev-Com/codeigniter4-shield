<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Feature;

use Ganadev\Shield\Codeigniter\ShieldServiceProvider;

function apiSkipSeedIp(string $ip): void
{
    service('superglobals')->setServer('REMOTE_ADDR', $ip);
}

it('returns a json block to api clients', function () {
    $config = config('Shield');
    $config->mode = 'enforce';
    $config->responseCode = 403;
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 2;
    $config->thresholdStrongBan = 99;
    ShieldServiceProvider::register();

    apiSkipSeedIp('198.23.10.11');

    $result = $this->withHeaders([
        'Accept' => 'application/json',
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-api', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-api');

    $result->assertStatus(403);
    $result->assertHeader('X-Shield-Blocked');

    $payload = json_decode((string) $result->getJSON(), true);
    expect($payload['error'] ?? null)->toBe('request_blocked')
        ->and($payload['rule_id'] ?? null)->not->toBe('')
        ->and($payload['score'] ?? 0)->toBeGreaterThan(0);
    $result->assertDontSee('probe-ok');
});

it('returns a json challenge response to api clients', function () {
    $config = config('Shield');
    $config->mode = 'challenge';
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 99;
    $config->thresholdStrongBan = 999;
    ShieldServiceProvider::register();

    apiSkipSeedIp('198.23.10.12');

    $result = $this->withHeaders([
        'Accept' => 'application/json',
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-api-challenge', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-api-challenge');

    $result->assertStatus(401);
    $result->assertHeader('X-Shield-Challenge');

    $payload = json_decode((string) $result->getJSON(), true);
    expect($payload['error'] ?? null)->toBe('challenge_required')
        ->and($payload['challenge_url'] ?? null)->toContain('shield/challenge');
});

it('detects api requests through configured paths and xhr headers', function () {
    $config = config('Shield');
    $config->mode = 'enforce';
    $config->responseCode = 403;
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 2;
    $config->thresholdStrongBan = 99;
    $config->apiPaths = ['/api'];
    ShieldServiceProvider::register();

    apiSkipSeedIp('198.23.10.13');

    $pathResult = $this->withHeaders([
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'api/ping', static fn () => 'api-ok'],
    ])->call('GET', 'api/ping');

    $pathResult->assertStatus(403);
    $payload = json_decode((string) $pathResult->getJSON(), true);
    expect($payload['error'] ?? null)->toBe('request_blocked');

    $xhrResult = $this->withHeaders([
        'X-Requested-With' => 'XMLHttpRequest',
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-xhr', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-xhr');

    $xhrResult->assertStatus(403);
    $payload = json_decode((string) $xhrResult->getJSON(), true);
    expect($payload['error'] ?? null)->toBe('request_blocked');
});

it('allows everything while the firewall is disabled', function () {
    $config = config('Shield');
    $config->enabled = false;
    ShieldServiceProvider::register();

    apiSkipSeedIp('198.23.10.14');

    $result = $this->withHeaders([
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-disabled', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-disabled');

    $result->assertOK();
    $result->assertSee('probe-ok');
});

it('skips behavior scoring on configured skip paths', function () {
    $config = config('Shield');
    $config->mode = 'enforce';
    $config->responseCode = 403;
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 2;
    $config->thresholdStrongBan = 99;
    $config->skipPaths = ['/safe-skip'];
    ShieldServiceProvider::register();

    apiSkipSeedIp('198.23.10.15');

    $skipped = $this->withRoutes([
        ['GET', 'safe-skip/page', static fn () => 'safe-ok'],
    ])->call('GET', 'safe-skip/page');

    $skipped->assertOK();
    $skipped->assertSee('safe-ok');

    $scored = $this->withRoutes([
        ['GET', 'probe-scored', static fn () => 'scored-ok'],
    ])->call('GET', 'probe-scored');

    $scored->assertStatus(403);
    $scored->assertDontSee('scored-ok');
});
