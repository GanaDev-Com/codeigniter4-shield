<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Feature;

use Ganadev\Shield\Codeigniter\ShieldServiceProvider;

function firewallSeedIp(string $ip): void
{
    service('superglobals')->setServer('REMOTE_ADDR', $ip);
}

it('allows a normal request while mode is enforcing', function () {
    $config = config('Shield');
    $config->mode = 'enforce';
    ShieldServiceProvider::register();

    firewallSeedIp('198.51.100.11');

    $result = $this->withRoutes([
        ['GET', 'probe-allow', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-allow');

    $result->assertOK();
    $result->assertSee('probe-ok');
});

it('blocks a scanner user agent with the blocked page', function () {
    $config = config('Shield');
    $config->mode = 'enforce';
    $config->responseCode = 403;
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 2;
    $config->thresholdStrongBan = 99;
    ShieldServiceProvider::register();

    firewallSeedIp('198.51.100.12');

    $result = $this->withHeaders([
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-block', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-block');

    $result->assertStatus(403);
    $result->assertHeader('X-Shield-Blocked');
    $result->assertDontSee('probe-ok');
});

it('redirects to the challenge page when the score requires a challenge', function () {
    $config = config('Shield');
    $config->mode = 'challenge';
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 99;
    $config->thresholdStrongBan = 999;
    ShieldServiceProvider::register();

    firewallSeedIp('198.51.100.13');

    $result = $this->withHeaders([
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-challenge', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-challenge');

    $result->assertStatus(302);
    $result->assertHeader('Location');
    expect($result->getRedirectUrl())->toContain('shield/challenge');
});

it('never blocks in observe mode even when thresholds are low', function () {
    $config = config('Shield');
    $config->mode = 'observe';
    $config->thresholdChallenge = 1;
    $config->thresholdBan = 2;
    $config->thresholdStrongBan = 99;
    ShieldServiceProvider::register();

    firewallSeedIp('198.51.100.14');

    $result = $this->withHeaders([
        'User-Agent' => 'sqlmap/1.7.2#stable',
    ])->withRoutes([
        ['GET', 'probe-observe', static fn () => 'probe-ok'],
    ])->call('GET', 'probe-observe');

    $result->assertOK();
    $result->assertSee('probe-ok');
});
