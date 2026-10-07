<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use Ganadev\Shield\Codeigniter\Cache\CodeIgniterCacheAdapter;
use Ganadev\Shield\Codeigniter\Challenge\NullTestDriver;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Context\RequestContext;

it('namespaces cache keys with the app id', function () {
    $adapter = new CodeIgniterCacheAdapter(service('cache'), 'my-app');
    $adapter->set('ban-1-2-3-4', ['status' => 'active'], 60);

    $result = service('cache')->get('shield-my-app-ban-1-2-3-4');
    expect($result)->toBe(['status' => 'active']);
    expect(service('cache')->get('ban-1-2-3-4'))->toBeNull();
});

it('increments counters atomically when supported', function () {
    $adapter = new CodeIgniterCacheAdapter(service('cache'), 'my-app');

    expect($adapter->increment('counters:x', 60))->toBe(1);
    expect($adapter->increment('counters:x', 60))->toBe(2);
});

it('resets the counter when the window expires', function () {
    $adapter = new CodeIgniterCacheAdapter(service('cache'), 'my-app');

    expect($adapter->increment('counters:burst', 60))->toBe(1);
    expect($adapter->increment('counters:burst', 60))->toBe(2);

    service('cache')->delete('shield-my-app-counters-burst');

    expect($adapter->increment('counters:burst', 60))->toBe(1);
});

it('supports delete and has operations', function () {
    $adapter = new CodeIgniterCacheAdapter(service('cache'), 'my-app');

    $adapter->set('k', 'v', 60);
    expect($adapter->has('k'))->toBeTrue();
    expect($adapter->delete('k'))->toBeTrue();
    expect($adapter->has('k'))->toBeFalse();
});

it('null test driver is deterministic', function () {
    $driver = new NullTestDriver;
    $context = RequestContext::create('/home', 'GET', 'example.test', '203.0.113.10');

    expect($driver->name())->toBe('null');
    expect($driver->verify('test-token', $context)->passed)->toBeTrue();
    expect($driver->verify('wrong', $context)->passed)->toBeFalse();
});

it('resolves a challenge driver from the container', function () {
    expect(service('shield.challenge'))->toBeInstanceOf(ChallengeDriverInterface::class);
});

it('treats an env-null driver value as the null test driver', function () {
    config('Shield')->challengeDriver = '';
    $resolver = new ShieldResolver;

    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);

    config('Shield')->challengeDriver = 'null';
    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);
});
