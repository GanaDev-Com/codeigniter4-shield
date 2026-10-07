<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use Ganadev\Shield\Codeigniter\Cache\CodeIgniterCacheAdapter;
use Ganadev\Shield\Codeigniter\Challenge\NullTestDriver;
use Ganadev\Shield\Codeigniter\Challenge\RecaptchaDriver;
use Ganadev\Shield\Codeigniter\Challenge\TurnstileDriver;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Codeigniter\Trust\DnsCrawlerVerifier;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Engine\ShieldEngine;

it('builds the core config from the live ci config', function () {
    config('Shield')->appId = 'resolver-app-id';
    config('Shield')->thresholdBan = 25;

    $config = (new ShieldResolver)->config();

    expect($config)->toBeInstanceOf(ShieldConfig::class)
        ->and($config->appId)->toBe('resolver-app-id')
        ->and($config->thresholdBan)->toBe(25);
});

it('builds the rule repository with and without optional packs', function () {
    $resolver = new ShieldResolver;
    $default = count($resolver->rules()->all());

    config('Shield')->rulesPacksWordpress = true;
    $withWordpress = count((new ShieldResolver)->rules()->all());

    config('Shield')->rulesPacksWordpress = false;
    config('Shield')->rulesPacksInjection = false;
    $withoutInjection = count((new ShieldResolver)->rules()->all());

    expect($withWordpress)->toBeGreaterThan($default)
        ->and($withoutInjection)->toBeLessThan($default);
});

it('builds an engine that inspects requests', function () {
    $engine = (new ShieldResolver)->engine();

    expect($engine)->toBeInstanceOf(ShieldEngine::class)
        ->and($engine->trustedCookieName())->toBeString()->not->toBe('');

    $result = $engine->inspect(
        RequestContext::create('/about', 'GET', 'localhost', '198.51.100.50'),
        new BehaviorCounters,
    );

    expect($result->shouldBlock())->toBeFalse();
});

it('builds the crawler verifier wired to the cache and config', function () {
    $verifier = (new ShieldResolver)->crawlerVerifier();

    expect($verifier)->toBeInstanceOf(DnsCrawlerVerifier::class);
});

it('builds a cache adapter that round trips values', function () {
    $adapter = (new ShieldResolver)->cacheAdapter();

    expect($adapter)->toBeInstanceOf(CodeIgniterCacheAdapter::class);

    $key = 'resolver-roundtrip-'.uniqid('', true);
    expect($adapter->has($key))->toBeFalse();

    $adapter->set($key, 'value-1', 60);
    expect($adapter->get($key))->toBe('value-1')
        ->and($adapter->has($key))->toBeTrue()
        ->and($adapter->increment($key, 60))->toBe(1);

    $adapter->delete($key);
    expect($adapter->has($key))->toBeFalse();
});

it('resolves challenge drivers from the driver name', function () {
    $resolver = new ShieldResolver;

    config('Shield')->challengeDriver = 'null';
    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);

    config('Shield')->challengeDriver = '';
    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);

    config('Shield')->challengeDriver = 'test';
    expect($resolver->challengeDriver())->toBeInstanceOf(NullTestDriver::class);

    config('Shield')->challengeDriver = '  Recaptcha ';
    expect($resolver->challengeDriver())->toBeInstanceOf(RecaptchaDriver::class);

    config('Shield')->challengeDriver = 'google_recaptcha';
    expect($resolver->challengeDriver())->toBeInstanceOf(RecaptchaDriver::class);

    config('Shield')->challengeDriver = 'turnstile';
    expect($resolver->challengeDriver())->toBeInstanceOf(TurnstileDriver::class);

    config('Shield')->challengeDriver = 'unknown-driver';
    expect($resolver->challengeDriver())->toBeInstanceOf(TurnstileDriver::class);
});
