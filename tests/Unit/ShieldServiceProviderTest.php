<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use CodeIgniter\Test\TestLogger;
use Ganadev\Shield\Codeigniter\Cache\CodeIgniterCacheAdapter;
use Ganadev\Shield\Codeigniter\Commands\ShieldHealthCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldPruneCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReleaseCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReplayCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReportCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldRulesListCommand;
use Ganadev\Shield\Codeigniter\Filters\SecurityFirewallFilter;
use Ganadev\Shield\Codeigniter\ShieldServiceProvider;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Engine\ShieldEngine;

it('registers the shared shield services', function () {
    expect(service('shield.resolver'))->toBeInstanceOf(ShieldResolver::class)
        ->and(service('shield.config'))->toBeInstanceOf(ShieldConfig::class)
        ->and(service('shield.engine'))->toBeInstanceOf(ShieldEngine::class)
        ->and(service('shield.cache'))->toBeInstanceOf(CodeIgniterCacheAdapter::class)
        ->and(service('shield.challenge'))->toBeInstanceOf(ChallengeDriverInterface::class);
});

it('rebuilds the services from the mutated config', function () {
    $engineBefore = service('shield.engine');
    $originalAppId = config('Shield')->appId;

    try {
        config('Shield')->appId = 'provider-rebuild';
        ShieldServiceProvider::register();

        expect(service('shield.engine'))->not->toBe($engineBefore)
            ->and(service('shield.config')->appId)->toBe('provider-rebuild');
    } finally {
        config('Shield')->appId = $originalAppId;
    }
});

it('registers the firewall filter exactly once', function () {
    ShieldServiceProvider::register();
    ShieldServiceProvider::register();

    $filters = config('Filters');
    $occurrences = count(array_keys($filters->globals['before'], 'shield.firewall', true));

    expect($occurrences)->toBe(1)
        ->and($filters->aliases['shield.firewall'])->toBe(SecurityFirewallFilter::class);
});

it('skips command registration when the app has no Config\Commands', function () {
    ShieldServiceProvider::register();

    expect(class_exists('Config\\Commands', false))->toBeFalse()
        ->and(config('Commands'))->toBeNull();
});

it('registers the shield commands without duplicating them', function () {
    if (! class_exists('Config\\Commands', false)) {
        eval('namespace Config; class Commands { public array $shield = []; }');
    }

    ShieldServiceProvider::register();
    ShieldServiceProvider::register();

    $registered = config('Commands')->shield;

    expect($registered)->toContain(
        ShieldPruneCommand::class,
        ShieldReleaseCommand::class,
        ShieldHealthCommand::class,
        ShieldReportCommand::class,
        ShieldRulesListCommand::class,
        ShieldReplayCommand::class,
    )->and($registered)->toHaveCount(6);
});

it('warns when running on a public host without trusted proxies', function () {
    $app = config('App');
    $shield = config('Shield');
    $originalBase = $app->baseURL;
    $originalProxies = $app->proxyIPs;
    $originalMode = $shield->mode;

    try {
        $app->proxyIPs = [];
        $app->baseURL = 'https://warn-public.example.test/';
        $shield->mode = 'enforce';

        ShieldServiceProvider::register();

        expect(TestLogger::didLog('warning', 'warn-public.example.test', false))->toBeTrue();

        $app->baseURL = 'https://warn-skip.example.test/';
        $shield->mode = 'observe';
        ShieldServiceProvider::register();
        expect(TestLogger::didLog('warning', 'warn-skip.example.test', false))->toBeFalse();

        $app->baseURL = 'http://localhost:9090/';
        $shield->mode = 'enforce';
        ShieldServiceProvider::register();
        expect(TestLogger::didLog('warning', 'localhost:9090', false))->toBeFalse();
    } finally {
        $app->baseURL = $originalBase;
        $app->proxyIPs = $originalProxies;
        $shield->mode = $originalMode;
    }
});

it('skips the proxy warning when trusted proxies are configured', function () {
    $app = config('App');
    $shield = config('Shield');
    $originalBase = $app->baseURL;
    $originalProxies = $app->proxyIPs;
    $originalMode = $shield->mode;

    try {
        $app->proxyIPs = ['203.0.113.7'];
        $app->baseURL = 'https://warn-proxied.example.test/';
        $shield->mode = 'enforce';

        ShieldServiceProvider::register();

        expect(TestLogger::didLog('warning', 'warn-proxied.example.test', false))->toBeFalse();
    } finally {
        $app->baseURL = $originalBase;
        $app->proxyIPs = $originalProxies;
        $shield->mode = $originalMode;
    }
});
