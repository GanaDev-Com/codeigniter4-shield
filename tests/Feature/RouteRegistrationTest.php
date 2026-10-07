<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Feature;

use CodeIgniter\Exceptions\PageNotFoundException;
use Ganadev\Shield\Codeigniter\ShieldServiceProvider;

it('always exposes the challenge route through auto discovery', function () {
    $result = $this->withRoutes([])->call('GET', 'shield/challenge');

    $result->assertOK();
});

it('keeps the admin routes hidden while the panel is disabled', function () {
    config('Shield')->adminEnabled = false;
    ShieldServiceProvider::register();

    expect(fn () => $this->withRoutes([])->call('GET', 'shield/bans'))
        ->toThrow(PageNotFoundException::class);
    expect(fn () => $this->withRoutes([])->call('GET', 'shield/events'))
        ->toThrow(PageNotFoundException::class);
    expect(fn () => $this->withRoutes([])->call('GET', 'shield/health'))
        ->toThrow(PageNotFoundException::class);
});

it('exposes the admin routes once the panel is enabled', function () {
    config('Shield')->adminEnabled = true;
    ShieldServiceProvider::register();

    $bans = $this->withRoutes([])->call('GET', 'shield/bans');
    $events = $this->withRoutes([])->call('GET', 'shield/events');
    $rules = $this->withRoutes([])->call('GET', 'shield/rules');
    $health = $this->withRoutes([])->call('GET', 'shield/health');

    $bans->assertOK();
    $events->assertOK();
    $rules->assertOK();
    $health->assertOK();
});
