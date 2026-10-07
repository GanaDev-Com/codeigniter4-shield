<?php

declare(strict_types=1);

use CodeIgniter\Router\RouteCollection;
use Ganadev\Shield\Codeigniter\Controllers\AdminController;
use Ganadev\Shield\Codeigniter\Controllers\ChallengeController;

/**
 * @var RouteCollection $routes
 */
$routes->get('shield/challenge', [ChallengeController::class, 'show'], ['as' => 'shield.challenge']);
$routes->post('shield/challenge/verify', [ChallengeController::class, 'verify'], ['as' => 'shield.challenge.verify']);

if (config('Shield')->adminEnabled) {
    $prefix = config('Shield')->adminPrefix;

    $routes->group($prefix, static function (RouteCollection $routes): void {
        $routes->get('bans', [AdminController::class, 'bans'], ['as' => 'shield.bans']);
        $routes->get('bans/([0-9]+)', [AdminController::class, 'banDetail'], ['as' => 'shield.bans.detail']);
        $routes->post('bans/([0-9]+)/release', [AdminController::class, 'release'], ['as' => 'shield.bans.release']);
        $routes->post('bans/([0-9]+)/extend', [AdminController::class, 'extend'], ['as' => 'shield.bans.extend']);
        $routes->get('events', [AdminController::class, 'events'], ['as' => 'shield.events']);
        $routes->get('rules', [AdminController::class, 'rules'], ['as' => 'shield.rules']);
        $routes->get('health', [AdminController::class, 'health'], ['as' => 'shield.health']);
    });
}
