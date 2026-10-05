<?php

declare(strict_types=1);

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */

$routes->get('/', 'HomeController::index');
$routes->get('home', 'HomeController::index');
$routes->get('login', 'HomeController::login');
$routes->post('login', 'HomeController::login');
$routes->get('api/users', 'HomeController::apiUsers');
$routes->post('api/login', 'HomeController::apiLogin');
