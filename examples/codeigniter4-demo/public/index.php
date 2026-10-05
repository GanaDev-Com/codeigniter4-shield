<?php

declare(strict_types=1);

// Path to the front controller
define('FCPATH', __DIR__ . DIRECTORY_SEPARATOR);

// Ensure the current directory is pointing to the front controller's directory
chdir(FCPATH);

// Load the framework
require_once FCPATH . '../vendor/codeigniter4/framework/system/bootstrap.php';

// Load the config
$paths = new Config\Paths();

// Launch the app
$app = new CodeIgniter\CodeIgniter($paths);
$app->run();
