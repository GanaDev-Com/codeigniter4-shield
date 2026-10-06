<?php

declare(strict_types=1);

$base = dirname(__DIR__);

define('HOMEPATH', $base.'/');
define('CONFIGPATH', $base.'/vendor/codeigniter4/framework/app/Config/');
define('PUBLICPATH', $base.'/vendor/codeigniter4/framework/public/');
define('SYSTEMPATH', $base.'/vendor/codeigniter4/framework/system/');
define('ROOTPATH', $base.'/vendor/codeigniter4/framework/');
define('APPPATH', $base.'/vendor/codeigniter4/framework/app/');
define('WRITEPATH', $base.'/vendor/codeigniter4/framework/writable/');
define('TESTPATH', $base.'/tests/');

require_once SYSTEMPATH.'Test/bootstrap.php';
