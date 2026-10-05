<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Cache\Handlers\FileHandler;
use CodeIgniter\Config\BaseConfig;

class Cache extends BaseConfig
{
    public string $handler = 'file';
    public string $backupHandler = 'dummy';
    public string $prefix = '';
    public int $ttl = 60;
    public string $fileStorePath = WRITEPATH . 'cache/';
}
