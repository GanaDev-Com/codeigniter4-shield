<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Database\Config;

class Database extends Config
{
    public string $filesPath = APPPATH . 'Database' . DIRECTORY_SEPARATOR;
    public string $DBDriver = 'SQLite3';
    public string $database = 'database/shield.sqlite';
    public string $DBPrefix = '';
    public int $port = 3306;
    public string $hostname = 'localhost';
    public string $username = '';
    public string $password = '';
    public string $charset = 'utf8mb4';
    public string $DBCollat = 'utf8mb4_general_ci';
    public bool $encrypt = false;
    public bool $compress = false;
    public bool $strictOn = false;
    public array $failover = [];
    public bool $saveQueries = true;
}
