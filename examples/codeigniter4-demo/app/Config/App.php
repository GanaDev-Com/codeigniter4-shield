<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\BaseConfig;

class App extends BaseConfig
{
    public string $baseURL = 'http://localhost:8080';
    public string $indexPage = '';
    public array $proxyIPs = [];
    public bool $CSRFProtection = true;
    public string $CSRFTokenName = 'csrf_test_name';
    public string $CSRFCookieName = 'csrf_cookie_name';
    public int $CSRFExpire = 7200;
    public bool $CSRFRegenerate = true;
    public array $CSRFExcludeURIs = [];
    public bool $CSRFRedirect = true;
    public string $CSRFSameSite = 'Lax';
}
