<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;

abstract class TestCase extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $namespace = 'Ganadev\Shield\Codeigniter';
    protected $seed = '';
    protected $basePath = __DIR__.'/../';

    protected function setUp(): void
    {
        parent::setUp();

        $config = new \Config\Encryption();
        $config->key = 'base64:47v1LbFEGV5Tsf+IMtI66K/PVuyP/r9wGCE67OFTYZY=';
        $config->driver = 'OpenSSL';

        $encrypter = \Config\Services::encrypter($config);
        \Config\Services::injectMock('encrypter', $encrypter);

        $cache = \Config\Services::cache();
        \Config\Services::injectMock('cache', $cache);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }
}
