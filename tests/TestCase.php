<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use Config\Encryption;
use Config\Services;
use Ganadev\Shield\Codeigniter\ShieldServiceProvider;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;

abstract class TestCase extends CIUnitTestCase
{
    use DatabaseTestTrait;

    protected $namespace = 'Ganadev\Shield\Codeigniter';

    protected $seed = '';

    protected $basePath = __DIR__.'/../';

    protected function setUp(): void
    {
        parent::setUp();

        $config = new Encryption;
        $config->key = 'base64:47v1LbFEGV5Tsf+IMtI66K/PVuyP/r9wGCE67OFTYZY=';
        $config->driver = 'OpenSSL';

        $encrypter = Services::encrypter($config);
        Services::injectMock('encrypter', $encrypter);

        $cache = Services::cache();
        Services::injectMock('cache', $cache);

        ShieldServiceProvider::register();
        // Ensure challenge service is registered for unit tests
        if (function_exists('service')) {
            if (service('shield.challenge') === null) {
                $resolver = service('shield.resolver') ?? new ShieldResolver;
                Services::injectMock('shield.challenge', $resolver->challengeDriver());
            }
        }
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }
}
