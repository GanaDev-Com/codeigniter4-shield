<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests;

use CodeIgniter\Test\CIUnitTestCase;
use CodeIgniter\Test\DatabaseTestTrait;
use CodeIgniter\Test\FeatureTestTrait;

abstract class TestCase extends CIUnitTestCase
{
    use DatabaseTestTrait;
    use FeatureTestTrait;

    protected $namespace = 'Ganadev\Shield\Codeigniter';
    protected $seed = '';
    protected $basePath = __DIR__.'/../';

    protected function setUp(): void
    {
        parent::setUp();

        $this->db->table('security_ip_bans')->emptyTable();
        $this->db->table('security_events')->emptyTable();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        $this->db->table('security_ip_bans')->emptyTable();
        $this->db->table('security_events')->emptyTable();
    }
}
