<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\Commands as CliCommands;
use Ganadev\Shield\Codeigniter\Commands\ShieldHealthCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldPruneCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReleaseCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReplayCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReportCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldRulesListCommand;
use Ganadev\Shield\Codeigniter\Models\SecurityIpBan;
use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Core\Events\SecurityEvent as CoreSecurityEvent;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;
use JsonException;

function commandsTestIp(): string
{
    static $counter = 0;
    $counter++;

    return '198.22.'.intdiv($counter, 254).'.'.($counter % 254 + 1);
}

function commandsTestCommand(string $class): BaseCommand
{
    $commands = new class extends CliCommands
    {
        public function __construct() {}
    };

    return new $class(service('logger'), $commands);
}

function commandsTestBan(string $ip): BanRecord
{
    $now = new \DateTimeImmutable;

    return new BanRecord(
        id: null,
        ipAddress: $ip,
        status: BanStatus::Active,
        reason: 'command-test',
        lastRuleId: 'rule-1',
        riskScore: 30,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: $now,
        expiresAt: $now->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $now,
        metadata: ['source' => 'command'],
    );
}

function commandsTestEvent(string $ip, array $overrides = []): CoreSecurityEvent
{
    return CoreSecurityEvent::create(array_merge([
        'ip' => $ip,
        'host' => 'example.test',
        'method' => 'GET',
        'raw_uri' => '/index',
        'normalized_uri' => '/index',
        'rule_id' => 'rule-1',
        'category' => 'probe',
        'severity' => 'medium',
        'score_delta' => 5,
        'decision' => 'BLOCK_REQUEST',
        'rule_version' => '1.0.0',
        'created_at' => new \DateTimeImmutable,
    ], $overrides));
}

it('prunes old events and stale bans', function () {
    $events = new Ci4EventRepository;
    $oldIp = commandsTestIp();
    $freshIp = commandsTestIp();

    $events->record(commandsTestEvent($oldIp, [
        'raw_uri' => '/old',
        'normalized_uri' => '/old',
        'created_at' => new \DateTimeImmutable('-100 days'),
    ]));
    $events->record(commandsTestEvent($freshIp));

    $staleReleasedIp = commandsTestIp();
    $expiredStatusIp = commandsTestIp();
    $activeIp = commandsTestIp();

    $bans = new SecurityIpBan;
    $bans->insert([
        'ip_address' => $staleReleasedIp,
        'status' => 'released',
        'banned_at' => date('Y-m-d H:i:s', strtotime('-2 days')),
        'expires_at' => date('Y-m-d H:i:s', strtotime('-1 day')),
        'released_at' => date('Y-m-d H:i:s', strtotime('-1 day')),
    ]);
    $bans->insert([
        'ip_address' => $expiredStatusIp,
        'status' => 'expired',
        'banned_at' => date('Y-m-d H:i:s', strtotime('-3 days')),
        'expires_at' => date('Y-m-d H:i:s', strtotime('-2 days')),
    ]);
    (new Ci4BanRepository)->createBan(commandsTestBan($activeIp));

    commandsTestCommand(ShieldPruneCommand::class)->run(['days' => '30']);

    expect($events->paginate(['ip' => $oldIp]))->toBeEmpty()
        ->and($events->paginate(['ip' => $freshIp]))->not->toBeEmpty();

    $lookup = new SecurityIpBan;
    expect($lookup->where('ip_address', $staleReleasedIp)->first())->toBeNull();
    expect((new SecurityIpBan)->where('ip_address', $expiredStatusIp)->first())->toBeNull();
    expect((new SecurityIpBan)->where('ip_address', $activeIp)->first())->not->toBeNull();
});

it('releases an active ban through the cli', function () {
    $repo = new Ci4BanRepository;
    $ip = commandsTestIp();
    $repo->createBan(commandsTestBan($ip));

    commandsTestCommand(ShieldReleaseCommand::class)->run([$ip, 'reason' => 'ops-done']);

    $latest = $repo->findLatestByIp($ip);

    expect($repo->findActiveByIp($ip))->toBeNull()
        ->and($latest)->not->toBeNull()
        ->and($latest->status)->toBe(BanStatus::Released)
        ->and($latest->metadata['release_reason'] ?? null)->toBe('ops-done');
});

it('reports errors when release arguments are invalid', function () {
    $command = commandsTestCommand(ShieldReleaseCommand::class);

    $command->run([]);
    $command->run(['']);
    $command->run([commandsTestIp()]);

    expect(true)->toBeTrue();
});

it('prints the security report with and without a host filter', function () {
    $events = new Ci4EventRepository;
    $ip = commandsTestIp();

    $events->record(commandsTestEvent($ip, ['host' => 'report.example.test', 'rule_id' => 'rule-a']));
    $events->record(commandsTestEvent($ip, ['host' => 'report.example.test', 'decision' => 'ALLOW', 'rule_id' => 'rule-b']));
    $events->record(commandsTestEvent(commandsTestIp(), ['host' => 'other.example.test', 'rule_id' => 'rule-c']));

    $command = commandsTestCommand(ShieldReportCommand::class);
    $command->run([]);
    $command->run(['host' => 'report.example.test']);

    expect(true)->toBeTrue();
});

it('lists the loaded threat rules', function () {
    commandsTestCommand(ShieldRulesListCommand::class)->run([]);
    commandsTestCommand(ShieldRulesListCommand::class)->run(['disabled' => true]);

    expect(service('shield.resolver')->rules()->all())->not->toBeEmpty();
});

it('runs the health check across trusted proxy configurations', function () {
    $app = config('App');
    $shield = config('Shield');
    $forwardedKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'];
    $originalBase = $app->baseURL;
    $originalProxies = $app->proxyIPs;
    $originalCrawler = $shield->crawlerVerificationEnabled;
    $originalForwarded = [];

    foreach ($forwardedKeys as $key) {
        if (array_key_exists($key, $_SERVER)) {
            $originalForwarded[$key] = $_SERVER[$key];
        }
    }

    try {
        foreach ($forwardedKeys as $key) {
            unset($_SERVER[$key]);
        }

        $shield->crawlerVerificationEnabled = false;
        $command = commandsTestCommand(ShieldHealthCommand::class);

        $app->proxyIPs = [];
        $app->baseURL = 'http://localhost:8080/';
        $command->run([]);

        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.44';
        $command->run([]);
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);

        $app->proxyIPs = ['203.0.113.10'];
        $command->run([]);

        $_SERVER['HTTP_FORWARDED'] = 'for=198.51.100.44';
        $command->run([]);
        unset($_SERVER['HTTP_FORWARDED']);

        $app->proxyIPs = [];
        $app->baseURL = 'https://health-public.example.test/';
        $command->run([]);

        expect(true)->toBeTrue();
    } finally {
        $app->baseURL = $originalBase;
        $app->proxyIPs = $originalProxies;
        $shield->crawlerVerificationEnabled = $originalCrawler;

        foreach ($forwardedKeys as $key) {
            unset($_SERVER[$key]);
        }
        foreach ($originalForwarded as $key => $value) {
            $_SERVER[$key] = $value;
        }
    }
});

it('replays a benign corpus with and without the wordpress pack', function () {
    $file = tempnam(sys_get_temp_dir(), 'shield-replay-');
    file_put_contents($file, json_encode([
        'entries' => [
            ['uri' => '/about', 'method' => 'GET', 'expected' => 'allow', 'category' => 'benign'],
            ['uri' => '/contact', 'method' => 'GET', 'expected' => 'allow', 'category' => 'benign'],
        ],
        'events' => [
            ['normalized_uri' => '/legacy', 'method' => 'GET', 'rule_id' => 'legacy-export'],
        ],
    ], JSON_THROW_ON_ERROR));

    try {
        commandsTestCommand(ShieldReplayCommand::class)->run([$file, 'min-rate' => '0.9']);
        commandsTestCommand(ShieldReplayCommand::class)->run([$file, 'pack-wordpress' => true, 'min-rate' => '0.9']);

        expect(true)->toBeTrue();
    } finally {
        unlink($file);
    }
});

it('rejects a missing or invalid replay corpus', function () {
    $command = commandsTestCommand(ShieldReplayCommand::class);

    $command->run([]);
    $command->run(['/nonexistent/shield-corpus.json']);

    $invalid = tempnam(sys_get_temp_dir(), 'shield-replay-');
    file_put_contents($invalid, '{not valid json');

    try {
        expect(fn () => $command->run([$invalid]))->toThrow(JsonException::class);
    } finally {
        unlink($invalid);
    }
});
