<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Core\Events\SecurityEvent;

function eventRepoUniqueIp(): string
{
    static $counter = 0;
    $counter++;

    return '198.19.'.intdiv($counter, 254).'.'.($counter % 254 + 1);
}

function eventRepoMake(string $ip, array $extra = []): SecurityEvent
{
    return SecurityEvent::create(array_merge([
        'ip' => $ip,
        'host' => 'example.test',
        'method' => 'GET',
        'raw_uri' => '/login?token=x',
        'normalized_uri' => '/login',
        'rule_id' => 'rule-7',
        'category' => 'sqli',
        'severity' => 'high',
        'score_delta' => 12,
        'decision' => 'BLOCK_REQUEST',
        'user_agent' => 'sqlmap/1.7',
        'rule_version' => '1.0.0',
        'created_at' => new \DateTimeImmutable,
    ], $extra));
}

it('records an event row', function () {
    $repo = new Ci4EventRepository;
    $ip = eventRepoUniqueIp();

    $repo->record(eventRepoMake($ip));

    $rows = $repo->paginate(['ip' => $ip]);

    expect($rows)->toHaveCount(1);
    expect($rows[0])->toMatchArray([
        'ip_address' => $ip,
        'host' => 'example.test',
        'method' => 'GET',
        'raw_uri' => '/login?token=x',
        'normalized_uri' => '/login',
        'rule_id' => 'rule-7',
        'category' => 'sqli',
        'severity' => 'high',
        'score_delta' => 12,
        'decision' => 'BLOCK_REQUEST',
        'user_agent' => 'sqlmap/1.7',
        'rule_version' => '1.0.0',
    ]);
});

it('filters and pages paginated events', function () {
    $repo = new Ci4EventRepository;
    $ip = eventRepoUniqueIp();

    $repo->record(eventRepoMake($ip));
    $repo->record(eventRepoMake($ip, [
        'rule_id' => 'rule-9',
        'severity' => 'low',
        'decision' => 'ALLOW',
        'host' => 'other.test',
    ]));

    expect($repo->paginate(['ip' => $ip], 10, 1))->toHaveCount(2)
        ->and($repo->paginate(['ip' => $ip, 'decision' => 'BLOCK_REQUEST'], 10, 1))->toHaveCount(1)
        ->and($repo->paginate(['ip' => $ip, 'rule_id' => 'rule-9'], 10, 1))->toHaveCount(1)
        ->and($repo->paginate(['ip' => $ip, 'severity' => 'low'], 10, 1))->toHaveCount(1)
        ->and($repo->paginate(['ip' => $ip, 'host' => 'other.test'], 10, 1))->toHaveCount(1)
        ->and($repo->paginate(['ip' => $ip, 'host' => 'missing.test'], 10, 1))->toHaveCount(0);

    $pageOne = $repo->paginate(['ip' => $ip], 1, 1);
    $pageTwo = $repo->paginate(['ip' => $ip], 1, 2);
    expect($pageOne)->toHaveCount(1)
        ->and($pageTwo)->toHaveCount(1)
        ->and($pageTwo[0]['id'])->not->toBe($pageOne[0]['id']);
});

it('prunes events older than the cutoff', function () {
    $repo = new Ci4EventRepository;
    $oldIp = eventRepoUniqueIp();
    $freshIp = eventRepoUniqueIp();

    $repo->record(eventRepoMake($oldIp, [
        'created_at' => new \DateTimeImmutable('-100 days'),
    ]));
    $repo->record(eventRepoMake($freshIp));

    $deleted = $repo->pruneOlderThan(new \DateTimeImmutable('-30 days'));

    expect($deleted)->toBeGreaterThanOrEqual(1);
    expect($repo->paginate(['ip' => $oldIp]))->toBeEmpty()
        ->and($repo->paginate(['ip' => $freshIp]))->not->toBeEmpty();
});
