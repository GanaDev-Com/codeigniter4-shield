<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;

function banRepoUniqueIp(): string
{
    static $counter = 0;
    $counter++;

    return '198.18.'.intdiv($counter, 254).'.'.($counter % 254 + 1);
}

function banRepoMake(string $ip, ?\DateTimeImmutable $expiresAt = null): BanRecord
{
    $now = new \DateTimeImmutable;

    return new BanRecord(
        id: null,
        ipAddress: $ip,
        status: BanStatus::Active,
        reason: 'unit-test',
        lastRuleId: 'rule-1',
        riskScore: 40,
        violationCount: 2,
        offenseCount: 1,
        bannedAt: $now,
        expiresAt: $expiresAt ?? $now->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $now,
        metadata: ['source' => 'unit'],
    );
}

it('creates and looks up an active ban', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $created = $repo->createBan(banRepoMake($ip));

    expect($created->id)->not->toBeNull()
        ->and($created->ipAddress)->toBe($ip)
        ->and($created->status)->toBe(BanStatus::Active)
        ->and($created->metadata)->toBe(['source' => 'unit']);

    $active = $repo->findActiveByIp($ip);
    expect($active)->not->toBeNull()
        ->and($active->ipAddress)->toBe($ip)
        ->and($active->status)->toBe(BanStatus::Active)
        ->and($active->reason)->toBe('unit-test')
        ->and($active->riskScore)->toBe(40)
        ->and($active->violationCount)->toBe(2)
        ->and($active->offenseCount)->toBe(1);

    expect($repo->findLatestByIp($ip))->not->toBeNull()
        ->and($repo->findById((string) $created->id))->not->toBeNull()
        ->and($repo->findActiveByIp(banRepoUniqueIp()))->toBeNull()
        ->and($repo->findLatestByIp(banRepoUniqueIp()))->toBeNull()
        ->and($repo->findById('999999'))->toBeNull();
});

it('hides expired bans from the active lookup', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $repo->createBan(banRepoMake($ip, new \DateTimeImmutable('-1 minute')));

    expect($repo->findActiveByIp($ip))->toBeNull()
        ->and($repo->findLatestByIp($ip))->not->toBeNull();
});

it('releases an active ban and records the reason', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $created = $repo->createBan(banRepoMake($ip));
    $released = $repo->release($created, 'manual_release', 'tester');

    expect($released->status)->toBe(BanStatus::Released)
        ->and($released->releasedAt)->not->toBeNull()
        ->and($released->metadata)->toBe([
            'source' => 'unit',
            'release_reason' => 'manual_release',
            'released_by' => 'tester',
        ]);

    expect($repo->findActiveByIp($ip))->toBeNull();
});

it('extends a ban expiry', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $created = $repo->createBan(banRepoMake($ip));
    $expires = (new \DateTimeImmutable)->modify('+3 hours');
    $extended = $repo->extend($created, $expires, 'admin');

    expect($extended->expiresAt?->format('Y-m-d H:i:s'))->toBe($expires->format('Y-m-d H:i:s'))
        ->and($extended->metadata['extended_by'] ?? null)->toBe('admin');
});

it('marks the challenge as passed', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $created = $repo->createBan(banRepoMake($ip));
    $at = new \DateTimeImmutable;
    $result = $repo->markChallengePassed($created, $at);

    expect($result->status)->toBe(BanStatus::Released)
        ->and($result->releasedAt)->not->toBeNull()
        ->and($result->challengePassedAt?->format('Y-m-d H:i:s'))->toBe($at->format('Y-m-d H:i:s'));

    expect($repo->findActiveByIp($ip))->toBeNull();
});

it('touches the last seen timestamp of a ban', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $created = $repo->createBan(banRepoMake($ip));
    $at = (new \DateTimeImmutable)->modify('+5 minutes');
    $touched = $repo->touchLastSeen($created, $at);

    expect($touched->lastSeenAt?->format('Y-m-d H:i:s'))->toBe($at->format('Y-m-d H:i:s'));
});

it('paginates bans with filters and pages', function () {
    $repo = new Ci4BanRepository;
    $ip = banRepoUniqueIp();

    $first = $repo->createBan(banRepoMake($ip));
    $second = $repo->createBan(banRepoMake($ip));

    $all = $repo->paginate(['ip' => $ip], 10, 1);
    expect(count($all))->toBe(2);
    expect(array_column($all, 'ip_address'))->each->toBe($ip);

    $pageOne = $repo->paginate(['ip' => $ip], 1, 1);
    $pageTwo = $repo->paginate(['ip' => $ip], 1, 2);
    expect($pageOne)->toHaveCount(1)
        ->and($pageTwo)->toHaveCount(1)
        ->and($pageTwo[0]['id'])->not->toBe($pageOne[0]['id']);

    expect($repo->paginate(['active' => true, 'ip' => $ip], 10, 1))->toHaveCount(2);
    expect($repo->paginate(['status' => 'released', 'ip' => $ip], 10, 1))->toHaveCount(0);
    expect($repo->paginate(['ip' => banRepoUniqueIp()], 10, 1))->toHaveCount(0);

    $repo->release($repo->findActiveByIp($ip) ?? $first, 'done', null);

    expect($repo->paginate(['active' => true, 'ip' => $ip], 10, 1))->toHaveCount(1)
        ->and($repo->paginate(['status' => 'released', 'ip' => $ip], 10, 1))->toHaveCount(1);

    expect($second->id)->not->toBeNull();
});
