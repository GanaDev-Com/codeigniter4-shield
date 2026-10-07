<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Feature;

use CodeIgniter\Config\Services;
use CodeIgniter\Exceptions\PageNotFoundException;
use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Core\Events\SecurityEvent as CoreSecurityEvent;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;

function adminApiUniqueIp(): string
{
    static $counter = 0;
    $counter++;

    return '198.23.'.intdiv($counter, 254).'.'.($counter % 254 + 1);
}

function adminApiMakeBan(string $ip): BanRecord
{
    $now = new \DateTimeImmutable;

    return new BanRecord(
        id: null,
        ipAddress: $ip,
        status: BanStatus::Active,
        reason: 'admin-api-test',
        lastRuleId: 'rule-1',
        riskScore: 35,
        violationCount: 1,
        offenseCount: 1,
        bannedAt: $now,
        expiresAt: $now->modify('+1 hour'),
        releasedAt: null,
        challengePassedAt: null,
        lastSeenAt: $now,
        metadata: ['source' => 'admin-api'],
    );
}

function adminApiMakeEvent(string $ip, array $overrides = []): CoreSecurityEvent
{
    return CoreSecurityEvent::create(array_merge([
        'ip' => $ip,
        'host' => 'admin.example.test',
        'method' => 'GET',
        'raw_uri' => '/admin-probe',
        'normalized_uri' => '/admin-probe',
        'rule_id' => 'rule-admin',
        'category' => 'probe',
        'severity' => 'medium',
        'score_delta' => 5,
        'decision' => 'BLOCK_REQUEST',
        'rule_version' => '1.0.0',
        'created_at' => new \DateTimeImmutable,
    ], $overrides));
}

function adminApiUser(string $id, array $permissions): object
{
    return new class($id, $permissions)
    {
        public function __construct(
            public string $id,
            private array $permissions,
        ) {}

        public function getPermissions(): array
        {
            return $this->permissions;
        }
    };
}

function adminApiFakeAuth(?object $user): void
{
    $auth = new class($user)
    {
        public function __construct(private ?object $user) {}

        public function user(): ?object
        {
            return $this->user;
        }
    };

    Services::injectMock('authentication', $auth);
}

beforeEach(function () {
    Services::resetSingle('authentication');
    config('Shield')->adminEnabled = true;
});

it('lists bans with filters and pagination clamps', function () {
    $ip = adminApiUniqueIp();
    (new Ci4BanRepository)->createBan(adminApiMakeBan($ip));

    $result = $this->withRoutes([])->call('GET', 'shield/bans');
    $result->assertOK();
    $payload = json_decode((string) $result->getJSON(), true);
    expect(array_column($payload['data'] ?? [], 'ip_address'))->toContain($ip);

    $filtered = $this->withRoutes([])->call('GET', 'shield/bans', [
        'ip' => $ip,
        'status' => 'active',
        'active' => '1',
        'per_page' => '10',
        'page' => '1',
    ]);
    $filtered->assertOK();
    $payload = json_decode((string) $filtered->getJSON(), true);
    expect(array_column($payload['data'] ?? [], 'ip_address'))->each->toBe($ip);

    $empty = $this->withRoutes([])->call('GET', 'shield/bans', ['ip' => adminApiUniqueIp()]);
    $payload = json_decode((string) $empty->getJSON(), true);
    expect($payload['data'] ?? null)->toBe([]);

    $clamped = $this->withRoutes([])->call('GET', 'shield/bans', ['per_page' => '0', 'page' => '0']);
    $clamped->assertOK();
    $clamped = $this->withRoutes([])->call('GET', 'shield/bans', ['per_page' => '9999']);
    $clamped->assertOK();
});

it('serves a ban detail and reports missing ones', function () {
    $ip = adminApiUniqueIp();
    $created = (new Ci4BanRepository)->createBan(adminApiMakeBan($ip));

    $result = $this->withRoutes([])->call('GET', 'shield/bans/'.$created->id);
    $result->assertOK();
    $payload = json_decode((string) $result->getJSON(), true);
    expect($payload['ban']['ipAddress'] ?? null)->toBe($ip);

    $missing = $this->withRoutes([])->call('GET', 'shield/bans/99999999');
    $missing->assertStatus(404);
    $payload = json_decode((string) $missing->getJSON(), true);
    expect($payload['error'] ?? null)->toBe('not_found');
});

it('releases and extends a ban', function () {
    $repo = new Ci4BanRepository;
    $releaseIp = adminApiUniqueIp();
    $extendIp = adminApiUniqueIp();
    $releaseBan = $repo->createBan(adminApiMakeBan($releaseIp));
    $extendBan = $repo->createBan(adminApiMakeBan($extendIp));

    $released = $this->withRoutes([])->call('POST', 'shield/bans/'.$releaseBan->id.'/release', [
        'reason' => 'from-test',
    ]);
    $released->assertOK();
    expect($repo->findActiveByIp($releaseIp))->toBeNull()
        ->and($repo->findLatestByIp($releaseIp)?->status)->toBe(BanStatus::Released)
        ->and($repo->findLatestByIp($releaseIp)?->metadata['release_reason'] ?? null)->toBe('from-test');

    $originalExpiry = $repo->findLatestByIp($extendIp)?->expiresAt;
    $extended = $this->withRoutes([])->call('POST', 'shield/bans/'.$extendBan->id.'/extend', [
        'minutes' => '120',
    ]);
    $extended->assertOK();
    $newExpiry = $repo->findLatestByIp($extendIp)?->expiresAt;
    expect($newExpiry?->getTimestamp())->toBeGreaterThan((int) $originalExpiry?->getTimestamp());

    $missing = $this->withRoutes([])->call('POST', 'shield/bans/99999999/release');
    $missing->assertStatus(404);
    $missing = $this->withRoutes([])->call('POST', 'shield/bans/99999999/extend');
    $missing->assertStatus(404);
});

it('filters the security events feed', function () {
    $ip = adminApiUniqueIp();
    $events = new Ci4EventRepository;
    $events->record(adminApiMakeEvent($ip));
    $events->record(adminApiMakeEvent($ip, ['decision' => 'ALLOW', 'rule_id' => 'rule-other']));

    $result = $this->withRoutes([])->call('GET', 'shield/events', ['ip' => $ip]);
    $result->assertOK();
    $payload = json_decode((string) $result->getJSON(), true);
    expect(array_column($payload['data'] ?? [], 'ip_address'))->each->toBe($ip);

    $combined = $this->withRoutes([])->call('GET', 'shield/events', [
        'ip' => $ip,
        'host' => 'admin.example.test',
        'rule_id' => 'rule-other',
        'severity' => 'medium',
        'decision' => 'ALLOW',
        'per_page' => '5',
        'page' => '1',
    ]);
    $combined->assertOK();
    $payload = json_decode((string) $combined->getJSON(), true);
    expect($payload['data'] ?? [])->toHaveCount(1);
});

it('lists rules and reports health', function () {
    $result = $this->withRoutes([])->call('GET', 'shield/rules');
    $result->assertOK();
    $payload = json_decode((string) $result->getJSON(), true);
    expect($payload['count'] ?? 0)->toBeGreaterThan(0)
        ->and($payload['rules'][0] ?? null)->toHaveKeys(['id', 'category', 'matcher', 'severity', 'score', 'immediate_ban', 'enabled']);

    $health = $this->withHeaders(['X-Forwarded-For' => '203.0.113.55'])
        ->withRoutes([])
        ->call('GET', 'shield/health');
    $health->assertOK();
    $payload = json_decode((string) $health->getJSON(), true);
    expect($payload['healthy'] ?? null)->toBeTrue()
        ->and($payload['database'] ?? null)->toBeTrue()
        ->and($payload['cache'] ?? null)->toBeTrue()
        ->and($payload['trusted_proxy_warning'] ?? null)->not->toBeNull()
        ->and($payload['admin_authorize_warning'] ?? null)->not->toBeNull();
});

it('denies admin access without the required permission', function () {
    config('Shield')->adminAuthorize = 'shield.admin';

    $anonymous = $this->withRoutes([])->call('GET', 'shield/bans');
    $anonymous->assertStatus(403);
    $payload = json_decode((string) $anonymous->getJSON(), true);
    expect($payload['error'] ?? null)->toBe('forbidden');

    adminApiFakeAuth(adminApiUser('user-1', ['other.permission']));
    $wrongPermission = $this->withRoutes([])->call('GET', 'shield/bans');
    $wrongPermission->assertStatus(403);

    adminApiFakeAuth(adminApiUser('user-2', ['shield.admin']));
    $allowed = $this->withRoutes([])->call('GET', 'shield/bans');
    $allowed->assertOK();
});

it('records the acting user when releasing a ban', function () {
    config('Shield')->adminAuthorize = 'shield.admin';
    adminApiFakeAuth(adminApiUser('user-77', ['shield.admin']));

    $ip = adminApiUniqueIp();
    $repo = new Ci4BanRepository;
    $ban = $repo->createBan(adminApiMakeBan($ip));

    $released = $this->withRoutes([])->call('POST', 'shield/bans/'.$ban->id.'/release');
    $released->assertOK();
    expect($repo->findLatestByIp($ip)?->metadata['released_by'] ?? null)->toBe('user-77');
});

it('hides the admin api while the panel is disabled', function () {
    config('Shield')->adminEnabled = false;

    expect(fn () => $this->withRoutes([])->call('GET', 'shield/bans'))
        ->toThrow(PageNotFoundException::class);
});
