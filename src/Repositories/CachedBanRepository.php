<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Repositories;

use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;

final class CachedBanRepository implements BanRepositoryInterface
{
    private const NULL_SENTINEL = false;

    public function __construct(
        private readonly BanRepositoryInterface $inner,
        private readonly CacheAdapterInterface $cache,
        private readonly int $ttlSeconds,
    ) {}

    public function findActiveByIp(string $ip): ?BanRecord
    {
        $key = $this->key($ip);
        $cached = $this->cache->get($key);

        if ($cached !== null) {
            if ($cached === self::NULL_SENTINEL) {
                return null;
            }

            if (is_array($cached)) {
                try {
                    return BanRecord::fromArray($cached);
                } catch (\Throwable) {
                    $this->cache->delete($key);
                }
            } else {
                $this->cache->delete($key);
            }
        }

        $record = $this->inner->findActiveByIp($ip);
        $this->cache->set($key, $record === null ? self::NULL_SENTINEL : $record->toArray(), $this->ttlSeconds);

        return $record;
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        return $this->inner->findLatestByIp($ip);
    }

    public function findById(string $id): ?BanRecord
    {
        return $this->inner->findById($id);
    }

    public function createBan(BanRecord $record): BanRecord
    {
        $created = $this->inner->createBan($record);
        $this->cache->delete($this->key($record->ipAddress));

        return $created;
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        $released = $this->inner->release($ban, $reason, $actor);
        $this->cache->delete($this->key($ban->ipAddress));

        return $released;
    }

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        $extended = $this->inner->extend($ban, $expiresAt, $actor);
        $this->cache->delete($this->key($ban->ipAddress));

        return $extended;
    }

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $updated = $this->inner->markChallengePassed($ban, $at);
        $this->cache->delete($this->key($ban->ipAddress));

        return $updated;
    }

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $updated = $this->inner->touchLastSeen($ban, $at);
        $this->cache->delete($this->key($ban->ipAddress));

        return $updated;
    }

    private function key(string $ip): string
    {
        return 'ban:active:'.$ip;
    }
}
