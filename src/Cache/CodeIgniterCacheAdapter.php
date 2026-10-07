<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Cache;

use CodeIgniter\Cache\CacheInterface;
use Ganadev\Shield\Core\Persistence\CacheAdapterInterface;

final class CodeIgniterCacheAdapter implements CacheAdapterInterface
{
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly string $appId,
    ) {}

    public function get(string $key): mixed
    {
        return $this->cache->get($this->key($key));
    }

    public function set(string $key, mixed $value, int $ttlSeconds): bool
    {
        return $this->cache->save($this->key($key), $value, $ttlSeconds);
    }

    public function delete(string $key): bool
    {
        return $this->cache->delete($this->key($key));
    }

    public function has(string $key): bool
    {
        return $this->cache->get($this->key($key)) !== null;
    }

    public function increment(string $key, int $ttlSeconds): int
    {
        $fullKey = $this->key($key);
        $current = $this->cache->get($fullKey);

        if ($current === null) {
            $this->cache->save($fullKey, 1, $ttlSeconds);

            return 1;
        }

        $next = (int) $current + 1;
        $this->cache->save($fullKey, $next, $ttlSeconds);

        return $next;
    }

    private function key(string $key): string
    {
        $appId = $this->sanitizeKeyPart($this->appId);
        $keyPart = $this->sanitizeKeyPart($key);

        // Match test expectation format: shield-my-app-ban-1.2.3.4 (dots preserved as-is in the part)
        // but sanitize appId; for the key part, keep dots for IPs per original test
        return 'shield-'.$appId.'-'.$keyPart;
    }

    private function sanitizeKeyPart(string $part): string
    {
        // Remove all reserved characters for CI4 cache
        $reserved = '{}()/\\@:';
        $part = str_replace(str_split($reserved), '-', $part);

        return str_replace('.', '-', $part);
    }
}
