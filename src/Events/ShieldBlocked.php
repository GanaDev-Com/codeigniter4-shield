<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Events;

final class ShieldBlocked
{
    public function __construct(
        public readonly string $ip,
        public readonly string $ruleId,
        public readonly string $reason,
        public readonly int $score,
        public readonly string $uri,
        public readonly string $method,
    ) {}
}
