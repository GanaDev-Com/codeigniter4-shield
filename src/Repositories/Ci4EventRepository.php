<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Repositories;

use Ganadev\Shield\Codeigniter\Models\SecurityEvent as SecurityEventModel;
use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;

final class Ci4EventRepository implements EventRepositoryInterface
{
    public function record(SecurityEvent $event): void
    {
        $model = new SecurityEventModel;
        $model->insert($event->toArray());
    }

    public function pruneOlderThan(\DateTimeImmutable $cutoff): int
    {
        $model = new SecurityEventModel;
        $builder = $model->builder();
        $builder->where('created_at <', $cutoff->format('Y-m-d H:i:s'));

        return $builder->delete();
    }

    public function paginate(array $filters = [], int $perPage = 50)
    {
        $model = new SecurityEventModel;
        $builder = $model->builder();

        if (! empty($filters['ip'])) {
            $builder->where('ip_address', (string) $filters['ip']);
        }
        if (! empty($filters['host'])) {
            $builder->where('host', (string) $filters['host']);
        }
        if (! empty($filters['rule_id'])) {
            $builder->where('rule_id', (string) $filters['rule_id']);
        }
        if (! empty($filters['severity'])) {
            $builder->where('severity', (string) $filters['severity']);
        }
        if (! empty($filters['decision'])) {
            $builder->where('decision', (string) $filters['decision']);
        }

        return $builder->orderBy('created_at', 'DESC')->paginate($perPage);
    }
}
