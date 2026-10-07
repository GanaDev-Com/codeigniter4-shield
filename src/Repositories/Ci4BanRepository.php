<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Repositories;

use Ganadev\Shield\Codeigniter\Models\SecurityIpBan;
use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\BanStatus;

final class Ci4BanRepository implements BanRepositoryInterface
{
    public function findActiveByIp(string $ip): ?BanRecord
    {
        $model = new SecurityIpBan;
        $row = $model->where('ip_address', $ip)
            ->whereIn('status', [BanStatus::Active->value, BanStatus::ManualBlock->value])
            ->groupStart()
            ->where('expires_at IS NULL', null, false)
            ->orWhere('expires_at >', date('Y-m-d H:i:s'))
            ->groupEnd()
            ->orderBy('banned_at', 'DESC')
            ->first();

        return $row !== null ? $this->toRecord($row) : null;
    }

    public function findLatestByIp(string $ip): ?BanRecord
    {
        $model = new SecurityIpBan;
        $row = $model->where('ip_address', $ip)
            ->orderBy('banned_at', 'DESC')
            ->first();

        return $row !== null ? $this->toRecord($row) : null;
    }

    public function findById(string $id): ?BanRecord
    {
        $model = new SecurityIpBan;
        $row = $model->find($id);

        return is_array($row) ? $this->toRecord($row) : null;
    }

    public function createBan(BanRecord $record): BanRecord
    {
        $model = new SecurityIpBan;
        $model->insert([
            'ip_address' => $record->ipAddress,
            'status' => $record->status->value,
            'reason' => $record->reason,
            'last_rule_id' => $record->lastRuleId,
            'risk_score' => $record->riskScore,
            'violation_count' => $record->violationCount,
            'offense_count' => $record->offenseCount,
            'banned_at' => $record->bannedAt->format('Y-m-d H:i:s'),
            'expires_at' => $record->expiresAt?->format('Y-m-d H:i:s'),
            'released_at' => $record->releasedAt?->format('Y-m-d H:i:s'),
            'challenge_passed_at' => $record->challengePassedAt?->format('Y-m-d H:i:s'),
            'last_seen_at' => $record->lastSeenAt->format('Y-m-d H:i:s'),
            'metadata' => $record->metadata !== null ? json_encode($record->metadata) : null,
        ]);

        return $this->toRecord($model->find($model->getInsertID()));
    }

    public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
    {
        $model = new SecurityIpBan;
        $model->update($ban->id, [
            'status' => BanStatus::Released->value,
            'released_at' => date('Y-m-d H:i:s'),
            'metadata' => json_encode(array_merge(
                json_decode($model->find($ban->id)['metadata'] ?? '{}', true) ?: [],
                ['release_reason' => $reason, 'released_by' => $actor ?? 'system'],
            )),
        ]);

        return $this->toRecord($model->find($ban->id));
    }

    public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
    {
        $model = new SecurityIpBan;
        $model->update($ban->id, [
            'expires_at' => $expiresAt->format('Y-m-d H:i:s'),
            'metadata' => json_encode(array_merge(
                json_decode($model->find($ban->id)['metadata'] ?? '{}', true) ?: [],
                ['extended_by' => $actor ?? 'system'],
            )),
        ]);

        return $this->toRecord($model->find($ban->id));
    }

    public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $model = new SecurityIpBan;
        $model->update($ban->id, [
            'status' => BanStatus::Released->value,
            'released_at' => $at->format('Y-m-d H:i:s'),
            'challenge_passed_at' => $at->format('Y-m-d H:i:s'),
        ]);

        return $this->toRecord($model->find($ban->id));
    }

    public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
    {
        $model = new SecurityIpBan;
        $model->update($ban->id, ['last_seen_at' => $at->format('Y-m-d H:i:s')]);

        return $this->toRecord($model->find($ban->id));
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function paginate(array $filters = [], int $perPage = 50, int $page = 1): array
    {
        $model = new SecurityIpBan;
        $builder = $model->builder();

        if (! empty($filters['ip'])) {
            $builder->where('ip_address', (string) $filters['ip']);
        }
        if (! empty($filters['status'])) {
            $builder->where('status', (string) $filters['status']);
        }
        if (($filters['active'] ?? false) === true) {
            $builder->whereIn('status', [BanStatus::Active->value, BanStatus::ManualBlock->value]);
        }

        $page = max(1, $page);

        return $builder
            ->orderBy('banned_at', 'DESC')
            ->limit($perPage, ($page - 1) * $perPage)
            ->get()
            ->getResultArray();
    }

    private function toRecord(array $row): BanRecord
    {
        return new BanRecord(
            id: (string) $row['id'],
            ipAddress: (string) $row['ip_address'],
            status: BanStatus::from((string) $row['status']),
            reason: (string) ($row['reason'] ?? ''),
            lastRuleId: $row['last_rule_id'] ?? null,
            riskScore: (int) ($row['risk_score'] ?? 0),
            violationCount: (int) ($row['violation_count'] ?? 0),
            offenseCount: (int) ($row['offense_count'] ?? 0),
            bannedAt: new \DateTimeImmutable($row['banned_at']),
            expiresAt: $row['expires_at'] !== null ? new \DateTimeImmutable($row['expires_at']) : null,
            releasedAt: $row['released_at'] !== null ? new \DateTimeImmutable($row['released_at']) : null,
            challengePassedAt: $row['challenge_passed_at'] !== null ? new \DateTimeImmutable($row['challenge_passed_at']) : null,
            lastSeenAt: new \DateTimeImmutable($row['last_seen_at']),
            metadata: isset($row['metadata']) ? json_decode((string) $row['metadata'], true) : null,
        );
    }
}
