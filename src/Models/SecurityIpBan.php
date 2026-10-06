<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Models;

use CodeIgniter\Model;

class SecurityIpBan extends Model
{
    protected $table = 'security_ip_bans';

    protected $primaryKey = 'id';

    protected $returnType = 'array';

    protected $useTimestamps = true;

    protected $createdField = 'created_at';

    protected $updatedField = 'updated_at';

    protected $allowedFields = [
        'ip_address', 'status', 'reason', 'last_rule_id', 'risk_score',
        'violation_count', 'offense_count', 'banned_at', 'expires_at',
        'released_at', 'challenge_passed_at', 'last_seen_at', 'metadata',
    ];

    protected array $casts = [
        'risk_score' => 'integer',
        'violation_count' => 'integer',
        'offense_count' => 'integer',
        'banned_at' => 'datetime',
        'expires_at' => 'datetime',
        'released_at' => 'datetime',
        'challenge_passed_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'metadata' => 'array',
    ];
}
