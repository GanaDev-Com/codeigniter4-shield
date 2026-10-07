<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Models;

use CodeIgniter\Model;

class SecurityEvent extends Model
{
    protected $table = 'security_events';

    protected $primaryKey = 'id';

    protected $returnType = 'array';

    protected $useTimestamps = false;

    protected $allowedFields = [
        'ip_address', 'host', 'method', 'raw_uri', 'normalized_uri',
        'rule_id', 'category', 'severity', 'score_delta', 'decision',
        'intended_decision', 'user_agent', 'referer', 'request_id',
        'rule_version', 'created_at',
    ];

    protected array $casts = [
        'score_delta' => 'integer',
    ];
}
