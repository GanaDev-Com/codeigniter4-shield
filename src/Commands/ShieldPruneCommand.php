<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ganadev\Shield\Codeigniter\Models\SecurityEvent;
use Ganadev\Shield\Codeigniter\Models\SecurityIpBan;

final class ShieldPruneCommand extends BaseCommand
{
    protected $group = 'Shield';

    protected $name = 'shield:prune';

    protected $description = 'Prune expired security events and clear expired bans.';

    protected $usage = 'shield:prune [--days=]';

    protected $options = [
        '--days' => 'Prune security events older than N days (default from config)',
    ];

    public function run(array $params): void
    {
        $days = (int) ($params['days'] ?? config('Shield')->retentionDays);
        $cutoff = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        $eventModel = new SecurityEvent;
        $eventModel->where('created_at <', $cutoff)->delete();
        $deletedEvents = (int) $eventModel->affectedRows();

        $banModel = new SecurityIpBan;
        $banModel->where('status', 'released')
            ->where('expires_at <', date('Y-m-d H:i:s'))
            ->delete();
        $deletedBans = (int) $banModel->affectedRows();

        $banModel->where('status', 'expired')->delete();

        CLI::write("Pruned {$deletedEvents} events older than {$days} days and {$deletedBans} stale bans.", 'green');
    }
}
