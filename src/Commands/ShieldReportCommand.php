<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ganadev\Shield\Codeigniter\Models\SecurityEvent;

final class ShieldReportCommand extends BaseCommand
{
    protected $group = 'Shield';

    protected $name = 'shield:report';

    protected $description = 'Print a security event summary report.';

    protected $usage = 'shield:report [--host=]';

    protected $options = [
        '--host' => 'Filter by host',
    ];

    public function run(array $params): void
    {
        $host = $params['host'] ?? null;

        $model = new SecurityEvent;
        $builder = $model->builder();

        if ($host !== null) {
            $builder->where('host', $host);
        }

        $total = $builder->countAllResults();
        $blocked = (clone $builder)->where('decision', 'BLOCK_REQUEST')->countAllResults();
        $offenders = (clone $builder)->distinct()->countAllResults();

        CLI::newLine();
        CLI::write('Ganadev Shield Report', 'green');
        CLI::newLine();
        CLI::table([
            ['Metric', 'Value'],
            ['Total events', $total],
            ['Blocked requests', $blocked],
            ['Unique offenders', $offenders],
        ]);

        $topRules = (clone $builder)
            ->where('rule_id IS NOT NULL', null, false)
            ->select('rule_id, COUNT(*) as total')
            ->groupBy('rule_id')
            ->orderBy('total', 'DESC')
            ->limit(10)
            ->get()
            ->getResultArray();

        if (! empty($topRules)) {
            CLI::newLine();
            CLI::write('Top matched rules', 'green');
            $rows = array_map(fn ($row) => [$row['rule_id'], $row['total']], $topRules);
            CLI::table(['Rule', 'Count'], $rows);
        }
    }
}
