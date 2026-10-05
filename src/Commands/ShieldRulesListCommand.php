<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;

final class ShieldRulesListCommand extends BaseCommand
{
    protected $group = 'Shield';
    protected $name = 'shield:rules:list';
    protected $description = 'List loaded threat rules and their version.';
    protected $usage = 'shield:rules:list [--disabled]';
    protected $options = [
        '--disabled' => 'Show disabled rules too',
    ];

    public function run(array $params): void
    {
        $showDisabled = isset($params['disabled']);
        $resolver = new ShieldResolver();
        $rules = $resolver->rules();

        $rows = [];
        foreach ($rules->all() as $rule) {
            if (! $rule->enabled && ! $showDisabled) {
                continue;
            }

            $rows[] = [
                $rule->id,
                $rule->category,
                $rule->matcher->value,
                $rule->severity->value,
                $rule->score,
                $rule->immediateBan ? 'yes' : 'no',
                $rule->enabled ? 'enabled' : 'disabled',
            ];
        }

        CLI::table(
            ['ID', 'Category', 'Matcher', 'Severity', 'Score', 'Immediate Ban', 'State'],
            $rows,
        );

        CLI::write('Loaded '.count($rows).' rule(s).', 'green');
    }
}
