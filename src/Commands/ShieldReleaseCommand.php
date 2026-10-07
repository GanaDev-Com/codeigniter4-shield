<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ganadev\Shield\Codeigniter\Support\InputValue;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;

final class ShieldReleaseCommand extends BaseCommand
{
    protected $group = 'Shield';

    protected $name = 'shield:release';

    protected $description = 'Release an active ban for an IP address.';

    protected $usage = 'shield:release <ip> [--reason=]';

    protected $arguments = [
        'ip' => 'IP address to unblock',
    ];

    protected $options = [
        '--reason' => 'Reason for release (default: manual_release)',
    ];

    public function run(array $params): void
    {
        $ip = (new InputValue)->string($params[0] ?? '');
        if ($ip === null) {
            CLI::error('A valid IP address argument is required.');

            return;
        }

        $reason = (new InputValue)->string($params['reason'] ?? '') ?? 'manual_release';

        $engine = service('shield.engine') ?? (new ShieldResolver)->engine();
        $released = $engine->releaseBan($ip, $reason, 'cli:'.get_current_user());

        if (! $released) {
            CLI::error('No active ban found for that IP.');

            return;
        }

        CLI::write('Ban released.', 'green');
    }
}
