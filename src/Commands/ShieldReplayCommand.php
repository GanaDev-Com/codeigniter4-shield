<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ganadev\Shield\Codeigniter\Support\InputValue;
use Ganadev\Shield\Core\Clock\SystemClock;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Events\SecurityEvent;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Persistence\BanRepositoryInterface;
use Ganadev\Shield\Core\Persistence\EventRepositoryInterface;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\BanRecord;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

final class ShieldReplayCommand extends BaseCommand
{
    protected $group = 'Shield';

    protected $name = 'shield:replay';

    protected $description = 'Replay a corpus/event export against the current threat rules.';

    protected $usage = 'shield:replay <file> [--pack-wordpress] [--min-rate=0.98]';

    protected $arguments = [
        'file' => 'JSON corpus or security-events export',
    ];

    protected $options = [
        '--pack-wordpress' => 'Enable the WordPress rule pack for this run',
        '--min-rate' => 'Minimum detection rate for the exit code (default: 0.98)',
    ];

    public function run(array $params): void
    {
        $file = (new InputValue)->string($params[0] ?? '');
        if ($file === null) {
            CLI::error('A file path argument is required.');

            return;
        }

        if (! is_file($file)) {
            CLI::error("File not found: {$file}");

            return;
        }

        $data = json_decode((string) file_get_contents($file), true, 512, JSON_THROW_ON_ERROR);

        $definitions = DefaultRules::definitions();
        if (isset($params['pack-wordpress'])) {
            $definitions = array_merge($definitions, DefaultRules::wordpressDefinitions());
        }

        $engine = new ShieldEngine(
            config: ShieldConfig::fromArray(['mode' => 'enforce']),
            normalizer: new Normalizer,
            signatures: new ThreatSignatureEngine(RuleRepository::fromArray($definitions)),
            behavior: new BehaviorDetector,
            scorer: new RiskScorer,
            decisionEngine: new DecisionEngine,
            banPolicy: new BanPolicy,
            riskDecay: new RiskDecay,
            events: new class implements EventRepositoryInterface
            {
                public function record(SecurityEvent $event): void {}

                public function pruneOlderThan(\DateTimeImmutable $cutoff): int
                {
                    return 0;
                }
            },
            clock: new SystemClock,
            bans: new class implements BanRepositoryInterface
            {
                public function findActiveByIp(string $ip): ?BanRecord
                {
                    return null;
                }

                public function findLatestByIp(string $ip): ?BanRecord
                {
                    return null;
                }

                public function findById(string $id): ?BanRecord
                {
                    return null;
                }

                public function createBan(BanRecord $record): BanRecord
                {
                    return $record;
                }

                public function release(BanRecord $ban, string $reason, ?string $actor): BanRecord
                {
                    return $ban;
                }

                public function extend(BanRecord $ban, \DateTimeImmutable $expiresAt, ?string $actor): BanRecord
                {
                    return $ban;
                }

                public function markChallengePassed(BanRecord $ban, \DateTimeImmutable $at): BanRecord
                {
                    return $ban;
                }

                public function touchLastSeen(BanRecord $ban, \DateTimeImmutable $at): BanRecord
                {
                    return $ban;
                }
            },
            trusted: new class implements TrustedCookieInterface
            {
                public function name(): string
                {
                    return 'shield_trusted';
                }

                public function issue(RequestContext $context, int $ttlMinutes): string
                {
                    return '';
                }

                public function validate(string $cookieValue, RequestContext $context): bool
                {
                    return false;
                }
            },
        );

        $entries = $data['entries'] ?? [];
        foreach ($data['events'] ?? [] as $event) {
            $entries[] = [
                'uri' => (string) ($event['normalized_uri'] ?? $event['uri'] ?? '/'),
                'method' => (string) ($event['method'] ?? 'GET'),
                'expected' => 'allow',
                'category' => (string) ($event['rule_id'] ?? 'event'),
            ];
        }

        $minRate = (float) ($params['min-rate'] ?? 0.98);
        $totalBlock = 0;
        $detected = 0;
        $falsePositives = 0;
        $byCategory = [];

        foreach ($entries as $index => $entry) {
            $expected = (string) ($entry['expected'] ?? 'allow');
            $ctx = RequestContext::create(
                (string) ($entry['uri'] ?? '/'),
                (string) ($entry['method'] ?? 'GET'),
                'replay.test',
                '203.0.113.'.(($index % 200) + 1),
            );
            $blocked = $engine->inspect($ctx, new BehaviorCounters)->shouldBlock();
            $category = (string) ($entry['category'] ?? 'uncategorized');

            $byCategory[$category]['total'] = ($byCategory[$category]['total'] ?? 0) + 1;
            $byCategory[$category]['blocked'] = ($byCategory[$category]['blocked'] ?? 0) + ($blocked ? 1 : 0);

            if ($expected === 'block') {
                $totalBlock++;
                $detected += $blocked ? 1 : 0;
            } elseif ($blocked) {
                $falsePositives++;
            }
        }

        ksort($byCategory);

        CLI::newLine();
        CLI::write('Ganadev Shield — replay', 'green');
        CLI::newLine();
        $rows = [];
        foreach ($byCategory as $category => $counts) {
            $rows[] = [mb_substr($category, 0, 52), $counts['total'], $counts['blocked']];
        }
        CLI::table(['Category', 'Total', 'Blocked'], $rows);

        $rate = $totalBlock > 0 ? $detected / $totalBlock : 1.0;
        CLI::newLine();
        CLI::write(sprintf('Detection rate (expected=block): %.1f%% (%d/%d), target >= %.0f%%', $rate * 100, $detected, $totalBlock, $minRate * 100));
        CLI::write("False positives (expected=allow but blocked): {$falsePositives}");

        if ($rate < $minRate || $falsePositives > 0) {
            exit(1);
        }
    }
}
