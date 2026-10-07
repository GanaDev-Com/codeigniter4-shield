<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Config\Database;
use Ganadev\Shield\Codeigniter\Support\TrustedProxyInspector;

final class ShieldHealthCommand extends BaseCommand
{
    private const PROBE_IP = '66.249.66.1';

    protected $group = 'Shield';

    protected $name = 'shield:health';

    protected $description = 'Check Ganadev Shield component health.';

    protected $usage = 'shield:health';

    public function run(array $params): void
    {
        $healthy = true;

        try {
            $db = Database::connect();
            $db->initialize();
            $dbStatus = 'ok';
        } catch (\Throwable $e) {
            $dbStatus = 'down ('.$e->getMessage().')';
            $healthy = false;
        }

        try {
            $cache = service('cache');
            $cache->get('shield-health-probe');
            $cacheStatus = 'ok';
        } catch (\Throwable $e) {
            $cacheStatus = 'down ('.$e->getMessage().')';
            $healthy = false;
        }

        [$proxyStatus, $proxyWarning] = $this->proxyStatus();
        [$crawlerStatus, $crawlerWarning] = $this->crawlerVerificationStatus();

        CLI::table([
            ['Component', 'Status'],
            ['Database', $dbStatus],
            ['Cache', $cacheStatus],
            ['Rule engine', 'ok'],
            ['Trusted proxy', $proxyStatus],
            ['Crawler verification', $crawlerStatus],
        ]);

        if ($proxyWarning !== null) {
            CLI::newLine();
            CLI::write('Trusted proxy warning: '.$proxyWarning, 'yellow');
        }

        if ($crawlerWarning !== null) {
            CLI::newLine();
            CLI::write('Crawler verification warning: '.$crawlerWarning, 'yellow');
        }

        if (! $healthy) {
            exit(1);
        }
    }

    private function crawlerVerificationStatus(): array
    {
        if (! config('Shield')->crawlerVerificationEnabled) {
            return ['disabled (crawlerVerificationEnabled = false)', null];
        }

        if (! function_exists('gethostbyaddr')) {
            return [
                'untestable',
                'gethostbyaddr() not available, reverse DNS will not work.',
            ];
        }

        $hostname = @gethostbyaddr(self::PROBE_IP);
        $looksLikeCrawler = is_string($hostname) && $hostname !== self::PROBE_IP
            && (str_contains(strtolower($hostname), 'googlebot')
                || str_contains(strtolower($hostname), 'google.com'));

        if ($looksLikeCrawler) {
            return ['ok (reverse DNS works)', null];
        }

        return [
            'resolver did not return PTR',
            'Reverse DNS for known Googlebot IP ('.self::PROBE_IP.') did not return expected hostname. '
            .'If resolver has no internet access, this is normal; but if it should have access, '
            .'crawler verification will always fail and real crawlers will be treated as unverified claims.',
        ];
    }

    private function proxyStatus(): array
    {
        $forwarded = TrustedProxyInspector::forwardedHeaderSeen($_SERVER);
        $hasProxies = TrustedProxyInspector::hasConfiguredProxies();

        if ($hasProxies) {
            $status = 'ok';
            $warning = null;
            if (! $forwarded) {
                $warning = 'Trusted proxies configured but no request with forwarded headers seen yet.';
            }

            return [$status, $warning];
        }

        if ($forwarded) {
            return [
                'forwarded headers, trusted proxies empty',
                'Forwarded headers found but trusted proxies not configured. '
                .'All clients will appear as proxy IP, making per-IP rate limits and bans ineffective.',
            ];
        }

        $baseURL = config('App')->baseURL ?? '';

        if (TrustedProxyInspector::looksDeployedBehindProxy($baseURL)) {
            return [
                'not configured (public host)',
                'App runs on public host ('.$baseURL.') but trusted proxies not configured. '
                .'If behind reverse proxy/Cloudflare, configure App::$proxyIPs so real client IP is read.',
            ];
        }

        return ['not detected', null];
    }
}
