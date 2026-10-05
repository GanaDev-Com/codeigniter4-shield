<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter;

use CodeIgniter\Events\Events;
use Ganadev\Shield\Codeigniter\Commands\ShieldHealthCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldPruneCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReleaseCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReplayCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldReportCommand;
use Ganadev\Shield\Codeigniter\Commands\ShieldRulesListCommand;
use Ganadev\Shield\Codeigniter\Filters\SecurityFirewallFilter;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Codeigniter\Support\TrustedProxyInspector;

final class ShieldServiceProvider
{
    public static function register(): void
    {
        $resolver = new ShieldResolver();

        service('singleton', 'shield.resolver', fn () => $resolver);
        service('singleton', 'shield.config', fn () => $resolver->config());
        service('singleton', 'shield.engine', fn () => $resolver->engine());
        service('singleton', 'shield.cache', fn () => $resolver->cacheAdapter());
        service('singleton', 'shield.challenge', fn () => $resolver->challengeDriver());

        self::registerFilter();
        self::registerCommands();
        self::registerRoutes();
        self::warnAboutMissingTrustedProxies();
    }

    private static function registerFilter(): void
    {
        $filters = config('Filters');
        $filters->aliases['shield.firewall'] = SecurityFirewallFilter::class;
        $filters->globals['before'][] = 'shield.firewall';
    }

    private static function registerCommands(): void
    {
        $commands = config('Commands');
        $commands->shield = [
            ShieldPruneCommand::class,
            ShieldReleaseCommand::class,
            ShieldHealthCommand::class,
            ShieldReportCommand::class,
            ShieldRulesListCommand::class,
            ShieldReplayCommand::class,
        ];
    }

    private static function registerRoutes(): void
    {
        $routes = service('routes');
        $routes->load(__DIR__.'/../routes/shield.php');
    }

    private static function warnAboutMissingTrustedProxies(): void
    {
        if (TrustedProxyInspector::hasConfiguredProxies()) {
            return;
        }

        $config = config('Shield');
        if (! in_array($config->mode, ['challenge', 'enforce'], true)) {
            return;
        }

        $baseURL = config('App')->baseURL ?? '';
        if (! TrustedProxyInspector::looksDeployedBehindProxy($baseURL)) {
            return;
        }

        log_message('warning', 'Ganadev Shield: trusted proxies not configured while app runs on public host '
            .$baseURL.'. If behind reverse proxy/Cloudflare, configure App::$proxyIPs so real client IP is read.');
    }
}
