<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter;

use CodeIgniter\Config\Services;
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
    /**
     * Registers the shared Shield services and the global firewall filter.
     *
     * This is an optional convenience: every component of this package falls
     * back to a fresh ShieldResolver when the services are missing, so calling
     * register() is only required when you want shared, pre-built instances
     * (recommended in app/Config/Events.php on the `pre_system` event).
     *
     * Calling it repeatedly rebuilds the services from the current config,
     * which also makes configuration changes visible to already-resolved code.
     */
    public static function register(): void
    {
        $resolver = new ShieldResolver;

        self::setService('shield.resolver', $resolver);
        self::setService('shield.config', $resolver->config());
        self::setService('shield.engine', $resolver->engine());
        self::setService('shield.cache', $resolver->cacheAdapter());
        self::setService('shield.challenge', $resolver->challengeDriver());

        self::registerFilter();
        self::registerCommands();
        self::warnAboutMissingTrustedProxies();
    }

    private static function setService(string $name, object $value): void
    {
        Services::resetSingle($name);
        Services::set($name, $value);
    }

    private static function registerFilter(): void
    {
        $filters = config('Filters');
        $filters->aliases['shield.firewall'] = SecurityFirewallFilter::class;

        if (! in_array('shield.firewall', $filters->globals['before'] ?? [], true)) {
            $filters->globals['before'][] = 'shield.firewall';
        }
    }

    private static function registerCommands(): void
    {
        if (! class_exists('\\Config\\Commands')) {
            return;
        }

        $commands = config('Commands');
        if ($commands === null) {
            return;
        }

        $commands->shield = array_values(array_unique(array_merge((array) ($commands->shield ?? []), [
            ShieldPruneCommand::class,
            ShieldReleaseCommand::class,
            ShieldHealthCommand::class,
            ShieldReportCommand::class,
            ShieldRulesListCommand::class,
            ShieldReplayCommand::class,
        ])));
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
