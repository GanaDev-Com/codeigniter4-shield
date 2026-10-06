<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Config;

use CodeIgniter\Config\BaseConfig;

class Shield extends BaseConfig
{
    public bool $enabled = true;

    public string $mode = 'observe';

    public string $appId = 'my-app';

    public int $responseCode = 404;

    public int $decodeDepth = 2;

    public string $failMode = 'open';

    public int $thresholdChallenge = 10;

    public int $thresholdBan = 20;

    public int $thresholdStrongBan = 30;

    public array $banDurations = [15, 60, 360, 1440];

    public string $challengeDriver = 'turnstile';

    public int $uniqueUriLimit = 25;

    public int $behaviorWindowSeconds = 60;

    public int $notFoundLimit = 20;

    public array $suspiciousUserAgents = [];

    public array $suspiciousUserAgentOverrides = [];

    public array $scannerUserAgents = [
        'sqlmap', 'nikto', 'metasploit', 'wpscan', 'dirbuster',
        'gobuster', 'masscan', 'nmap', 'nessus', 'acunetix',
        'x00c', 'zgrab', 'httpx',
    ];

    public int $scannerUaSignal = 4;

    public int $pathRateLimit = 30;

    public int $sensitivePathRateLimit = 8;

    public array $sensitivePaths = [
        '/login', '/wp-login.php', '/admin/login', '/administrator/',
        '/api/login', '/api/auth', '/user/login',
    ];

    public string $botMode = 'observe';

    public bool $missingRefererSignal = true;

    public int $unverifiedClaimSignal = 4;

    public bool $crawlerVerificationEnabled = true;

    public int $crawlerVerificationTtlHours = 24;

    public array $crawlerHostnames = [
        'googlebot' => ['.googlebot.com', '.google.com'],
        'bingbot' => ['.search.msn.com'],
        'yandexbot' => ['.yandex.ru', '.yandex.net'],
        'baiduspider' => ['.baidu.com', '.baidu.jp'],
        'duckduckbot' => ['.duckduckgo.com'],
        'ahrefsbot' => ['.ahrefs.com'],
        'semrushbot' => ['.semrush.com'],
        'dotbot' => ['.moz.com'],
        'ccbot' => ['.cc'],
    ];

    public array $crawlerIpRanges = [];

    public array $knownBotAgents = [
        'googlebot', 'bingbot', 'yandexbot', 'baiduspider', 'duckduckbot',
        'ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'bytespider',
        'ccbot', 'gptbot', 'chatgpt-user', 'claudebot', 'anthropic',
        'openai', 'oai-searchbot', 'perplexitybot',
    ];

    public bool $rulesPacksInjection = true;

    public bool $rulesPacksWordpress = false;

    public array $skipPaths = [];

    public bool $bodyInspectionEnabled = true;

    public int $bodyInspectionMaxBytes = 65536;

    public string $loggingLevel = 'suspicious';

    public bool $logBypassEvents = true;

    public int $retentionDays = 30;

    public array $apiPaths = [];

    public bool $apiDetectAccept = true;

    public bool $adminEnabled = false;

    public string $adminAuthorize = '';

    public string $adminPrefix = 'shield';

    public array $allowlistHosts = [];

    public array $allowlistPaths = [];

    public array $allowlistIps = [];

    public bool $trustedEnabled = true;

    public int $trustedTtlMinutes = 60;

    public int $maxUriLength = 2048;

    public int $banCacheTtlSeconds = 30;

    public int $escalationStep = 5;

    public array $sensitiveQueryParameters = ['token', 'password', 'passwd', 'key', 'secret', 'code', 'auth'];

    public string $ruleVersion = '1.0.0';

    public string $blockedView = 'shield/blocked';

    public string $challengeView = 'shield/challenge';

    public string $brandingTitle = 'Ganadev CodeIgniter Shield';

    public string $brandingAccentColor = '#22d3ee';

    public string $brandingBackgroundColor = '#0b1220';

    public bool $brandingShowRuleId = false;

    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled,
            'mode' => $this->mode,
            'app_id' => $this->appId,
            'response_code' => $this->responseCode,
            'decode_depth' => $this->decodeDepth,
            'fail_mode' => $this->failMode,
            'thresholds' => [
                'challenge' => $this->thresholdChallenge,
                'ban' => $this->thresholdBan,
                'strong_ban' => $this->thresholdStrongBan,
            ],
            'ban' => ['durations' => $this->banDurations],
            'challenge' => [
                'driver' => $this->challengeDriver,
                'turnstile' => [
                    'site_key' => getenv('SHIELD_TURNSTILE_SITE_KEY') ?: '',
                    'secret_key' => getenv('SHIELD_TURNSTILE_SECRET_KEY') ?: '',
                    'verify_url' => getenv('SHIELD_TURNSTILE_VERIFY_URL') ?: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
                ],
                'recaptcha' => [
                    'site_key' => getenv('SHIELD_RECAPTCHA_SITE_KEY') ?: '',
                    'secret_key' => getenv('SHIELD_RECAPTCHA_SECRET_KEY') ?: '',
                    'verify_url' => getenv('SHIELD_RECAPTCHA_VERIFY_URL') ?: 'https://www.google.com/recaptcha/api/siteverify',
                ],
            ],
            'behavior' => [
                'unique_uri_limit' => $this->uniqueUriLimit,
                'window_seconds' => $this->behaviorWindowSeconds,
                'not_found_limit' => $this->notFoundLimit,
                'missing_referer_signal' => $this->missingRefererSignal,
                'suspicious_user_agents' => $this->suspiciousUserAgents,
                'scanner_user_agents' => $this->scannerUserAgents,
                'scanner_ua_signal' => $this->scannerUaSignal,
                'path_rate_limit' => $this->pathRateLimit,
                'sensitive_path_rate_limit' => $this->sensitivePathRateLimit,
                'sensitive_paths' => $this->sensitivePaths,
            ],
            'bots' => [
                'mode' => $this->botMode,
                'unverified_claim_signal' => $this->unverifiedClaimSignal,
                'verification' => [
                    'enabled' => $this->crawlerVerificationEnabled,
                    'ttl_hours' => $this->crawlerVerificationTtlHours,
                    'hostnames' => $this->crawlerHostnames,
                    'ip_ranges' => $this->crawlerIpRanges,
                ],
                'known_agents' => $this->knownBotAgents,
                'known_bot_agents' => $this->knownBotAgents,
                'suspicious_user_agent_overrides' => $this->suspiciousUserAgentOverrides,
                'missing_referer_signal' => $this->missingRefererSignal,
            ],
            'rules' => [
                'packs' => [
                    'wordpress' => $this->rulesPacksWordpress,
                    'injection' => $this->rulesPacksInjection,
                ],
                'skip_paths' => $this->skipPaths,
            ],
            'inspection' => [
                'body' => [
                    'enabled' => $this->bodyInspectionEnabled,
                    'max_bytes' => $this->bodyInspectionMaxBytes,
                ],
            ],
            'logging' => [
                'level' => $this->loggingLevel,
                'bypass_events' => $this->logBypassEvents,
                'retention_days' => $this->retentionDays,
            ],
            'api' => [
                'paths' => $this->apiPaths,
                'detect_accept' => $this->apiDetectAccept,
            ],
            'admin' => [
                'enabled' => $this->adminEnabled,
                'authorize' => $this->adminAuthorize,
                'prefix' => $this->adminPrefix,
            ],
            'allowlist' => [
                'hosts' => $this->allowlistHosts,
                'paths' => $this->allowlistPaths,
                'ips' => $this->allowlistIps,
            ],
            'trusted' => [
                'enabled' => $this->trustedEnabled,
                'ttl_minutes' => $this->trustedTtlMinutes,
            ],
            'performance' => [
                'max_uri_length' => $this->maxUriLength,
                'ban_cache_ttl_seconds' => $this->banCacheTtlSeconds,
            ],
            'escalation' => ['step' => $this->escalationStep],
            'privacy' => ['sensitive_query_parameters' => $this->sensitiveQueryParameters],
            'rule_version' => $this->ruleVersion,
            'views' => [
                'blocked' => $this->blockedView,
                'challenge' => $this->challengeView,
            ],
            'branding' => [
                'title' => $this->brandingTitle,
                'accent_color' => $this->brandingAccentColor,
                'background_color' => $this->brandingBackgroundColor,
                'show_rule_id' => $this->brandingShowRuleId,
            ],
        ];
    }
}
