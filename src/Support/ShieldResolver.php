<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Support;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Clock\SystemClock;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Rules\DefaultRules;
use Ganadev\Shield\Core\Rules\RuleRepository;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Codeigniter\Cache\CodeIgniterCacheAdapter;
use Ganadev\Shield\Codeigniter\Challenge\NullTestDriver;
use Ganadev\Shield\Codeigniter\Challenge\RecaptchaDriver;
use Ganadev\Shield\Codeigniter\Challenge\TurnstileDriver;
use Ganadev\Shield\Codeigniter\Config\Shield as ShieldConfigClass;
use Ganadev\Shield\Codeigniter\Repositories\CachedBanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Codeigniter\Trust\Ci4TrustedCookie;
use Ganadev\Shield\Codeigniter\Trust\DnsCrawlerVerifier;

final class ShieldResolver
{
    public function config(): ShieldConfig
    {
        $configClass = new ShieldConfigClass();

        return ShieldConfig::fromArray($configClass->toArray());
    }

    public function rules(): RuleRepository
    {
        $config = $this->config();
        $definitions = DefaultRules::definitions();

        if ($config->rulesPacksWordpress) {
            $definitions = array_merge($definitions, DefaultRules::wordpressDefinitions());
        }

        if ($config->rulesPacksInjection) {
            $definitions = array_merge($definitions, DefaultRules::injectionDefinitions());
        }

        return RuleRepository::fromArray($definitions);
    }

    public function engine(?ShieldConfig $config = null): ShieldEngine
    {
        $config ??= $this->config();

        return new ShieldEngine(
            config: $config,
            normalizer: new Normalizer,
            signatures: new ThreatSignatureEngine($this->rules()),
            behavior: new BehaviorDetector($this->crawlerVerifier($config)),
            scorer: new RiskScorer,
            decisionEngine: new DecisionEngine,
            banPolicy: new BanPolicy,
            riskDecay: new RiskDecay,
            events: new Ci4EventRepository,
            clock: new SystemClock,
            bans: new CachedBanRepository(
                new Ci4BanRepository,
                $this->cacheAdapter(),
                $config->banCacheTtlSeconds,
            ),
            trusted: new Ci4TrustedCookie,
        );
    }

    public function crawlerVerifier(?ShieldConfig $config = null): DnsCrawlerVerifier
    {
        $config ??= $this->config();

        return new DnsCrawlerVerifier($this->cacheAdapter(), $config);
    }

    public function cacheAdapter(): CodeIgniterCacheAdapter
    {
        return new CodeIgniterCacheAdapter(
            service('cache'),
            $this->config()->appId,
        );
    }

    public function challengeDriver(): ChallengeDriverInterface
    {
        $config = $this->config();

        return match ($config->challengeDriver) {
            '', 'null', 'test' => new NullTestDriver,
            'recaptcha', 'google_recaptcha' => new RecaptchaDriver([
                'site_key' => getenv('SHIELD_RECAPTCHA_SITE_KEY') ?: '',
                'secret_key' => getenv('SHIELD_RECAPTCHA_SECRET_KEY') ?: '',
                'verify_url' => getenv('SHIELD_RECAPTCHA_VERIFY_URL') ?: 'https://www.google.com/recaptcha/api/siteverify',
            ]),
            default => new TurnstileDriver([
                'site_key' => getenv('SHIELD_TURNSTILE_SITE_KEY') ?: '',
                'secret_key' => getenv('SHIELD_TURNSTILE_SECRET_KEY') ?: '',
                'verify_url' => getenv('SHIELD_TURNSTILE_VERIFY_URL') ?: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            ]),
        };
    }
}
