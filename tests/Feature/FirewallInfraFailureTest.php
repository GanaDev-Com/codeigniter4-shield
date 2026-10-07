<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Feature;

use CodeIgniter\Config\Services;
use Ganadev\Shield\Codeigniter\Repositories\CachedBanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Codeigniter\ShieldServiceProvider;
use Ganadev\Shield\Core\Clock\SystemClock;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Decision\DecisionEngine;
use Ganadev\Shield\Core\Detection\BehaviorDetector;
use Ganadev\Shield\Core\Detection\ThreatSignatureEngine;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Normalization\Normalizer;
use Ganadev\Shield\Core\Reputation\BanPolicy;
use Ganadev\Shield\Core\Reputation\RiskDecay;
use Ganadev\Shield\Core\Scoring\RiskScorer;
use Ganadev\Shield\Core\Trust\TrustedCookieInterface;

function infraThrowingEngine(): ShieldEngine
{
    $resolver = service('shield.resolver');
    $config = $resolver->config();

    return new ShieldEngine(
        config: $config,
        normalizer: new Normalizer,
        signatures: new ThreatSignatureEngine($resolver->rules()),
        behavior: new BehaviorDetector($resolver->crawlerVerifier($config)),
        scorer: new RiskScorer,
        decisionEngine: new DecisionEngine,
        banPolicy: new BanPolicy,
        riskDecay: new RiskDecay,
        events: new Ci4EventRepository,
        clock: new SystemClock,
        bans: new CachedBanRepository(
            new Ci4BanRepository,
            $resolver->cacheAdapter(),
            $config->banCacheTtlSeconds,
        ),
        trusted: new class implements TrustedCookieInterface
        {
            public function name(): string
            {
                return 'shield_trusted';
            }

            public function issue(RequestContext $context, int $ttlMinutes): string
            {
                throw new \RuntimeException('trusted cookie infrastructure is down');
            }

            public function validate(string $cookieValue, RequestContext $context): bool
            {
                throw new \RuntimeException('trusted cookie infrastructure is down');
            }
        },
    );
}

/**
 * @return array{cookie: array|string|null, engine: ShieldEngine}
 */
function infraPrepareThrowingEngine(string $failMode): array
{
    config('Shield')->failMode = $failMode;
    ShieldServiceProvider::register();
    $engine = infraThrowingEngine();
    Services::injectMock('shield.engine', $engine);

    // Cookies must go through the Superglobals service: it snapshots
    // $_COOKIE on construction, so raw $_COOKIE writes are invisible.
    $superglobals = service('superglobals');
    $previous = $superglobals->cookie('shield_trusted');
    $superglobals->setCookie('shield_trusted', 'garbage');
    $superglobals->setServer('REMOTE_ADDR', '198.23.20.'.random_int(11, 250));

    return ['cookie' => $previous, 'engine' => $engine];
}

function infraRestoreCookie(array|string|null $previous): void
{
    $superglobals = service('superglobals');
    if ($previous === null) {
        $superglobals->unsetCookie('shield_trusted');
    } else {
        $superglobals->setCookie('shield_trusted', $previous);
    }
}

it('fails open when the engine throws', function () {
    $state = infraPrepareThrowingEngine('open');

    try {
        $result = $this->withRoutes([
            ['GET', 'probe-fail-open', static fn () => 'probe-ok'],
        ])->call('GET', 'probe-fail-open');
    } finally {
        infraRestoreCookie($state['cookie']);
    }

    $result->assertOK();
    $result->assertSee('probe-ok');
});

it('fails closed when the engine throws', function () {
    $state = infraPrepareThrowingEngine('closed');

    try {
        $result = $this->withRoutes([
            ['GET', 'probe-fail-closed', static fn () => 'probe-ok'],
        ])->call('GET', 'probe-fail-closed');
    } finally {
        infraRestoreCookie($state['cookie']);
    }

    $result->assertStatus(503);
    $result->assertSee('Service unavailable.');
    $result->assertDontSee('probe-ok');
});
