<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Filters;

use CodeIgniter\Events\Events;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ganadev\Shield\Codeigniter\Cache\CodeIgniterCacheAdapter;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Codeigniter\Support\ShieldView;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Detection\BehaviorCounters;
use Ganadev\Shield\Core\Engine\EngineResult;
use Ganadev\Shield\Core\Engine\ShieldEngine;
use Ganadev\Shield\Core\Privacy\UriMasker;

final class SecurityFirewallFilter implements FilterInterface
{
    private readonly ShieldConfig $config;

    private ?ShieldEngine $engine;

    private ?CodeIgniterCacheAdapter $cache;

    private string $adminPrefix;

    /**
     * All dependencies are optional: CodeIgniter instantiates filters through
     * `new $className()` (see Filters::createFilter()), so every collaborator
     * is resolved lazily from the shared services or a fresh resolver.
     */
    public function __construct(
        ?ShieldEngine $engine = null,
        ?ShieldConfig $config = null,
        ?CodeIgniterCacheAdapter $cache = null,
        ?string $adminPrefix = null,
    ) {
        $this->engine = $engine;
        $this->config = $config ?? (new ShieldResolver)->config();
        $this->cache = $cache;
        $this->adminPrefix = $adminPrefix ?? (string) (config('Shield')->adminPrefix ?? 'shield');
    }

    public function before(RequestInterface $request, $arguments = null): ?ResponseInterface
    {
        if (! $this->config->enabled || $this->isShieldRoute($request)) {
            return null;
        }

        $context = $this->buildContext($request);
        $counters = $this->readCounters($context);
        $engine = $this->engine();

        try {
            $cookie = $request->getCookie($engine->trustedCookieName());
            $result = $engine->inspect($context, $counters, [
                'trusted_cookie' => is_string($cookie) ? $cookie : '',
            ]);
        } catch (\Throwable) {
            return $this->onInfrastructureFailure($request);
        }

        if ($result->shouldBlock()) {
            Events::trigger('ShieldBlocked', $context->ip, $result->verdict->ruleId ?? 'unknown', $result->verdict->reason, $result->score->total, $this->maskUri($context->rawUri), $context->method);

            return $this->blockResponse($request, $result);
        }

        if ($result->shouldChallenge()) {
            return $this->challengeResponse($request);
        }

        return null;
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): void
    {
        if (! $this->config->enabled || $this->isShieldRoute($request)) {
            return;
        }

        if ($response->getStatusCode() === 404) {
            $this->countNotFound($this->buildContext($request));
        }
    }

    private function buildContext(RequestInterface $request): RequestContext
    {
        // getPath() is relative to baseURL and has no leading slash; core
        // prefix matching (skip paths, api paths, allowlists) expects one.
        $path = $request->getPath() ?: '/';
        if ($path[0] !== '/') {
            $path = '/'.$path;
        }

        return RequestContext::create(
            rawUri: $path,
            method: $request->getMethod(),
            host: $request->getHeaderLine('host') ?: 'localhost',
            ip: $request->getIPAddress(),
            headersSubset: [
                'user-agent' => $request->getHeaderLine('user-agent'),
                'referer' => $request->getHeaderLine('referer'),
            ],
            body: $this->captureBody($request),
        );
    }

    private function captureBody(RequestInterface $request): string
    {
        if (! $this->config->bodyInspectionEnabled) {
            return '';
        }

        if ($this->isSkippedPath($request->getPath() ?: '/')) {
            return '';
        }

        $contentType = strtolower($request->getHeaderLine('content-type'));
        if (str_starts_with($contentType, 'multipart/')) {
            return '';
        }

        $body = (string) $request->getBody();
        if (strlen($body) > $this->config->bodyInspectionMaxBytes) {
            $body = substr($body, 0, $this->config->bodyInspectionMaxBytes);
        }

        if (str_starts_with($contentType, 'application/x-www-form-urlencoded')) {
            $body = urldecode($body);
        }

        return $body;
    }

    private function isSkippedPath(string $path): bool
    {
        return $this->matchesPathPrefix($path, $this->config->skipPaths);
    }

    private function readCounters(RequestContext $context): BehaviorCounters
    {
        try {
            $cache = $this->cache();
            $unique = $cache->increment(
                "counters:{$context->ip}:unique",
                $this->config->behaviorWindowSeconds,
            );
            $notFound = (int) $cache->get("counters:{$context->ip}:not_found");
            $pathKey = strtolower((string) preg_replace('#/{2,}#', '/', $context->rawPath));
            $pathCount = $cache->increment(
                'counters:'.$context->ip.':path:'.hash('sha256', $pathKey),
                $this->config->behaviorWindowSeconds,
            );
            $sensitive = $this->isSensitivePath($pathKey);
        } catch (\Throwable) {
            return new BehaviorCounters;
        }

        return new BehaviorCounters(
            uniqueUriCount: $unique,
            notFoundCount: $notFound,
            pathRequestCount: $pathCount,
            isSensitivePath: $sensitive,
        );
    }

    private function isSensitivePath(string $path): bool
    {
        foreach ($this->config->sensitivePaths as $sensitive) {
            if (str_starts_with($path, $sensitive)) {
                return true;
            }
        }

        return false;
    }

    private function countNotFound(RequestContext $context): void
    {
        try {
            $this->cache()->increment(
                "counters:{$context->ip}:not_found",
                $this->config->behaviorWindowSeconds,
            );
        } catch (\Throwable) {
        }
    }

    private function maskUri(string $uri): string
    {
        return (new UriMasker)->mask($uri, $this->config->sensitiveQueryParameters);
    }

    private function blockResponse(RequestInterface $request, EngineResult $result): ResponseInterface
    {
        if ($this->isApiRequest($request)) {
            return $this->jsonBlockResponse($result);
        }

        $data = [
            'ruleId' => $result->verdict->ruleId ?? 'unknown',
            'appId' => $this->config->appId,
            'branding' => [
                'title' => $this->config->branding['title'] ?? 'Ganadev Shield',
                'accent_color' => $this->config->branding['accent_color'] ?? '#22d3ee',
                'background_color' => $this->config->branding['background_color'] ?? '#0b1220',
                'show_rule_id' => $this->config->branding['show_rule_id'] ?? false,
            ],
        ];

        $html = ShieldView::render($this->config->blockedView, $data);

        $response = service('response');
        $response->setBody($html);
        $response->setStatusCode($this->config->responseCode);
        $response->setHeader('X-Shield-Blocked', $result->verdict->ruleId ?? 'shield');
        $response->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

        return $response;
    }

    private function jsonBlockResponse(EngineResult $result): ResponseInterface
    {
        $response = service('response');
        $response->setJSON([
            'error' => 'request_blocked',
            'app_id' => $this->config->appId,
            'rule_id' => $result->verdict->ruleId ?? 'unknown',
            'decision' => $result->verdict->decision->value,
            'score' => $result->verdict->score,
        ]);
        $response->setStatusCode($this->config->responseCode);
        $response->setHeader('X-Shield-Blocked', $result->verdict->ruleId ?? 'shield');
        $response->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

        return $response;
    }

    private function challengeResponse(RequestInterface $request): ResponseInterface
    {
        $challengeUrl = site_url('shield/challenge?redirect='.urlencode($request->getPath() ?: '/'));

        if ($this->isApiRequest($request)) {
            return $this->jsonChallengeResponse($challengeUrl);
        }

        return redirect()->to($challengeUrl);
    }

    private function jsonChallengeResponse(string $challengeUrl): ResponseInterface
    {
        $response = service('response');
        $response->setJSON([
            'error' => 'challenge_required',
            'app_id' => $this->config->appId,
            'challenge_url' => $challengeUrl,
        ]);
        $response->setStatusCode(401);
        $response->setHeader('X-Shield-Challenge', '1');
        $response->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

        return $response;
    }

    private function isApiRequest(RequestInterface $request): bool
    {
        if ($this->matchesPathPrefix($request->getPath() ?: '/', $this->config->apiPaths)) {
            return true;
        }

        $accept = $request->getHeaderLine('accept');
        $xRequestedWith = $request->getHeaderLine('x-requested-with');

        return $this->config->apiDetectAccept && (
            str_contains($accept, 'application/json') ||
            str_contains($accept, 'text/javascript') ||
            $xRequestedWith === 'XMLHttpRequest'
        );
    }

    private function matchesPathPrefix(string $path, array $prefixes): bool
    {
        $normalized = '/'.ltrim($path, '/');

        foreach ($prefixes as $prefix) {
            $prefix = '/'.ltrim($prefix, '/');

            if ($normalized === $prefix || str_starts_with($normalized, rtrim($prefix, '/').'/')) {
                return true;
            }
        }

        return false;
    }

    private function onInfrastructureFailure(RequestInterface $request): ?ResponseInterface
    {
        if ($this->config->failMode === ShieldConfig::FAIL_CLOSED) {
            $response = service('response');
            $response->setBody('Service unavailable.');
            $response->setStatusCode(503);

            return $response;
        }

        return null;
    }

    private function isShieldRoute(RequestInterface $request): bool
    {
        $path = $request->getPath() ?: '/';

        foreach ($this->shieldRoutePrefixes() as $prefix) {
            if ($path === $prefix || str_starts_with($path, $prefix.'/')) {
                return true;
            }
        }

        return false;
    }

    private function shieldRoutePrefixes(): array
    {
        return array_values(array_unique(array_filter(
            ['shield', trim($this->adminPrefix, '/')],
        )));
    }

    private function engine(): ShieldEngine
    {
        return $this->engine ??= service('shield.engine') ?? (new ShieldResolver)->engine($this->config);
    }

    private function cache(): CodeIgniterCacheAdapter
    {
        return $this->cache ??= service('shield.cache') ?? (new ShieldResolver)->cacheAdapter();
    }
}
