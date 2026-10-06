<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Controllers;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Database;
use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Codeigniter\Support\TrustedProxyInspector;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Rules\RuleRepository;

final class AdminController
{
    public function __construct(
        private readonly Ci4BanRepository $bans,
        private readonly Ci4EventRepository $events,
        private readonly RuleRepository $rules,
        private readonly ShieldConfig $config,
    ) {}

    public function bans(RequestInterface $request): ResponseInterface
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $result = $this->bans->paginate([
            'ip' => $request->getGet('ip'),
            'status' => $request->getGet('status'),
            'active' => $request->getGet('active'),
        ], $this->perPage($request));

        return $this->json(['data' => $result]);
    }

    public function banDetail(string $id): ResponseInterface
    {
        if (! $this->authorized(request())) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->json(['error' => 'not_found'], 404);
        }

        return $this->json(['ban' => $ban]);
    }

    public function release(RequestInterface $request, string $id): ResponseInterface
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->json(['error' => 'not_found'], 404);
        }

        $released = $this->bans->release(
            $ban,
            (string) $request->getPost('reason', 'manual_release'),
            $this->actor($request),
        );

        return $this->json(['ban' => $released]);
    }

    public function extend(RequestInterface $request, string $id): ResponseInterface
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->json(['error' => 'not_found'], 404);
        }

        $minutes = max(1, (int) $request->getPost('minutes', 60));
        $expires = \DateTimeImmutable::createFromInterface($ban->expiresAt ?? new \DateTimeImmutable);
        $expires = $expires->modify("+{$minutes} minutes");

        $extended = $this->bans->extend($ban, $expires, $this->actor($request));

        return $this->json(['ban' => $extended]);
    }

    public function events(RequestInterface $request): ResponseInterface
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $result = $this->events->paginate([
            'ip' => $request->getGet('ip'),
            'host' => $request->getGet('host'),
            'rule_id' => $request->getGet('rule_id'),
            'severity' => $request->getGet('severity'),
            'decision' => $request->getGet('decision'),
        ], $this->perPage($request));

        return $this->json(['data' => $result]);
    }

    public function rules(RequestInterface $request): ResponseInterface
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $rules = [];
        foreach ($this->rules->all() as $rule) {
            $rules[] = [
                'id' => $rule->id,
                'category' => $rule->category,
                'matcher' => $rule->matcher->value,
                'severity' => $rule->severity->value,
                'score' => $rule->score,
                'immediate_ban' => $rule->immediateBan,
                'enabled' => $rule->enabled,
            ];
        }

        return $this->json(['version' => '1.0.0', 'count' => count($rules), 'rules' => $rules]);
    }

    public function health(RequestInterface $request): ResponseInterface
    {
        if (! $this->authorized($request)) {
            return $this->denied();
        }

        $dbOk = true;
        $cacheOk = true;
        $exception = null;

        try {
            $db = Database::connect();
            $db->initialize();
        } catch (\Throwable $e) {
            $dbOk = false;
            $exception = $e;
        }

        try {
            $cache = service('cache');
            $cache->get('shield:health:probe');
        } catch (\Throwable) {
            $cacheOk = false;
        }

        $proxyWarning = null;
        $forwarded = $request->getHeaderLine('X-Forwarded-For') !== ''
            || $request->getHeaderLine('Forwarded') !== '';
        if ($forwarded && ! TrustedProxyInspector::hasConfiguredProxies()) {
            $proxyWarning = 'Forwarded headers present but trusted proxies are not configured.';
        }

        $adminWarning = null;
        if ($this->config->adminEnabled && $this->config->adminAuthorize === '') {
            $adminWarning = 'Admin panel is enabled but admin.authorize is empty: any authenticated user can manage bans.';
        }

        $healthy = $dbOk && $cacheOk;

        return $this->json([
            'healthy' => $healthy,
            'database' => $dbOk,
            'cache' => $cacheOk,
            'engine' => true,
            'trusted_proxy_warning' => $proxyWarning,
            'admin_authorize_warning' => $adminWarning,
            'error' => $exception?->getMessage(),
        ], $healthy ? 200 : 503);
    }

    private function perPage(RequestInterface $request): int
    {
        return min(max((int) $request->getGet('per_page', 50), 1), 200);
    }

    private function authorized(RequestInterface $request): bool
    {
        if ($this->config->adminAuthorize === '') {
            return true;
        }

        $user = service('authentication')->user();

        return $user !== null && in_array($this->config->adminAuthorize, $user->getPermissions(), true);
    }

    private function denied(): ResponseInterface
    {
        return $this->json(['error' => 'forbidden'], 403);
    }

    private function actor(RequestInterface $request): ?string
    {
        $user = service('authentication')->user();

        return $user !== null ? (string) $user->id : null;
    }

    private function json(array $data, int $status = 200): ResponseInterface
    {
        $response = service('response');
        $response->setJSON($data);
        $response->setStatusCode($status);

        return $response;
    }
}
