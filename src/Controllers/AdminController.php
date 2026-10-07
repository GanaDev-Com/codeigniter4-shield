<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Database;
use Ganadev\Shield\Codeigniter\Repositories\Ci4BanRepository;
use Ganadev\Shield\Codeigniter\Repositories\Ci4EventRepository;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Codeigniter\Support\TrustedProxyInspector;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Rules\RuleRepository;

final class AdminController extends Controller
{
    private readonly Ci4BanRepository $bans;

    private readonly Ci4EventRepository $events;

    private readonly RuleRepository $rules;

    private readonly ShieldConfig $config;

    /**
     * CodeIgniter instantiates controllers with `new $class()` and calls
     * initController() afterwards, so all dependencies are resolved here
     * without constructor arguments.
     */
    public function __construct()
    {
        /** @var ShieldResolver $resolver */
        $resolver = service('shield.resolver') ?? new ShieldResolver;

        $this->bans = new Ci4BanRepository;
        $this->events = new Ci4EventRepository;
        $this->rules = $resolver->rules();
        $this->config = $resolver->config();
    }

    public function bans(): ResponseInterface
    {
        if (! $this->authorized()) {
            return $this->denied();
        }

        $result = $this->bans->paginate([
            'ip' => $this->request->getGet('ip'),
            'status' => $this->request->getGet('status'),
            'active' => $this->request->getGet('active') !== null,
        ], $this->perPage(), $this->currentPage());

        return $this->json(['data' => $result]);
    }

    public function banDetail(string $id): ResponseInterface
    {
        if (! $this->authorized()) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->json(['error' => 'not_found'], 404);
        }

        return $this->json(['ban' => $ban]);
    }

    public function release(string $id): ResponseInterface
    {
        if (! $this->authorized()) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->json(['error' => 'not_found'], 404);
        }

        $reason = $this->request->getPost('reason');

        $released = $this->bans->release(
            $ban,
            is_string($reason) && $reason !== '' ? $reason : 'manual_release',
            $this->actor(),
        );

        return $this->json(['ban' => $released]);
    }

    public function extend(string $id): ResponseInterface
    {
        if (! $this->authorized()) {
            return $this->denied();
        }

        $ban = $this->bans->findById($id);
        if ($ban === null) {
            return $this->json(['error' => 'not_found'], 404);
        }

        $minutes = $this->request->getPost('minutes');
        $minutes = is_numeric($minutes) ? (int) $minutes : 60;
        $minutes = max(1, $minutes);
        $expires = \DateTimeImmutable::createFromInterface($ban->expiresAt ?? new \DateTimeImmutable);
        $expires = $expires->modify("+{$minutes} minutes");

        $extended = $this->bans->extend($ban, $expires, $this->actor());

        return $this->json(['ban' => $extended]);
    }

    public function events(): ResponseInterface
    {
        if (! $this->authorized()) {
            return $this->denied();
        }

        $result = $this->events->paginate([
            'ip' => $this->request->getGet('ip'),
            'host' => $this->request->getGet('host'),
            'rule_id' => $this->request->getGet('rule_id'),
            'severity' => $this->request->getGet('severity'),
            'decision' => $this->request->getGet('decision'),
        ], $this->perPage(), $this->currentPage());

        return $this->json(['data' => $result]);
    }

    public function rules(): ResponseInterface
    {
        if (! $this->authorized()) {
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

    public function health(): ResponseInterface
    {
        if (! $this->authorized()) {
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
            $cache->get('shield-health-probe');
        } catch (\Throwable) {
            $cacheOk = false;
        }

        $proxyWarning = null;
        $forwarded = $this->request->getHeaderLine('X-Forwarded-For') !== ''
            || $this->request->getHeaderLine('Forwarded') !== '';
        if ($forwarded && ! TrustedProxyInspector::hasConfiguredProxies()) {
            $proxyWarning = 'Forwarded headers present but trusted proxies are not configured.';
        }

        $adminWarning = null;
        $adminEnabled = (bool) (config('Shield')->adminEnabled ?? false);
        if ($adminEnabled && $this->config->adminAuthorize === '') {
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

    private function perPage(): int
    {
        $perPage = $this->request->getGet('per_page');

        return min(max(is_numeric($perPage) ? (int) $perPage : 50, 1), 200);
    }

    private function currentPage(): int
    {
        $page = $this->request->getGet('page');

        return max(1, is_numeric($page) ? (int) $page : 1);
    }

    private function authorized(): bool
    {
        if ($this->config->adminAuthorize === '') {
            return true;
        }

        $user = $this->authenticatedUser();

        if ($user === null) {
            return false;
        }

        $permissions = method_exists($user, 'getPermissions') ? (array) $user->getPermissions() : [];

        return in_array($this->config->adminAuthorize, $permissions, true);
    }

    private function denied(): ResponseInterface
    {
        return $this->json(['error' => 'forbidden'], 403);
    }

    /**
     * Resolves the authenticated user without assuming an authentication
     * service exists: apps without an auth library simply get null.
     */
    private function authenticatedUser(): ?object
    {
        try {
            $auth = service('authentication');
        } catch (\Throwable) {
            return null;
        }

        if (! is_object($auth) || ! method_exists($auth, 'user')) {
            return null;
        }

        $user = $auth->user();

        return is_object($user) ? $user : null;
    }

    private function actor(): ?string
    {
        $user = $this->authenticatedUser();

        if ($user === null) {
            return null;
        }

        $id = $user->id ?? null;

        return is_scalar($id) ? (string) $id : null;
    }

    private function json(array $data, int $status = 200): ResponseInterface
    {
        $response = service('response');
        $response->setJSON($data);
        $response->setStatusCode($status);

        return $response;
    }
}
