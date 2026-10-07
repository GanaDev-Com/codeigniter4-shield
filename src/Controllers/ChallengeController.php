<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Controllers;

use CodeIgniter\Controller;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\ResponseInterface;
use Ganadev\Shield\Codeigniter\Support\ShieldResolver;
use Ganadev\Shield\Codeigniter\Support\ShieldView;
use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Engine\ShieldEngine;

final class ChallengeController extends Controller
{
    private readonly ChallengeDriverInterface $driver;

    private readonly ShieldEngine $engine;

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

        $this->driver = service('shield.challenge') ?? $resolver->challengeDriver();
        $this->engine = service('shield.engine') ?? $resolver->engine();
        $this->config = $resolver->config();
    }

    public function show(): ResponseInterface
    {
        $payload = $this->driver->render($this->context());

        $data = [
            'driver' => $payload->driver,
            'siteKey' => $payload->siteKey,
            'testToken' => (string) ($payload->data['test_token'] ?? ''),
            'csrfToken' => csrf_token(),
            'redirect' => $this->safeRedirect(),
            'error' => (bool) $this->request->getGet('error'),
            'branding' => [
                'title' => $this->config->branding['title'] ?? 'Ganadev Shield',
                'accent_color' => $this->config->branding['accent_color'] ?? '#22d3ee',
                'background_color' => $this->config->branding['background_color'] ?? '#0b1220',
                'show_rule_id' => $this->config->branding['show_rule_id'] ?? false,
            ],
        ];

        $html = ShieldView::render($this->config->challengeView, $data);

        $response = service('response');
        $response->setBody($html);
        $response->setStatusCode(200);
        $response->setHeader('Cache-Control', 'no-store');

        return $response;
    }

    public function verify(): RedirectResponse
    {
        $context = $this->context();
        $token = (string) $this->request->getPost('shield_challenge_token');

        $result = $this->driver->verify($token, $context);

        if (! $result->passed) {
            return redirect()->to('shield/challenge?error=1&redirect='.urlencode($this->safeRedirect()));
        }

        $this->engine->markChallengePassed($context->ip);
        $cookie = $this->engine->issueTrustedCookie($context);

        $redirectResponse = redirect()->to($this->safeRedirect());

        if ($cookie !== '') {
            $redirectResponse->setCookie(
                name: $this->engine->trustedCookieName(),
                value: $cookie,
                expire: $this->config->trustedTtlMinutes * 60,
                path: '/',
                secure: true,
                httponly: true,
                samesite: 'Lax',
            );
        }

        return $redirectResponse;
    }

    private function context(): RequestContext
    {
        return RequestContext::create(
            rawUri: $this->request->getPath() ?: '/',
            method: $this->request->getMethod(),
            host: $this->request->getHeaderLine('host') ?: 'localhost',
            ip: $this->request->getIPAddress(),
            headersSubset: ['user-agent' => $this->request->getHeaderLine('user-agent')],
        );
    }

    private function safeRedirect(): string
    {
        $redirect = $this->request->getPost('redirect');
        if (! is_string($redirect)) {
            $redirect = $this->request->getGet('redirect');
        }
        $redirect = is_string($redirect) ? $redirect : '/';

        if ($redirect === '' || ! str_starts_with($redirect, '/')) {
            return '/';
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $redirect) === 1) {
            return '/';
        }

        $normalized = strtolower(str_replace(
            ['\\', '%5c', '%2f'],
            ['/', '/', '/'],
            $redirect,
        ));

        if (str_starts_with($normalized, '//')) {
            return '/';
        }

        if (preg_match('#^/[a-z][a-z0-9+.-]*:#', $normalized) === 1) {
            return '/';
        }

        return $redirect;
    }
}
