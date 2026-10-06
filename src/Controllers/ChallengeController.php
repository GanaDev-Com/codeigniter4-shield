<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Controllers;

use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Config\ShieldConfig;
use Ganadev\Shield\Core\Context\RequestContext;
use Ganadev\Shield\Core\Engine\ShieldEngine;

final class ChallengeController
{
    public function __construct(
        private readonly ChallengeDriverInterface $driver,
        private readonly ShieldEngine $engine,
        private readonly ShieldConfig $config,
    ) {}

    public function show(RequestInterface $request): ResponseInterface
    {
        $payload = $this->driver->render($this->context($request));

        $data = [
            'driver' => $payload->driver,
            'siteKey' => $payload->siteKey,
            'testToken' => (string) ($payload->data['test_token'] ?? ''),
            'csrfToken' => csrf_token(),
            'redirect' => $this->safeRedirect($request),
            'error' => (bool) $request->getGet('error'),
            'branding' => [
                'title' => $this->config->branding['title'] ?? 'Ganadev Shield',
                'accent_color' => $this->config->branding['accent_color'] ?? '#22d3ee',
                'background_color' => $this->config->branding['background_color'] ?? '#0b1220',
                'show_rule_id' => $this->config->branding['show_rule_id'] ?? false,
            ],
        ];

        $html = view($this->config->challengeView, $data);

        $response = service('response');
        $response->setBody($html);
        $response->setStatusCode(200);
        $response->setHeader('Cache-Control', 'no-store');

        return $response;
    }

    public function verify(RequestInterface $request): RedirectResponse
    {
        $context = $this->context($request);
        $token = (string) $request->getPost('shield_challenge_token');

        $result = $this->driver->verify($token, $context);

        if (! $result->passed) {
            return redirect()->to('shield/challenge?error=1&redirect='.urlencode($this->safeRedirect($request)));
        }

        $this->engine->markChallengePassed($context->ip);
        $cookie = $this->engine->issueTrustedCookie($context);

        $redirectResponse = redirect()->to($this->safeRedirect($request));

        if ($cookie !== '') {
            $redirectResponse->setCookie(
                $this->engine->trustedCookieName(),
                $cookie,
                $this->config->trustedTtlMinutes * 60,
                '/',
                null,
                true,
                true,
                false,
                'Lax'
            );
        }

        return $redirectResponse;
    }

    private function context(RequestInterface $request): RequestContext
    {
        return RequestContext::create(
            rawUri: $request->getPath() ?: '/',
            method: $request->getMethod(),
            host: $request->getHeaderLine('host') ?: 'localhost',
            ip: $request->getIPAddress(),
            headersSubset: ['user-agent' => $request->getHeaderLine('user-agent')],
        );
    }

    private function safeRedirect(RequestInterface $request): string
    {
        $redirect = (string) $request->getPost('redirect', $request->getGet('redirect', '/'));

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
