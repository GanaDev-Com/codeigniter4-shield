<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Challenge;

use Ganadev\Shield\Core\Challenge\ChallengeDriverInterface;
use Ganadev\Shield\Core\Challenge\ChallengePayload;
use Ganadev\Shield\Core\Challenge\ChallengeResult;
use Ganadev\Shield\Core\Context\RequestContext;

final class TurnstileDriver implements ChallengeDriverInterface
{
    private const DEFAULT_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

    public function __construct(
        private readonly array $options = [],
    ) {}

    public function name(): string
    {
        return 'turnstile';
    }

    public function render(RequestContext $context): ChallengePayload
    {
        return new ChallengePayload(
            driver: 'turnstile',
            siteKey: (string) ($this->options['site_key'] ?? ''),
            action: 'shield_challenge',
        );
    }

    public function verify(string $token, RequestContext $context): ChallengeResult
    {
        $secret = (string) ($this->options['secret_key'] ?? '');
        if ($secret === '') {
            return ChallengeResult::failure('turnstile', 'missing_secret');
        }

        try {
            $client = service('curlrequest');
            $response = $client->post(
                (string) ($this->options['verify_url'] ?? self::DEFAULT_VERIFY_URL),
                [
                    'form_params' => [
                        'secret' => $secret,
                        'response' => $token,
                        'remoteip' => $context->ip,
                    ],
                    'http_errors' => false,
                ],
            );
        } catch (\Throwable) {
            return ChallengeResult::failure('turnstile', 'provider_unavailable');
        }

        $data = json_decode($response->getBody(), true);
        $ok = is_array($data) && ($data['success'] ?? false) === true;

        return $ok
            ? ChallengeResult::success('turnstile')
            : ChallengeResult::failure('turnstile', $this->firstError($data));
    }

    private function firstError(mixed $data): string
    {
        if (is_array($data) && isset($data['error-codes'][0])) {
            return (string) $data['error-codes'][0];
        }

        return 'invalid';
    }
}
