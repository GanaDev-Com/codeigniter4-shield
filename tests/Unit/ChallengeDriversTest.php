<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use CodeIgniter\Config\Services;
use Ganadev\Shield\Codeigniter\Challenge\NullTestDriver;
use Ganadev\Shield\Codeigniter\Challenge\RecaptchaDriver;
use Ganadev\Shield\Codeigniter\Challenge\TurnstileDriver;
use Ganadev\Shield\Core\Context\RequestContext;

function challengeStubHttp(string $body): object
{
    return new class($body)
    {
        public array $calls = [];

        public function __construct(private readonly string $body) {}

        public function post(string $url, array $options = []): object
        {
            $this->calls[] = [$url, $options];

            $body = $this->body;

            return new class($body)
            {
                public function __construct(private readonly string $body) {}

                public function getBody(): string
                {
                    return $this->body;
                }
            };
        }
    };
}

function challengeFailingHttp(): object
{
    return new class
    {
        public function post(string $url, array $options = []): object
        {
            throw new \RuntimeException('network down');
        }
    };
}

function challengeContext(): RequestContext
{
    return RequestContext::create('/challenge', 'GET', 'localhost', '203.0.113.77');
}

it('renders and verifies with the null test driver', function () {
    $driver = new NullTestDriver;

    $payload = $driver->render(challengeContext());

    expect($payload->driver)->toBe('null')
        ->and($payload->siteKey)->toBe('test')
        ->and($payload->data['test_token'])->toBe(NullTestDriver::TEST_TOKEN);

    $ok = $driver->verify(NullTestDriver::TEST_TOKEN, challengeContext());
    expect($ok->passed)->toBeTrue()->and($ok->provider)->toBe('null');

    $bad = $driver->verify('wrong-token', challengeContext());
    expect($bad->passed)->toBeFalse()->and($bad->reason)->toBe('invalid_token');
});

it('fails turnstile verification without a secret key', function () {
    $driver = new TurnstileDriver(['site_key' => 'site-123']);

    $result = $driver->verify('token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('missing_secret');

    $payload = $driver->render(challengeContext());
    expect($payload->siteKey)->toBe('site-123')->and($payload->driver)->toBe('turnstile');
});

it('verifies a turnstile token against the provider', function () {
    $stub = challengeStubHttp('{"success": true}');
    Services::injectMock('curlrequest', $stub);

    $driver = new TurnstileDriver([
        'secret_key' => 'sec-123',
        'verify_url' => 'https://verify.test/turnstile',
    ]);

    $result = $driver->verify('good-token', challengeContext());

    expect($result->passed)->toBeTrue()->and($result->provider)->toBe('turnstile')
        ->and($stub->calls)->toHaveCount(1)
        ->and($stub->calls[0][0])->toBe('https://verify.test/turnstile')
        ->and($stub->calls[0][1]['form_params']['secret'])->toBe('sec-123')
        ->and($stub->calls[0][1]['form_params']['response'])->toBe('good-token')
        ->and($stub->calls[0][1]['form_params']['remoteip'])->toBe('203.0.113.77');
});

it('maps turnstile provider errors to the failure reason', function () {
    Services::injectMock('curlrequest', challengeStubHttp('{"success": false, "error-codes": ["invalid-input-response"]}'));

    $driver = new TurnstileDriver(['secret_key' => 'sec-123']);
    $result = $driver->verify('bad-token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('invalid-input-response');
});

it('treats a malformed turnstile response as invalid', function () {
    Services::injectMock('curlrequest', challengeStubHttp('not-json'));

    $driver = new TurnstileDriver(['secret_key' => 'sec-123']);
    $result = $driver->verify('bad-token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('invalid');
});

it('fails turnstile verification when the provider is unreachable', function () {
    Services::injectMock('curlrequest', challengeFailingHttp());

    $driver = new TurnstileDriver(['secret_key' => 'sec-123']);
    $result = $driver->verify('token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('provider_unavailable');
});

it('fails recaptcha verification without a secret key', function () {
    $driver = new RecaptchaDriver([]);

    $result = $driver->verify('token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('missing_secret');

    $payload = $driver->render(challengeContext());
    expect($payload->driver)->toBe('recaptcha');
});

it('verifies a recaptcha token against the provider', function () {
    $stub = challengeStubHttp('{"success": true}');
    Services::injectMock('curlrequest', $stub);

    $driver = new RecaptchaDriver([
        'secret_key' => 'g-secret',
        'verify_url' => 'https://verify.test/recaptcha',
    ]);

    $result = $driver->verify('good-token', challengeContext());

    expect($result->passed)->toBeTrue()->and($result->provider)->toBe('recaptcha')
        ->and($stub->calls[0][0])->toBe('https://verify.test/recaptcha')
        ->and($stub->calls[0][1]['form_params']['secret'])->toBe('g-secret');
});

it('maps a rejected recaptcha response to invalid', function () {
    Services::injectMock('curlrequest', challengeStubHttp('{"success": false}'));

    $driver = new RecaptchaDriver(['secret_key' => 'g-secret']);
    $result = $driver->verify('bad-token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('invalid');
});

it('fails recaptcha verification when the provider is unreachable', function () {
    Services::injectMock('curlrequest', challengeFailingHttp());

    $driver = new RecaptchaDriver(['secret_key' => 'g-secret']);
    $result = $driver->verify('token', challengeContext());

    expect($result->passed)->toBeFalse()->and($result->reason)->toBe('provider_unavailable');
});
