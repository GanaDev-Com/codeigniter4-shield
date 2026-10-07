<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Feature;

use Ganadev\Shield\Codeigniter\ShieldServiceProvider;

function challengeFlowUseTestDriver(): void
{
    config('Shield')->challengeDriver = 'test';
    ShieldServiceProvider::register();
}

it('renders the challenge page with the test driver', function () {
    challengeFlowUseTestDriver();

    $result = $this->withRoutes([])->call('GET', 'shield/challenge?redirect=%2Fdashboard');

    $result->assertOK();
    $result->assertSee('Verify you are human');
    $result->assertSeeInField('shield_challenge_token', 'test-token');
    $result->assertSeeInField('redirect', '/dashboard');
});

it('shows the failure message when error is set', function () {
    challengeFlowUseTestDriver();

    $result = $this->withRoutes([])->call('GET', 'shield/challenge?error=1');

    $result->assertOK();
    $result->assertSee('Verification failed. Please try again.');
    $result->assertSeeInField('redirect', '/');
});

it('verifies a valid token and redirects with a trusted cookie', function () {
    challengeFlowUseTestDriver();

    $result = $this->withRoutes([])->call('POST', 'shield/challenge/verify', [
        'shield_challenge_token' => 'test-token',
        'redirect' => '/dashboard',
    ]);

    $result->assertStatus(302);
    expect($result->getRedirectUrl())->toContain('/dashboard');
    $result->assertCookie('shield_trusted');
});

it('rejects an invalid token and loops back to the challenge page', function () {
    challengeFlowUseTestDriver();

    $result = $this->withRoutes([])->call('POST', 'shield/challenge/verify', [
        'shield_challenge_token' => 'wrong-token',
        'redirect' => '/dashboard',
    ]);

    $result->assertStatus(302);
    $location = (string) $result->getRedirectUrl();
    expect($location)->toContain('shield/challenge')
        ->and($location)->toContain('error=1')
        ->and($location)->toContain('redirect=%2Fdashboard');
});

it('hardens the redirect target against open redirects', function () {
    challengeFlowUseTestDriver();

    $failed = $this->withRoutes([])->call('POST', 'shield/challenge/verify', [
        'shield_challenge_token' => 'wrong-token',
        'redirect' => '//evil.example/phish',
    ]);

    $failed->assertStatus(302);
    expect((string) $failed->getRedirectUrl())->not->toContain('evil.example');

    $javascript = $this->withRoutes([])->call('POST', 'shield/challenge/verify', [
        'shield_challenge_token' => 'wrong-token',
        'redirect' => 'javascript:alert(1)',
    ]);

    expect((string) $javascript->getRedirectUrl())->not->toContain('javascript:');

    $passed = $this->withRoutes([])->call('POST', 'shield/challenge/verify', [
        'shield_challenge_token' => 'test-token',
        'redirect' => '//evil.example/phish',
    ]);

    $passed->assertStatus(302);
    expect((string) $passed->getRedirectUrl())->not->toContain('evil.example');
});
