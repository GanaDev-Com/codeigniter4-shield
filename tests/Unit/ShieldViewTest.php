<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Tests\Unit;

use CodeIgniter\View\Exceptions\ViewException;
use Ganadev\Shield\Codeigniter\Support\ShieldView;

it('falls back to the package view when no app override exists', function () {
    $html = ShieldView::render('shield/blocked', [
        'ruleId' => 'sqli-001',
        'appId' => 'my-app',
        'branding' => [
            'title' => 'Custom Shield Title',
            'accent_color' => '#ff0000',
            'background_color' => '#000000',
            'show_rule_id' => true,
        ],
    ]);

    expect($html)->toContain('<!doctype html>')
        ->and($html)->toContain('Custom Shield Title')
        ->and($html)->toContain('sqli-001');
});

it('passes data through to the rendered challenge view', function () {
    $html = ShieldView::render('shield/challenge', [
        'driver' => 'null',
        'siteKey' => 'test-site-key',
        'testToken' => 'tok-123',
        'csrfToken' => 'csrf-123',
        'redirect' => '/dashboard',
        'error' => false,
        'branding' => [
            'title' => 'Brand X',
            'accent_color' => '#22d3ee',
            'background_color' => '#0b1220',
            'show_rule_id' => false,
        ],
    ]);

    expect($html)->toContain('Brand X')
        ->and($html)->toContain('tok-123')
        ->and($html)->toContain('/dashboard');
});

it('uses an application view override when one exists', function () {
    $html = ShieldView::render('welcome_message', []);

    expect($html)->toContain('Welcome to CodeIgniter 4!');
});

it('propagates the view exception when no view exists at all', function () {
    expect(fn () => ShieldView::render('missing/unknown-view', []))
        ->toThrow(ViewException::class);
});
