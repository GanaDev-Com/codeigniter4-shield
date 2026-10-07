<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Support;

use CodeIgniter\View\Exceptions\ViewException;

final class ShieldView
{
    /**
     * Renders a Shield view.
     *
     * Tries the configured view name first (which resolves to an application
     * override in APPPATH/Views when one has been published) and falls back to
     * the view bundled with this package.
     */
    public static function render(string $view, array $data = []): string
    {
        try {
            return view($view, $data);
        } catch (ViewException) {
            return view(self::packageViewName($view), $data);
        }
    }

    private static function packageViewName(string $view): string
    {
        return 'Ganadev\Shield\Codeigniter\\Views\\'.trim(str_replace('/', '\\', $view), '\\');
    }
}
