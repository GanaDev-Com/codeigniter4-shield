<?php

declare(strict_types=1);

namespace Ganadev\Shield\Codeigniter\Support;

final class InputValue
{
    public function string(mixed $value): ?string
    {
        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }
}
