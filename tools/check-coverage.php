<?php

declare(strict_types=1);

$file = $argv[1] ?? '';
$threshold = (float) ($argv[2] ?? 0);

if ($file === '' || ! is_file($file)) {
    fwrite(STDERR, "Coverage report file not found: {$file}\n");
    exit(2);
}

$text = (string) file_get_contents($file);

if (! preg_match('/^  Lines:\s+([0-9.]+)%/m', $text, $m)) {
    fwrite(STDERR, "Cannot read 'Lines:' from coverage report: {$file}\n");
    exit(2);
}

$pct = (float) $m[1];

printf("Lines coverage: %.2f%% (threshold %.2f%%)\n", $pct, $threshold);

exit($pct >= $threshold ? 0 : 1);
