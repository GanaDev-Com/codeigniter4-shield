<?php
$accent = $branding['accent_color'] ?? '#22d3ee';
$bg = $branding['background_color'] ?? '#0b1220';
$title = $branding['title'] ?? 'Ganadev CodeIgniter Shield';
$showRule = $branding['show_rule_id'] ?? false;
$rule = $ruleId ?? 'unknown';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Access Blocked — <?= esc($title) ?></title>
  <style>
    :root { --accent: <?= esc($accent) ?>; --bg: <?= esc($bg) ?>; }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color: #e6edf3;
      background:
        radial-gradient(1200px 600px at 50% -10%, <?= esc($accent) ?>22 0%, transparent 60%),
        linear-gradient(160deg, var(--bg) 0%, #05080f 100%);
      padding: 24px;
    }
    .grid-overlay {
      position: fixed; inset: 0; pointer-events: none; opacity: .35;
      background-image:
        linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
      background-size: 42px 42px;
    }
    .card {
      position: relative; width: 100%; max-width: 460px; text-align: center;
      background: rgba(255,255,255,.04); border: 1px solid rgba(255,255,255,.08);
      border-radius: 20px; padding: 48px 40px 36px; backdrop-filter: blur(14px);
      box-shadow: 0 24px 80px rgba(0,0,0,.55);
    }
    h1 { margin: 0 0 10px; font-size: 26px; font-weight: 700; letter-spacing: -.01em; }
    p { margin: 0 0 26px; color: #93a4b8; font-size: 15px; line-height: 1.6; }
    .rule {
      display: inline-block; padding: 8px 16px; font-family: 'Cascadia Code', Consolas, monospace;
      font-size: 13px; color: <?= esc($accent) ?>; background: <?= esc($accent) ?>12;
      border: 1px dashed <?= esc($accent) ?>55; border-radius: 8px; word-break: break-all;
    }
    .meta { margin-top: 28px; font-size: 12px; color: #5b6b80; }
    .footer { margin-top: 26px; font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: #46566b; }
  </style>
</head>
<body>
  <div class="grid-overlay"></div>
  <div class="card">
    <h1>Access Blocked</h1>
    <p>This request was denied by the application security layer. If you believe this is a mistake, contact the site administrator.</p>
    <?php if ($showRule): ?>
    <span class="rule"><?= esc($rule) ?></span>
    <?php endif; ?>
    <div class="meta">App: <strong><?= esc($appId) ?></strong> &nbsp;·&nbsp; <?= date('Y-m-d H:i:s') ?></div>
    <div class="footer"><?= esc($title) ?></div>
  </div>
</body>
</html>
