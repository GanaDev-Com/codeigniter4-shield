<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 400px; margin: 40px auto; padding: 0 20px; }
        input { display: block; width: 100%; margin: 10px 0; padding: 10px; }
        button { padding: 10px 20px; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form method="post" action="<?= site_url('login') ?>">
        <input type="hidden" name="<?= csrf_token() ?>" value="<?= csrf_hash() ?>">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
