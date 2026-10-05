<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome to CodeIgniter 4 Shield Demo</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; }
        .card { background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Welcome to CodeIgniter 4 Shield Demo</h1>

    <div class="card">
        <h2>Test Normal Traffic</h2>
        <p>This page should load normally without any blocking.</p>
        <code>curl http://localhost:8080/home</code>
    </div>

    <div class="card">
        <h2>Test Blocked Requests</h2>
        <p>These requests should be blocked by Shield:</p>
        <ul>
            <li><code>curl http://localhost:8080/.env</code></li>
            <li><code>curl http://localhost:8080/.git/config</code></li>
            <li><code>curl "http://localhost:8080/?file=/root/.aws/credentials"</code></li>
        </ul>
    </div>

    <div class="card">
        <h2>Test SQL Injection</h2>
        <p>SQL injection in POST body should be blocked:</p>
        <code>curl -X POST http://localhost:8080/login -d "username=admin' UNION SELECT password FROM users--"</code>
    </div>

    <div class="card">
        <h2>Test API Response</h2>
        <p>API requests get JSON responses:</p>
        <code>curl -H "Accept: application/json" http://localhost:8080/.env</code>
    </div>
</body>
</html>
