"""
HTTP Honeypot Server
====================
A fake HTTP server that mimics common vulnerable endpoints
and logs all requests including headers, payloads, and paths.

Captures SQL injection attempts, XSS payloads, directory traversal,
and web shell upload attempts.
"""

import asyncio
from aiohttp import web
import time
import re

from config import HTTP_PORT, BIND_HOST
from log_collector import collector

# Fake admin panel HTML (looks vulnerable to attract attackers)
FAKE_ADMIN_HTML = """<!DOCTYPE html>
<html>
<head><title>Admin Panel - Login</title><style>
body{font-family:Arial,sans-serif;background:#f0f0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.login-box{background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);width:320px}
h2{color:#333;text-align:center}
input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
button{width:100%;padding:10px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#0056b3}
.error{color:#dc3545;font-size:12px;margin-top:5px}
</style></head>
<body>
<div class="login-box">
<h2>System Administration</h2>
<form method="POST" action="/admin/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Sign In</button>
</form>
<p class="error" id="msg"></p>
</div>
</body>
</html>"""

FAKE_DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><title>Dashboard</title></head>
<body><h1>Welcome, Administrator</h1>
<p>Server Status: <span style="color:green">ONLINE</span></p>
<p>Active Connections: 47</p>
<p>Database: <a href="/admin/db">Manage Database</a></p>
<p>Users: <a href="/admin/users">Manage Users</a></p>
<p>Logs: <a href="/admin/logs">View System Logs</a></p>
</body></html>"""

FAKE_PHPINFO = """<html><body><h1>phpinfo()</h1>
<table border="1"><tr><td>System</td><td>Linux prod-server-01 5.15.0-91-generic</td></tr>
<tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
<tr><td>PHP Version</td><td>7.4.33</td></tr>
<tr><td>Loaded Extensions</td><td>mysqli, pdo_mysql, gd, curl, xml, json, openssl</td></tr>
</table></body></html>"""

# Suspicious patterns to flag
SUSPICIOUS_PATTERNS = {
    "sql_injection": re.compile(
        r"(\'|\"|%27|%22)\s*(OR|AND)\s*\d*\s*=\s*\d*|UNION\s+SELECT|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE|1\s*=\s*1|--|;--|\\x27|\\x22",
        re.IGNORECASE
    ),
    "xss": re.compile(
        r"<script|javascript:|on\w+\s*=|alert\(|<iframe|<object|<embed|document\.cookie",
        re.IGNORECASE
    ),
    "path_traversal": re.compile(
        r"\.\./|\.\\\.|%2e%2e%2f|%252e%252e%252f",
        re.IGNORECASE
    ),
    "command_injection": re.compile(
        r";\s*\w+|\|\s*\w+|\`\w+`|\$\(|\$\{.*\}",
        re.IGNORECASE
    ),
    "web_shell": re.compile(
        r"cmd=|command=|exec=|system=|shell=|c99|b374k|r57",
        re.IGNORECASE
    ),
    "lfi": re.compile(
        r"file=|include=|page=|path=.*\.txt|path=.*\.log|path=.*\.conf",
        re.IGNORECASE
    ),
}


def detect_attack(payload):
    """Analyze payload and return list of detected attack types."""
    attacks = []
    if not payload:
        return attacks
    for attack_type, pattern in SUSPICIOUS_PATTERNS.items():
        if pattern.search(payload):
            attacks.append(attack_type)
    return attacks


async def handle_request(request):
    """Main request handler for all HTTP paths."""
    source_ip = request.remote or "unknown"
    path = request.path
    method = request.method

    # Collect all request data
    headers = dict(request.headers)
    query = dict(request.query)

    # Try to get body
    body = ""
    try:
        body_bytes = await request.read()
        body = body_bytes.decode("utf-8", errors="replace")[:4096]
    except:
        pass

    # Combine everything for attack detection
    full_payload = f"{path}?{request.query_string} {body}"
    detected_attacks = detect_attack(full_payload)

    # Log the request
    event = collector.log_event(
        "http_request",
        source_ip=source_ip,
        service="http",
        port=HTTP_PORT,
        method=method,
        path=path,
        query=query,
        headers=headers,
        body=body[:1000],
        detected_attacks=detected_attacks,
        user_agent=headers.get("User-Agent", "")
    )

    print(f"[HTTP] {method} {path} from {source_ip} | Attacks: {detected_attacks}")

    # Return appropriate fake response
    if path == "/" or path == "/admin":
        return web.Response(text=FAKE_ADMIN_HTML, content_type="text/html")

    if path == "/admin/login":
        if method == "POST":
            data = await request.post()
            username = data.get("username", "")
            password = data.get("password", "")

            collector.log_event(
                "http_login_attempt",
                source_ip=source_ip,
                service="http",
                username=username,
                password=password,
                path=path
            )
            print(f"[HTTP] Login attempt from {source_ip}: {username}:{password}")

            return web.Response(
                text="<script>document.getElementById('msg').innerHTML='Invalid credentials. Please try again.'</script>",
                content_type="text/html"
            )
        return web.Response(text=FAKE_ADMIN_HTML, content_type="text/html")

    if path == "/admin/dashboard":
        return web.Response(text=FAKE_DASHBOARD_HTML, content_type="text/html")

    if path == "/phpinfo.php" or path == "/info.php":
        return web.Response(text=FAKE_PHPINFO, content_type="text/html")

    if path == "/robots.txt":
        return web.Response(text="User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n")

    if path == "/.env":
        return web.Response(text="DB_HOST=localhost\nDB_USER=root\nDB_PASS=SuperSecret123!\nAPP_KEY=base64:abc123...")

    if path.startswith("/wp-admin") or path.startswith("/wordpress"):
        return web.Response(text="<h1>WordPress</h1><p>Admin panel temporarily unavailable.</p>", status=503)

    # Generic 404 but log it
    return web.Response(
        text=f"<h1>404 Not Found</h1><p>The requested URL {path} was not found.</p>",
        status=404
    )


async def start_http_honeypot():
    """Start the HTTP honeypot server."""
    app = web.Application()
    app.router.add_get("/{path:.*}", handle_request)
    app.router.add_post("/{path:.*}", handle_request)
    app.router.add_put("/{path:.*}", handle_request)
    app.router.add_delete("/{path:.*}", handle_request)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BIND_HOST, HTTP_PORT)
    await site.start()

    print(f"[HTTP] Honeypot listening on {BIND_HOST}:{HTTP_PORT}")
    print(f"[HTTP] Fake admin panel: http://{BIND_HOST}:{HTTP_PORT}/admin")
    print(f"[HTTP] Fake phpinfo: http://{BIND_HOST}:{HTTP_PORT}/phpinfo.php")

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(start_http_honeypot())
    except KeyboardInterrupt:
        print("\n[HTTP] Server stopped.")
    except Exception as e:
        print(f"[HTTP] Error: {e}")
