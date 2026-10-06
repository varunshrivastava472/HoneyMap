"""
Decoy Fake Login Handlers via FastAPI APIRouter.
Routes: /admin, /wp-admin, /login
GET renders realistic authentication forms; POST captures credential stuffing attempts.
"""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from decoys.logger import log_decoy_hit

fake_login_router = APIRouter()

LOGIN_HTML_TEMPLATES = {
    "/wp-admin": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WordPress &rsaquo; Log In</title>
    <style>
        body { background: #f0f0f1; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-card { background: #fff; border: 1px solid #c3c4c7; padding: 26px 24px 34px; width: 320px; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
        .login-card h1 { font-size: 20px; text-align: center; margin-bottom: 20px; color: #3c434a; }
        .input-group { margin-bottom: 16px; }
        label { display: block; font-size: 14px; margin-bottom: 5px; color: #3c434a; }
        input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 6px 10px; border: 1px solid #8c8f94; border-radius: 4px; font-size: 14px; }
        button { background: #2271b1; color: #fff; border: none; padding: 8px 16px; border-radius: 3px; cursor: pointer; width: 100%; font-weight: 600; font-size: 14px; }
        button:hover { background: #135e96; }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>WordPress Core</h1>
        <form method="POST" action="/wp-admin">
            <div class="input-group">
                <label for="log">Username or Email Address</label>
                <input type="text" name="log" id="log" autocomplete="username" required>
            </div>
            <div class="input-group">
                <label for="pwd">Password</label>
                <input type="password" name="pwd" id="pwd" autocomplete="current-password" required>
            </div>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>""",
    "/admin": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Administrative Portal</title>
    <style>
        body { background: #0f172a; font-family: Inter, system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; color: #e2e8f0; }
        .login-box { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 32px; width: 340px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
        h2 { margin-top: 0; font-size: 20px; font-weight: 600; color: #f8fafc; }
        p { color: #94a3b8; font-size: 13px; margin-bottom: 24px; }
        .input-group { margin-bottom: 18px; }
        label { display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; color: #cbd5e1; font-weight: 500; }
        input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; background: #0f172a; border: 1px solid #475569; border-radius: 6px; padding: 10px 12px; color: #f8fafc; font-size: 14px; }
        input:focus { outline: none; border-color: #38bdf8; }
        button { background: #0284c7; color: white; border: none; border-radius: 6px; padding: 10px; width: 100%; font-weight: 600; cursor: pointer; transition: background 0.15s; }
        button:hover { background: #0369a1; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Cluster Admin Access</h2>
        <p>Restricted access: Internal enterprise personnel only.</p>
        <form method="POST" action="/admin">
            <div class="input-group">
                <label>Admin ID / Email</label>
                <input type="text" name="username" placeholder="admin@internal.local" required>
            </div>
            <div class="input-group">
                <label>Security Credential</label>
                <input type="password" name="password" placeholder="••••••••••••" required>
            </div>
            <button type="submit">Authorize Session</button>
        </form>
    </div>
</body>
</html>""",
    "/login": """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Customer Account Sign In</title>
    <style>
        body { background: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 32px; width: 320px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        h2 { margin: 0 0 8px 0; color: #1e293b; font-size: 22px; }
        p { margin: 0 0 24px 0; color: #64748b; font-size: 14px; }
        .field { margin-bottom: 16px; }
        label { display: block; font-size: 13px; font-weight: 500; color: #475569; margin-bottom: 6px; }
        input { width: 100%; box-sizing: border-box; padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; }
        button { width: 100%; background: #4f46e5; color: #fff; padding: 10px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }
        button:hover { background: #4338ca; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Sign In</h2>
        <p>Enter your credentials to continue</p>
        <form method="POST" action="/login">
            <div class="field">
                <label>Username / Email</label>
                <input type="text" name="email" required>
            </div>
            <div class="field">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>"""
}


@fake_login_router.api_route("/admin", methods=["GET", "POST"])
@fake_login_router.api_route("/wp-admin", methods=["GET", "POST"])
@fake_login_router.api_route("/login", methods=["GET", "POST"])
async def handle_fake_login(request: Request):
    """
    Handles GET by rendering plausible bait login form and logging probe event.
    Handles POST by capturing submitted credential attempt, logging credential brute force attempt,
    and returning an authentic failure message.
    """
    path = request.url.path
    if request.method == "GET":
        await log_decoy_hit(
            request,
            attack_type="credential_recon",
            metadata={"surface": "fake_login_form", "path": path}
        )
        html = LOGIN_HTML_TEMPLATES.get(path, LOGIN_HTML_TEMPLATES["/login"])
        return HTMLResponse(content=html, status_code=200)

    # POST attempt
    await log_decoy_hit(
        request,
        attack_type="credential_stuffing",
        metadata={"surface": "fake_login_post", "path": path}
    )
    # Return realistic failure response
    return JSONResponse(
        status_code=401,
        content={
            "status": "error",
            "error_code": "AUTH_FAILED_004",
            "message": "Invalid username or password. This access attempt has been logged."
        }
    )
