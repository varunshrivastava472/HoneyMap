"""
Stage 12 Automated Verification: FastAPI Hardening Checklist Audit

Verifies:
1. Request-size caps (Stage 2 & 12):
   - MAX_CONTENT_LENGTH configured to 1MB.
   - sanitize_and_cap_request_data enforces 2000 char payload/headers and 500 char UA limits.
2. SQLite async thread-safety & WAL mode (aiosqlite):
   - aiosqlite runs WAL journal mode and busy_timeout=30000ms.
   - Concurrent multi-task writes execute with zero database locking errors.
3. ASGI SocketIO configuration:
   - async_mode="asgi" configured in python-socketio AsyncServer.
4. Per-IP rate limiting:
   - Sliding-window rate limiter triggers 429 Too Many Requests with Retry-After header.
5. Scoped CORS:
   - CORS is strictly scoped to http://localhost:5173 in both REST and WebSocket layers (never '*').
6. Zero Flask / Greenlet dependencies:
   - requirements.txt is verified free of flask, eventlet, and gevent.
7. React XSS audit:
   - Zero occurrences of dangerouslySetInnerHTML across all frontend source files.
8. Comprehensive README documentation:
   - Setup, 3-terminal demo flow, architecture, and out-of-scope declarations verified.
"""

import os
import sys
import asyncio
import sqlite3
import requests
from typing import List

BASE_URL = "http://127.0.0.1:5000"
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
FRONTEND_SRC = os.path.join(PROJECT_ROOT, "frontend", "src")

def test_stage12():
    print("[*] ===================================================")
    print("[*] Stage 12 Automated Verification: FastAPI Hardening Audit")
    print("[*] ===================================================")

    # -------------------------------------------------------------
    # 1. VERIFY REQUEST-SIZE CAPS (STAGE 2 & STAGE 12)
    # -------------------------------------------------------------
    print("\n[*] 1. Verifying request-size caps...")
    from app import MAX_CONTENT_LENGTH
    assert MAX_CONTENT_LENGTH == 1 * 1024 * 1024, (
        f"MAX_CONTENT_LENGTH expected 1MB, got {MAX_CONTENT_LENGTH}"
    )
    print("    [+] FastAPI MAX_CONTENT_LENGTH verified at 1MB (1,048,576 bytes).")

    # Verify input capping helper
    from decoys.request_utils import sanitize_and_cap_request_data
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/test_probe",
        "headers": [
            (b"user-agent", b"A" * 1000),
            (b"x-custom-header", b"B" * 3000),
            (b"x-forwarded-for", b"198.51.100.11"),
            (b"content-type", b"application/x-www-form-urlencoded")
        ],
        "query_string": b"",
        "client": ("127.0.0.1", 12345)
    }
    body_data = b"body=" + (b"X" * 4000)
    async def receive():
        return {"type": "http.request", "body": body_data, "more_body": False}

    req = Request(scope, receive)
    capped = asyncio.run(sanitize_and_cap_request_data(req))
    assert len(capped["user_agent"]) <= 500, f"UA cap violated: {len(capped['user_agent'])}"
    assert len(capped["payload"]) <= 2000, f"Payload cap violated: {len(capped['payload'])}"
    assert len(capped["headers_json"]) <= 2000, f"Headers cap violated: {len(capped['headers_json'])}"
    print("    [+] Input capping helper verified: UA <= 500, payload <= 2000, headers <= 2000.")

    # -------------------------------------------------------------
    # 2. VERIFY SQLITE ASYNC WAL MODE & CONCURRENCY
    # -------------------------------------------------------------
    print("\n[*] 2. Verifying aiosqlite WAL mode & async concurrency...")
    import database

    async def verify_sqlite():
        conn = await database.get_db_connection()
        cur = await conn.cursor()
        await cur.execute("PRAGMA journal_mode;")
        row = await cur.fetchone()
        mode = row[0] if row else ""
        await conn.close()
        assert mode.upper() == "WAL", f"Expected WAL mode, got {mode}"

        # Test concurrent writes
        errors = []
        async def write_worker(worker_id):
            for i in range(25):
                try:
                    await database.execute_write(
                        "INSERT INTO events (source_ip, endpoint, attack_type, severity) VALUES (?, ?, ?, ?)",
                        (f"192.0.2.{worker_id}", f"/test_worker_{worker_id}_{i}", "test_write", "low")
                    )
                except Exception as e:
                    errors.append((worker_id, str(e)))

        tasks = [write_worker(w) for w in range(4)]
        await asyncio.gather(*tasks)
        assert len(errors) == 0, f"Encountered SQLite lock errors during concurrent writes: {errors}"

    asyncio.run(verify_sqlite())
    print("    [+] SQLite journal_mode confirmed: WAL")
    print("    [+] 100 concurrent aiosqlite writes completed with ZERO lock errors.")

    # -------------------------------------------------------------
    # 3. VERIFY ASGI SOCKETIO CONFIGURATION
    # -------------------------------------------------------------
    print("\n[*] 3. Verifying server ASGI SocketIO configuration...")
    from socket_instance import sio
    assert sio.async_mode == "asgi", f"Expected async_mode 'asgi', got {sio.async_mode}"
    print("    [+] python-socketio async_mode confirmed as 'asgi'.")

    # -------------------------------------------------------------
    # 4. VERIFY PER-IP SLIDING-WINDOW RATE LIMIT
    # -------------------------------------------------------------
    print("\n[*] 4. Verifying per-IP sliding-window rate limit...")
    test_ip = "203.0.113.250"
    headers = {"X-Forwarded-For": test_ip}
    s = requests.Session()
    got_429 = False
    for i in range(350):
        r = s.get(f"{BASE_URL}/api/health", headers=headers, timeout=2.0)
        if r.status_code == 429:
            got_429 = True
            retry_after = r.headers.get("Retry-After")
            assert retry_after is not None, "Missing Retry-After header on 429 response!"
            print(f"    [+] Received 429 Too Many Requests on request #{i+1} with Retry-After: {retry_after}s.")
            break
    assert got_429, "Rate limiter failed to trigger 429 within 350 requests!"

    # -------------------------------------------------------------
    # 5. VERIFY SCOPED CORS (NOT "*")
    # -------------------------------------------------------------
    print("\n[*] 5. Verifying CORS restriction to http://localhost:5173...")
    with open(os.path.join(BACKEND_DIR, "app.py"), "r", encoding="utf-8") as f:
        app_code = f.read()
    assert 'allow_origins=["http://localhost:5173"]' in app_code or "http://localhost:5173" in app_code, (
        "FastAPI CORS origins not scoped to http://localhost:5173!"
    )
    assert 'allow_origins=["*"]' not in app_code, "FastAPI CORS is insecurely configured with wildcard '*'!"

    with open(os.path.join(BACKEND_DIR, "socket_instance.py"), "r", encoding="utf-8") as f:
        sock_code = f.read()
    assert "http://localhost:5173" in sock_code, "SocketIO CORS origins not scoped to http://localhost:5173!"
    assert 'cors_allowed_origins="*"' not in sock_code and "cors_allowed_origins=['*']" not in sock_code, (
        "SocketIO CORS is insecurely configured with wildcard '*'!"
    )
    print("    [+] CORS verified: Scoped strictly to http://localhost:5173 in both REST and WebSockets.")

    # -------------------------------------------------------------
    # 6. VERIFY NO FLASK / GREENLET IN REQUIREMENTS.TXT
    # -------------------------------------------------------------
    print("\n[*] 6. Verifying absence of flask / eventlet / gevent in requirements.txt...")
    req_path = os.path.join(BACKEND_DIR, "requirements.txt")
    with open(req_path, "r", encoding="utf-8") as f:
        req_lines = [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    for line in req_lines:
        assert "flask" not in line, f"Found legacy dependency 'flask': {line}"
        assert "eventlet" not in line, f"Found prohibited greenlet dependency 'eventlet': {line}"
        assert "gevent" not in line, f"Found prohibited greenlet dependency 'gevent': {line}"
    print("    [+] requirements.txt verified: FastAPI + aiosqlite + uvicorn (zero Flask/eventlet/gevent).")

    # -------------------------------------------------------------
    # 7. AUDIT REACT SOURCE CODE FOR DANGEROUSLYSETINNERHTML
    # -------------------------------------------------------------
    print("\n[*] 7. Auditing React frontend for dangerouslySetInnerHTML / XSS regressions...")
    dangerous_matches = []
    for root, _, files in os.walk(FRONTEND_SRC):
        for file in files:
            if file.endswith((".jsx", ".js", ".tsx", ".ts")):
                filepath = os.path.join(root, file)
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    if "dangerouslySetInnerHTML" in content:
                        dangerous_matches.append(filepath)

    assert len(dangerous_matches) == 0, f"Found dangerouslySetInnerHTML in React source: {dangerous_matches}"
    print("    [+] React frontend audit passed: ZERO occurrences of dangerouslySetInnerHTML across all components.")

    # -------------------------------------------------------------
    # 8. VERIFY README.MD COMPLETENESS
    # -------------------------------------------------------------
    print("\n[*] 8. Verifying README.md completeness...")
    readme_path = os.path.join(PROJECT_ROOT, "README.md")
    assert os.path.isfile(readme_path), "README.md is missing from project root!"
    with open(readme_path, "r", encoding="utf-8") as f:
        readme_text = f.read()

    assert "Terminal 1" in readme_text, "README.md missing Terminal 1 backend setup"
    assert "Terminal 2" in readme_text, "README.md missing Terminal 2 frontend setup"
    assert "Terminal 3" in readme_text, "README.md missing Terminal 3 demo flow"
    assert "scripted" in readme_text, "README.md missing scripted attack command"
    assert "Anthropic" in readme_text, "README.md missing out-of-scope Anthropic note"
    assert "http://localhost:5173" in readme_text, "README.md missing frontend URL"
    print("    [+] README.md verified: Complete backend/frontend setup, 3-terminal demo flow, and out-of-scope note.")

    print("\n[***] ALL STAGE 12 FASTAPI HARDENING CHECKS PASSED [***]")

if __name__ == "__main__":
    test_stage12()
