import threading
import time
import requests
import json
import sqlite3
import os
import sys

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeymap.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def run_e2e_cross_stage_test():
    print("[*] ===================================================")
    print("[*] HoneyMap E2E Multi-Stage Integration Verification")
    print("[*] ===================================================")

    session = requests.Session()

    # 1. Boot, DB & Health Integrity
    print("[*] [Check 1] Verifying /api/health and /dashboard routes under concurrency...")
    errors = []
    
    def probe_worker(wid, n=25):
        s = requests.Session()
        for _ in range(n):
            try:
                r1 = s.get(f"{BASE_URL}/api/health", timeout=3.0)
                r2 = s.get(f"{BASE_URL}/dashboard", timeout=3.0)
                if r1.status_code != 200 or r2.status_code != 200:
                    errors.append((wid, r1.status_code, r2.status_code))
            except Exception as e:
                errors.append((wid, "exception", str(e)))

    t1 = threading.Thread(target=probe_worker, args=(1,))
    t2 = threading.Thread(target=probe_worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Errors in concurrent health/dashboard probes: {errors}"
    print("    [+] Zero lock errors across concurrent /api/health and /dashboard queries.")

    # 2. Exclusions (favicon, static, OPTIONS) produce 0 events
    print("[*] [Check 2] Testing tooling noise exclusion...")
    conn = get_db()
    c0 = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()

    session.get(f"{BASE_URL}/favicon.ico")
    session.get(f"{BASE_URL}/static/test.css")
    session.options(f"{BASE_URL}/admin")
    session.options(f"{BASE_URL}/.env")

    conn = get_db()
    c1 = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    assert c0 == c1, f"Noise routes wrote events! Before: {c0}, After: {c1}"
    print(f"    [+] Verified: favicon, static, and OPTIONS generated 0 event rows.")

    # 3. Decoys and live honeytoken generation
    print("[*] [Check 3] Verifying live honeytoken generation and injection into decoys...")
    r_env = session.get(f"{BASE_URL}/.env")
    assert r_env.status_code == 200

    conn = get_db()
    tokens = {row["token_type"]: row["token_value"] for row in conn.execute("SELECT * FROM honeytokens").fetchall()}
    conn.close()

    aws_key = tokens.get("aws_access_key")
    db_pass = tokens.get("database_password")
    assert aws_key and db_pass, f"Missing tokens in DB: {tokens}"
    assert aws_key in r_env.text, "Live AWS key not found in /.env"
    assert db_pass in r_env.text, "Live DB password not found in /.env"
    print("    [+] Live tokens verified and injected correctly.")

    # 4. Severity hierarchy and session elevation under concurrency
    print("[*] [Check 4] Testing severity hierarchy & session elevation under concurrent hits...")
    import random
    unique_id = f"{int(time.time())}_{random.randint(1000, 9999)}"
    target_ip = f"198.51.100.{random.randint(10, 240)}"
    headers = {"X-Forwarded-For": target_ip, "User-Agent": f"Multi-Vector-Tester-{unique_id}"}

    # Hit 1: LOW severity (clean login GET)
    session.get(f"{BASE_URL}/login", headers=headers)
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE source_ip = ? ORDER BY rowid DESC", (target_ip,)).fetchone()
    assert sess["max_severity"] == "low"
    conn.close()
    print("    [+] Hit 1: Login GET -> LOW severity, session max_severity=low")

    # Hit 2: MEDIUM severity (sensitive decoy path /.env)
    session.get(f"{BASE_URL}/.env", headers=headers)
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE source_ip = ? ORDER BY rowid DESC", (target_ip,)).fetchone()
    assert sess["max_severity"] == "medium"
    conn.close()
    print("    [+] Hit 2: /.env -> MEDIUM severity, session max_severity elevated to medium")

    # Hit 3: HIGH severity (SQLi attempt in POST)
    session.post(
        f"{BASE_URL}/login",
        data={"email": "admin' OR 1=1 --", "password": "x"},
        headers=headers
    )
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE source_ip = ? ORDER BY rowid DESC", (target_ip,)).fetchone()
    assert sess["max_severity"] == "high"
    conn.close()
    print("    [+] Hit 3: SQLi POST -> HIGH severity, session max_severity elevated to high")

    # Hit 4: Near-miss honeytoken -> MUST NOT elevate to CRITICAL
    near_key = aws_key[:-2] + "99"
    session.post(
        f"{BASE_URL}/api/v1/auth",
        data={"token": near_key},
        headers=headers
    )
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE source_ip = ? ORDER BY rowid DESC", (target_ip,)).fetchone()
    assert sess["max_severity"] == "high", f"Near miss caused elevation! {sess['max_severity']}"
    conn.close()
    print("    [+] Hit 4: Near-miss honeytoken -> did NOT elevate to CRITICAL")

    # Hit 5: CRITICAL severity (exact honeytoken reuse)
    session.post(
        f"{BASE_URL}/api/v1/auth",
        data={"token": aws_key},
        headers=headers
    )
    conn = get_db()
    sess = conn.execute("SELECT * FROM sessions WHERE source_ip = ? ORDER BY rowid DESC", (target_ip,)).fetchone()
    assert sess["max_severity"] == "critical"
    latest_ev = conn.execute("SELECT * FROM events WHERE source_ip = ? ORDER BY id DESC LIMIT 1", (target_ip,)).fetchone()
    conn.close()

    assert latest_ev["severity"] == "critical"
    meta = json.loads(latest_ev["metadata_json"])
    assert meta["classifier_reason"] == "honeytoken reuse detected"
    assert latest_ev["flagged_token"] == aws_key
    print(f"    [+] Hit 5: Authentic honeytoken reuse -> CRITICAL severity with exact reason '{meta['classifier_reason']}'")

    # 5. Rate limit enforcement
    print("[*] [Check 5] Verifying sliding-window rate limiter returns 429 when threshold exceeded...")
    rate_ip = "198.51.100.222"
    rate_headers = {"X-Forwarded-For": rate_ip}
    got_429 = False
    for i in range(350):
        r = session.get(f"{BASE_URL}/api/health", headers=rate_headers)
        if r.status_code == 429:
            got_429 = True
            break

    assert got_429, "Rate limiter did not return 429!"
    print("    [+] Sliding window rate limit enforced cleanly.")

    # 6. Design tokens & visual language integrity
    print("[*] [Check 6] Verifying Stage 6 design system tokens and zero hardcoded hex constraint...")
    from test_stage6 import test_stage6
    test_stage6()
    print("    [+] Visual tokens and zero hardcoded hex verified.")

    print("\n[***] ALL INTEGRATION & REGRESSION CHECKS PASSED PERFECTLY [***]")

if __name__ == "__main__":
    run_e2e_cross_stage_test()

