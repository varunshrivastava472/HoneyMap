import requests
import json
import sqlite3
import os
import re

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeymap.db")

def get_latest_event():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def get_live_honeytokens():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT token_type, token_value FROM honeytokens")
    rows = cur.fetchall()
    conn.close()
    return {row["token_type"]: row["token_value"] for row in rows}

def test_stage3():
    print("[*] Starting Stage 3 Classification Verification...")
    session = requests.Session()

    # 1. Verify honeytokens were generated and injected into fake files
    print("[*] 1. Checking generated honeytokens in /.env...")
    r_env = session.get(f"{BASE_URL}/.env")
    assert r_env.status_code == 200
    
    tokens = get_live_honeytokens()
    print("    Live DB tokens:", tokens)
    aws_key = tokens.get("aws_access_key")
    db_pass = tokens.get("database_password")
    assert aws_key is not None, "Missing live AWS honeytoken!"
    assert aws_key in r_env.text, "Live AWS key not injected into /.env!"
    assert db_pass in r_env.text, "Live DB password not injected into /.env!"

    # Verify accessing /.env yields MEDIUM severity
    ev = get_latest_event()
    assert ev["endpoint"] == "/.env"
    assert ev["severity"] == "medium", f"Expected medium severity for /.env hit, got {ev['severity']}"
    assert "Sensitive decoy path accessed" in ev["metadata_json"]
    print("    [+] Hit on /.env correctly classified as MEDIUM severity!")

    # 2. Test exact live honeytoken reuse -> CRITICAL with exact reason "honeytoken reuse detected"
    print("[*] 2. Testing real honeytoken reuse in POST attempt...")
    r_reuse = session.post(
        f"{BASE_URL}/api/v1/auth",
        data={"access_key": aws_key, "action": "login"},
        headers={"X-Forwarded-For": "198.51.100.77"}
    )
    assert r_reuse.status_code == 404  # Handled by catch-all
    ev = get_latest_event()
    assert ev["severity"] == "critical", f"Expected CRITICAL for honeytoken reuse, got {ev['severity']}"
    meta = json.loads(ev["metadata_json"])
    assert meta.get("classifier_reason") == "honeytoken reuse detected", (
        f"Expected exact reason 'honeytoken reuse detected', got {meta.get('classifier_reason')}"
    )
    assert ev["flagged_token"] == aws_key
    print(f"    [+] Honeytoken reuse correctly triggered CRITICAL with reason: '{meta.get('classifier_reason')}'!")

    # 3. Test near-miss string -> MUST NOT trigger CRITICAL
    print("[*] 3. Testing near-miss honeytoken string (fuzzy match prevention)...")
    # Slightly alter the token value (e.g. change last char or omit first char)
    near_miss_key = aws_key[:-1] + ("0" if aws_key[-1] != "0" else "1")
    r_near = session.post(
        f"{BASE_URL}/api/v1/auth",
        data={"access_key": near_miss_key, "action": "login"},
        headers={"X-Forwarded-For": "198.51.100.78"}
    )
    ev = get_latest_event()
    assert ev["severity"] != "critical", (
        f"False positive! Near-miss key '{near_miss_key}' triggered CRITICAL severity!"
    )
    meta = json.loads(ev["metadata_json"])
    assert meta.get("classifier_reason") != "honeytoken reuse detected"
    print("    [+] Near-miss string did NOT trigger CRITICAL (exact-match enforcement confirmed)!")

    # 4. Test HIGH severity SQLi and XSS signatures
    print("[*] 4. Testing HIGH severity SQLi and XSS signatures...")
    # SQLi test
    r_sqli = session.get(f"{BASE_URL}/search?q=' UNION SELECT 1,username,password FROM admin_users --")
    ev = get_latest_event()
    assert ev["severity"] == "high", f"Expected HIGH for SQLi, got {ev['severity']}"
    assert "SQL Injection detected" in ev["metadata_json"]
    print("    [+] SQLi correctly classified as HIGH severity!")

    # XSS test
    r_xss = session.post(f"{BASE_URL}/feedback", data={"comment": "<script>alert('xss')</script>"})
    ev = get_latest_event()
    assert ev["severity"] == "high", f"Expected HIGH for XSS, got {ev['severity']}"
    assert "Cross-Site Scripting detected" in ev["metadata_json"]
    print("    [+] XSS correctly classified as HIGH severity!")

    # 5. Test LOW severity on login-page hit with no injection
    print("[*] 5. Testing LOW severity on clean login hit...")
    r_login = session.get(f"{BASE_URL}/login")
    assert r_login.status_code == 200
    ev = get_latest_event()
    assert ev["severity"] == "low", f"Expected LOW for clean login get, got {ev['severity']}"
    print("    [+] Clean login page hit correctly classified as LOW severity!")

    print("\n[***] ALL STAGE 3 CHECKS PASSED [***]")

if __name__ == "__main__":
    test_stage3()
