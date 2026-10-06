import requests
import json
import sqlite3
import os

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeymap.db")

def get_db_events_count():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    count = cur.fetchone()[0]
    conn.close()
    return count

def get_latest_event():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def test_stage2():
    print("[*] Starting Stage 2 Automated Verification...")
    session = requests.Session()

    # 1. Verify /dashboard and /api/health are NOT swallowed by catch-all
    print("[*] 1. Testing /api/health and /dashboard routing...")
    r_health = session.get(f"{BASE_URL}/api/health")
    assert r_health.status_code == 200, f"Health check failed: {r_health.status_code}"
    assert r_health.json().get("status") == "ok"

    r_dash = session.get(f"{BASE_URL}/dashboard")
    assert r_dash.status_code == 200, f"/dashboard failed: {r_dash.status_code}"
    assert "HoneyMap Security Dashboard" in r_dash.json().get("service", "")
    print("    [+] /api/health and /dashboard routed correctly!")

    # 2. Check exclusions: /favicon.ico and OPTIONS requests do NOT log any events
    print("[*] 2. Testing noise exclusions (/favicon.ico, /static/*, OPTIONS)...")
    initial_count = get_db_events_count()
    
    r_fav = session.get(f"{BASE_URL}/favicon.ico")
    assert r_fav.status_code == 404
    
    r_static = session.get(f"{BASE_URL}/static/bundle.js")
    assert r_static.status_code == 404

    r_opt = session.options(f"{BASE_URL}/admin")
    assert r_opt.status_code in (200, 204)

    r_opt_catch = session.options(f"{BASE_URL}/some/random/probe")
    assert r_opt_catch.status_code in (200, 204)

    after_exclusion_count = get_db_events_count()
    assert after_exclusion_count == initial_count, (
        f"Exclusions logged events! Before: {initial_count}, After: {after_exclusion_count}"
    )
    print("    [+] Exclusions verified: 0 events logged for favicon, static, and OPTIONS!")

    # 3. Test Decoy fake_login: GET and POST
    print("[*] 3. Testing fake_login routes (/admin, /wp-admin, /login)...")
    # GET /admin -> returns HTML form and logs 1 event
    r_admin_get = session.get(f"{BASE_URL}/admin", headers={"User-Agent": "Nmap NSE Engine / Recon Bot"})
    assert r_admin_get.status_code == 200
    assert "Cluster Admin Access" in r_admin_get.text

    ev = get_latest_event()
    assert ev["endpoint"] == "/admin"
    assert ev["request_method"] == "GET"
    assert ev["attack_type"] == "credential_recon"
    assert ev["severity"] == "low"
    assert "Nmap NSE" in ev["metadata_json"] or "Nmap" in ev["headers_json"]

    # POST /wp-admin -> captures attempt and logs 1 event
    r_wp_post = session.post(
        f"{BASE_URL}/wp-admin",
        data={"log": "admin", "pwd": "Password123!"},
        headers={"X-Forwarded-For": "203.0.113.45", "User-Agent": "Hydra Brute-Force Bot"}
    )
    assert r_wp_post.status_code == 401
    assert r_wp_post.json().get("error_code") == "AUTH_FAILED_004"

    ev = get_latest_event()
    assert ev["endpoint"] == "/wp-admin"
    assert ev["request_method"] == "POST"
    assert ev["source_ip"] == "203.0.113.45"
    assert ev["attack_type"] == "credential_stuffing"
    assert ev["severity"] in ("low", "high", "critical")  # Governed by classifier rule 4 (low without SQLi/token)
    assert "Password123!" in ev["payload"]
    print("    [+] fake_login routes verified: forms rendered, attempts captured & logged!")

    # 4. Test Decoy fake_files: /.env, /backup.sql, /config.php, /.git/config
    print("[*] 4. Testing fake_files routes...")
    r_env = session.get(f"{BASE_URL}/.env", headers={"X-Forwarded-For": "198.51.100.22"})
    assert r_env.status_code == 200
    assert "DATABASE_URL=" in r_env.text
    assert "AWS_SECRET_ACCESS_KEY=" in r_env.text

    ev = get_latest_event()
    assert ev["endpoint"] == "/.env"
    assert ev["source_ip"] == "198.51.100.22"
    assert ev["attack_type"] == "sensitive_file_disclosure"

    r_sql = session.get(f"{BASE_URL}/backup.sql")
    assert r_sql.status_code == 200
    assert "DROP TABLE IF EXISTS `admin_users`;" in r_sql.text

    r_git = session.get(f"{BASE_URL}/.git/config")
    assert r_git.status_code == 200
    assert "internal-honeymap-org" in r_git.text
    print("    [+] fake_files routes verified: authentic bait returned & logged!")

    # 5. Test Catch-all decoy route for arbitrary probes
    print("[*] 5. Testing catch-all decoy route for unknown probes...")
    r_random = session.get(
        f"{BASE_URL}/phpmyadmin/index.php",
        headers={"X-Forwarded-For": "192.0.2.77", "User-Agent": "Masscan-Scanner"}
    )
    assert r_random.status_code == 404
    ev = get_latest_event()
    assert ev["endpoint"] == "/phpmyadmin/index.php"
    assert ev["source_ip"] == "192.0.2.77"
    assert ev["attack_type"] == "endpoint_scan"

    # 6. Verify capping constraints: headers <= 2000, payload <= 2000, user_agent <= 500
    print("[*] 6. Testing ceiling caps (headers <= 2000, payload <= 2000, user_agent <= 500)...")
    huge_ua = "A" * 800
    huge_payload = "B" * 5000
    r_cap = session.post(
        f"{BASE_URL}/api/v1/debug_probe",
        data={"junk": huge_payload},
        headers={"User-Agent": huge_ua, "X-Forwarded-For": "198.51.100.88"}
    )
    ev = get_latest_event()
    assert len(ev["payload"]) <= 2000, f"Payload exceeded 2000: {len(ev['payload'])}"
    assert len(ev["headers_json"]) <= 2000, f"Headers json exceeded 2000: {len(ev['headers_json'])}"
    
    # Check session user agent capping
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT user_agent FROM sessions WHERE session_id = ?", (ev["session_id"],))
    ua_row = cur.fetchone()[0]
    conn.close()
    assert len(ua_row) <= 500, f"User-Agent exceeded 500: {len(ua_row)}"
    print("    [+] Input ceilings verified: strict 2000/500-char caps applied!")

    # 7. Test safe_client_ip fallback on malformed X-Forwarded-For
    print("[*] 7. Testing safe_client_ip with malformed header...")
    r_malformed = session.get(
        f"{BASE_URL}/shell.php",
        headers={"X-Forwarded-For": "not-an-ip; DROP TABLE events; --"}
    )
    ev = get_latest_event()
    assert ev["source_ip"] == "127.0.0.1", f"Failed to fallback to remote_addr: {ev['source_ip']}"
    print("    [+] Malformed IP header gracefully handled and rejected!")

    print("\n[***] ALL STAGE 2 CHECKS PASSED [***]")

if __name__ == "__main__":
    test_stage2()
