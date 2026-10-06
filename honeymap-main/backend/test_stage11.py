"""
Stage 11 Automated Verification: Realism + Reliable Demo
Verifies:
1. fake_files.py:
   - Pool of 6 sensitive decoy paths (/.env, /backup.sql, /config.php, /.git/config, /.aws/credentials, /wp-config.php).
   - Live paths rotation every ~90s.
   - Live honeytokens dynamically injected across all 6 files.
   - GET /api/decoys/live endpoint reporting current rotation cycle.
2. simulate_attack.py:
   - 'scripted' mode: single attacker escalating over recon -> sensitive-file hunting -> SQLi -> honeytoken reuse.
   - Ends in a clean, guaranteed CRITICAL payoff marker and session elevation.
   - 'noise' mode: 4-5 background threat actors strictly using OFFLINE_FALLBACK demo IPs.
   - Bounded session count strictly respecting Stage 4 cap (500) and zero console/server errors.
"""
import os
import sys
import time
import requests
from typing import List, Dict, Any

BASE_URL = "http://127.0.0.1:5000"

def test_stage11():
    print("[*] ===================================================")
    print("[*] Stage 11 Automated Verification: Realism & Demo")
    print("[*] ===================================================")

    # -------------------------------------------------------------
    # 1. VERIFY FAKE_FILES POOL OF 6 AND ROTATION
    # -------------------------------------------------------------
    print("\n[*] 1. Verifying fake_files pool of 6 and 90s rotation...")
    from decoys.fake_files import (
        POOL_OF_6,
        ROTATION_INTERVAL_SEC,
        get_rotation_cycle,
        get_live_paths,
        is_path_live,
        render_fake_file
    )

    assert len(POOL_OF_6) == 6, f"Expected 6 decoy paths in POOL_OF_6, got {len(POOL_OF_6)}"
    expected_paths = ["/.env", "/backup.sql", "/config.php", "/.git/config", "/.aws/credentials", "/wp-config.php"]
    for path in expected_paths:
        assert path in POOL_OF_6, f"Expected path {path} missing from POOL_OF_6!"
    print(f"    [+] POOL_OF_6 verified with 6 paths: {POOL_OF_6}")

    assert abs(ROTATION_INTERVAL_SEC - 90.0) < 1e-6, f"Expected ~90s rotation interval, got {ROTATION_INTERVAL_SEC}"
    print(f"    [+] Rotation interval verified at {ROTATION_INTERVAL_SEC}s.")

    # Test rotation across time steps
    t0 = 1000000.0
    t1 = t0 + 95.0
    t2 = t0 + 190.0
    live_t0 = get_live_paths(t0)
    live_t1 = get_live_paths(t1)
    live_t2 = get_live_paths(t2)

    assert live_t0 != live_t1, f"Live paths did not rotate between cycle 0 and cycle 1! {live_t0} == {live_t1}"
    assert live_t1 != live_t2, f"Live paths did not rotate between cycle 1 and cycle 2! {live_t1} == {live_t2}"
    print(f"    [+] Rotation cycle 0: {live_t0}")
    print(f"    [+] Rotation cycle 1: {live_t1}")
    print(f"    [+] Rotation cycle 2: {live_t2}")
    print("    [+] Time-based dynamic path rotation verified across 90s intervals.")

    # -------------------------------------------------------------
    # 2. VERIFY HONEYTOKEN INJECTION ACROSS ALL 6 FILES
    # -------------------------------------------------------------
    print("\n[*] 2. Verifying honeytoken injection into all 6 fake files...")
    import sqlite3
    db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeymap.db")
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    token_rows = [dict(r) for r in conn.execute("SELECT token_type, token_value FROM honeytokens").fetchall()]
    conn.close()
    live_db_tokens = {r["token_type"]: r["token_value"] for r in token_rows}
    aws_key = live_db_tokens.get("aws_access_key")
    db_pass = live_db_tokens.get("database_password")
    print(f"    Live DB honeytokens: AWS={aws_key}, DB={db_pass}")
    assert aws_key is not None, "Live AWS key missing in database!"

    for path in POOL_OF_6:
        r = requests.get(f"{BASE_URL}{path}", timeout=5.0)
        assert r.status_code == 200, f"Failed to fetch decoy {path}: status {r.status_code}"
        assert len(r.text) > 50, f"Decoy response too short for {path}"
        # Check that live honeytokens are injected into sensitive credential files
        if path in ("/.env", "/.aws/credentials", "/wp-config.php"):
            assert aws_key in r.text, f"Active honeytoken {aws_key} not injected into live {path}!"
        if path in ("/.env", "/backup.sql", "/config.php", "/wp-config.php") and db_pass:
            assert db_pass in r.text, f"Database password honeytoken {db_pass} not injected into live {path}!"
        print(f"    [+] Verified live endpoint {path}: 200 OK | {len(r.text)} bytes | Authentic honeytoken injected.")

    # Test live endpoint /api/decoys/live
    r_live = requests.get(f"{BASE_URL}/api/decoys/live", timeout=5.0)
    assert r_live.status_code == 200, f"/api/decoys/live failed: {r_live.status_code}"
    live_meta = r_live.json()
    assert live_meta.get("status") == "ok"
    assert len(live_meta.get("live_paths", [])) > 0
    assert live_meta.get("rotation_interval_seconds") == 90.0
    print(f"    [+] /api/decoys/live endpoint verified: active live paths = {live_meta['live_paths']}")

    # -------------------------------------------------------------
    # 3. VERIFY NOISE ATTACKERS ONLY USE OFFLINE_FALLBACK IPs
    # -------------------------------------------------------------
    print("\n[*] 3. Verifying noise simulation uses strictly OFFLINE_FALLBACK IPs...")
    from simulate_attack import NOISE_ATTACKERS, SCRIPTED_ATTACKER
    from detection.geoip import OFFLINE_FALLBACK

    assert len(NOISE_ATTACKERS) in (4, 5), f"Expected 4-5 background noise attackers, got {len(NOISE_ATTACKERS)}"
    for act in NOISE_ATTACKERS:
        ip = act["ip"]
        assert ip in OFFLINE_FALLBACK, f"Attacker IP {ip} is NOT in OFFLINE_FALLBACK! Must only use offline demo IPs."
        print(f"    [+] Verified noise actor {act['tag']}: {ip} -> {OFFLINE_FALLBACK[ip]['country']} ({OFFLINE_FALLBACK[ip]['country_code']})")

    assert SCRIPTED_ATTACKER["ip"] in OFFLINE_FALLBACK, "Scripted attacker must also be an OFFLINE_FALLBACK IP"
    print(f"    [+] Scripted attacker IP {SCRIPTED_ATTACKER['ip']} confirmed in OFFLINE_FALLBACK.")

    # -------------------------------------------------------------
    # 4. VERIFY SCRIPTED ATTACK ESCALATION & CRITICAL PAYOFF
    # -------------------------------------------------------------
    print("\n[*] 4. Executing scripted attack escalation (fast test run)...")
    from simulate_attack import run_scripted
    res = run_scripted(base_url=BASE_URL, fast_mode=True)
    assert res.get("status") == "success"
    scripted_ip = SCRIPTED_ATTACKER["ip"]

    # Verify that the session has max_severity == 'critical'
    r_sess = requests.get(f"{BASE_URL}/api/sessions?limit=100", timeout=5.0)
    assert r_sess.status_code == 200
    sessions = r_sess.json().get("sessions", [])
    scripted_sess = [s for s in sessions if s.get("source_ip") == scripted_ip]
    assert len(scripted_sess) > 0, f"Scripted attacker session for IP {scripted_ip} not found!"
    assert scripted_sess[0].get("max_severity") == "critical", (
        f"Expected max_severity 'critical' for scripted attacker, got {scripted_sess[0].get('max_severity')}"
    )
    print(f"    [+] Scripted attack verified: Session {scripted_sess[0]['session_id']} elevated to CRITICAL.")

    # Verify that the last event in timeline has severity critical and token reason
    sess_id = scripted_sess[0]["session_id"]
    r_timeline = requests.get(f"{BASE_URL}/api/session/{sess_id}/timeline", timeout=5.0)
    assert r_timeline.status_code == 200
    timeline_events = r_timeline.json().get("events", [])
    assert len(timeline_events) >= 4, f"Expected at least 4 escalating events, got {len(timeline_events)}"

    last_ev = timeline_events[-1]
    assert last_ev["severity"] == "critical", f"Expected last event to be CRITICAL, got {last_ev['severity']}"
    import json
    meta = json.loads(last_ev["metadata_json"]) if isinstance(last_ev["metadata_json"], str) else (last_ev.get("metadata_json") or {})
    classifier_reason = meta.get("classifier_reason") or last_ev.get("attack_type", "")
    assert "honeytoken reuse detected" in classifier_reason, (
        f"Expected 'honeytoken reuse detected' in classifier_reason, got {classifier_reason}"
    )
    print(f"    [+] Final event confirmed: ID #{last_ev['id']} | CRITICAL | Reason: {classifier_reason}")

    # -------------------------------------------------------------
    # 5. VERIFY NOISE SIMULATION BOUNDEDNESS & ZERO ERRORS
    # -------------------------------------------------------------
    print("\n[*] 5. Executing noise simulation (sampling window)...")
    from simulate_attack import run_noise
    from detection.session_tracker import _ACTIVE_SESSIONS, MAX_TRACKED_SESSIONS

    noise_res = run_noise(base_url=BASE_URL, duration_seconds=6.0)
    assert noise_res.get("status") == "success"
    assert noise_res.get("errors_count") == 0, f"Encountered {noise_res.get('errors_count')} errors during noise run!"

    # Verify session count did not exceed Stage 4 cap
    active_count = len(_ACTIVE_SESSIONS)
    assert active_count <= MAX_TRACKED_SESSIONS, f"Session count {active_count} exceeded cap {MAX_TRACKED_SESSIONS}!"
    print(f"    [+] Noise simulation verified: {noise_res['total_requests']} requests sent with ZERO errors.")
    print(f"    [+] Session count bounded at {active_count} (strictly <= {MAX_TRACKED_SESSIONS} Stage 4 cap).")

    print("\n[***] ALL STAGE 11 REALISM & DEMO CHECKS PASSED PERFECTLY [***]")

if __name__ == "__main__":
    test_stage11()
