import time
import requests
import json
import sqlite3
import os
import sys

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeymap.db")

def test_stage4():
    print("[*] Starting Stage 4 Automated Verification...")
    session = requests.Session()

    # 1. Offline GeoIP resolution using demo IPs
    print("[*] 1. Testing offline-safe GeoIP lookup (resolving demo IPs)...")
    demo_ips = [
        ("185.220.101.5", "Germany", "DE"),
        ("194.26.29.112", "Russia", "RU"),
        ("45.154.255.88", "Netherlands", "NL"),
        ("103.145.13.12", "China", "CN"),
        ("198.51.100.99", "Japan", "JP"),
        ("203.0.113.45", "Australia", "AU"),
        ("127.0.0.1", "Localhost", "LOC")
    ]

    for ip, expected_country, expected_code in demo_ips:
        r = session.get(f"{BASE_URL}/api/geoip/{ip}", timeout=3.0)
        assert r.status_code == 200, f"GeoIP query failed for {ip}: {r.status_code}"
        data = r.json().get("geoip", {})
        assert data.get("country") == expected_country, f"Expected {expected_country} for {ip}, got {data.get('country')}"
        assert data.get("country_code") == expected_code, f"Expected {expected_code} for {ip}, got {data.get('country_code')}"
        print(f"    [+] {ip} -> {data.get('country')} ({data.get('country_code')}) [lat={data.get('latitude')}, lon={data.get('longitude')}]")

    # 2. Defensive Tarpit Delay: repeat hits show increasing delay up to the 3s cap
    print("[*] 2. Testing defensive tarpit delay: repeat hits showing increasing delay up to 3.0s cap...")
    import random
    tarpit_ip = f"198.51.100.{random.randint(20, 220)}"
    headers = {"X-Forwarded-For": tarpit_ip, "User-Agent": "Tarpit-Test-Bot"}

    # Request 1: delay ~ min(0.2 * 1, 3.0) = 0.2s
    t0 = time.time()
    r1 = session.get(f"{BASE_URL}/admin", headers=headers)
    d1 = time.time() - t0
    assert r1.status_code == 200
    print(f"    Hit 1 (count=1): measured {d1:.2f}s (expected >= 0.20s)")
    assert d1 >= 0.18, f"Hit 1 too fast: {d1}"

    # Request 2: delay ~ min(0.2 * 2, 3.0) = 0.4s
    t0 = time.time()
    r2 = session.get(f"{BASE_URL}/admin", headers=headers)
    d2 = time.time() - t0
    print(f"    Hit 2 (count=2): measured {d2:.2f}s (expected >= 0.38s)")
    assert d2 >= 0.35, f"Hit 2 too fast: {d2}"
    assert d2 > d1, f"Delay did not increase! {d2} vs {d1}"

    # Request 3: delay ~ min(0.2 * 3, 3.0) = 0.6s
    t0 = time.time()
    r3 = session.get(f"{BASE_URL}/admin", headers=headers)
    d3 = time.time() - t0
    print(f"    Hit 3 (count=3): measured {d3:.2f}s (expected >= 0.55s)")
    assert d3 >= 0.55, f"Hit 3 too fast: {d3}"
    assert d3 > d2, f"Delay did not increase! {d3} vs {d2}"

    # Test that tarpit delay caps at 3.0s (e.g. simulated 20 requests)
    from detection.session_tracker import tarpit_delay
    cap_delay_20 = tarpit_delay(20)
    cap_delay_50 = tarpit_delay(50)
    assert cap_delay_20 == 3.0, f"Expected 3.0s cap for 20 requests, got {cap_delay_20}"
    assert cap_delay_50 == 3.0, f"Expected 3.0s cap for 50 requests, got {cap_delay_50}"
    print("    [+] Tarpit delay cap confirmed at exactly 3.0s.")

    # 3. Score decay alignment: leaderboard score and live-feed score for the same session NEVER diverge
    print("[*] 3. Testing score decay alignment between read path and push path...")
    from detection.session_tracker import score_decay, get_session_info, get_all_sessions
    import asyncio
    
    # Grab the active session
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    sess_row = conn.execute("SELECT * FROM sessions WHERE source_ip = ?", (tarpit_ip,)).fetchone()
    conn.close()
    assert sess_row is not None, "Session row missing in database!"

    target_sess_id = sess_row["session_id"]
    sess_info = asyncio.run(get_session_info(target_sess_id))

    # Calculate live-feed score
    shared_now = time.time()
    live_feed_score = score_decay(sess_info, current_time=shared_now)

    # Calculate leaderboard score (via get_all_sessions)
    all_sess = asyncio.run(get_all_sessions(limit=1000))
    matched = [s for s in all_sess if s["session_id"] == target_sess_id]
    assert len(matched) == 1, f"Session {target_sess_id} not found in get_all_sessions (total found: {len(all_sess)})!"
    leaderboard_score = score_decay(matched[0], current_time=shared_now)

    print(f"    Live feed score: {live_feed_score} | Leaderboard score: {leaderboard_score}")
    assert live_feed_score == leaderboard_score, (
        f"Divergence detected! Live-feed: {live_feed_score}, Leaderboard: {leaderboard_score}"
    )
    print("    [+] Zero divergence: live-feed and leaderboard scores are 100% synchronized!")

    # Verify score decay over 5 minutes (half-life)
    score_t0 = score_decay(sess_info, current_time=shared_now)
    score_t5 = score_decay(sess_info, current_time=shared_now + 300)
    expected_t5 = round(score_t0 * 0.5, 2)
    print(f"    Score at t=0: {score_t0} | Score at t=5min (half-life): {score_t5} (expected ~{expected_t5})")
    assert abs(score_t5 - expected_t5) <= 0.1, f"Decay calculation mismatch! {score_t5} vs {expected_t5}"
    print("    [+] 5-minute half-life decay formula verified!")

    # 4. LRU Cache Eviction under sustained load (MAX_TRACKED_SESSIONS = 500)
    print("[*] 4. Testing in-memory LRU eviction under sustained load (500 cap)...")
    from detection.session_tracker import get_or_create_session, get_eviction_count, _ACTIVE_SESSIONS, MAX_TRACKED_SESSIONS

    initial_evictions = get_eviction_count()
    print(f"    Current cache size: {len(_ACTIVE_SESSIONS)}, initial evictions: {initial_evictions}")

    # Generate 550 distinct sessions
    for i in range(550):
        dummy_ip = f"10.200.{(i // 250) + 1}.{(i % 250) + 1}"
        asyncio.run(get_or_create_session(dummy_ip, f"EvictionBot-{i}"))

    new_evictions = get_eviction_count()
    cache_len = len(_ACTIVE_SESSIONS)
    print(f"    Cache size after 550 insertions: {cache_len} (capped at {MAX_TRACKED_SESSIONS})")
    print(f"    Eviction count: {new_evictions} (increased by {new_evictions - initial_evictions})")
    assert cache_len <= MAX_TRACKED_SESSIONS, f"Cache exceeded limit! {cache_len} > {MAX_TRACKED_SESSIONS}"
    assert new_evictions > initial_evictions, "LRU eviction did not fire under load!"
    print("    [+] In-memory LRU eviction confirmed firing properly under sustained load!")

    print("\n[***] ALL STAGE 4 CHECKS PASSED PERFECTLY [***]")

if __name__ == "__main__":
    test_stage4()
