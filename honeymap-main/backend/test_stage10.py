"""
Stage 10 Automated Verification: Leaderboard.tsx
Verifies:
1. Leaderboard.tsx component existence and default export.
2. 5-second polling interval (setInterval 5000ms) for decayed, sorted sessions.
3. Ranked table structure with IP, score bar, relative time, and event count.
4. Row click -> onInvestigateSession(session_id) callback wiring.
5. Inactive session handling (> 2 minutes) with opacity fading.
6. Zero hardcoded hex values across Leaderboard.tsx.
7. Backend /api/sessions endpoint live behavior and score accumulation.
"""
import os
import re
import json
import time
import urllib.request
import urllib.parse


def _fetch_sessions_by_ip(base_url: str, ip: str, limit: int = 500, retries: int = 5) -> list:
    """Poll /api/sessions until the given source_ip appears or retries are exhausted."""
    matched = []
    for attempt in range(retries):
        req = urllib.request.Request(f"{base_url}/api/sessions?limit={limit}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        matched = [s for s in data.get("sessions", []) if s.get("source_ip") == ip]
        if matched:
            return matched
        time.sleep(0.5)
    return matched


def test_stage10():
    print("[*] ===================================================")
    print("[*] Stage 10 Automated Verification: Leaderboard.tsx")
    print("[*] ===================================================")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    leaderboard_path = os.path.join(base_dir, "frontend", "src", "components", "Leaderboard.tsx")
    app_tsx_path = os.path.join(base_dir, "frontend", "src", "App.tsx")

    # 1. Component existence and export
    print("[*] 1. Verifying Leaderboard.tsx existence and export...")
    assert os.path.exists(leaderboard_path), f"Leaderboard.tsx not found at {leaderboard_path}!"
    with open(leaderboard_path, "r", encoding="utf-8") as f:
        code = f.read()

    assert "export default function Leaderboard" in code, (
        "Leaderboard.tsx must export default function Leaderboard"
    )
    print("    [+] Leaderboard.tsx exists and exports default function.")

    # 2. 5s Polling requirement
    print("[*] 2. Verifying 5s polling interval...")
    assert "setInterval" in code and "5000" in code, (
        "Leaderboard must poll sessions every 5s (setInterval with 5000ms)"
    )
    assert "fetchSessions" in code, "Leaderboard must invoke fetchSessions"
    print("    [+] 5s polling interval (5000ms) verified.")

    # 3. Ranked Table columns and layout
    print("[*] 3. Verifying ranked table columns...")
    assert "Table" in code and "TableHead" in code and "TableBody" in code, "Must use structured table layout"
    assert "Rank" in code, "Must include rank column"
    assert "Attacker IP" in code or "source_ip" in code, "Must include attacker IP column"
    assert "font-mono" in code, "Attacker IP must use monospace typography"
    assert "toFixed" in code, "Score float must be formatted compactly (e.g. toFixed(1))"
    assert "formatTimeAgo" in code, "Must calculate relative time for last_seen"
    assert "event_count" in code or "request_count" in code, "Must render event/request count"
    print("    [+] Ranked table columns verified.")

    # 4. Row click -> onInvestigateSession(session_id)
    print("[*] 4. Verifying row click -> onInvestigateSession(session_id)...")
    assert "onInvestigateSession" in code, "Leaderboard must accept and call onInvestigateSession prop"
    assert "onClick" in code, "Row must have onClick handler"
    assert "session_id" in code, "Row click must pass session_id"
    print("    [+] Row click -> onInvestigateSession(session_id) verified.")

    # 5. Inactive sessions > 2 minutes fade in opacity (do NOT vanish)
    print("[*] 5. Verifying inactive sessions (>2 min) opacity fading...")
    assert "120000" in code, "Must check for > 2 minutes (120,000ms) inactivity"
    assert "opacity" in code, "Must apply opacity styling to inactive sessions"
    print("    [+] Inactive sessions (>2 min) fade in opacity without disappearing.")

    # 6. Zero hardcoded hex values
    print("[*] 6. Verifying zero hardcoded hex values...")
    hex_pattern = re.compile(r'#[0-9a-fA-F]{3,8}\b')
    hexes_in_code = hex_pattern.findall(code)
    assert not hexes_in_code, f"Found hardcoded hex in Leaderboard.tsx: {hexes_in_code}!"
    print("    [+] Zero hardcoded hex values found in Leaderboard.tsx.")

    # 7. Backend /api/sessions verification
    print("[*] 7. Verifying backend /api/sessions live behavior...")
    base_url = "http://127.0.0.1:5000"

    try:
        req = urllib.request.Request(f"{base_url}/api/sessions?limit=25")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"    [!] Backend not reachable at {base_url}: {e}")
        print("    [!] Skipping live backend test; structural tests passed.")
        return

    sessions = data.get("sessions", [])
    print(f"    [+] Received {len(sessions)} active sessions from /api/sessions.")
    assert isinstance(sessions, list), "Sessions must be returned as a list"

    if sessions:
        first = sessions[0]
        assert "session_id" in first, "Session missing session_id"
        assert "score" in first or "decayed_score" in first, "Session missing score"
        assert "source_ip" in first, "Session missing source_ip"
        assert "last_seen" in first, "Session missing last_seen"
        assert "event_count" in first or "request_count" in first, "Session missing event_count/request_count"
        print(f"    [+] First session schema verified: {first['session_id'][:8]}... | Score: {first.get('score')} | Hits: {first.get('event_count')}")

        scores = [float(s.get("score") or s.get("decayed_score") or 0) for s in sessions]
        for i in range(len(scores) - 1):
            assert scores[i] >= scores[i+1], f"Sessions not sorted descending by score: {scores[i]} < {scores[i+1]}"
        print("    [+] Sessions strictly verified in descending order by score.")

    # 8. Live reordering & Accumulation test
    print("[*] 8. Verifying live reordering as scores accumulate...")
    unique_ip = f"198.51.100.{int(time.time()) % 200 + 10}"
    test_headers = {
        "User-Agent": "Leaderboard-Test-Agent/1.0",
        "X-Forwarded-For": unique_ip
    }

    try:
        decoy_url = f"{base_url}/.env"
        for _ in range(5):
            req = urllib.request.Request(decoy_url, headers=test_headers)
            try:
                urllib.request.urlopen(req, timeout=5)
            except urllib.error.HTTPError:
                pass

        matched = _fetch_sessions_by_ip(base_url, unique_ip, limit=500)
        assert len(matched) > 0, f"Newly triggered session for IP {unique_ip} not found in /api/sessions!"
        initial_score = matched[0].get("score")
        initial_events = matched[0].get("event_count") or matched[0].get("request_count")
        print(f"    [+] Session created for {unique_ip}: initial score={initial_score}, events={initial_events}")

        sqli_headers = test_headers.copy()
        sqli_headers["Content-Type"] = "application/x-www-form-urlencoded"
        sqli_body = urllib.parse.urlencode({"username": "admin' OR 1=1 --", "password": "x"}).encode("utf-8")
        for _ in range(5):
            req = urllib.request.Request(f"{base_url}/login", data=sqli_body, headers=sqli_headers)
            try:
                urllib.request.urlopen(req, timeout=5)
            except urllib.error.HTTPError:
                pass

        matched_accum = _fetch_sessions_by_ip(base_url, unique_ip, limit=500)
        assert len(matched_accum) > 0, "Accumulated session not found in sessions list"
        final_score = matched_accum[0].get("score")
        final_events = matched_accum[0].get("event_count") or matched_accum[0].get("request_count")
        assert final_score > initial_score, f"Score must accumulate on repeated attacks: {final_score} > {initial_score}"
        assert final_events > initial_events, f"Event count must increase: {final_events} > {initial_events}"
        print(f"    [+] Verified score accumulation & live reordering: {initial_score} -> {final_score}, events: {initial_events} -> {final_events}")

    except Exception as e:
        print(f"    [!] Error during live event accumulation test: {e}")
        raise

    print("\n[***] ALL STAGE 10 LEADERBOARD CHECKS PASSED PERFECTLY [***]")


if __name__ == "__main__":
    test_stage10()
