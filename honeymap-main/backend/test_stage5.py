import time
import requests
import json
import socketio
import threading
import sys

BASE_URL = "http://127.0.0.1:5000"

def test_stage5():
    print("[*] Starting Stage 5 Automated Push + Poll Verification...")

    # Set up real SocketIO client connected to live backend feed
    sio = socketio.Client()
    received_socket_events = []
    connected_event = threading.Event()

    @sio.on("connect")
    def on_connect():
        print("    [+] Socket.IO client connected to backend feed!")
        connected_event.set()

    @sio.on("new_event")
    def on_new_event(data):
        received_socket_events.append(data)
        print(f"    [WS Event Received] id={data.get('id')}, endpoint={data.get('endpoint')}, severity={data.get('severity')}")

    try:
        sio.connect(
            BASE_URL,
            headers={"Origin": "http://localhost:5173"}
        )
        connected_event.wait(timeout=3.0)
    except Exception as e:
        print(f"[-] Socket.IO connection failed: {e}")
        sys.exit(1)

    time.sleep(0.5)

    # 1. Trigger an attack hit via REST to generate an event
    print("[*] 1. Triggering live attack hit to test WebSocket emission vs Polling...")
    test_ip = "198.51.100.177"
    headers = {"X-Forwarded-For": test_ip, "User-Agent": "Push-Poll-Verifier 1.0"}

    # Record timestamp right before request for 'since' parameter
    poll_since = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - 2))

    r_hit = requests.get(f"{BASE_URL}/.env", headers=headers)
    assert r_hit.status_code == 200

    # Wait briefly for WebSocket dispatch
    time.sleep(0.8)

    assert len(received_socket_events) >= 1, "No event received over WebSocket!"
    ws_event = received_socket_events[-1]

    # 2. Query polling endpoint GET /api/events?since=<timestamp>
    print(f"[*] 2. Querying polling fallback GET /api/events?since={poll_since}...")
    r_poll = requests.get(f"{BASE_URL}/api/events?since={poll_since}&limit=10")
    assert r_poll.status_code == 200
    poll_data = r_poll.json()
    assert poll_data.get("status") == "ok"
    events = poll_data.get("events", [])
    assert len(events) >= 1, "Polling endpoint returned 0 events!"

    # Find matching event in polled events
    matching_poll_event = None
    for ev in events:
        if ev["id"] == ws_event["id"]:
            matching_poll_event = ev
            break

    assert matching_poll_event is not None, (
        f"Event id {ws_event['id']} emitted over Socket.IO was NOT found in polling response! Available IDs: {[e['id'] for e in events]}"
    )
    print(f"    [+] Verified: Socket payload and Polling payload carry identical stable 'id' = {ws_event['id']}!")

    # 3. Verify identical schema shape between WS event and Polling event
    print("[*] 3. Verifying identical payload shape between Socket.IO and Polling...")
    expected_keys = {
        "id", "session_id", "timestamp", "source_ip", "source_port",
        "request_method", "endpoint", "headers_json", "payload",
        "attack_type", "severity", "flagged_token", "metadata_json", "geoip"
    }

    ws_keys = set(ws_event.keys())
    poll_keys = set(matching_poll_event.keys())
    assert expected_keys.issubset(ws_keys), f"Missing keys in WS event: {expected_keys - ws_keys}"
    assert expected_keys.issubset(poll_keys), f"Missing keys in Polling event: {expected_keys - poll_keys}"
    assert ws_event["id"] == matching_poll_event["id"]
    assert ws_event["session_id"] == matching_poll_event["session_id"]
    assert ws_event["endpoint"] == matching_poll_event["endpoint"]
    assert ws_event["severity"] == matching_poll_event["severity"]
    print("    [+] Identical schema verified across push and poll!")

    # 4. Test GET /api/sessions leaderboard
    print("[*] 4. Testing GET /api/sessions (leaderboard, decayed scores, sorted descending)...")
    r_sessions = requests.get(f"{BASE_URL}/api/sessions")
    assert r_sessions.status_code == 200
    sess_list = r_sessions.json().get("sessions", [])
    assert len(sess_list) >= 1

    # Verify descending sort order by score
    scores = [s["score"] for s in sess_list]
    assert scores == sorted(scores, reverse=True), f"Leaderboard not sorted descending: {scores}"
    print(f"    [+] Leaderboard verified: {len(sess_list)} sessions returned in strictly descending score order.")

    # 5. Test GET /api/session/<id>/timeline
    target_session_id = ws_event["session_id"]
    print(f"[*] 5. Testing GET /api/session/{target_session_id}/timeline...")
    r_timeline = requests.get(f"{BASE_URL}/api/session/{target_session_id}/timeline")
    assert r_timeline.status_code == 200
    timeline_data = r_timeline.json()
    assert timeline_data["status"] == "ok"
    assert timeline_data["session_id"] == target_session_id
    timeline_events = timeline_data["events"]
    assert len(timeline_events) >= 1
    # Verify chronological order
    event_ids = [e["id"] for e in timeline_events]
    assert event_ids == sorted(event_ids), f"Timeline events not in chronological order: {event_ids}"
    print(f"    [+] Timeline verified: {len(timeline_events)} events returned in chronological sequence.")

    # 6. Test GET /api/report/<session_id> structured incident report
    print(f"[*] 6. Testing GET /api/report/{target_session_id} (structured incident summary)...")
    r_report = requests.get(f"{BASE_URL}/api/report/{target_session_id}")
    assert r_report.status_code == 200
    rep = r_report.json().get("report", {})
    assert "report_id" in rep
    assert rep["session_id"] == target_session_id
    assert "attacker" in rep
    assert "executive_summary" in rep
    assert "timeline_events" in rep
    assert "narrative_analysis" in rep
    print(f"    [+] Report verified: {rep['report_id']} generated with executive summary and IoCs!")

    sio.disconnect()
    print("\n[***] ALL STAGE 5 CHECKS PASSED PERFECTLY [***]")

if __name__ == "__main__":
    test_stage5()
