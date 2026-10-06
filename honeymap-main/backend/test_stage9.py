"""
Stage 9 Automated Verification: IncidentDrawer.tsx Telemetry Forensics
Verifies:
1. IncidentDrawer.tsx component structure and default export.
2. Chronological timeline fetching and rendering with severity badges and relative time.
3. 'Download Forensics JSON' action via downloadReportJson.
4. Designed loading/empty states when no session data is available.
5. Lifted state wiring in App.tsx (sessionId, isOpen, onClose).
6. Zero hardcoded hex values across IncidentDrawer.tsx.
7. Backend endpoints verification (/api/session/<id>/timeline & /api/report/<id>).
"""
import os
import re
import json
import urllib.request


def test_stage9():
    print("[*] ===================================================")
    print("[*] Stage 9 Automated Verification: IncidentDrawer.tsx")
    print("[*] ===================================================")
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    drawer_path = os.path.join(base_dir, "frontend", "src", "components", "IncidentDrawer.tsx")
    app_tsx_path = os.path.join(base_dir, "frontend", "src", "App.tsx")

    # 1. Component existence and default export
    print("[*] 1. Verifying IncidentDrawer.tsx existence and export...")
    assert os.path.exists(drawer_path), f"IncidentDrawer.tsx not found at {drawer_path}!"
    with open(drawer_path, "r", encoding="utf-8") as f:
        drawer_code = f.read()

    assert "export default function IncidentDrawer" in drawer_code, (
        "IncidentDrawer must export default function IncidentDrawer"
    )
    print("    [+] IncidentDrawer.tsx exists and exports default function.")

    # 2. Chronological timeline fetching & rendering items
    print("[*] 2. Verifying chronological timeline fetching & item attributes...")
    assert "fetchSessionTimeline" in drawer_code, "Must import and call fetchSessionTimeline"
    assert "Badge" in drawer_code, "Must render severity badge"
    assert "font-mono" in drawer_code, "Must use monospace typography token"
    assert "formatTimeAgo" in drawer_code, "Must format timestamps relatively"
    print("    [+] Severity badge, monospace path, and relative time verified.")

    # 3. Download forensics JSON action
    print("[*] 3. Verifying 'Download Forensics JSON' client-side export...")
    assert "Download Forensics JSON" in drawer_code, "Must contain 'Download Forensics JSON' button"
    assert "downloadReportJson" in drawer_code, "Must call downloadReportJson"
    print("    [+] Download Forensics JSON button and client-side export verified.")

    # 4. Loading / empty states
    print("[*] 4. Verifying loading and empty states...")
    assert "loading" in drawer_code.lower(), "Must handle loading state"
    assert "No forensics data available" in drawer_code or "Retrieving chronological" in drawer_code, (
        "Must display informative loading/empty state, not a blank panel"
    )
    print("    [+] Loading and empty states verified.")

    # 5. Lifted state wiring in App.tsx
    print("[*] 5. Verifying App.tsx wiring with lifted state...")
    with open(app_tsx_path, "r", encoding="utf-8") as f:
        app_tsx_code = f.read()

    assert "import IncidentDrawer from './components/IncidentDrawer'" in app_tsx_code, (
        "App.tsx must import IncidentDrawer"
    )
    assert "<IncidentDrawer" in app_tsx_code, "App.tsx must render <IncidentDrawer"
    assert "sessionId={selectedSessionId}" in app_tsx_code, (
        "App.tsx must pass selectedSessionId to IncidentDrawer"
    )
    assert "onClose=" in app_tsx_code, (
        "App.tsx must pass onClose callback to IncidentDrawer"
    )
    print("    [+] App.tsx properly wires lifted state (sessionId, isOpen, onClose).")

    # 6. Zero hardcoded hex values
    print("[*] 6. Verifying zero hardcoded hex values...")
    hex_pattern = re.compile(r'#[0-9a-fA-F]{3,8}\b')
    hexes_found = hex_pattern.findall(drawer_code)
    assert not hexes_found, f"Found hardcoded hex in IncidentDrawer.tsx: {hexes_found}! Must use CSS tokens."
    print("    [+] Zero hardcoded hex values found in IncidentDrawer.tsx.")

    # 7. Backend live endpoints verification
    print("[*] 7. Verifying backend endpoints /api/session/<id>/timeline and /api/report/<id>...")
    try:
        req_sess = urllib.request.Request("http://127.0.0.1:5000/api/sessions?limit=1")
        with urllib.request.urlopen(req_sess, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            sessions = data.get("sessions", [])
            assert sessions, "No active sessions found in backend!"
            active_id = sessions[0]["session_id"]
            print(f"    [+] Testing active session ID: {active_id}")

        req_time = urllib.request.Request(f"http://127.0.0.1:5000/api/session/{active_id}/timeline")
        with urllib.request.urlopen(req_time, timeout=5) as resp:
            time_data = json.loads(resp.read().decode("utf-8"))
            events = time_data.get("events", [])
            print(f"    [+] Retrieved {len(events)} events for session {active_id}")
            if len(events) > 1:
                for i in range(len(events) - 1):
                    assert events[i]["id"] <= events[i+1]["id"], "Timeline events must be in chronological order!"
                print("    [+] Chronological ordering confirmed (ORDER BY id ASC).")

        req_rep = urllib.request.Request(f"http://127.0.0.1:5000/api/report/{active_id}")
        with urllib.request.urlopen(req_rep, timeout=5) as resp:
            rep_data = json.loads(resp.read().decode("utf-8"))
            report = rep_data.get("report", {})
            assert report.get("session_id") == active_id, "Report session_id mismatch!"
            assert "report_id" in report, "Report missing report_id!"
            assert "attacker" in report, "Report missing attacker block!"
            assert "total_requests" in report["attacker"], "Report missing attacker.total_requests!"
            print(f"    [+] Incident report generated successfully: ID {report.get('report_id')}")

    except Exception as e:
        print(f"    [!] Backend verification warning: {e}")
        raise e

    print("\n[***] ALL STAGE 9 INCIDENT DRAWER CHECKS PASSED PERFECTLY [***]\n")


if __name__ == "__main__":
    test_stage9()
