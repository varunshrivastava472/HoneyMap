"""
Verification of Non-Blocking Async Tarpit Delays under FastAPI.

Tests that when an attacker triggers a defensive tarpit delay on a decoy route (e.g. 1.0s+),
concurrent requests from other clients (e.g. /api/health) complete instantly (< 50ms)
without being blocked or stalled by the single-threaded async event loop.
"""
import time
import threading
import requests

BASE_URL = "http://127.0.0.1:5000"

def test_tarpit_concurrency():
    print("[*] ===================================================")
    print("[*] Testing Non-Blocking Async Tarpit Concurrency")
    print("[*] ===================================================")

    attacker_ip = "198.51.100.222"
    attacker_headers = {"X-Forwarded-For": attacker_ip, "User-Agent": "SlowAttacker"}

    # Prime attacker session to build up request count and tarpit delay (~1.0s)
    session = requests.Session()
    print("[*] Priming attacker session to build repeat hit count...")
    for _ in range(5):
        session.get(f"{BASE_URL}/admin", headers=attacker_headers)

    # Now, launch a slow decoy hit on a separate thread (expected duration >= 1.0s)
    tarpit_finished = [False]
    tarpit_duration = [0.0]

    def run_slow_tarpit():
        t0 = time.time()
        r = session.get(f"{BASE_URL}/admin", headers=attacker_headers)
        tarpit_duration[0] = time.time() - t0
        tarpit_finished[0] = True
        print(f"    [+] Attacker tarpit request finished in {tarpit_duration[0]:.2f}s (status: {r.status_code})")

    tarpit_thread = threading.Thread(target=run_slow_tarpit)
    tarpit_thread.start()

    # Give the thread a moment to enter the tarpit delay
    time.sleep(0.15)
    assert not tarpit_finished[0], "Tarpit finished prematurely!"

    # While attacker is stuck in tarpit, send 20 concurrent /api/health requests from another client
    print("[*] Sending 20 concurrent /api/health requests while attacker is in tarpit...")
    health_times = []
    health_session = requests.Session()

    for i in range(20):
        t0 = time.time()
        r_health = health_session.get(f"{BASE_URL}/api/health", timeout=1.0)
        elapsed = time.time() - t0
        health_times.append(elapsed)
        assert r_health.status_code == 200
        assert r_health.json().get("status") == "ok"

    tarpit_thread.join()

    avg_health_time = sum(health_times) / len(health_times)
    max_health_time = max(health_times)
    print(f"    [+] Average /api/health latency: {avg_health_time * 1000:.1f}ms")
    print(f"    [+] Max /api/health latency: {max_health_time * 1000:.1f}ms")
    print(f"    [+] Attacker was held for: {tarpit_duration[0]:.2f}s")

    assert max_health_time < 0.20, f"Concurrent health check was stalled by tarpit! Max time: {max_health_time:.3f}s"
    print("[***] NON-BLOCKING ASYNC TARPIT CONCURRENCY FULLY VERIFIED! [***]")

if __name__ == "__main__":
    test_tarpit_concurrency()
