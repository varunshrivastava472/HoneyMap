import time
import os
import requests
import threading
import sys

# Test script to thoroughly verify Stage 1 checks:
# 1. Boot health
# 2. Concurrent requests testing SQLite without lock errors
# 3. Rate limiting (sliding window) returning 429

BASE_URL = "http://127.0.0.1:5000"

def test_health():
    print("[*] Testing /api/health...")
    session = requests.Session()
    resp = session.get(f"{BASE_URL}/api/health", timeout=3.0)
    assert resp.status_code == 200, f"Health check failed with code {resp.status_code}"
    data = resp.json()
    assert data.get("status") == "ok", f"Health payload invalid: {data}"
    print("[+] Health check OK:", data)

def test_concurrent_sqlite():
    print("[*] Testing 2 concurrent request loops against /api/health...")
    errors = []
    successes = [0, 0]

    def worker(worker_id, count=50):
        s = requests.Session()
        for _ in range(count):
            try:
                r = s.get(f"{BASE_URL}/api/health", timeout=5.0)
                if r.status_code == 200:
                    successes[worker_id] += 1
                else:
                    errors.append((worker_id, r.status_code, r.text))
            except Exception as ex:
                errors.append((worker_id, "exception", str(ex)))

    t1 = threading.Thread(target=worker, args=(0, 50))
    t2 = threading.Thread(target=worker, args=(1, 50))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    print(f"[+] Worker 0 succeeded: {successes[0]}, Worker 1 succeeded: {successes[1]}")
    if errors:
        print(f"[-] Encountered errors during concurrency test: {errors}")
        sys.exit(1)
    else:
        print("[+] Zero SQLite lock errors across concurrent loops!")

def test_rate_limit():
    print("[*] Testing sliding-window rate limit (sending rapid requests to trigger 429)...")
    test_ip = "198.51.100.99"
    headers = {"X-Forwarded-For": test_ip}

    s = requests.Session()
    got_429 = False
    count = 0
    for i in range(350):
        r = s.get(f"{BASE_URL}/api/health", headers=headers, timeout=2.0)
        count += 1
        if r.status_code == 429:
            print(f"[+] Received 429 Too Many Requests as expected on request #{count}: {r.json()}")
            got_429 = True
            break

    if not got_429:
        print(f"[-] Failed to trigger 429 within {count} requests.")
        sys.exit(1)
    else:
        print("[+] Rate limiting verified successfully!")

if __name__ == "__main__":
    time.sleep(1)
    test_health()
    test_concurrent_sqlite()
    test_rate_limit()
    print("[***] ALL STAGE 1 CHECKS PASSED [***]")
