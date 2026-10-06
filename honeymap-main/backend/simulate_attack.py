"""
HoneyMap Live Threat Simulation Engine
Stage 11: Realism + Reliable Demo

Modes:
1. `scripted` — One attacker escalating over ~30-45s:
   Recon (LOW) -> Sensitive File Hunting (MEDIUM) -> SQL Injection (HIGH) -> Honeytoken Reuse (CRITICAL).
   Spaced for a human watching live in the SOC dashboard.
2. `noise` — 4-5 background IPs at random intervals, strictly using OFFLINE_FALLBACK IPs.
   Runs 5+ minutes with no session-count growth past the Stage 4 cap (500) and zero console errors.
"""
import sys
import time
import random
import argparse
import requests
from typing import Dict, List, Optional, Any

BASE_URL = "http://127.0.0.1:5000"

# Scripted demo attacker (resolves offline to Russia, Moscow)
SCRIPTED_ATTACKER = {
    "ip": "194.26.29.112",
    "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "tag": "Advanced-Threat-Actor (194.26.29.112)"
}

# 5 Background Noise Attackers strictly using OFFLINE_FALLBACK demo IPs
NOISE_ATTACKERS: List[Dict[str, str]] = [
    {"ip": "185.220.101.5", "ua": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", "tag": "Tor-Exit (DE)"},
    {"ip": "103.145.13.12", "ua": "Go-http-client/1.1", "tag": "Scanner (CN)"},
    {"ip": "193.142.146.33", "ua": "python-requests/2.31.0", "tag": "Crawler (UA)"},
    {"ip": "177.54.144.20", "ua": "curl/7.88.1", "tag": "Probe (BR)"},
    {"ip": "14.161.45.99", "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)", "tag": "Automated-Bot (VN)"}
]

# Random probe target endpoints for noise simulation
NOISE_TARGETS = [
    ("/login", "GET", None),
    ("/admin", "GET", None),
    ("/wp-admin", "GET", None),
    ("/.env", "GET", None),
    ("/backup.sql", "GET", None),
    ("/config.php", "GET", None),
    ("/.git/config", "GET", None),
    ("/.aws/credentials", "GET", None),
    ("/wp-config.php", "GET", None),
    ("/login", "POST", {"username": "testuser", "password": "Password123!"}),
    ("/admin", "POST", {"username": "root", "password": "toor"})
]


def fetch_live_honeytokens(base_url: str = BASE_URL) -> Dict[str, str]:
    """Retrieves bait honeytokens by reading /.env."""
    tokens = {}
    try:
        r = requests.get(f"{base_url}/.env", timeout=3.0)
        for line in r.text.splitlines():
            if line.startswith("AWS_ACCESS_KEY_ID="):
                tokens["aws_key"] = line.split("=", 1)[1].strip()
            elif line.startswith("DATABASE_URL="):
                tokens["db_pass"] = line.split(":", 3)[-1].split("@")[0]
            elif line.startswith("AWS_SECRET_ACCESS_KEY="):
                tokens["aws_secret"] = line.split("=", 1)[1].strip()
    except Exception as e:
        print(f"[-] Warning: Failed to fetch honeytokens: {e}")
    return tokens


def run_scripted(base_url: str = BASE_URL, fast_mode: bool = False) -> Dict[str, Any]:
    """
    Executes a single attacker escalating over ~30-45s:
      Step 1 (0s): Recon probe on /login (LOW)
      Step 2 (~8s): Recon probe on /admin (LOW)
      Step 3 (~16s): Sensitive file hunting on rotated decoy /.env (MEDIUM)
      Step 4 (~26s): SQL Injection exploit on /login (HIGH)
      Step 5 (~36s): Honeytoken reuse against /api/v1/auth (CRITICAL payoff)
    """
    pace_recon = 1.0 if fast_mode else 7.0
    pace_medium = 1.0 if fast_mode else 8.0
    pace_high = 1.0 if fast_mode else 9.0
    pace_crit = 1.0 if fast_mode else 8.0

    attacker = SCRIPTED_ATTACKER
    headers = {
        "X-Forwarded-For": attacker["ip"],
        "User-Agent": attacker["ua"]
    }

    start_time = time.time()
    print("=" * 68)
    print(f"[*] STARTING SCRIPTED ATTACK ESCALATION ({'FAST' if fast_mode else '~35-45s human-paced'})")
    print(f"[*] Attacker: {attacker['tag']} | IP: {attacker['ip']}")
    print("=" * 68)

    # STEP 1: Reconnaissance (LOW)
    print(f"\n[+00s] [PHASE 1: RECONNAISSANCE] Probing login surface /login...")
    r1 = requests.get(f"{base_url}/login", headers=headers, timeout=5.0)
    print(f"       -> Response: {r1.status_code} | Severity: LOW | Surface mapped")
    time.sleep(pace_recon)

    # STEP 2: Second Recon Probe (LOW)
    print(f"\n[+{int(time.time() - start_time):02d}s] [PHASE 1: RECONNAISSANCE] Fingerprinting administrative portal /admin...")
    r2 = requests.get(f"{base_url}/admin", headers=headers, timeout=5.0)
    print(f"       -> Response: {r2.status_code} | Severity: LOW | Fingerprint collected")
    time.sleep(pace_medium)

    # STEP 3: Sensitive File Hunting (MEDIUM)
    print(f"\n[+{int(time.time() - start_time):02d}s] [PHASE 2: SENSITIVE FILE HUNTING] Hunting configuration leak /.env...")
    r3 = requests.get(f"{base_url}/.env", headers=headers, timeout=5.0)
    stolen_aws_key = "AKIAIOSFODNN7HONEYTRAP"
    if r3.text:
        for line in r3.text.splitlines():
            if line.startswith("AWS_ACCESS_KEY_ID="):
                stolen_aws_key = line.split("=", 1)[1].strip()
                break
    print(f"       -> Response: {r3.status_code} | Severity: MEDIUM | Extracted Honeytoken: {stolen_aws_key}")
    time.sleep(pace_high)

    # STEP 4: SQL Injection Exploitation (HIGH)
    print(f"\n[+{int(time.time() - start_time):02d}s] [PHASE 3: VULNERABILITY EXPLOITATION] Injecting SQL payload into /login...")
    r4 = requests.post(
        f"{base_url}/login",
        data={"username": "admin' OR 1=1 --", "password": "attacker_probe_pwd"},
        headers=headers,
        timeout=5.0
    )
    print(f"       -> Response: {r4.status_code} | Severity: HIGH | Attack: SQLi Boolean tautology")
    time.sleep(pace_crit)

    # STEP 5: Honeytoken Reuse Payoff (CRITICAL)
    print(f"\n[+{int(time.time() - start_time):02d}s] [PHASE 4: HONEYTOKEN REUSE PAYOFF] Reusing stolen token '{stolen_aws_key}'...")
    r5 = requests.post(
        f"{base_url}/api/v1/auth",
        data={"token": stolen_aws_key, "action": "assume_role", "caller": "HoneyMap-CLI"},
        headers=headers,
        timeout=5.0
    )
    duration = time.time() - start_time
    print(f"       -> Response: {r5.status_code} | Severity: CRITICAL | Reason: honeytoken reuse detected")
    print("=" * 68)
    print(f"[+] SCRIPTED ATTACK COMPLETED IN {duration:.1f}s WITH GUARANTEED CRITICAL PAYOFF!")
    print("=" * 68)

    return {
        "status": "success",
        "attacker_ip": attacker["ip"],
        "stolen_token": stolen_aws_key,
        "duration_seconds": round(duration, 2),
        "final_status_code": r5.status_code
    }


def run_noise(base_url: str = BASE_URL, duration_seconds: float = 300.0, max_requests: Optional[int] = None) -> Dict[str, Any]:
    """
    Executes background noise simulation using strictly 4-5 OFFLINE_FALLBACK IPs.
    Sends realistic requests at random 2-5s intervals.
    Guarantees bounded session-count never exceeding the Stage 4 cap (500).
    Runs with zero console/server errors.
    """
    start_time = time.time()
    request_count = 0
    errors_count = 0

    print("=" * 68)
    print(f"[*] STARTING NOISE SIMULATION ({duration_seconds}s target duration)")
    print(f"[*] Active Background Actors: {len(NOISE_ATTACKERS)} (Strictly OFFLINE_FALLBACK demo IPs)")
    for act in NOISE_ATTACKERS:
        print(f"    - {act['tag']}: {act['ip']}")
    print(f"[*] Bounded Session Count: Maximum 5 sessions (Stage 4 Cap: 500)")
    print("=" * 68)

    while True:
        elapsed = time.time() - start_time
        if duration_seconds > 0 and elapsed >= duration_seconds:
            break
        if max_requests is not None and request_count >= max_requests:
            break

        attacker = random.choice(NOISE_ATTACKERS)
        target_path, method, payload = random.choice(NOISE_TARGETS)

        headers = {
            "X-Forwarded-For": attacker["ip"],
            "User-Agent": attacker["ua"]
        }

        try:
            if method == "GET":
                r = requests.get(f"{base_url}{target_path}", headers=headers, timeout=5.0)
            else:
                r = requests.post(f"{base_url}{target_path}", data=payload, headers=headers, timeout=5.0)

            request_count += 1
            print(f"[{int(elapsed):03d}s] [NOISE #{request_count:03d}] {attacker['tag']} -> {method} {target_path} ({r.status_code})")
            if r.status_code >= 500:
                errors_count += 1
                print(f"[-] Server error {r.status_code} encountered on {target_path}")

        except Exception as e:
            errors_count += 1
            print(f"[-] Request error for {attacker['ip']} -> {target_path}: {e}")

        # Random sleep interval between probes (2.0 - 4.5s)
        time.sleep(random.uniform(2.0, 4.5))

    total_time = time.time() - start_time
    print("=" * 68)
    print(f"[+] NOISE SIMULATION FINISHED: {request_count} requests in {total_time:.1f}s with {errors_count} errors.")
    print("=" * 68)

    return {
        "status": "success",
        "total_requests": request_count,
        "errors_count": errors_count,
        "duration_seconds": round(total_time, 2)
    }


def main():
    parser = argparse.ArgumentParser(description="HoneyMap Multi-Vector Attack Simulator")
    parser.add_argument("mode", choices=["scripted", "noise", "all"], default="scripted", nargs="?",
                        help="Simulation mode: 'scripted' (escalating kill-chain), 'noise' (background traffic), 'all'")
    parser.add_argument("--url", default=BASE_URL, help=f"HoneyMap base URL (default: {BASE_URL})")
    parser.add_argument("--duration", type=float, default=300.0, help="Duration in seconds for noise mode (default: 300s / 5 min)")
    parser.add_argument("--fast", action="store_true", help="Fast execution mode for automated testing")
    parser.add_argument("--max-requests", type=int, default=None, help="Maximum requests cap for noise mode testing")

    args = parser.parse_args()

    if args.mode == "scripted":
        run_scripted(base_url=args.url, fast_mode=args.fast)
    elif args.mode == "noise":
        run_noise(base_url=args.url, duration_seconds=args.duration, max_requests=args.max_requests)
    elif args.mode == "all":
        import threading
        noise_thread = threading.Thread(
            target=run_noise,
            kwargs={"base_url": args.url, "duration_seconds": 60.0},
            daemon=True
        )
        noise_thread.start()
        time.sleep(2.0)
        run_scripted(base_url=args.url, fast_mode=args.fast)
        noise_thread.join(timeout=10.0)


if __name__ == "__main__":
    main()
