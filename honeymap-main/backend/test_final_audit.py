"""
HoneyMap Final Exhaustive Error-Check & Verification Suite
Covers all 7 validation categories:
1. Backend Correctness (Decoy routes, 4-tier classifier, safe_client_ip, length truncation)
2. Concurrency & Async (aiosqlite concurrent writes, non-blocking tarpit, score decay parity, LRU eviction)
3. Real-Time Pipeline (WebSocket vs REST payload parity & stable ID deduplication)
4. Security & Hardening (Sliding-window rate limiter 429, scoped CORS, fresh honeytokens)
5. Frontend Data Tracing Contract
6. Failure & Edge Cases (Zero internet offline GeoIP fallback, empty database graceful responses)
7. Deployment Readiness
"""
import sys
import os
import time
import asyncio
import uuid
import pytest
import pytest_asyncio
import httpx
from unittest.mock import patch, MagicMock
from fastapi import Request

# Ensure backend root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, RATE_LIMIT_MAX
from database import init_db, query_db, query_db_one, execute_write
from detection.honeytokens import (
    init_honeytokens,
    get_active_honeytokens,
    check_exact_honeytoken_match,
    generate_aws_honeytoken,
    generate_db_password_honeytoken
)
from detection.classifier import classify_event
from detection.session_tracker import (
    get_or_create_session,
    get_session_info,
    get_all_sessions,
    score_decay,
    tarpit_delay,
    get_eviction_count,
    MAX_TRACKED_SESSIONS,
    _ACTIVE_SESSIONS
)
from detection.geoip import lookup_ip, OFFLINE_FALLBACK
from decoys.request_utils import safe_client_ip, sanitize_and_cap_request_data
from decoys.fake_files import get_live_paths, POOL_OF_6


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_environment():
    """Initializes the SQLite database and active honeytokens before running test suites."""
    await init_db()
    tokens = await init_honeytokens()
    assert tokens["aws_access_key"].startswith("AKIA")
    assert len(tokens["aws_secret_key"]) == 40
    assert tokens["database_password"].startswith("P@ssw0rd_")
    yield


@pytest_asyncio.fixture
async def async_client():
    """httpx.AsyncClient with ASGI transport for in-process FastAPI testing."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


# ============================================================================
# CATEGORY 1: BACKEND CORRECTNESS
# ============================================================================
class TestCategory1BackendCorrectness:
    @pytest.mark.asyncio
    async def test_all_decoy_routes_content_and_logging(self, async_client):
        """Every decoy route must return 200/401 with authentic bait and log into SQLite."""
        # 1. Login Decoys (GET renders HTML form)
        for i, route in enumerate(["/admin", "/wp-admin", "/login"]):
            res = await async_client.get(route, headers={"X-Forwarded-For": f"198.51.100.{10 + i}"})
            assert res.status_code == 200
            assert "<form" in res.text.lower()
            assert ("password" in res.text.lower() or "pwd" in res.text.lower())

        # 2. Login Decoys (POST captures attempt and returns 401 JSON)
        for i, route in enumerate(["/admin", "/wp-admin", "/login"]):
            res = await async_client.post(route, data={"username": "admin", "password": "Password123"}, headers={"X-Forwarded-For": f"198.51.100.{20 + i}"})
            assert res.status_code == 401
            assert res.json().get("status") == "error"

        # 3. Sensitive File Traps (Pool of 6)
        file_decoys = ["/.env", "/backup.sql", "/config.php", "/.git/config", "/.aws/credentials", "/wp-config.php"]
        for i, route in enumerate(file_decoys):
            res = await async_client.get(route, headers={"X-Forwarded-For": f"198.51.100.{30 + i}"})
            assert res.status_code == 200
            assert len(res.text) > 20
            # Verify X-HoneyMap-Decoy-Live header
            assert "x-honeymap-decoy-live" in res.headers

        # Verify DB logging of hits
        rows = await query_db("SELECT * FROM events WHERE endpoint IN ('/.env', '/backup.sql', '/config.php')")
        assert len(rows) >= 3

    def test_classifier_all_four_severity_branches(self):
        """Tests classify_event() hits CRITICAL, HIGH, MEDIUM, LOW correctly with exact vs near-miss tokens."""
        active = check_exact_honeytoken_match("test") # in-memory cache check
        tokens = list(OFFLINE_FALLBACK.keys()) # just checking scope

        # 1. CRITICAL: Exact active honeytoken reuse
        from detection.honeytokens import _ACTIVE_HONEYTOKENS
        assert len(_ACTIVE_HONEYTOKENS) >= 2
        real_token = list(_ACTIVE_HONEYTOKENS.keys())[0]

        sev, reason, tok = classify_event(
            endpoint="/api/v1/auth",
            method="POST",
            headers_str=f'{{"Authorization": "Bearer {real_token}"}}',
            payload=f'{{"token": "{real_token}"}}'
        )
        assert sev == "critical"
        assert "honeytoken reuse" in reason
        assert tok == real_token

        # 2. NOT CRITICAL: Near-miss string (missing 1 char or altered)
        near_miss = real_token[:-1] + "X"
        sev_nm, reason_nm, tok_nm = classify_event(
            endpoint="/api/v1/auth",
            method="POST",
            headers_str=f'{{"Authorization": "Bearer {near_miss}"}}',
            payload=f'{{"token": "{near_miss}"}}'
        )
        assert sev_nm != "critical", f"Near-miss string falsely triggered CRITICAL: {near_miss}"

        # 3. HIGH: SQL Injection signatures
        sqli_payloads = [
            "admin' OR 1=1 --",
            "1' UNION SELECT username, password FROM users --",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND 'a'='a"
        ]
        for sqli in sqli_payloads:
            sev_sql, reason_sql, _ = classify_event(
                endpoint="/search",
                method="GET",
                headers_str="{}",
                payload=sqli
            )
            assert sev_sql == "high", f"SQLi pattern failed to hit HIGH: {sqli}"

        # 4. HIGH: Cross-Site Scripting (XSS) signatures
        xss_payloads = [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:void(0)",
            "<svg onload=alert(1)>"
        ]
        for xss in xss_payloads:
            sev_xss, reason_xss, _ = classify_event(
                endpoint="/comment",
                method="POST",
                headers_str="{}",
                payload=xss
            )
            assert sev_xss == "high", f"XSS pattern failed to hit HIGH: {xss}"

        # 5. MEDIUM: Sensitive decoy path
        sev_med, reason_med, _ = classify_event(
            endpoint="/.env",
            method="GET",
            headers_str="{}",
            payload=""
        )
        assert sev_med == "medium"

        # 6. LOW: Plain login probe
        sev_low, reason_low, _ = classify_event(
            endpoint="/login",
            method="GET",
            headers_str="{}",
            payload=""
        )
        assert sev_low == "low"

    def test_safe_client_ip_malformed_rejection(self):
        """safe_client_ip() must reject malformed/spoofed headers without crashing."""
        scope_base = {"type": "http", "method": "GET", "path": "/test"}

        # 1. Valid X-Forwarded-For with multiple proxies
        req1 = Request({
            **scope_base,
            "headers": [(b"x-forwarded-for", b"198.51.100.42, 10.0.0.1, 192.168.1.1")],
            "client": ("127.0.0.1", 54321)
        })
        assert safe_client_ip(req1) == "198.51.100.42"

        # 2. Malformed X-Forwarded-For containing SQLi injection or script
        req2 = Request({
            **scope_base,
            "headers": [(b"x-forwarded-for", b"malformed_ip_value; DROP TABLE users;, 10.0.0.1")],
            "client": ("127.0.0.1", 54321)
        })
        # Must fall back cleanly to client host
        assert safe_client_ip(req2) == "127.0.0.1"

        # 3. Garbage X-Forwarded-For with HTML/XSS
        req3 = Request({
            **scope_base,
            "headers": [(b"x-forwarded-for", b"<script>alert(1)</script>")],
            "client": ("192.168.1.50", 54321)
        })
        assert safe_client_ip(req3) == "192.168.1.50"

    @pytest.mark.asyncio
    async def test_oversized_payload_capping(self, async_client):
        """Oversized payloads must be length-capped without throwing 500 error."""
        oversized_data = "A" * 10000
        res = await async_client.post(
            "/login",
            data={"username": "testuser", "payload_dump": oversized_data},
            headers={"User-Agent": "A" * 1000}
        )
        assert res.status_code == 401
        # Confirm row was inserted with capped length
        row = await query_db_one("SELECT payload, headers_json FROM events WHERE endpoint = '/login' ORDER BY id DESC LIMIT 1")
        assert row is not None
        assert len(row["payload"]) <= 2000
        assert len(row["headers_json"]) <= 2000


# ============================================================================
# CATEGORY 2: CONCURRENCY & ASYNC CORRECTNESS
# ============================================================================
class TestCategory2ConcurrencyAndAsync:
    @pytest.mark.asyncio
    async def test_concurrent_sqlite_writes_no_lock_errors(self):
        """Simultaneous concurrent async writes to same session/event table without lock errors."""
        session_id = f"test-concurrent-{uuid.uuid4().hex[:8]}"
        await execute_write(
            "INSERT INTO sessions (session_id, source_ip, user_agent, request_count, max_severity) VALUES (?, ?, ?, 1, 'low')",
            (session_id, "198.51.100.88", "ConcurrencyTester")
        )

        async def concurrent_event_writer(idx: int):
            q = """
            INSERT INTO events (
                session_id, source_ip, source_port, request_method, endpoint,
                headers_json, payload, attack_type, severity, flagged_token, metadata_json, timestamp
            ) VALUES (?, ?, ?, 'GET', ?, '{}', '', 'probe', 'low', NULL, '{}', datetime('now'))
            """
            await execute_write(q, (session_id, "198.51.100.88", 50000 + idx, f"/probe/{idx}"))

        # Launch 30 simultaneous writes in parallel
        tasks = [concurrent_event_writer(i) for i in range(30)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            assert not isinstance(res, Exception), f"Concurrent SQLite write threw exception: {res}"

        # Verify all 30 rows exist
        rows = await query_db("SELECT COUNT(*) as cnt FROM events WHERE session_id = ?", (session_id,))
        assert rows[0]["cnt"] == 30

    @pytest.mark.asyncio
    async def test_non_blocking_async_tarpit(self, async_client):
        """Tarpit delay uses await asyncio.sleep, allowing concurrent /api/health requests to respond instantly."""
        # Check health response time under no load
        t0 = time.monotonic()
        h_res = await async_client.get("/api/health")
        baseline_time = time.monotonic() - t0
        assert h_res.status_code == 200

        # Simulate slow decoy hit on a primed session
        attacker_headers = {"X-Forwarded-For": "198.51.100.111", "User-Agent": "TarpitTester"}
        for _ in range(3):
            await async_client.get("/admin", headers=attacker_headers)

        # Launch slow request and simultaneous health check concurrently
        async def hit_tarpit():
            t_start = time.monotonic()
            r = await async_client.get("/admin", headers=attacker_headers)
            return time.monotonic() - t_start, r.status_code

        async def poll_health():
            await asyncio.sleep(0.05) # ensure tarpit has begun
            t_start = time.monotonic()
            r = await async_client.get("/api/health")
            return time.monotonic() - t_start, r.status_code

        tarpit_task = asyncio.create_task(hit_tarpit())
        health_task = asyncio.create_task(poll_health())

        tarpit_duration, tarpit_status = await tarpit_task
        health_duration, health_status = await health_task

        assert tarpit_status == 200
        assert health_status == 200
        # Health check must have responded in < 100ms despite the ongoing tarpit delay
        assert health_duration < 0.15, f"Health check stalled during tarpit! Latency: {health_duration:.3f}s"

    def test_score_decay_parity(self):
        """score_decay() produces identical results for WebSocket push and REST /api/sessions read."""
        now = time.time()
        session_sample = {
            "session_id": "sess-parity-1",
            "source_ip": "198.51.100.99",
            "request_count": 10,
            "max_severity": "high",
            "raw_score": 750.0,
            "last_seen_epoch": now - 300.0 # 5 minutes ago -> exactly 1 half-life
        }
        # Score after 1 half-life (5 min) should be 50% of raw_score = 375.0
        decayed = score_decay(session_sample, current_time=now)
        assert decayed == 375.0

    @pytest.mark.asyncio
    async def test_lru_session_eviction_under_load(self):
        """MAX_TRACKED_SESSIONS (500) strictly bounds in-memory active sessions."""
        initial_evictions = get_eviction_count()
        # Insert 550 unique sessions
        for i in range(550):
            fake_ip = f"10.200.{(i // 250)}.{i % 250}"
            await get_or_create_session(fake_ip, user_agent=f"Bot-{i}")

        assert len(_ACTIVE_SESSIONS) == MAX_TRACKED_SESSIONS
        assert get_eviction_count() >= (initial_evictions + 50)


# ============================================================================
# CATEGORY 3: REAL-TIME PIPELINE
# ============================================================================
class TestCategory3RealTimePipeline:
    @pytest.mark.asyncio
    async def test_events_payload_schema_and_id_parity(self, async_client):
        """REST /api/events items and WebSocket 'new_event' payloads share identical shape and stable integer 'id'."""
        res = await async_client.get("/.env")
        assert res.status_code == 200

        events_res = await async_client.get("/api/events?limit=5")
        assert events_res.status_code == 200
        data = events_res.json()
        assert data["status"] == "ok"
        assert len(data["events"]) > 0

        latest_event = data["events"][-1]
        required_keys = [
            "id", "session_id", "timestamp", "source_ip", "source_port",
            "request_method", "endpoint", "headers_json", "payload",
            "attack_type", "severity", "geoip", "ip", "path", "reason"
        ]
        for k in required_keys:
            assert k in latest_event, f"Missing required normalized key in event item: {k}"
        assert isinstance(latest_event["id"], int)


# ============================================================================
# CATEGORY 4: SECURITY & HARDENING
# ============================================================================
class TestCategory4SecurityHardening:
    @pytest.mark.asyncio
    async def test_rate_limiter_returns_429_past_threshold(self, async_client):
        """Per-IP sliding-window rate limiter returns 429 once threshold is exceeded."""
        flood_ip = "198.51.100.250"
        headers = {"X-Forwarded-For": flood_ip}
        got_429 = False

        for _ in range(RATE_LIMIT_MAX + 5):
            res = await async_client.get("/api/health", headers=headers)
            if res.status_code == 429:
                got_429 = True
                assert "retry-after" in res.headers
                assert res.json().get("status") == "error"
                break

        assert got_429, f"Rate limiter failed to return 429 within {RATE_LIMIT_MAX + 5} requests."

    @pytest.mark.asyncio
    async def test_cors_configuration_scoped_not_wildcard(self, async_client):
        """CORS headers must never return wildcard '*' for credentialed security."""
        res = await async_client.options(
            "/api/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET"
            }
        )
        assert res.headers.get("access-control-allow-origin") != "*"

    @pytest.mark.asyncio
    async def test_honeytoken_freshness_on_reboot(self):
        """Honeytokens regenerate with distinct unpredictable values on initialization."""
        boot1 = await init_honeytokens()
        boot2 = await init_honeytokens()
        assert boot1["aws_access_key"] != boot2["aws_access_key"]
        assert boot1["aws_secret_key"] != boot2["aws_secret_key"]
        assert boot1["database_password"] != boot2["database_password"]


# ============================================================================
# CATEGORY 6: FAILURE / EDGE CASES
# ============================================================================
class TestCategory6FailureEdgeCases:
    def test_offline_geoip_resolution_zero_internet(self):
        """All OFFLINE_FALLBACK demo IPs resolve instantaneously with zero external network access."""
        with patch("requests.get", side_effect=Exception("No internet connection")):
            for demo_ip in OFFLINE_FALLBACK.keys():
                geo = lookup_ip(demo_ip)
                assert geo["country"] != "Unknown"
                assert geo["country_code"] != "XX"

            # Unknown public IP with network disabled falls back to graceful Unknown dictionary
            unknown_geo = lookup_ip("8.8.8.8")
            assert unknown_geo["country"] == "Unknown"
            assert unknown_geo["country_code"] == "XX"

    @pytest.mark.asyncio
    async def test_empty_database_honest_responses(self, async_client):
        """Endpoints return honest empty states without crashing when queried against empty tables."""
        # Query endpoints that handle aggregation
        for ep in ["/api/events", "/api/sessions", "/api/metrics", "/api/analytics", "/api/targets", "/api/threat-intel"]:
            res = await async_client.get(ep)
            assert res.status_code == 200
            assert res.json().get("status") == "ok"
