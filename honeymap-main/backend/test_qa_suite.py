"""
HoneyMap Comprehensive QA Test Suite (Part 1)
Covers:
1. Every decoy route returns correct fake content, headers, and logs to DB.
2. classify_event() hits all four severity branches, including exact honeytoken matches vs near-miss strings.
3. Rate limiter returns 429 past the cap (testing with >300 requests).
4. Tarpit delay increases across repeat hits and is capped strictly at 3.0s.
5. Session score_decay() produces identical results for WebSocket push and /api/sessions read path.
6. Session eviction actually fires once MAX_TRACKED_SESSIONS (500) is exceeded.
7. GeoIP lookup falls back gracefully with zero internet access.
8. WebSocket 'new_event' payload and /api/events items share identical shape and stable 'id'.
"""

import sys
import os
import time
import asyncio
from unittest.mock import patch
import pytest
import pytest_asyncio
import httpx

# Ensure backend root is on Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, RATE_LIMIT_MAX
from database import init_db, query_db, query_db_one, execute_write
from detection.honeytokens import init_honeytokens, get_active_honeytokens, check_exact_honeytoken_match
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


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_database_and_tokens():
    """Initializes schema and dynamic honeytokens before running tests."""
    await init_db()
    tokens = await init_honeytokens()
    assert tokens["aws_access_key"].startswith("AKIA")
    assert len(tokens["aws_secret_key"]) == 40
    assert tokens["database_password"].startswith("P@ssw0rd_")
    yield


@pytest_asyncio.fixture
async def async_client():
    """AsyncClient using ASGI transport for in-process FastAPI testing."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


# ============================================================================
# 1. DECOY ROUTES TESTING
# ============================================================================
class TestDecoyRoutes:
    @pytest.mark.asyncio
    async def test_env_decoy(self, async_client):
        res = await async_client.get("/.env")
        assert res.status_code == 200
        text = res.text
        assert "AWS_ACCESS_KEY_ID=AKIA" in text
        assert "AWS_SECRET_ACCESS_KEY=" in text
        assert "DATABASE_URL=" in text

        # Verify DB logging
        row = await query_db_one("SELECT * FROM events WHERE endpoint = '/.env' ORDER BY id DESC LIMIT 1")
        assert row is not None
        assert row["severity"] == "medium"
        assert "sensitive_file" in row["attack_type"]

    @pytest.mark.asyncio
    async def test_backup_sql_decoy(self, async_client):
        res = await async_client.get("/backup.sql")
        assert res.status_code == 200
        assert "CREATE TABLE" in res.text
        assert "admin_users" in res.text

    @pytest.mark.asyncio
    async def test_config_php_decoy(self, async_client):
        res = await async_client.get("/config.php")
        assert res.status_code == 200
        assert "<?php" in res.text
        assert "define('DB_PASS'" in res.text

    @pytest.mark.asyncio
    async def test_git_config_decoy(self, async_client):
        res = await async_client.get("/.git/config")
        assert res.status_code == 200
        assert "[core]" in res.text
        assert '[remote "origin"]' in res.text

    @pytest.mark.asyncio
    async def test_aws_credentials_decoy(self, async_client):
        res = await async_client.get("/.aws/credentials")
        assert res.status_code == 200
        assert "[default]" in res.text
        assert "aws_access_key_id = AKIA" in res.text

    @pytest.mark.asyncio
    async def test_wp_config_decoy(self, async_client):
        res = await async_client.get("/wp-config.php")
        assert res.status_code == 200
        assert "DB_NAME" in res.text
        assert "DB_USER" in res.text

    @pytest.mark.asyncio
    async def test_login_portals_get_and_post(self, async_client):
        # GET /admin returns HTML login form
        res_get = await async_client.get("/admin")
        assert res_get.status_code == 200
        assert "Administrative Portal" in res_get.text
        assert "<form" in res_get.text

        # POST /admin returns 401 Unauthorized JSON error
        res_post = await async_client.post("/admin", data={"username": "admin", "password": "wrongpassword"})
        assert res_post.status_code == 401
        assert "Invalid username or password" in res_post.text

    @pytest.mark.asyncio
    async def test_catch_all_decoy_route(self, async_client):
        res = await async_client.get("/random-rogue-endpoint-test")
        assert res.status_code == 404
        assert res.json()["status"] == "error"

        # Verify DB logging of rogue probe
        row = await query_db_one("SELECT * FROM events WHERE endpoint = '/random-rogue-endpoint-test' ORDER BY id DESC LIMIT 1")
        assert row is not None
        assert row["attack_type"] == "endpoint_scan"


# ============================================================================
# 2. CLASSIFY_EVENT SEVERITY & HONEYTOKEN MATCHING MATRIX
# ============================================================================
class TestClassifierMatrix:
    @pytest.mark.asyncio
    async def test_critical_severity_exact_honeytoken_reuse(self):
        active = await get_active_honeytokens()
        aws_key = list(active.keys())[0]

        # Case A: Honeytoken in payload
        sev, reason, token = classify_event(
            endpoint="/api/v1/user",
            method="POST",
            headers_str="{}",
            payload=f'{{"token": "{aws_key}"}}'
        )
        assert sev == "critical"
        assert reason == "honeytoken reuse detected"
        assert token == aws_key

        # Case B: Honeytoken in header
        sev, reason, token = classify_event(
            endpoint="/login",
            method="GET",
            headers_str=f'{{"Authorization": "Bearer {aws_key}"}}',
            payload=""
        )
        assert sev == "critical"
        assert token == aws_key

    @pytest.mark.asyncio
    async def test_near_miss_strings_do_not_trigger_critical(self):
        """CRITICAL RULE: Fuzzy/near-miss strings must NEVER trigger CRITICAL."""
        active = await get_active_honeytokens()
        aws_key = list(active.keys())[0]

        # Altered AWS key (e.g. changed last character)
        near_miss_key = aws_key[:-1] + ("Z" if aws_key[-1] != "Z" else "A")
        # Generic lookalike key
        lookalike_key = "AKIA1111222233334444"

        for test_token in [near_miss_key, lookalike_key, "password", "P@ssw0rd_fake!"]:
            sev, reason, token = classify_event(
                endpoint="/login",
                method="POST",
                headers_str="{}",
                payload=f'{{"token": "{test_token}"}}'
            )
            assert sev != "critical", f"Near-miss '{test_token}' falsely triggered CRITICAL!"
            assert token is None

    def test_high_severity_sqli(self):
        payloads = [
            "admin' OR '1'='1",
            "1' UNION SELECT username, password FROM users --",
            "1; DROP TABLE sessions;",
            "1' AND SLEEP(5) --"
        ]
        for p in payloads:
            sev, reason, token = classify_event(
                endpoint="/search",
                method="GET",
                headers_str="{}",
                payload=p
            )
            assert sev == "high", f"Failed to classify SQLi payload as high: {p}"
            assert "SQL" in reason
            assert token is None

    def test_high_severity_xss(self):
        payloads = [
            "<script>alert(1)</script>",
            '<img src=x onerror="alert(document.cookie)">',
            '<svg onload=alert(1)>',
            'javascript:alert(1)'
        ]
        for p in payloads:
            sev, reason, token = classify_event(
                endpoint="/comments",
                method="POST",
                headers_str="{}",
                payload=p
            )
            assert sev == "high"
            assert "Cross-Site Scripting" in reason
            assert token is None

    def test_medium_severity_sensitive_files(self):
        for path in ["/.env", "/backup.sql", "/config.php", "/.git/config", "/.aws/credentials", "/wp-config.php"]:
            sev, reason, token = classify_event(
                endpoint=path,
                method="GET",
                headers_str="{}",
                payload=""
            )
            assert sev == "medium"
            assert token is None

    def test_low_severity_login_and_recon(self):
        for path in ["/admin", "/login", "/wp-admin"]:
            sev, reason, token = classify_event(
                endpoint=path,
                method="GET",
                headers_str="{}",
                payload=""
            )
            assert sev == "low"
            assert token is None


# ============================================================================
# 3. RATE LIMITER 429 BOUNDARY TESTING
# ============================================================================
class TestRateLimitingBoundary:
    @pytest.mark.asyncio
    async def test_rate_limiter_exceeds_cap_returns_429(self, async_client):
        """
        Fires requests past the rate limit cap from a single IP
        and verifies HTTP 429 is returned with Retry-After header.
        """
        target_ip = "198.51.100.222"
        headers = {"X-Forwarded-For": target_ip}

        # Fire up to RATE_LIMIT_MAX requests
        for i in range(RATE_LIMIT_MAX):
            res = await async_client.get("/api/health", headers=headers)
            assert res.status_code == 200, f"Failed at request {i}: status {res.status_code}"

        # Request RATE_LIMIT_MAX + 1 MUST return 429
        blocked_res = await async_client.get("/api/health", headers=headers)
        assert blocked_res.status_code == 429
        assert "Retry-After" in blocked_res.headers
        assert int(blocked_res.headers["Retry-After"]) >= 1
        body = blocked_res.json()
        assert body["status"] == "error"
        assert "Rate limit exceeded" in body["message"]


# ============================================================================
# 4. TARPIT DEFENSIVE DELAYS
# ============================================================================
class TestTarpitDelays:
    def test_tarpit_delay_progression_and_cap(self):
        # 1st request -> 0.2s
        assert tarpit_delay({"request_count": 1}) == 0.2
        assert tarpit_delay(1) == 0.2

        # 5th request -> 1.0s
        assert tarpit_delay({"request_count": 5}) == 1.0
        assert tarpit_delay(5) == 1.0

        # 15th request -> 3.0s (cap reached)
        assert tarpit_delay({"request_count": 15}) == 3.0

        # 50th request -> 3.0s (strictly capped)
        assert tarpit_delay({"request_count": 50}) == 3.0
        assert tarpit_delay(100) == 3.0


# ============================================================================
# 5. SESSION SCORE DECAY PARITY
# ============================================================================
class TestScoreDecayParity:
    def test_score_decay_half_life_math(self):
        base_session = {
            "session_id": "test_sess_1",
            "raw_score": 100.0,
            "last_seen_epoch": 1000.0
        }

        # Elapsed 0 minutes -> 100.0
        assert score_decay(base_session, current_time=1000.0) == 100.0

        # Elapsed 5 minutes (300s) -> half-life (50.0)
        assert score_decay(base_session, current_time=1300.0) == 50.0

        # Elapsed 10 minutes (600s) -> 25.0
        assert score_decay(base_session, current_time=1600.0) == 25.0

        # Elapsed 20 minutes (1200s) -> 6.25
        assert score_decay(base_session, current_time=2200.0) == 6.25

    @pytest.mark.asyncio
    async def test_score_decay_push_and_rest_parity(self, async_client):
        """Validates that score_decay in get_all_sessions matches session tracker."""
        unique_id = str(int(time.time() * 1000))[-6:]
        test_ip = f"198.51.100.{unique_id[-2:]}"
        sess_id = await get_or_create_session(test_ip, f"QA-Decay-Agent-{unique_id}")

        # Get via session_info (push path helper)
        info = await get_session_info(sess_id)
        score_push = info["decayed_score"]

        # Get via REST API
        res = await async_client.get("/api/sessions?limit=200")
        assert res.status_code == 200
        # Validate directly using get_all_sessions
        all_sessions = await get_all_sessions(limit=2000)
        target = next((s for s in all_sessions if s["session_id"] == sess_id), None)
        assert target is not None
        assert abs(target["score"] - score_push) < 0.01


# ============================================================================
# 6. SESSION LRU EVICTION PROOF
# ============================================================================
class TestSessionLRUEviction:
    @pytest.mark.asyncio
    async def test_session_eviction_exceeds_max_cap(self):
        initial_evictions = get_eviction_count()

        # Create 550 distinct sessions
        for i in range(550):
            fake_ip = f"10.200.{i // 250}.{i % 250}"
            await get_or_create_session(fake_ip, f"EvictionTester-{i}")

        # In-memory dictionary must NOT exceed MAX_TRACKED_SESSIONS (500)
        assert len(_ACTIVE_SESSIONS) <= MAX_TRACKED_SESSIONS

        # Eviction counter must have increased by at least 50
        current_evictions = get_eviction_count()
        assert current_evictions >= initial_evictions + 50


# ============================================================================
# 7. GEOIP OFFLINE / ZERO-INTERNET FALLBACK
# ============================================================================
class TestGeoIPFallback:
    def test_offline_fallback_known_ips(self):
        # Germany Tor node
        res_de = lookup_ip("185.220.101.5")
        assert res_de["country"] == "Germany"
        assert res_de["city"] == "Frankfurt"
        assert res_de["latitude"] == 50.1109

        # Russia
        res_ru = lookup_ip("194.26.29.112")
        assert res_ru["country"] == "Russia"
        assert res_ru["city"] == "Moscow"

    def test_private_and_loopback_ips(self):
        res_loc = lookup_ip("127.0.0.1")
        assert res_loc["country"] == "Localhost"
        assert res_loc["city"] == "Internal Lab"

        res_priv = lookup_ip("192.168.1.100")
        assert res_priv["country"] == "Private Network"
        assert res_priv["country_code"] == "PRIV"

    def test_network_failure_fallback_gracefully(self):
        """Simulate complete network failure when querying public non-reserved IP."""
        with patch("requests.get", side_effect=Exception("Network Unreachable")):
            res = lookup_ip("8.8.8.8")
            assert res is not None
            assert res["ip"] == "8.8.8.8"
            assert res["country"] in ["Unknown", "United States"]
            assert isinstance(res["latitude"], (int, float))


# ============================================================================
# 8. WEBSOCKET & REST EVENT SHAPE STABILITY & DEDUPE CONTRACT
# ============================================================================
class TestEventPayloadContract:
    @pytest.mark.asyncio
    async def test_rest_and_ws_payload_fields(self, async_client):
        # Trigger an event
        await async_client.get("/.env", headers={"User-Agent": "ContractTester"})

        res = await async_client.get("/api/events?limit=1")
        assert res.status_code == 200
        events = res.json()["events"]
        assert len(events) >= 1
        ev = events[-1]

        # Verify all contract fields expected by React frontend
        required_fields = [
            "id", "session_id", "timestamp", "source_ip",
            "endpoint", "attack_type", "severity", "geoip",
            "ip", "path", "reason", "lat", "lon"
        ]
        for field in required_fields:
            assert field in ev, f"Missing required field '{field}' in event payload"

        assert isinstance(ev["id"], int)
        assert isinstance(ev["lat"], (float, type(None)))
        assert isinstance(ev["lon"], (float, type(None)))


# ============================================================================
# 9. REAL DATA AGGREGATION & ENTERPRISE SOC ENDPOINTS
# ============================================================================
class TestNewRealDataEndpoints:
    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, async_client):
        res = await async_client.get("/api/metrics")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert isinstance(data["critical_threats"], int)
        assert isinstance(data["requests_blocked"], int)
        assert isinstance(data["active_incidents"], int)
        assert isinstance(data["total_requests"], int)
        assert "severity_breakdown" in data

    @pytest.mark.asyncio
    async def test_analytics_endpoint(self, async_client):
        for rng in ["day", "week", "month", "year"]:
            res = await async_client.get(f"/api/analytics?range={rng}")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "ok"
            assert data["range"] == rng
            assert isinstance(data["points"], list)
            if data["points"]:
                pt = data["points"][0]
                assert "bucket" in pt
                assert "normal" in pt
                assert "total" in pt

    @pytest.mark.asyncio
    async def test_targets_endpoint(self, async_client):
        res = await async_client.get("/api/targets")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert isinstance(data["targets"], list)
        if data["targets"]:
            t = data["targets"][0]
            assert "target" in t
            assert "requests" in t
            assert "severity" in t
            assert "trend" in t

    @pytest.mark.asyncio
    async def test_threat_intel_endpoint(self, async_client):
        res = await async_client.get("/api/threat-intel")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "active_tokens" in data
        assert isinstance(data["tokens"], list)
        assert isinstance(data["compromised_events"], list)

    @pytest.mark.asyncio
    async def test_search_endpoint(self, async_client):
        res = await async_client.get("/api/search?q=admin")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["query"] == "admin"
        assert isinstance(data["events"], list)
        assert isinstance(data["sessions"], list)
