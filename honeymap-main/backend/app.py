"""
HoneyMap FastAPI Backend & ASGI Real-Time Feed.
Migrated from Flask to FastAPI, with python-socketio ASGI mount,
aiosqlite async database layer, non-blocking tarpit delays, and Pydantic schema validation.
"""
import os
import time
import asyncio
from collections import deque
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any
from fastapi import FastAPI, Request, Response, Query, HTTPException, status
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import socketio

from database import init_db, query_db, query_db_one, execute_write
from detection.honeytokens import init_honeytokens, get_active_honeytokens, get_active_honeytokens_cached
from detection.geoip import lookup_ip
from detection.session_tracker import get_all_sessions, get_session_info, clear_sessions
from decoys.request_utils import safe_client_ip
from decoys.fake_login import fake_login_router
from decoys.fake_files import fake_files_router
from decoys.logger import log_decoy_hit
from socket_instance import sio

# -------------------------------------------------------------
# PYDANTIC RESPONSE MODELS
# -------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = "ok"


class EventItem(BaseModel):
    id: int
    session_id: Optional[str] = None
    timestamp: str
    source_ip: str
    source_port: Optional[int] = 0
    request_method: Optional[str] = "GET"
    endpoint: str
    headers_json: Optional[str] = "{}"
    payload: Optional[str] = ""
    attack_type: Optional[str] = "suspicious_request"
    severity: Optional[str] = "low"
    flagged_token: Optional[str] = None
    metadata_json: Optional[str] = "{}"
    geoip: Optional[Dict[str, Any]] = None
    ip: Optional[str] = None
    path: Optional[str] = None
    reason: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None


class EventsResponse(BaseModel):
    status: str = "ok"
    events: List[EventItem]
    count: int


class SessionsResponse(BaseModel):
    status: str = "ok"
    sessions: List[Dict[str, Any]]
    count: int


class TimelineResponse(BaseModel):
    status: str = "ok"
    session_id: str
    session: Optional[Dict[str, Any]] = None
    geoip: Optional[Dict[str, Any]] = None
    events: List[Dict[str, Any]]
    event_count: int


class ReportResponse(BaseModel):
    status: str = "ok"
    report: Dict[str, Any]


class GeoIPResponse(BaseModel):
    status: str = "ok"
    geoip: Dict[str, Any]


class DashboardResponse(BaseModel):
    status: str = "ok"
    service: str
    version: str


class MetricsResponse(BaseModel):
    status: str = "ok"
    critical_threats: int
    requests_blocked: int
    active_incidents: int
    total_requests: int
    severity_breakdown: Dict[str, int]


class AnalyticsDataPoint(BaseModel):
    bucket: str
    normal: int
    low: int
    medium: int
    high: int
    critical: int
    total: int


class AnalyticsResponse(BaseModel):
    status: str = "ok"
    range: str
    points: List[AnalyticsDataPoint]


class TargetItem(BaseModel):
    target: str
    incidents: int
    requests: int
    severity: str
    trend: float
    last_seen: Optional[str] = None


class TargetsResponse(BaseModel):
    status: str = "ok"
    targets: List[TargetItem]
    count: int


class ThreatIntelItem(BaseModel):
    token_id: str
    token_type: str
    token_value: str
    description: Optional[str] = None
    created_at: Optional[str] = None
    trigger_count: int = 0
    last_triggered: Optional[str] = None
    is_active: bool = True


class ThreatIntelResponse(BaseModel):
    status: str = "ok"
    active_tokens: Dict[str, str]
    tokens: List[ThreatIntelItem]
    compromised_events: List[Dict[str, Any]]
    total_compromised_count: int


class SearchResponse(BaseModel):
    status: str = "ok"
    query: str
    events: List[EventItem]
    sessions: List[Dict[str, Any]]
    total_matches: int


# -------------------------------------------------------------
# RATE LIMITING & SECURITY CONFIGURATION
# -------------------------------------------------------------
RATE_LIMIT_WINDOW = 60.0
RATE_LIMIT_MAX = int(os.environ.get("HONEYMAP_RATE_LIMIT_MAX", "300"))
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB limit per Stage 2 / Stage 12

_ip_request_timestamps: Dict[str, deque] = {}


# -------------------------------------------------------------
# LIFESPAN CONTEXT MANAGER
# -------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan handler: initializes database and fresh honeytokens on startup.
    """
    await init_db()
    active_tokens = await init_honeytokens()
    print(f"[*] Honeytokens initialized: AWS key {active_tokens['aws_access_key']}")
    yield


# Initialize FastAPI application
app = FastAPI(
    title="HoneyMap Security Platform",
    description="Real-Time Intrusion & Honeytoken Monitoring Grid",
    version="2.0.0",
    lifespan=lifespan
)

# Scoped CORS restriction & Vercel deployment support
cors_env = os.environ.get("HONEYMAP_CORS_ORIGINS", "http://localhost:5173")
cors_origins = [orig.strip() for orig in cors_env.split(",") if orig.strip()]

if "*" in cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"]
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_origin_regex=r"https://.*\.vercel\.app",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"]
    )



# Request Size & Sliding-Window Rate Limit Middleware
@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next):
    # 1. Check Content-Length size cap (1MB)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_CONTENT_LENGTH:
                return JSONResponse(
                    status_code=413,
                    content={
                        "status": "error",
                        "message": "Payload Too Large. Maximum allowed request size is 1MB."
                    }
                )
        except ValueError:
            pass

    # 2. Exclude preflight OPTIONS
    if request.method == "OPTIONS":
        return await call_next(request)

    # 3. Sliding-window rate limit
    ip = safe_client_ip(request)
    now = time.monotonic()

    # Periodic cleanup of stale IPs
    if len(_ip_request_timestamps) > 1000:
        stale_ips = [
            k for k, dq in _ip_request_timestamps.items()
            if not dq or dq[-1] < (now - RATE_LIMIT_WINDOW)
        ]
        for k in stale_ips:
            del _ip_request_timestamps[k]

    if ip not in _ip_request_timestamps:
        _ip_request_timestamps[ip] = deque()

    timestamps = _ip_request_timestamps[ip]
    cutoff = now - RATE_LIMIT_WINDOW
    while timestamps and timestamps[0] < cutoff:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT_MAX:
        retry_after = int(RATE_LIMIT_WINDOW - (now - timestamps[0])) + 1
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(max(1, retry_after))},
            content={
                "status": "error",
                "message": "Too Many Requests. Rate limit exceeded.",
                "retry_after_seconds": max(1, retry_after)
            }
        )

    timestamps.append(now)
    return await call_next(request)


# Register decoy routers
app.include_router(fake_login_router)
app.include_router(fake_files_router)


# -------------------------------------------------------------
# REST API ROUTES
# -------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint: verifies async SQLite connectivity and WAL access.
    """
    await query_db_one("SELECT 1 AS alive")
    return {"status": "ok"}


@app.get("/api/events", response_model=EventsResponse)
async def get_events_api(
    since: Optional[str] = Query(None, description="ISO/UTC timestamp cutoff"),
    limit: int = Query(50, ge=1, le=200, description="Max rows to return")
):
    """
    Polling fallback endpoint for real-time intrusion feed.
    Guarantees IDENTICAL shape to socketio 'new_event' payload.
    """
    if since:
        rows = await query_db(
            """
            SELECT id, session_id, timestamp, source_ip, source_port, request_method,
                   endpoint, headers_json, payload, attack_type, severity, flagged_token, metadata_json
            FROM events
            WHERE timestamp > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (since, limit)
        )
    else:
        rows = await query_db(
            """
            SELECT id, session_id, timestamp, source_ip, source_port, request_method,
                   endpoint, headers_json, payload, attack_type, severity, flagged_token, metadata_json
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )
        rows = list(reversed(rows))

    events = []
    for r in rows:
        item = dict(r)
        geo = lookup_ip(item["source_ip"])
        item["geoip"] = geo
        item["ip"] = item["source_ip"]
        item["path"] = item["endpoint"]
        item["reason"] = item["attack_type"]
        item["lat"] = geo.get("latitude") if isinstance(geo, dict) else None
        item["lon"] = geo.get("longitude") if isinstance(geo, dict) else None
        events.append(item)

    return {"status": "ok", "events": events, "count": len(events)}


def _session_last_seen_epoch(session: Dict[str, Any]) -> float:
    """Best-effort epoch for pinning recently active sessions in leaderboard responses."""
    if session.get("last_seen_epoch") is not None:
        return float(session["last_seen_epoch"])
    last_seen = session.get("last_seen")
    if not last_seen:
        return 0.0
    try:
        iso = last_seen.replace(" ", "T") if "T" not in last_seen else last_seen
        if not iso.endswith("Z"):
            iso += "Z"
        from datetime import datetime
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


@app.get("/api/sessions", response_model=SessionsResponse)
async def get_sessions_api(
    limit: int = Query(50, ge=1, le=500, description="Max sessions to return")
):
    """
    Leaderboard endpoint: lists attacker sessions with decayed scores, sorted descending.
    Applies the incoming response limit in the HTTP layer so the session tracker keeps
    the full ranked list for internal callers and tests. Recently active sessions (5 min)
    are always included even if their score would place them below the cutoff.
    """
    all_ranked = await get_all_sessions(limit=limit)
    now = time.time()
    recent_window = 300
    recent = [s for s in all_ranked if _session_last_seen_epoch(s) >= now - recent_window]
    recent_ids = {s["session_id"] for s in recent}
    top = [s for s in all_ranked if s["session_id"] not in recent_ids][:max(0, limit - len(recent))]
    sessions = recent + top
    for s in sessions:
        s["geoip"] = lookup_ip(s["source_ip"])
        s["event_count"] = s.get("request_count", 1)

    return {"status": "ok", "sessions": sessions, "count": len(sessions)}


@app.get("/api/session/{session_id}/timeline", response_model=TimelineResponse)
async def get_session_timeline_api(session_id: str):
    """
    Returns the chronologically ordered event timeline for an individual session.
    """
    sess = await get_session_info(session_id)
    rows = await query_db(
        """
        SELECT id, session_id, timestamp, source_ip, source_port, request_method,
               endpoint, headers_json, payload, attack_type, severity, flagged_token, metadata_json
        FROM events
        WHERE session_id = ?
        ORDER BY id ASC
        """,
        (session_id,)
    )
    events = [dict(r) for r in rows]

    return {
        "status": "ok",
        "session_id": session_id,
        "session": sess,
        "geoip": lookup_ip(sess.get("source_ip", "")),
        "events": events,
        "event_count": len(events)
    }


@app.get("/api/report/{session_id}", response_model=ReportResponse)
async def get_incident_report_api(session_id: str):
    """
    Structured JSON incident summary report for an attacker session.
    Calculates threat profile, targeted endpoints, MITRE tactics, and indicators of compromise.
    """
    sess = await get_session_info(session_id)
    events = await query_db(
        """
        SELECT id, timestamp, request_method, endpoint, attack_type, severity, flagged_token, payload, metadata_json
        FROM events
        WHERE session_id = ?
        ORDER BY id ASC
        """,
        (session_id,)
    )

    if not events:
        raise HTTPException(
            status_code=404,
            detail=f"Session '{session_id}' not found or has no events."
        )

    event_list = [dict(e) for e in events]
    targeted_endpoints = list(dict.fromkeys(e["endpoint"] for e in event_list))
    attack_types = list(dict.fromkeys(e["attack_type"] for e in event_list if e.get("attack_type")))
    honeytokens_triggered = list(dict.fromkeys(e["flagged_token"] for e in event_list if e.get("flagged_token")))

    report = {
        "report_id": f"REP-{session_id[:8].upper()}",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "session_id": session_id,
        "attacker": {
            "source_ip": sess.get("source_ip"),
            "user_agent": sess.get("user_agent"),
            "geoip": lookup_ip(sess.get("source_ip", "")),
            "threat_score": sess.get("decayed_score", 0.0),
            "max_severity": sess.get("max_severity", "low"),
            "total_requests": len(event_list),
            "first_seen": sess.get("first_seen"),
            "last_seen": sess.get("last_seen")
        },
        "executive_summary": {
            "criticality": sess.get("max_severity", "low").upper(),
            "target_count": len(targeted_endpoints),
            "targeted_endpoints": targeted_endpoints,
            "attack_tactics_observed": attack_types,
            "honeytokens_compromised": honeytokens_triggered
        },
        "timeline_events": [
            {
                "event_id": e["id"],
                "timestamp": e["timestamp"],
                "method": e["request_method"],
                "endpoint": e["endpoint"],
                "attack_type": e["attack_type"],
                "severity": e["severity"],
                "flagged_token": e["flagged_token"]
            }
            for e in event_list
        ],
        "narrative_analysis": None
    }

    return {"status": "ok", "report": report}


@app.post("/api/reset")
async def reset_platform_api():
    """
    Resets HoneyMap database and session state for a fresh test/demo run.
    Clears events, sessions, in-memory session cache, and re-initializes honeytokens.
    """
    await execute_write("DELETE FROM events")
    await execute_write("DELETE FROM sessions")
    clear_sessions()
    _ip_request_timestamps.clear()
    active_tokens = await init_honeytokens()
    await sio.emit("system_reset", {"status": "ok", "timestamp": time.time()})
    return {
        "status": "ok",
        "message": "HoneyMap platform reset to clean baseline (0 events, fresh honeytokens).",
        "active_aws_key": active_tokens.get("aws_access_key")
    }


@app.get("/api/metrics", response_model=MetricsResponse)
async def get_metrics_api():
    """
    Returns real aggregated metrics: critical count, blocked/tarpitted count,
    active incidents above score threshold, and total requests. Zero fabricated numbers.
    """
    rows = await query_db(
        "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity"
    )
    severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    total_events = 0
    for r in rows:
        sev = (r["severity"] or "low").lower()
        count = r["cnt"] or 0
        severity_breakdown[sev] = count
        total_events += count

    critical_threats = severity_breakdown.get("critical", 0)
    requests_blocked = severity_breakdown.get("critical", 0) + severity_breakdown.get("high", 0)

    all_sessions = await get_all_sessions(limit=500)
    active_incidents = sum(1 for s in all_sessions if s.get("decayed_score", s.get("score", 0)) >= 30.0)

    return {
        "status": "ok",
        "critical_threats": critical_threats,
        "requests_blocked": requests_blocked,
        "active_incidents": active_incidents,
        "total_requests": total_events,
        "severity_breakdown": severity_breakdown,
    }


@app.get("/api/analytics", response_model=AnalyticsResponse)
async def get_analytics_api(
    range: str = Query("day", pattern="^(day|week|month|year)$")
):
    """
    Aggregates real events into chronological time buckets grouped by severity.
    Zero fabricated stats.
    """
    if range == "day":
        time_modifier = "-24 hours"
        bucket_format = "%Y-%m-%d %H:00"
    elif range == "week":
        time_modifier = "-7 days"
        bucket_format = "%Y-%m-%d"
    elif range == "month":
        time_modifier = "-30 days"
        bucket_format = "%Y-%m-%d"
    else:  # year
        time_modifier = "-12 months"
        bucket_format = "%Y-%m"

    rows = await query_db(
        f"""
        SELECT strftime('{bucket_format}', timestamp) as bucket,
               severity,
               COUNT(*) as cnt
        FROM events
        WHERE timestamp >= datetime('now', '{time_modifier}')
        GROUP BY bucket, severity
        ORDER BY bucket ASC
        """
    )

    buckets_map: Dict[str, Dict[str, int]] = {}
    for r in rows:
        b = r["bucket"] or "recent"
        sev = (r["severity"] or "low").lower()
        cnt = r["cnt"] or 0
        if b not in buckets_map:
            buckets_map[b] = {"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}
        buckets_map[b][sev] = buckets_map[b].get(sev, 0) + cnt
        buckets_map[b]["total"] += cnt

    if not buckets_map:
        all_rows = await query_db(
            f"""
            SELECT strftime('{bucket_format}', timestamp) as bucket,
                   severity,
                   COUNT(*) as cnt
            FROM events
            GROUP BY bucket, severity
            ORDER BY bucket ASC
            """
        )
        for r in all_rows:
            b = r["bucket"] or "current"
            sev = (r["severity"] or "low").lower()
            cnt = r["cnt"] or 0
            if b not in buckets_map:
                buckets_map[b] = {"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}
            buckets_map[b][sev] = buckets_map[b].get(sev, 0) + cnt
            buckets_map[b]["total"] += cnt

    points = []
    for b, counts in buckets_map.items():
        normal_count = counts.get("low", 0)
        points.append(
            AnalyticsDataPoint(
                bucket=b,
                normal=normal_count,
                low=counts.get("low", 0),
                medium=counts.get("medium", 0),
                high=counts.get("high", 0),
                critical=counts.get("critical", 0),
                total=counts.get("total", 0),
            )
        )

    return {
        "status": "ok",
        "range": range,
        "points": points
    }


@app.get("/api/targets", response_model=TargetsResponse)
async def get_attack_targets_api():
    """
    Groups real events by decoy path to display target hit frequencies,
    highest severity seen, and real computed delta trend.
    """
    rows = await query_db(
        """
        SELECT endpoint,
               COUNT(*) as total_requests,
               SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) as incidents,
               MAX(timestamp) as last_seen
        FROM events
        GROUP BY endpoint
        ORDER BY total_requests DESC
        LIMIT 50
        """
    )

    targets = []
    for r in rows:
        ep = r["endpoint"]
        total_reqs = r["total_requests"]
        incidents = r["incidents"] or 0
        last_seen = r["last_seen"]

        sev_row = await query_db_one(
            """
            SELECT severity FROM events
            WHERE endpoint = ?
            ORDER BY CASE severity
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                ELSE 1
            END DESC
            LIMIT 1
            """,
            (ep,)
        )
        max_sev = sev_row["severity"] if sev_row else "low"

        recent_cnt_row = await query_db_one(
            "SELECT COUNT(*) as cnt FROM events WHERE endpoint = ? AND timestamp >= datetime('now', '-1 hour')",
            (ep,)
        )
        prev_cnt_row = await query_db_one(
            "SELECT COUNT(*) as cnt FROM events WHERE endpoint = ? AND timestamp < datetime('now', '-1 hour') AND timestamp >= datetime('now', '-2 hours')",
            (ep,)
        )
        recent_cnt = recent_cnt_row["cnt"] if recent_cnt_row else 0
        prev_cnt = prev_cnt_row["cnt"] if prev_cnt_row else 0

        if prev_cnt == 0 and recent_cnt > 0:
            trend_val = 100.0
        elif prev_cnt > 0:
            trend_val = round(((recent_cnt - prev_cnt) / prev_cnt) * 100.0, 1)
        else:
            trend_val = 0.0

        targets.append(
            TargetItem(
                target=ep,
                incidents=incidents,
                requests=total_reqs,
                severity=max_sev,
                trend=trend_val,
                last_seen=last_seen
            )
        )

    return {"status": "ok", "targets": targets, "count": len(targets)}


@app.get("/api/threat-intel", response_model=ThreatIntelResponse)
async def get_threat_intel_api():
    """
    Threat Intelligence endpoint: active honeytokens in memory/db,
    plus compromised token reuse event history.
    """
    active_tokens = get_active_honeytokens_cached()
    rows = await query_db(
        "SELECT token_id, token_type, token_value, description, created_at, trigger_count, last_triggered FROM honeytokens"
    )
    token_items = []
    for r in rows:
        val = r["token_value"]
        token_items.append(
            ThreatIntelItem(
                token_id=r["token_id"],
                token_type=r["token_type"],
                token_value=val,
                description=r["description"],
                created_at=r["created_at"],
                trigger_count=r["trigger_count"] or 0,
                last_triggered=r["last_triggered"],
                is_active=(val in active_tokens)
            )
        )

    compromised_rows = await query_db(
        """
        SELECT id, timestamp, source_ip, endpoint, request_method, attack_type, severity, flagged_token, payload
        FROM events
        WHERE flagged_token IS NOT NULL AND flagged_token != ''
        ORDER BY id DESC
        LIMIT 30
        """
    )
    compromised_events = [dict(c) for c in compromised_rows]

    return {
        "status": "ok",
        "active_tokens": {v: k["token_type"] for v, k in active_tokens.items()},
        "tokens": token_items,
        "compromised_events": compromised_events,
        "total_compromised_count": len(compromised_events)
    }


@app.get("/api/search", response_model=SearchResponse)
async def search_telemetry_api(q: str = Query(..., min_length=1, max_length=100)):
    """
    Search telemetry events and sessions by IP, endpoint, payload, or session ID.
    """
    pattern = f"%{q.strip()}%"
    event_rows = await query_db(
        """
        SELECT id, session_id, timestamp, source_ip, source_port, request_method,
               endpoint, headers_json, payload, attack_type, severity, flagged_token, metadata_json
        FROM events
        WHERE source_ip LIKE ? OR endpoint LIKE ? OR flagged_token LIKE ? OR attack_type LIKE ? OR session_id LIKE ?
        ORDER BY id DESC
        LIMIT 30
        """,
        (pattern, pattern, pattern, pattern, pattern)
    )
    events = []
    for r in event_rows:
        item = dict(r)
        geo = lookup_ip(item["source_ip"])
        item["geoip"] = geo
        item["ip"] = item["source_ip"]
        item["path"] = item["endpoint"]
        item["reason"] = item["attack_type"]
        item["lat"] = geo.get("latitude") if isinstance(geo, dict) else None
        item["lon"] = geo.get("longitude") if isinstance(geo, dict) else None
        events.append(item)

    sess_rows = await query_db(
        """
        SELECT session_id, source_ip, first_seen, last_seen, user_agent, request_count, max_severity, notes
        FROM sessions
        WHERE source_ip LIKE ? OR session_id LIKE ? OR user_agent LIKE ?
        ORDER BY last_seen DESC
        LIMIT 15
        """,
        (pattern, pattern, pattern)
    )
    sessions = [dict(s) for s in sess_rows]

    return {
        "status": "ok",
        "query": q,
        "events": events,
        "sessions": sessions,
        "total_matches": len(events) + len(sessions)
    }


@app.get("/api/geoip/{ip}", response_model=GeoIPResponse)
async def get_geoip_api(ip: str):
    """
    REST endpoint to lookup IP geolocation data with offline fallback.
    """
    data = lookup_ip(ip)
    return {"status": "ok", "geoip": data}


@app.get("/dashboard", response_model=DashboardResponse)
async def dashboard_view():
    """
    Legitimate dashboard route (not swallowed by catch-all decoy).
    """
    return {
        "status": "ok",
        "service": "HoneyMap Security Dashboard",
        "version": "1.0.0"
    }


# -------------------------------------------------------------
# CATCH-ALL DECOY PROBE ROUTE (REGISTERED LAST)
# -------------------------------------------------------------
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all_decoy(request: Request, path: str):
    """
    Catch-all decoy route registered LAST.
    Excludes /favicon.ico, /static/*, and OPTIONS preflights.
    All other unmatched hits are logged as decoy scans with safe capping.
    """
    clean_path = "/" + path.lstrip("/")

    # 1. Ignore OPTIONS preflight
    if request.method == "OPTIONS":
        return Response(content="", status_code=204)

    # 2. Ignore /favicon.ico and /static/*
    if clean_path == "/favicon.ico" or clean_path.startswith("/static/"):
        return Response(content="", status_code=404)

    # 3. Log all other rogue path probes with dynamic classification
    await log_decoy_hit(
        request,
        attack_type="endpoint_scan",
        metadata={"catch_all_path": clean_path}
    )

    return JSONResponse(
        status_code=404,
        content={
            "status": "error",
            "message": "Resource not found on this server."
        }
    )


# -------------------------------------------------------------
# SOCKET.IO ASGI WRAPPER
# -------------------------------------------------------------
socket_app = socketio.ASGIApp(sio, other_asgi_app=app)

if __name__ == "__main__":
    host = os.environ.get("HONEYMAP_HOST", "0.0.0.0")
    port = int(os.environ.get("HONEYMAP_PORT", os.environ.get("PORT", "5000")))
    uvicorn.run(
        socket_app,
        host=host,
        port=port,
        access_log=True
    )

