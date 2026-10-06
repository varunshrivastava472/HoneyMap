"""
Session Tracker, Correlation, Tarpit Defensive Delay, and Threat Scoring.
Features:
- Fingerprint: hashlib.sha256(ip + user_agent).hexdigest()
- In-memory OrderedDict capped at MAX_TRACKED_SESSIONS (500) with strict LRU eviction.
- Identical score_decay(session) for both WebSocket push and REST /api/sessions read paths:
    score *= 0.5 ** (minutes_since_last_seen / 5)
- Defensive tarpit delay:
    tarpit_delay(session): min(0.2 * repeat_count, 3.0)
- Asynchronous correlation with aiosqlite.
"""
import hashlib
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple, List
from database import query_db, query_db_one, execute_write

MAX_TRACKED_SESSIONS = 500

# In-memory OrderedDict for active sessions: fingerprint -> session dict
_ACTIVE_SESSIONS: OrderedDict[str, Dict[str, Any]] = OrderedDict()

# Metrics counter to verify LRU eviction under sustained load
_EVICTION_COUNT = 0


def calculate_fingerprint(source_ip: str, user_agent: str) -> str:
    """
    Computes deterministic SHA-256 fingerprint from source IP and User-Agent.
    """
    raw = f"{source_ip.strip()}|{user_agent.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def calculate_base_score(request_count: int, max_severity: str) -> float:
    """
    Calculates raw threat score based on request volume and attack severity.
    """
    severity_multipliers = {
        "low": 10.0,
        "medium": 35.0,
        "high": 75.0,
        "critical": 150.0
    }
    multiplier = severity_multipliers.get(str(max_severity).lower(), 10.0)
    # Base formula combining request frequency and severity
    return float(request_count * multiplier)


def score_decay(session: Dict[str, Any], current_time: Optional[float] = None) -> float:
    """
    Identical half-life score decay function used on both:
      1. WebSocket live-feed push path
      2. /api/sessions REST read path
    Formula:
      decayed_score = score * (0.5 ** (minutes_since_last_seen / 5))
    """
    raw_score = float(session.get("raw_score", 0.0))
    if raw_score <= 0.0:
        req_count = int(session.get("request_count", 1))
        max_sev = str(session.get("max_severity", "low"))
        raw_score = calculate_base_score(req_count, max_sev)

    # Determine minutes elapsed since last seen
    now_ts = current_time if current_time is not None else time.time()
    last_seen_ts = session.get("last_seen_epoch")

    if last_seen_ts is None:
        last_seen_str = session.get("last_seen")
        if last_seen_str:
            try:
                dt = datetime.strptime(str(last_seen_str).split(".")[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                last_seen_ts = dt.timestamp()
            except Exception:
                last_seen_ts = now_ts
        else:
            last_seen_ts = now_ts

    elapsed_minutes = max(0.0, (now_ts - last_seen_ts) / 60.0)
    # Exponential decay with 5-minute half-life: score *= 0.5 ** (minutes_since_last_seen / 5)
    decay_factor = 0.5 ** (elapsed_minutes / 5.0)
    return round(raw_score * decay_factor, 2)


def tarpit_delay(session_or_repeat_count: Any) -> float:
    """
    Defensive tarpit delay formula:
      delay = min(0.2 * repeat_count, 3.0)
    Returns delay in seconds capped strictly at 3.0s.
    """
    if isinstance(session_or_repeat_count, dict):
        repeat_count = int(session_or_repeat_count.get("request_count", 1))
    elif isinstance(session_or_repeat_count, (int, float)):
        repeat_count = int(session_or_repeat_count)
    else:
        repeat_count = 1

    delay = min(0.2 * max(1, repeat_count), 3.0)
    return round(delay, 3)


def get_eviction_count() -> int:
    """Returns number of sessions evicted via LRU."""
    return _EVICTION_COUNT


async def get_or_create_session(source_ip: str, user_agent: str = "") -> str:
    """
    Identifies or creates an active session correlated by IP and User-Agent fingerprint.
    Manages in-memory LRU cache capped at MAX_TRACKED_SESSIONS (500) and persists
    atomic correlation to SQLite asynchronously via aiosqlite.
    """
    global _EVICTION_COUNT
    fingerprint = calculate_fingerprint(source_ip, user_agent)
    now_epoch = time.time()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # 1. Update in-memory LRU cache
    if fingerprint in _ACTIVE_SESSIONS:
        sess = _ACTIVE_SESSIONS[fingerprint]
        sess["request_count"] += 1
        sess["last_seen_epoch"] = now_epoch
        sess["last_seen"] = now_str
        _ACTIVE_SESSIONS.move_to_end(fingerprint)
        session_id = sess["session_id"]
    else:
        # Check eviction cap
        if len(_ACTIVE_SESSIONS) >= MAX_TRACKED_SESSIONS:
            _ACTIVE_SESSIONS.popitem(last=False)  # Evict oldest LRU session
            _EVICTION_COUNT += 1

        session_id = fingerprint  # Deterministic session identifier from fingerprint
        sess = {
            "session_id": session_id,
            "source_ip": source_ip,
            "user_agent": user_agent[:500] if user_agent else "",
            "first_seen_epoch": now_epoch,
            "last_seen_epoch": now_epoch,
            "last_seen": now_str,
            "request_count": 1,
            "max_severity": "low",
            "raw_score": 10.0
        }
        _ACTIVE_SESSIONS[fingerprint] = sess

    # 2. Synchronize to SQLite via aiosqlite
    row = await query_db_one(
        "SELECT session_id, request_count, max_severity FROM sessions WHERE session_id = ?",
        (session_id,)
    )
    if row:
        new_count = row["request_count"] + 1
        await execute_write(
            "UPDATE sessions SET last_seen = CURRENT_TIMESTAMP, request_count = ? WHERE session_id = ?",
            (new_count, session_id)
        )
        if fingerprint in _ACTIVE_SESSIONS:
            _ACTIVE_SESSIONS[fingerprint]["request_count"] = new_count
            _ACTIVE_SESSIONS[fingerprint]["max_severity"] = row["max_severity"] or "low"
    else:
        await execute_write(
            """
            INSERT INTO sessions (session_id, source_ip, user_agent, request_count, max_severity)
            VALUES (?, ?, ?, 1, 'low')
            """,
            (session_id, source_ip, user_agent[:500] if user_agent else "")
        )

    return session_id


async def get_session_info(session_id: str) -> Dict[str, Any]:
    """
    Retrieves full session state with decayed score and tarpit delay.
    """
    if session_id in _ACTIVE_SESSIONS:
        sess = dict(_ACTIVE_SESSIONS[session_id])
        sess["decayed_score"] = score_decay(sess)
        sess["tarpit_delay"] = tarpit_delay(sess)
        return sess

    # Fallback to DB
    row = await query_db_one("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    if row:
        sess = dict(row)
        sess["decayed_score"] = score_decay(sess)
        sess["tarpit_delay"] = tarpit_delay(sess)
        return sess

    return {
        "session_id": session_id,
        "request_count": 1,
        "max_severity": "low",
        "decayed_score": 10.0,
        "tarpit_delay": 0.2
    }


async def get_all_sessions(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Returns ranked sessions with identical score_decay applied for leaderboard reads.
    Candidate sessions are queried by recency (last_seen DESC) and merged with the
    in-memory cache to guarantee real-time score accumulation and decay reordering.
    """
    candidate_limit = max(limit * 4, 300)
    rows = await query_db(
        "SELECT session_id, source_ip, first_seen, last_seen, user_agent, request_count, max_severity FROM sessions ORDER BY last_seen DESC, request_count DESC LIMIT ?",
        (candidate_limit,)
    )
    result_map = {}
    now_ts = time.time()
    for r in rows:
        item = dict(r)
        if item["session_id"] in _ACTIVE_SESSIONS:
            item["last_seen_epoch"] = _ACTIVE_SESSIONS[item["session_id"]]["last_seen_epoch"]
        item["score"] = score_decay(item, current_time=now_ts)
        item["tarpit_delay"] = tarpit_delay(item)
        result_map[item["session_id"]] = item

    for sess_id, sess_data in _ACTIVE_SESSIONS.items():
        if sess_id not in result_map:
            item = dict(sess_data)
            item["score"] = score_decay(item, current_time=now_ts)
            item["tarpit_delay"] = tarpit_delay(item)
            result_map[sess_id] = item

    result = list(result_map.values())
    # Sort descending by decayed score
    result.sort(key=lambda x: x["score"], reverse=True)
    return result


def clear_sessions() -> None:
    """Clears in-memory active session cache for a fresh baseline."""
    _ACTIVE_SESSIONS.clear()

