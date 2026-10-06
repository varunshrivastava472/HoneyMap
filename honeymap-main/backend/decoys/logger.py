"""
Decoy Hit Logger and Real-Time Telemetry Dispatcher.
Enforces rule-based classification, async non-blocking tarpit delays,
aiosqlite persistence, and ASGI Socket.IO event emission.
"""
import json
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import Request
from database import execute_write, query_db_one
from decoys.request_utils import sanitize_and_cap_request_data
from detection.session_tracker import get_or_create_session, get_session_info, tarpit_delay
from detection.classifier import classify_event
from detection.geoip import lookup_ip
from socket_instance import sio


async def emit_new_event(event_dict: Dict[str, Any]) -> None:
    """
    Safely emits 'new_event' over python-socketio ASGI to all connected dashboard clients.
    Carries a stable unique 'id' field matching the SQLite primary key.
    Catches and logs any unexpected dispatch error.
    """
    try:
        await sio.emit("new_event", event_dict)
    except Exception as e:
        print(f"[-] Error emitting new_event: {e}", flush=True)


async def log_decoy_hit(
    req: Request,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
    flagged_token: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    apply_tarpit: bool = True
) -> int:
    """
    Logs an intrusion/decoy hit into SQLite events asynchronously.
    Enforces rule-based classification:
      1. CRITICAL: exact substring match on live honeytoken
      2. HIGH: SQLi/XSS signatures
      3. MEDIUM: sensitive decoy path
      4. LOW: login page / general probe
    CRITICAL FIX: Applies defensive tarpit delay: min(0.2 * repeat_count, 3.0) via await asyncio.sleep()
    to ensure non-blocking concurrency across all clients.
    Emits 'new_event' over WebSocket containing a stable unique integer 'id'.
    """
    data = await sanitize_and_cap_request_data(req)
    session_id = await get_or_create_session(data["ip"], data["user_agent"])

    # Retrieve current session state to calculate tarpit delay
    sess_info = await get_session_info(session_id)
    delay_sec = tarpit_delay(sess_info)

    # NON-BLOCKING ASYNC TARPIT DELAY
    if apply_tarpit and delay_sec > 0:
        await asyncio.sleep(delay_sec)

    # Run rule-based classification
    calc_severity, reason, detected_token = classify_event(
        endpoint=data["path"],
        method=data["method"],
        headers_str=data["headers_json"],
        payload=data["payload"]
    )

    final_severity = calc_severity
    final_attack_type = reason if attack_type is None or attack_type == "decoy_probe" else attack_type
    final_token = detected_token or flagged_token

    # Assemble metadata dictionary with classifier reason
    meta_dict = metadata.copy() if metadata else {}
    meta_dict["classifier_reason"] = reason
    if final_token:
        meta_dict["flagged_honeytoken"] = final_token

    metadata_json = json.dumps(meta_dict, ensure_ascii=False)[:2000]
    timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    remote_port = req.client.port if req.client else 0

    query = """
    INSERT INTO events (
        session_id, source_ip, source_port, request_method, endpoint,
        headers_json, payload, attack_type, severity, flagged_token, metadata_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    params = (
        session_id,
        data["ip"],
        remote_port,
        data["method"],
        data["path"],
        data["headers_json"],
        data["payload"],
        final_attack_type,
        final_severity,
        final_token,
        metadata_json,
        timestamp_str
    )
    event_id = await execute_write(query, params)

    # Elevate session max_severity if appropriate
    severity_ranks = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    current_rank = severity_ranks.get(final_severity, 1)
    if current_rank > 1:
        try:
            await execute_write(
                """
                UPDATE sessions 
                SET max_severity = ?
                WHERE session_id = ? AND (
                    max_severity IS NULL 
                    OR max_severity = 'low' 
                    OR (max_severity = 'medium' AND ? IN ('high', 'critical'))
                    OR (max_severity = 'high' AND ? = 'critical')
                )
                """,
                (final_severity, session_id, final_severity, final_severity)
            )
        except Exception:
            pass

    # Build WebSocket emission payload with stable unique 'id'
    geo_info = lookup_ip(data["ip"])
    event_dict = {
        "id": event_id,
        "session_id": session_id,
        "timestamp": timestamp_str,
        "source_ip": data["ip"],
        "source_port": remote_port,
        "request_method": data["method"],
        "endpoint": data["path"],
        "headers_json": data["headers_json"],
        "payload": data["payload"],
        "attack_type": final_attack_type,
        "severity": final_severity,
        "flagged_token": final_token,
        "metadata_json": metadata_json,
        "geoip": geo_info,
        # Normalized alias keys for Stage 8 ThreatMap contract
        "ip": data["ip"],
        "path": data["path"],
        "reason": final_attack_type,
        "lat": geo_info.get("latitude") if isinstance(geo_info, dict) else None,
        "lon": geo_info.get("longitude") if isinstance(geo_info, dict) else None
    }

    # Emit to all connected Socket.IO clients asynchronously
    await emit_new_event(event_dict)

    return event_id
