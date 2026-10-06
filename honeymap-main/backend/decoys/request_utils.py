import json
import ipaddress
import urllib.parse
from typing import Dict, Any, Optional
from fastapi import Request


def safe_client_ip(req: Request) -> str:
    """
    Safely validates and extracts client IP address from FastAPI Request.
    If X-Forwarded-For is present, parses the leftmost IP and validates
    it using Python's ipaddress module. If invalid or malformed,
    falls back safely to req.client.host.
    """
    forwarded = req.headers.get("x-forwarded-for") or req.headers.get("X-Forwarded-For")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        try:
            ip_obj = ipaddress.ip_address(candidate)
            return str(ip_obj)
        except ValueError:
            pass  # Malformed header value; fallback to client host

    if req.client and req.client.host:
        try:
            ip_obj = ipaddress.ip_address(req.client.host)
            return str(ip_obj)
        except ValueError:
            pass

    return "127.0.0.1"


async def sanitize_and_cap_request_data(req: Request) -> Dict[str, Any]:
    """
    Extracts, validates, and caps request metadata to safe bounds:
    - ip: validated safe_client_ip
    - user_agent: capped at 500 chars
    - headers_json: json string capped at 2000 chars
    - payload: capped at 2000 chars
    """
    ip = safe_client_ip(req)

    # User-Agent capped to 500 chars
    raw_ua = req.headers.get("user-agent", "") or req.headers.get("User-Agent", "")
    user_agent = raw_ua[:500] if raw_ua else ""

    # Headers dict serialized to JSON and capped at 2000 chars
    headers_dict = dict(req.headers)
    try:
        raw_headers_json = json.dumps(headers_dict, ensure_ascii=False)
    except Exception:
        raw_headers_json = "{}"
    headers_json = raw_headers_json[:2000]

    # Payload extraction: read raw body asynchronously
    payload = ""
    try:
        body_bytes = await req.body()
        if body_bytes:
            content_type = req.headers.get("content-type", "").lower()
            if "application/json" in content_type:
                try:
                    parsed_json = json.loads(body_bytes.decode("utf-8", errors="replace"))
                    payload = json.dumps(parsed_json, ensure_ascii=False)[:2000]
                except Exception:
                    payload = body_bytes.decode("utf-8", errors="replace")[:2000]
            elif "application/x-www-form-urlencoded" in content_type:
                raw_text = body_bytes.decode("utf-8", errors="replace")
                try:
                    parsed_form = urllib.parse.parse_qs(raw_text)
                    flat_form = {k: v[0] if len(v) == 1 else v for k, v in parsed_form.items()}
                    payload = json.dumps(flat_form, ensure_ascii=False)[:2000]
                except Exception:
                    payload = raw_text[:2000]
            else:
                payload = body_bytes.decode("utf-8", errors="replace")[:2000]
    except Exception:
        payload = ""

    # If payload is empty but query string exists (e.g. GET /search?q=...), include query string
    if not payload and req.url.query:
        try:
            payload = urllib.parse.unquote_plus(req.url.query)[:2000]
        except Exception:
            payload = req.url.query[:2000]

    return {
        "ip": ip,
        "user_agent": user_agent,
        "headers_json": headers_json,
        "payload": payload,
        "path": req.url.path,
        "method": req.method
    }
