"""
Rule-based Intrusion and Attack Classifier
Priority order:
1. CRITICAL — exact substring match against a live honeytoken value -> reason "honeytoken reuse detected"
2. HIGH — SQLi/XSS signature match -> reason names the pattern
3. MEDIUM — hit on a sensitive decoy path
4. LOW — login-page hit, no injection signature (or general probe)

Exact match only for honeytokens — fuzzy match creates false CRITICALs.
"""
import re
from typing import Tuple, Optional, Dict, Any
from detection.honeytokens import check_exact_honeytoken_match

# Compiled signatures for SQL injection patterns
SQLI_PATTERNS = [
    (re.compile(r"(\b(UNION(\s+ALL)?)\s+SELECT\b)", re.IGNORECASE), "SQLi: UNION SELECT pattern"),
    (re.compile(r"(\bSELECT\b.+?\bFROM\b)", re.IGNORECASE), "SQLi: SELECT FROM pattern"),
    (re.compile(r"(\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)", re.IGNORECASE), "SQLi: Boolean tautology (OR 1=1)"),
    (re.compile(r"(\bAND\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?)", re.IGNORECASE), "SQLi: Boolean conjunction"),
    (re.compile(r"(--|/\*.*?\*/|;\s*DROP\s+TABLE|;\s*DELETE\s+FROM)", re.IGNORECASE), "SQLi: Query comment or destructive statement"),
    (re.compile(r"(\bSLEEP\s*\(\s*\d+\s*\)|\bBENCHMARK\s*\()", re.IGNORECASE), "SQLi: Time-based blind injection"),
    (re.compile(r"(\bWAITFOR\s+DELAY\b)", re.IGNORECASE), "SQLi: MSSQL WAITFOR DELAY"),
    (re.compile(r"('(''|[^'])*'\s*=\s*'(''|[^'])*')", re.IGNORECASE), "SQLi: String tautology ('a'='a')"),
]

# Compiled signatures for Cross-Site Scripting (XSS) patterns
XSS_PATTERNS = [
    (re.compile(r"(<script\b[^>]*>.*?</script>)", re.IGNORECASE), "XSS: Inline script tags"),
    (re.compile(r"(<script\b)", re.IGNORECASE), "XSS: Script tag invocation"),
    (re.compile(r"(javascript\s*:\s*[^\s]+)", re.IGNORECASE), "XSS: Javascript URI scheme"),
    (re.compile(r"(\bon(load|error|click|mouseover|focus|submit)\s*=)", re.IGNORECASE), "XSS: Inline DOM event handler"),
    (re.compile(r"(<img\b[^>]+src\s*=\s*['\"]?[^'\">]*\bonerror\b)", re.IGNORECASE), "XSS: Image onerror vector"),
    (re.compile(r"(<svg\b[^>]*\bonload\b)", re.IGNORECASE), "XSS: SVG onload vector"),
    (re.compile(r"(document\.(cookie|location|write))", re.IGNORECASE), "XSS: DOM document manipulation"),
]

# Sensitive decoy paths for MEDIUM severity classification
SENSITIVE_DECOY_PATHS = {
    "/.env",
    "/backup.sql",
    "/config.php",
    "/.git/config",
    "/.git",
    "/.aws/credentials",
    "/id_rsa",
    "/wp-config.php",
    "/server-status"
}

# Login decoy endpoints for LOW severity classification
LOGIN_DECOY_PATHS = {
    "/login",
    "/admin",
    "/wp-admin"
}


def classify_event(
    endpoint: str,
    method: str,
    headers_str: str,
    payload: str
) -> Tuple[str, str, Optional[str]]:
    """
    Classifies an incoming HTTP hit into severity and descriptive reason.
    Returns:
      (severity, reason, flagged_token_value_or_none)

    Rule evaluation order:
      1. CRITICAL: Exact substring match against live honeytokens (headers, payload, endpoint).
      2. HIGH: SQLi or XSS signature match in payload, headers, or query parameters.
      3. MEDIUM: Hit on a sensitive decoy path (/.env, /backup.sql, /config.php, etc.).
      4. LOW: Login page hit with no injection signature (or standard recon probe).
    """
    clean_endpoint = "/" + endpoint.lstrip("/")

    # Combine text targets for injection and token analysis
    combined_target = f"{clean_endpoint} {headers_str} {payload}"

    # 1. CRITICAL: Exact substring match against live honeytoken value
    # CRITICAL RULE: Exact match only — no regex/fuzzy match
    matched_token = check_exact_honeytoken_match(payload)
    if not matched_token:
        matched_token = check_exact_honeytoken_match(headers_str)
    if not matched_token:
        matched_token = check_exact_honeytoken_match(clean_endpoint)

    if matched_token:
        token_val, meta = matched_token
        return "critical", "honeytoken reuse detected", token_val

    # 2. HIGH: SQLi / XSS signature match
    for regex, pattern_name in SQLI_PATTERNS:
        if regex.search(combined_target):
            return "high", f"SQL Injection detected ({pattern_name})", None

    for regex, pattern_name in XSS_PATTERNS:
        if regex.search(combined_target):
            return "high", f"Cross-Site Scripting detected ({pattern_name})", None

    # 3. MEDIUM: Hit on sensitive decoy path
    # Check exact match or path containment
    if clean_endpoint in SENSITIVE_DECOY_PATHS or any(clean_endpoint.startswith(p) for p in SENSITIVE_DECOY_PATHS):
        return "medium", f"Sensitive decoy path accessed ({clean_endpoint})", None

    # 4. LOW: Login page hit (or general unknown probe)
    if clean_endpoint in LOGIN_DECOY_PATHS or any(clean_endpoint.startswith(p) for p in LOGIN_DECOY_PATHS):
        if method == "POST":
            return "low", f"Decoy login authentication attempt on {clean_endpoint}", None
        return "low", f"Decoy login page accessed on {clean_endpoint}", None

    # Fallback for generic catch-all probes
    return "low", f"Unrecognized decoy endpoint probe ({clean_endpoint})", None
