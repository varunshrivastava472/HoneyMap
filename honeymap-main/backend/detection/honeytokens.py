"""
Honeytokens Detection and Registry
Generates and manages fresh bait credentials per server boot:
- AWS-style access key / secret (e.g. AKIA...)
- Realistic database password / connection string

Stores active tokens in the `honeytokens` table via aiosqlite.
Provides exact substring matching to avoid false positives.
"""
import secrets
import string
import uuid
from typing import Optional, Dict, Any, List, Tuple
from database import query_db, query_db_one, execute_write, execute_write_many

# In-memory fast cache of active honeytoken values -> token_id, type, desc
_ACTIVE_HONEYTOKENS: Dict[str, Dict[str, Any]] = {}


def generate_aws_honeytoken() -> Tuple[str, str]:
    """
    Generates a realistic AWS-style Access Key ID (AKIA + 16 chars)
    and Secret Key (40 random base64-safe alphanumeric chars).
    """
    chars = string.ascii_uppercase + string.digits
    access_key = "AKIA" + "".join(secrets.choice(chars) for _ in range(16))
    secret_chars = string.ascii_letters + string.digits + "+/="
    secret_key = "".join(secrets.choice(secret_chars) for _ in range(40))
    return access_key, secret_key


def generate_db_password_honeytoken() -> str:
    """
    Generates a realistic complex database password.
    """
    prefix = "P@ssw0rd_"
    suffix = secrets.token_hex(6) + "!"
    return f"{prefix}{suffix}"


async def init_honeytokens() -> Dict[str, str]:
    """
    Generates a fresh AWS key pair and DB password per server start,
    persists them in the `honeytokens` SQLite table via aiosqlite,
    and returns a mapping for dynamic decoy template injection.
    """
    global _ACTIVE_HONEYTOKENS
    aws_key, aws_secret = generate_aws_honeytoken()
    db_pass = generate_db_password_honeytoken()

    # Clear stale honeytokens from previous server boots
    await execute_write("DELETE FROM honeytokens")

    # Insert fresh honeytokens for this boot
    tokens_to_insert = [
        (
            str(uuid.uuid4()),
            "aws_access_key",
            aws_key,
            "Dynamic bait AWS Access Key generated on server boot"
        ),
        (
            str(uuid.uuid4()),
            "aws_secret_key",
            aws_secret,
            "Dynamic bait AWS Secret Access Key generated on server boot"
        ),
        (
            str(uuid.uuid4()),
            "database_password",
            db_pass,
            "Dynamic bait database password generated on server boot"
        )
    ]

    await execute_write_many(
        """
        INSERT OR REPLACE INTO honeytokens 
        (token_id, token_type, token_value, description, created_at, trigger_count)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 0)
        """,
        tokens_to_insert
    )

    # Load all live honeytokens into memory for O(1) exact substring checks
    rows = await query_db("SELECT token_id, token_type, token_value, description FROM honeytokens")
    _ACTIVE_HONEYTOKENS = {
        row["token_value"]: {
            "token_id": row["token_id"],
            "token_type": row["token_type"],
            "description": row["description"]
        }
        for row in rows
    }

    return {
        "aws_access_key": aws_key,
        "aws_secret_key": aws_secret,
        "database_password": db_pass
    }


async def get_active_honeytokens(force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
    """
    Returns the dictionary of all live honeytokens in the system.
    """
    global _ACTIVE_HONEYTOKENS
    if force_refresh or not _ACTIVE_HONEYTOKENS:
        # Fallback reload from DB
        rows = await query_db("SELECT token_id, token_type, token_value, description FROM honeytokens")
        if not rows:
            return await init_honeytokens()
        _ACTIVE_HONEYTOKENS = {
            row["token_value"]: {
                "token_id": row["token_id"],
                "token_type": row["token_type"],
                "description": row["description"]
            }
            for row in rows
        }
    return _ACTIVE_HONEYTOKENS


def get_active_honeytokens_cached() -> Dict[str, Dict[str, Any]]:
    """
    Synchronous accessor to in-memory honeytoken cache.
    """
    return _ACTIVE_HONEYTOKENS


def check_exact_honeytoken_match(payload: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Checks if any active honeytoken value appears as an EXACT substring match
    inside the payload.
    CRITICAL RULE: Exact match only — no regex or fuzzy match to prevent false CRITICALs.
    Returns (matched_token_value, token_metadata) or None.
    """
    if not payload:
        return None

    active = _ACTIVE_HONEYTOKENS
    for token_value, meta in active.items():
        if token_value in payload:
            return token_value, meta

    return None
