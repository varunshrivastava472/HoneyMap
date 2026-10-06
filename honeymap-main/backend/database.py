"""
Asynchronous SQLite Database Access Layer via aiosqlite.
Configures WAL journal mode and 30-second busy timeout for concurrent throughput.
"""
import os
import aiosqlite
from typing import Any, Dict, List, Optional, Tuple

DATABASE_PATH = os.environ.get(
    "HONEYMAP_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeymap.db")
)


async def get_db_connection() -> aiosqlite.Connection:
    """
    Returns an aiosqlite connection configured with WAL journal mode,
    synchronous=NORMAL, and 30s busy timeout.
    """
    conn = await aiosqlite.connect(DATABASE_PATH, timeout=30.0)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA synchronous = NORMAL;")
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA busy_timeout = 30000;")
    return conn


async def init_db() -> None:
    """
    Initializes the SQLite schema using aiosqlite.
    Creates tables: events, sessions, geoip_cache, honeytokens.
    """
    schema = """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT NOT NULL,
        source_port INTEGER,
        request_method TEXT,
        endpoint TEXT NOT NULL,
        headers_json TEXT,
        payload TEXT,
        attack_type TEXT,
        severity TEXT DEFAULT 'low',
        flagged_token TEXT,
        metadata_json TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
    CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);

    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        source_ip TEXT NOT NULL,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        user_agent TEXT,
        request_count INTEGER DEFAULT 1,
        max_severity TEXT DEFAULT 'low',
        notes TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);

    CREATE TABLE IF NOT EXISTS geoip_cache (
        ip TEXT PRIMARY KEY,
        country TEXT,
        country_code TEXT,
        city TEXT,
        latitude REAL,
        longitude REAL,
        asn TEXT,
        org TEXT,
        cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS honeytokens (
        token_id TEXT PRIMARY KEY,
        token_type TEXT NOT NULL,
        token_value TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        trigger_count INTEGER DEFAULT 0,
        last_triggered DATETIME
    );

    CREATE INDEX IF NOT EXISTS idx_honeytokens_val ON honeytokens(token_value);
    """
    async with aiosqlite.connect(DATABASE_PATH, timeout=30.0) as conn:
        await conn.execute("PRAGMA journal_mode = WAL;")
        await conn.execute("PRAGMA synchronous = NORMAL;")
        await conn.execute("PRAGMA foreign_keys = ON;")
        await conn.execute("PRAGMA busy_timeout = 30000;")
        await conn.executescript(schema)
        await conn.commit()


async def execute_write(query: str, params: Tuple[Any, ...] = ()) -> int:
    """
    Executes an INSERT/UPDATE/DELETE query asynchronously.
    Returns the lastrowid or rowcount.
    """
    async with aiosqlite.connect(DATABASE_PATH, timeout=30.0) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode = WAL;")
        await conn.execute("PRAGMA synchronous = NORMAL;")
        await conn.execute("PRAGMA busy_timeout = 30000;")
        cur = await conn.cursor()
        await cur.execute(query, params)
        await conn.commit()
        return cur.lastrowid if cur.lastrowid else cur.rowcount


async def execute_write_many(query: str, params_list: List[Tuple[Any, ...]]) -> int:
    """
    Executes executemany asynchronously.
    """
    async with aiosqlite.connect(DATABASE_PATH, timeout=30.0) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode = WAL;")
        await conn.execute("PRAGMA synchronous = NORMAL;")
        await conn.execute("PRAGMA busy_timeout = 30000;")
        cur = await conn.cursor()
        await cur.executemany(query, params_list)
        await conn.commit()
        return cur.rowcount


async def query_db(query: str, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
    """
    Executes a SELECT query asynchronously returning rows as dictionary items.
    """
    async with aiosqlite.connect(DATABASE_PATH, timeout=30.0) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode = WAL;")
        await conn.execute("PRAGMA synchronous = NORMAL;")
        await conn.execute("PRAGMA busy_timeout = 30000;")
        cur = await conn.cursor()
        await cur.execute(query, params)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def query_db_one(query: str, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
    """
    Executes a SELECT query asynchronously returning the first matching row dict, or None.
    """
    async with aiosqlite.connect(DATABASE_PATH, timeout=30.0) as conn:
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode = WAL;")
        await conn.execute("PRAGMA synchronous = NORMAL;")
        await conn.execute("PRAGMA busy_timeout = 30000;")
        cur = await conn.cursor()
        await cur.execute(query, params)
        row = await cur.fetchone()
        return dict(row) if row else None
