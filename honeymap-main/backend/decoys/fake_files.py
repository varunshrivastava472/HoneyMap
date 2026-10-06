"""
Decoy Fake Files Handlers via FastAPI APIRouter.
Rotates live paths from a pool of 6 sensitive decoy paths every ~90s.
Pool: /.env, /backup.sql, /config.php, /.git/config, /.aws/credentials, /wp-config.php
Serves plausible bait file contents dynamically injected with live honeytokens.
"""
import time
from typing import Dict, Tuple, List, Optional
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from decoys.logger import log_decoy_hit
from detection.honeytokens import get_active_honeytokens

fake_files_router = APIRouter()

# Pool of 6 sensitive decoy files for periodic rotation
POOL_OF_6: List[str] = [
    "/.env",
    "/backup.sql",
    "/config.php",
    "/.git/config",
    "/.aws/credentials",
    "/wp-config.php"
]

# Rotation interval (~90s)
ROTATION_INTERVAL_SEC = 90.0


def get_rotation_cycle(ts: Optional[float] = None) -> int:
    """Returns integer rotation cycle based on ~90s time intervals."""
    now = ts if ts is not None else time.time()
    return int(now // ROTATION_INTERVAL_SEC)


def get_live_paths(ts: Optional[float] = None) -> List[str]:
    """
    Returns the currently active live paths rotated from the pool of 6 every ~90s.
    Rotates an active window of paths across the pool so targets shift dynamically.
    """
    cycle = get_rotation_cycle(ts)
    start_idx = cycle % len(POOL_OF_6)
    # Active rotating window of 4 paths from the pool of 6
    return [POOL_OF_6[(start_idx + i) % len(POOL_OF_6)] for i in range(4)]


def is_path_live(path: str, ts: Optional[float] = None) -> bool:
    """Checks if a given path is currently in the active live rotation set."""
    return path in get_live_paths(ts)


async def render_fake_file(path: str) -> Tuple[str, str]:
    """
    Renders bait content dynamically injecting the current session's live honeytokens
    (AWS key, secret, and database password).
    """
    tokens = await get_active_honeytokens(force_refresh=True)
    aws_key = "AKIAIOSFODNN7HONEYTRAP"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    db_pass = "P@ssw0rd_9824_trapped"

    for val, meta in tokens.items():
        if meta.get("token_type") == "aws_access_key":
            aws_key = val
        elif meta.get("token_type") == "aws_secret_key":
            aws_secret = val
        elif meta.get("token_type") == "database_password":
            db_pass = val

    if path == "/.env":
        content = (
            "# Production Environment Configuration\n"
            "APP_NAME=HoneyMap-Core\n"
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            "APP_KEY=base64:3fU7W2s8hUe3X9jN1kLk9+wJzX+Y5h6P/t4Q9v2Z=\n"
            f"DATABASE_URL=postgresql://honeydb_admin:{db_pass}@cluster-primary.internal:5432/core_prod\n"
            "REDIS_URL=redis://:cache_auth_token_7761@cache-cluster.internal:6379/0\n"
            f"AWS_ACCESS_KEY_ID={aws_key}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_secret}\n"
            "AWS_DEFAULT_REGION=us-east-1\n"
            "STRIPE_API_KEY=YOUR_FAKE_STRIPE_API_KEY_HERE\n"
            "ADMIN_JWT_SECRET=super-secret-cluster-honey-token-do-not-share\n"
        )
        return content, "text/plain"

    elif path == "/backup.sql":
        content = (
            "-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)\n"
            "-- Host: localhost    Database: production_core\n"
            "-- Server version: 8.0.32-0ubuntu0.22.04.2\n"
            "\n"
            "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
            "/*!40101 SET NAMES utf8mb4 */;\n"
            "\n"
            "-- Database Master Password Reference: " + db_pass + "\n"
            "DROP TABLE IF EXISTS `admin_users`;\n"
            "CREATE TABLE `admin_users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `username` varchar(50) NOT NULL,\n"
            "  `email` varchar(100) NOT NULL,\n"
            "  `password_hash` varchar(255) NOT NULL,\n"
            "  `role` varchar(20) DEFAULT 'admin',\n"
            "  `is_active` tinyint(1) DEFAULT '1',\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4;\n"
            "\n"
            "INSERT INTO `admin_users` VALUES "
            f"(1,'sysadmin','sysadmin@honeymap.internal','{db_pass}','superadmin',1),\n"
            "(2,'dev_lead','dan.miller@honeymap.internal','$2y$10$k1A2b3C4d5E6f7G8h9I0j1K2L3M4N5O6P7Q8R9S0T1U2V3W','developer',1);\n"
        )
        return content, "application/sql"

    elif path == "/config.php":
        content = (
            "<?php\n"
            "/**\n"
            " * Core Application Database and Security Configuration\n"
            " */\n"
            "define('DB_HOST', '127.0.0.1');\n"
            "define('DB_USER', 'db_root_agent');\n"
            f"define('DB_PASS', '{db_pass}');\n"
            "define('DB_NAME', 'prod_enterprise_db');\n"
            "define('AUTH_SALT', 'b8c97e1a3d5f2098471649abce341908');\n"
            "define('LOG_PATH', '/var/log/app/security.log');\n"
            "\n"
            "$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);\n"
            "if ($conn->connect_error) {\n"
            "    die('Connection failure: ' . $conn->connect_error);\n"
            "}\n"
        )
        return content, "text/plain"

    elif path == "/.git/config":
        content = (
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = true\n"
            "\tbare = false\n"
            "\tlogallrefupdates = true\n"
            "[remote \"origin\"]\n"
            "    url = https://github.com/internal-honeymap-org/production-service.git\n"
            "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
            "[branch \"main\"]\n"
            "    remote = origin\n"
            "    merge = refs/heads/main\n"
        )
        return content, "text/plain"

    elif path == "/.aws/credentials":
        content = (
            "# AWS CLI / SDK Configuration Credentials\n"
            "[default]\n"
            f"aws_access_key_id = {aws_key}\n"
            f"aws_secret_access_key = {aws_secret}\n"
            "region = us-east-1\n"
            "output = json\n"
            "\n"
            "[production-cluster]\n"
            f"aws_access_key_id = {aws_key}\n"
            f"aws_secret_access_key = {aws_secret}\n"
            "region = us-west-2\n"
        )
        return content, "text/plain"

    elif path == "/wp-config.php":
        content = (
            "<?php\n"
            "/**\n"
            " * WordPress Core Configuration & Salts\n"
            " */\n"
            "define('DB_NAME', 'honeymap_wp_prod');\n"
            "define('DB_USER', 'wp_db_admin');\n"
            f"define('DB_PASSWORD', '{db_pass}');\n"
            "define('DB_HOST', 'localhost:3306');\n"
            "define('DB_CHARSET', 'utf8mb4');\n"
            "define('DB_COLLATE', '');\n"
            f"define('AUTH_KEY', '{aws_key}');\n"
            f"define('SECURE_AUTH_KEY', '{aws_secret}');\n"
        )
        return content, "text/plain"

    return "# Not found\n", "text/plain"


@fake_files_router.get("/.env")
@fake_files_router.get("/backup.sql")
@fake_files_router.get("/config.php")
@fake_files_router.get("/.git/config")
@fake_files_router.get("/.aws/credentials")
@fake_files_router.get("/wp-config.php")
async def handle_fake_files(request: Request):
    """
    Serves realistic sensitive configuration or database dumps injected with live honeytokens.
    Tracks ~90s live path rotation while preserving honeypot bait across all 6 traps.
    """
    path = request.url.path
    is_live = is_path_live(path)
    await log_decoy_hit(
        request,
        attack_type="sensitive_file_disclosure",
        metadata={
            "file_requested": path,
            "is_live_rotation": is_live,
            "rotation_cycle": get_rotation_cycle(),
            "active_live_paths": get_live_paths()
        }
    )
    content, content_type = await render_fake_file(path)
    return Response(
        content=content,
        media_type=content_type,
        status_code=200,
        headers={"X-HoneyMap-Decoy-Live": "true" if is_live else "false"}
    )


@fake_files_router.get("/api/decoys/live")
async def get_live_decoys_api():
    """Returns currently rotated live decoy paths and rotation metadata."""
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "live_paths": get_live_paths(),
            "pool": POOL_OF_6,
            "rotation_cycle": get_rotation_cycle(),
            "rotation_interval_seconds": ROTATION_INTERVAL_SEC
        }
    )
