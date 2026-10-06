"""
Shared python-socketio AsyncServer instance in ASGI mode.
Provides asynchronous event dispatch to connected dashboard clients.
"""
import os
import socketio

cors_env = os.environ.get("HONEYMAP_CORS_ORIGINS", "http://localhost:5173")
cors_origins = [orig.strip() for orig in cors_env.split(",") if orig.strip()]

if "*" in cors_origins:
    cors_allowed = "*"
else:
    cors_allowed = cors_origins

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=cors_allowed
)

