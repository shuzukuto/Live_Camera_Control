"""
backend/app/api/ws.py

WebSocket and Server-Sent Events (SSE) Router for Real-Time Security Alerts.
Endpoints:
- WS  /api/ws/events     : Bi-directional WebSocket alert stream with heartbeat ping/pong
- GET /api/events/stream : Fallback SSE stream (text/event-stream)
- GET /api/ws/status     : Health telemetry for broadcast subsystem
Milestone 4: Feature 25.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

from app.services.broadcast_service import broadcast_manager

logger = logging.getLogger("nvr.api.ws")
router = APIRouter()


@router.websocket("/ws/events")
async def websocket_alert_feed(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="Optional authentication session token"),
):
    """
    Real-time security alert feed via WebSocket.
    Clients receive instant event toast payloads, audio alert flags, and heartbeat pings.
    """
    await broadcast_manager.connect_ws(websocket)
    try:
        # Send initial connected greeting
        await websocket.send_json({
            "type": "connected",
            "timestamp": time.time(),
            "message": "Subscribed to live surveillance alerts",
        })

        while True:
            data = await websocket.receive_text()
            # Handle client-initiated ping (JSON or plaintext)
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict) and parsed.get("type") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
            except (json.JSONDecodeError, AttributeError):
                if data.strip().lower() == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally")
    except Exception as e:
        logger.warning("WebSocket client connection closed: %s", e)
    finally:
        await broadcast_manager.disconnect_ws(websocket)


@router.get("/events/stream", summary="Server-Sent Events fallback feed")
async def sse_alert_feed(
    request: Request,
    token: Optional[str] = Query(None, description="Optional authentication session token"),
):
    """
    Server-Sent Events (SSE) fallback endpoint for environments unable to maintain WebSockets.
    Yields chunks formatted as 'data: {...}\\n\\n' with periodic ': ping\\n\\n' keepalive comments.
    """
    client_queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    await broadcast_manager.register_sse(client_queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Initial connect handshake
            initial_msg = json.dumps({"type": "connected", "timestamp": time.time()})
            yield f"data: {initial_msg}\n\n"

            idle_seconds = 0
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(client_queue.get(), timeout=1.0)
                    if payload is None:  # Shutdown sentinel
                        break
                    yield f"data: {json.dumps(payload)}\n\n"
                    idle_seconds = 0
                except asyncio.TimeoutError:
                    idle_seconds += 1
                    if idle_seconds >= 15:
                        yield ": ping\n\n"
                        idle_seconds = 0
        finally:
            await broadcast_manager.unregister_sse(client_queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/ws/status", summary="Broadcast manager status telemetry")
async def get_broadcast_status() -> Dict[str, Any]:
    """Returns active subscriber counts and broadcast telemetry metrics."""
    return broadcast_manager.get_status()
