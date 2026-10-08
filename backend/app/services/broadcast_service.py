"""
backend/app/services/broadcast_service.py

Real-Time Alert Broadcast Manager for WebSockets and SSE.
Handles active connection tracking, graceful disconnection,
heartbeat ping/pong, dead client pruning, and fan-out push.
Milestone 4: Feature 25.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger("nvr.broadcast")


class BroadcastManager:
    def __init__(self, heartbeat_interval_sec: float = 30.0, queue_maxsize: int = 100):
        self._active_ws: Set[WebSocket] = set()
        self._active_sse: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()
        self._heartbeat_interval = heartbeat_interval_sec
        self._queue_maxsize = queue_maxsize
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._broadcast_count: int = 0
        self._running: bool = False

    async def start(self) -> None:
        """Starts background heartbeat sweep."""
        if self._running:
            return
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("BroadcastManager started with %ss heartbeat interval", self._heartbeat_interval)

    async def stop(self) -> None:
        """Stops heartbeat loop and cleanly closes all active client connections."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        # Disconnect active WebSockets
        async with self._lock:
            for ws in list(self._active_ws):
                try:
                    await ws.close(code=1001, reason="Server shutting down")
                except Exception:
                    pass
            self._active_ws.clear()

            # Signal SSE queues to terminate
            for q in list(self._active_sse):
                try:
                    q.put_nowait(None)
                except Exception:
                    pass
            self._active_sse.clear()

        logger.info("BroadcastManager stopped")

    async def connect_ws(self, websocket: WebSocket) -> None:
        """Accepts and tracks a new WebSocket client."""
        await websocket.accept()
        async with self._lock:
            self._active_ws.add(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self._active_ws))

    async def disconnect_ws(self, websocket: WebSocket) -> None:
        """Removes a disconnected WebSocket client."""
        async with self._lock:
            self._active_ws.discard(websocket)
        logger.info("WebSocket client disconnected. Active: %d", len(self._active_ws))

    async def register_sse(self, queue: asyncio.Queue) -> None:
        """Registers a new SSE client queue."""
        async with self._lock:
            self._active_sse.add(queue)
        logger.debug("SSE subscriber registered. Active: %d", len(self._active_sse))

    async def unregister_sse(self, queue: asyncio.Queue) -> None:
        """Removes an SSE client queue."""
        async with self._lock:
            self._active_sse.discard(queue)
        logger.debug("SSE subscriber unregistered. Active: %d", len(self._active_sse))

    async def broadcast_event(self, event_data: Dict[str, Any]) -> int:
        """
        Broadcasts normalized alert event to all active WebSocket and SSE subscribers.
        Ensures strict payload format:
        {event_id, camera_id, camera_name, event_type, severity, timestamp, snapshot_url, clip_url, audio_alert, metadata}
        """
        self._broadcast_count += 1
        event_type = event_data.get("event_type", "Movement")
        severity = event_data.get("severity") or ("critical" if event_type == "Abnormal Sound" else "warning")

        # audio_alert must be strictly boolean (True for Abnormal Sound or critical)
        audio_alert_val = event_data.get("audio_alert")
        if audio_alert_val is not None:
            audio_alert = bool(audio_alert_val)
        else:
            audio_alert = (event_type == "Abnormal Sound")

        payload = {
            "event_id": str(event_data.get("event_id") or event_data.get("id") or f"evt_{int(time.time()*1000)}"),
            "camera_id": str(event_data.get("camera_id", "unknown")),
            "camera_name": str(event_data.get("camera_name", "Unknown Camera")),
            "event_type": str(event_type),
            "severity": str(severity),
            "timestamp": event_data.get("timestamp") or time.time(),
            "snapshot_url": event_data.get("snapshot_url") or event_data.get("snapshot_path") or "",
            "clip_url": event_data.get("clip_url") or event_data.get("clip_path") or "",
            "audio_alert": audio_alert,
            "metadata": event_data.get("metadata") or {},
        }

        # 1. Fan-out to active WebSockets (pruning dead sockets safely)
        dead_ws = []
        for ws in list(self._active_ws):
            try:
                await ws.send_json(payload)
            except Exception as e:
                logger.debug("Dead WebSocket encountered during broadcast: %s", e)
                dead_ws.append(ws)

        if dead_ws:
            async with self._lock:
                for ws in dead_ws:
                    self._active_ws.discard(ws)

        # 2. Fan-out to SSE Queues (with bounded capacity protection)
        for q in list(self._active_sse):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()  # Evict oldest item
                    q.put_nowait(payload)
                except Exception:
                    pass

        return len(self._active_ws) + len(self._active_sse)

    async def _heartbeat_loop(self) -> None:
        """Periodic background sweep sending keepalive ping to WebSockets."""
        while self._running:
            try:
                await asyncio.sleep(self._heartbeat_interval)
                if not self._active_ws:
                    continue
                ping_msg = {"type": "ping", "timestamp": time.time()}
                dead_ws = []
                for ws in list(self._active_ws):
                    try:
                        await ws.send_json(ping_msg)
                    except Exception:
                        dead_ws.append(ws)
                if dead_ws:
                    async with self._lock:
                        for ws in dead_ws:
                            self._active_ws.discard(ws)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Error in broadcast heartbeat loop: %s", e)

    def get_status(self) -> Dict[str, Any]:
        """Status telemetry for health and diagnostics."""
        return {
            "active_ws_clients": len(self._active_ws),
            "active_sse_clients": len(self._active_sse),
            "total_broadcasts": self._broadcast_count,
            "heartbeat_running": self._running,
        }


# Singleton broadcast manager instance
broadcast_manager = BroadcastManager()
