"""
backend/app/services/event_service.py

AI Event Ingestion, Canonical 3-Class Normalization, Query, Export & Real-Time Broadcast Orchestration.
Milestone 4: Features 21, 22, 23, 24, 25.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from app.database import get_camera_by_id, query_event_logs, save_event_log
from app.models.event import CanonicalEventType, EventCreate
from app.services.broadcast_service import broadcast_manager
from app.utils.export import export_events_csv, export_events_xlsx

logger = logging.getLogger("nvr.event_service")


class EventService:
    @staticmethod
    def normalize_event_type(raw_type: Optional[str]) -> str:
        """
        Map vendor alarm codes to exact 3 classes: 'Human', 'Movement', 'Abnormal Sound'.
        Strict precedence: Human -> Abnormal Sound -> Movement fallback.
        Safe O(N) substring matching without regex backtracking.
        Empty, null, or unrecognized strings default to 'Movement'.
        """
        if not raw_type:
            return CanonicalEventType.MOVEMENT.value

        s = str(raw_type).strip().lower()
        if not s:
            return CanonicalEventType.MOVEMENT.value

        # Precedence 1: Human detection
        human_keywords = (
            "human",
            "person",
            "body",
            "face",
            "facial",
            "people",
            "humanoid",
            "pedestrian",
            "intrud",
            "loiter",
        )
        if any(k in s for k in human_keywords):
            return CanonicalEventType.HUMAN.value

        # Precedence 2: Abnormal Sound detection
        sound_keywords = (
            "sound",
            "audio",
            "cry",
            "crying",
            "bark",
            "barking",
            "noise",
            "decibel",
            "glass",
            "shout",
            "db",
            "abnormal_sound",
        )
        if any(k in s for k in sound_keywords):
            return CanonicalEventType.ABNORMAL_SOUND.value

        # Precedence 3 & Fallback: Movement
        return CanonicalEventType.MOVEMENT.value

    async def record_event(self, event_data: Union[EventCreate, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Normalize event, resolve camera metadata, persist to SQLite, and dispatch real-time broadcast.
        """
        data = event_data.model_dump() if isinstance(event_data, EventCreate) else dict(event_data)

        # 1. Canonical normalization
        raw_type = data.get("event_type") or "Movement"
        canonical = self.normalize_event_type(raw_type)
        data["event_type"] = canonical
        data["vendor_raw_type"] = str(raw_type)

        # 2. Camera metadata resolution
        cam_id = data.get("camera_id")
        cam = None
        if cam_id:
            cam = await get_camera_by_id(cam_id)
            if not data.get("camera_name"):
                data["camera_name"] = cam.get("name") if cam else f"Camera {cam_id}"
        if not data.get("camera_name"):
            data["camera_name"] = f"Camera {cam_id or 'unknown'}"

        # 3. Snapshot / clip path synchronizations
        snap = data.get("snapshot_url") or data.get("snapshot_path") or ""
        clip = data.get("clip_url") or data.get("clip_path") or ""
        data["snapshot_url"] = snap
        data["snapshot_path"] = snap
        data["clip_url"] = clip
        data["clip_path"] = clip

        # 4. Optional event recording trigger if camera has recording_enabled
        if cam and cam.get("recording_enabled") and not clip:
            try:
                from app.services.nvr_service import nvr_service
                evt_id = data.get("event_id") or f"evt_{int(time.time()*1000)}"
                rec_res = await nvr_service.start_recording(
                    camera_id=cam_id,
                    trigger_type="event",
                    event_id=evt_id,
                    duration_sec=30,
                )
                if rec_res and rec_res.get("file_path"):
                    data["clip_path"] = rec_res["file_path"]
                    data["clip_url"] = rec_res["file_path"]
            except Exception as e:
                logger.debug("Automatic event-triggered recording skipped: %s", e)

        # 5. Persist to SQLite
        saved = await save_event_log(data)

        # 6. Dispatch real-time alert broadcast
        try:
            await broadcast_manager.broadcast_event(saved)
        except Exception as e:
            logger.debug("Broadcast notification dispatch failed: %s", e)

        return saved

    async def list_events(
        self,
        query: Optional[str] = None,
        camera_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[Union[str, float, int]] = None,
        end_time: Optional[Union[str, float, int]] = None,
        is_read: Optional[bool] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query event logs with multi-column search, filtering, and pagination."""
        return await query_event_logs(
            query=query,
            camera_id=camera_id,
            event_type=event_type,
            severity=severity,
            start_time=start_time,
            end_time=end_time,
            is_read=is_read,
            page=page,
            page_size=page_size,
            fetch_all=False,
        )

    async def export_events(
        self,
        mode: str = "all",
        fmt: str = "csv",
        query: Optional[str] = None,
        camera_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[Union[str, float, int]] = None,
        end_time: Optional[Union[str, float, int]] = None,
    ) -> Tuple[Union[str, bytes], str, str]:
        """
        Executes 3-mode export:
        - mode='template': header row only
        - mode='filtered': all records matching filter
        - mode='all': all records in database
        Fallback: any unrecognized mode defaults to 'all'.
        Returns: (content_data, media_type, filename)
        """
        valid_modes = {"template", "filtered", "all"}
        if mode not in valid_modes:
            mode = "all"  # Fallback per test_b24_04

        records: List[Dict[str, Any]] = []
        if mode == "template":
            records = []
        elif mode == "filtered":
            records, _ = await query_event_logs(
                query=query,
                camera_id=camera_id,
                event_type=event_type,
                severity=severity,
                start_time=start_time,
                end_time=end_time,
                fetch_all=True,
            )
        else:  # mode == "all"
            records, _ = await query_event_logs(fetch_all=True)

        timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        ext = "xlsx" if fmt.lower() == "xlsx" else "csv"
        filename = f"event_logs_{mode}_{timestamp_str}.{ext}"

        if ext == "xlsx":
            content = export_events_xlsx(records, mode=mode)
            media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            content = export_events_csv(records, mode=mode)
            media_type = "text/csv; charset=utf-8"

        return content, media_type, filename


# Singleton event service instance
event_service = EventService()
