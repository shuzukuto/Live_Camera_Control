"""
backend/app/api/nvr.py

REST API Router for NVR Recording Engine, Snapshots, and Storage Retention.
Milestone 3: Features 17, 18, 19, 20.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.database import get_db, get_camera_by_id
from app.services.nvr_service import (
    nvr_service,
    CameraNotFoundError,
    NoActiveRecordingError,
)
from app.services.storage_service import (
    snapshot_service,
    storage_manager,
)

logger = logging.getLogger("nvr.api.nvr")
router = APIRouter()


class ScheduleConfigRequest(BaseModel):
    enabled: bool = True
    mode: str = Field(default="continuous", description="'continuous', 'time_window', 'event_only'")
    start_hour: int = Field(default=0, ge=0, le=24)
    end_hour: int = Field(default=24, ge=0, le=24)
    pre_buffer_sec: int = Field(default=5, ge=0, le=30)
    post_buffer_sec: int = Field(default=10, ge=0, le=60)


# ==============================================================================
# Recording Endpoints (Features 17 & 18)
# ==============================================================================

@router.post("/cameras/{camera_id}/record/start", summary="Start recording")
async def start_recording(
    camera_id: str,
    trigger_type: str = Query("manual", description="'manual', 'scheduled', 'event'"),
    duration_sec: Optional[int] = Query(None, description="Optional clip duration"),
) -> Dict[str, Any]:
    try:
        return await nvr_service.start_recording(
            camera_id=camera_id,
            trigger_type=trigger_type,
            duration_sec=duration_sec,
        )
    except CameraNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/cameras/{camera_id}/record/stop", summary="Stop recording")
async def stop_recording(camera_id: str) -> Dict[str, Any]:
    try:
        return await nvr_service.stop_recording(camera_id=camera_id)
    except NoActiveRecordingError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/cameras/{camera_id}/record/status", summary="Get recording status")
async def get_recording_status(camera_id: str) -> Dict[str, Any]:
    is_recording = camera_id in nvr_service._active_sessions
    if not is_recording:
        return {"camera_id": camera_id, "is_recording": False}
    sess = nvr_service._active_sessions[camera_id]
    return {
        "camera_id": camera_id,
        "is_recording": True,
        "recording_id": sess.recording_id,
        "start_time": sess.start_iso,
        "trigger_type": sess.trigger_type,
        "duration_sec": time.time() - sess.start_time,
    }


# ==============================================================================
# Snapshot Endpoint (Feature 19)
# ==============================================================================

@router.post("/cameras/{camera_id}/snapshot", summary="Capture high-resolution camera snapshot")
async def take_snapshot(
    camera_id: str,
    watermark: bool = Query(True, description="Overlay timestamp OSD watermark"),
    watermark_text: Optional[str] = Query(None, description="Custom OSD watermark text"),
) -> Dict[str, Any]:
    try:
        return await snapshot_service.capture_snapshot(
            camera_id=camera_id,
            watermark=watermark,
            watermark_text=watermark_text,
        )
    except CameraNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ==============================================================================
# Recordings Management & FIFO (Features 17 & 20)
# ==============================================================================

@router.get("/recordings", summary="List recordings")
async def list_recordings(
    camera_id: Optional[str] = Query(None),
    record_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    async with get_db() as conn:
        sql = "SELECT * FROM recordings WHERE 1=1"
        params: List[Any] = []
        if camera_id:
            sql += " AND camera_id = ?"
            params.append(camera_id)
        if record_type:
            sql += " AND (record_type = ? OR trigger_type = ?)"
            params.extend([record_type, record_type])
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?;"
        offset = (page - 1) * page_size
        params.extend([page_size, offset])

        async with conn.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


@router.get("/recordings/{recording_id}", summary="Get recording metadata")
async def get_recording(recording_id: str) -> Dict[str, Any]:
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM recordings WHERE id = ?;", (recording_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
            return dict(row)


@router.delete("/recordings/{recording_id}", summary="Delete recording")
async def delete_recording(recording_id: str) -> Dict[str, Any]:
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM recordings WHERE id = ?;", (recording_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
            rec = dict(row)

        fpath = rec.get("file_path")
        if fpath:
            try:
                p = Path(fpath)
                if p.is_file():
                    p.unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to delete physical file %s: %s", fpath, e)

        tpath = rec.get("thumbnail_path")
        if tpath:
            try:
                p = Path(tpath)
                if p.is_file():
                    p.unlink(missing_ok=True)
            except Exception:
                pass

        await conn.execute("DELETE FROM recordings WHERE id = ?;", (recording_id,))
        await conn.commit()

    return {"status": "deleted", "id": recording_id}


@router.get("/recordings/{recording_id}/file", summary="Stream or download recording file")
async def get_recording_file(recording_id: str):
    async with get_db() as conn:
        async with conn.execute("SELECT file_path FROM recordings WHERE id = ?;", (recording_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
            fpath = Path(row["file_path"])
            if not fpath.is_file():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Physical file not found on disk")
            return FileResponse(path=str(fpath), media_type="video/mp4", filename=fpath.name)


@router.post("/recordings/{recording_id}/lock", summary="Lock recording against FIFO purge")
async def lock_recording(recording_id: str) -> Dict[str, Any]:
    async with get_db() as conn:
        await conn.execute(
            "UPDATE recordings SET is_locked = 1, is_protected = 1 WHERE id = ?;",
            (recording_id,),
        )
        await conn.commit()
    return {"recording_id": recording_id, "is_locked": True, "is_protected": True}


@router.post("/recordings/{recording_id}/unlock", summary="Unlock recording")
async def unlock_recording(recording_id: str) -> Dict[str, Any]:
    async with get_db() as conn:
        await conn.execute(
            "UPDATE recordings SET is_locked = 0, is_protected = 0 WHERE id = ?;",
            (recording_id,),
        )
        await conn.commit()
    return {"recording_id": recording_id, "is_locked": False, "is_protected": False}


# ==============================================================================
# Storage Hierarchy & Retention Endpoints (Feature 20)
# ==============================================================================

@router.get("/storage/status", summary="Get storage status and disk usage")
async def get_storage_status() -> Dict[str, Any]:
    return storage_manager.get_storage_stats()


@router.post("/storage/purge", summary="Manually trigger FIFO storage purge")
async def trigger_fifo_purge(needed_bytes: Optional[int] = Query(None)) -> Dict[str, Any]:
    return await storage_manager.run_fifo_purge(needed_bytes=needed_bytes)


# ==============================================================================
# Schedule Endpoints (Feature 18)
# ==============================================================================

@router.get("/cameras/{camera_id}/schedule", summary="Get camera recording schedule policy")
async def get_camera_schedule(camera_id: str) -> Dict[str, Any]:
    async with get_db() as conn:
        async with conn.execute(
            "SELECT value FROM system_settings WHERE key = ?;",
            (f"schedule.{camera_id}",),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                try:
                    return json.loads(row["value"])
                except Exception:
                    pass

        # Global fallback schedule
        async with conn.execute(
            "SELECT value FROM system_settings WHERE key = 'recording_schedule';"
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                try:
                    return json.loads(row["value"])
                except Exception:
                    pass

    return {
        "camera_id": camera_id,
        "enabled": True,
        "mode": "continuous",
        "start_hour": 0,
        "end_hour": 24,
        "pre_buffer_sec": 5,
        "post_buffer_sec": 10,
    }


@router.post("/cameras/{camera_id}/schedule", summary="Save camera recording schedule policy")
async def set_camera_schedule(camera_id: str, config: ScheduleConfigRequest) -> Dict[str, Any]:
    policy_json = config.model_dump_json()
    now_ts = time.time()
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO system_settings (key, value, category, description, updated_at)
            VALUES (?, ?, 'storage', 'Camera recording schedule policy', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
            """,
            (f"schedule.{camera_id}", policy_json, str(now_ts)),
        )
        # Also sync global default if recording_schedule
        await conn.execute(
            """
            INSERT INTO system_settings (key, value, category, description, updated_at)
            VALUES ('recording_schedule', ?, 'storage', 'Global recording schedule policy', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
            """,
            (policy_json, str(now_ts)),
        )
        await conn.commit()

    return {"status": "ok", "camera_id": camera_id, "schedule": config.model_dump()}
