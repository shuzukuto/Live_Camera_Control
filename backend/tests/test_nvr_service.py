"""
backend/tests/test_nvr_service.py

Unit and integration tests for crash-resilient fMP4 NVR recording engine,
faststart remuxing, schedule policies, and REST APIs.
Milestone 3: Features 17 & 18.
"""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from app.database import init_db, get_db, set_database_path
from app.main import create_app
from app.services.nvr_service import (
    NVRService,
    CameraNotFoundError,
    NoActiveRecordingError,
    ActiveRecordingSession,
)


@pytest_asyncio.fixture
async def nvr_test_env(tmp_path):
    """Sets up an isolated SQLite database and recording folder."""
    db_file = tmp_path / "test_nvr.db"
    rec_dir = tmp_path / "recordings"
    rec_dir.mkdir(parents=True, exist_ok=True)
    set_database_path(db_file)
    await init_db(db_file)

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type, live_url, enabled)
            VALUES ('cam_nvr_1', 'Driveway Cam', 'generic', 'stream_nvr_1', 'generic_rtsp', 'rtsp://mock/nvr1', 1),
                   ('cam_nvr_2', 'Hallway Cam', 'generic', 'stream_nvr_2', 'generic_rtsp', 'rtsp://mock/nvr2', 1);
            """
        )
        await conn.commit()

    svc = NVRService(recordings_dir=rec_dir)
    yield {"db_file": db_file, "rec_dir": rec_dir, "service": svc}


# ==============================================================================
# Feature 17: Crash-Resilient MP4 Recording Engine
# ==============================================================================

@pytest.mark.asyncio
async def test_start_recording_manual(nvr_test_env):
    """Starts manual recording, asserts sanitized path, SQLite record in 'recording' status."""
    svc: NVRService = nvr_test_env["service"]
    res = await svc.start_recording("cam_nvr_1", trigger_type="manual")

    assert res["status"] == "recording_started"
    assert "recording_id" in res
    assert "file_path" in res
    # Windows sanitization: no colons in filename
    assert ":" not in Path(res["file_path"]).name

    # Check session in-memory
    assert "cam_nvr_1" in svc._active_sessions
    sess = svc._active_sessions["cam_nvr_1"]
    assert sess.trigger_type == "manual"

    # Check database
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM recordings WHERE id = ?;", (res["recording_id"],)) as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["camera_id"] == "cam_nvr_1"
            assert row["status"] == "recording"


@pytest.mark.asyncio
async def test_start_recording_nonexistent_camera_raises_404(nvr_test_env):
    """Starting recording on unknown camera raises CameraNotFoundError."""
    svc: NVRService = nvr_test_env["service"]
    with pytest.raises(CameraNotFoundError):
        await svc.start_recording("ghost_camera_999")


@pytest.mark.asyncio
async def test_stop_recording_success(nvr_test_env):
    """Stops active recording, performs faststart remux, updates status to 'completed'."""
    svc: NVRService = nvr_test_env["service"]
    start_res = await svc.start_recording("cam_nvr_1")
    rec_id = start_res["recording_id"]

    await asyncio.sleep(0.05)
    stop_res = await svc.stop_recording("cam_nvr_1")

    assert stop_res["status"] == "recording_stopped"
    assert stop_res["recording_id"] == rec_id
    assert stop_res["duration_sec"] >= 0.05
    assert stop_res["size_bytes"] > 0
    assert "cam_nvr_1" not in svc._active_sessions

    # Check SQLite record finalized
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM recordings WHERE id = ?;", (rec_id,)) as cursor:
            row = await cursor.fetchone()
            assert row["status"] == "completed"
            assert row["duration_sec"] >= 0.05
            assert row["size_bytes"] > 0


@pytest.mark.asyncio
async def test_stop_unstarted_camera_raises_error(nvr_test_env):
    """Stopping recording on an idle channel raises NoActiveRecordingError."""
    svc: NVRService = nvr_test_env["service"]
    with pytest.raises(NoActiveRecordingError):
        await svc.stop_recording("cam_nvr_2")


@pytest.mark.asyncio
async def test_idempotent_start_recording(nvr_test_env):
    """Calling start_recording twice on the same camera returns the active session without error."""
    svc: NVRService = nvr_test_env["service"]
    r1 = await svc.start_recording("cam_nvr_1", trigger_type="manual")
    r2 = await svc.start_recording("cam_nvr_1", trigger_type="manual")

    assert r1["recording_id"] == r2["recording_id"]
    assert len(svc._active_sessions) == 1


@pytest.mark.asyncio
async def test_faststart_moov_precedes_mdat(nvr_test_env):
    """Finalized MP4 file contains moov atom before mdat atom."""
    svc: NVRService = nvr_test_env["service"]
    start_res = await svc.start_recording("cam_nvr_1")
    stop_res = await svc.stop_recording("cam_nvr_1")

    file_path = Path(stop_res["file_path"])
    assert file_path.is_file()
    with open(file_path, "rb") as f:
        content = f.read()

    moov_pos = content.find(b"moov")
    mdat_pos = content.find(b"mdat")
    assert moov_pos != -1
    assert mdat_pos != -1
    assert moov_pos < mdat_pos, "moov atom must precede mdat atom in faststart MP4"


@pytest.mark.asyncio
async def test_crash_recovery_unfinalized_recordings(nvr_test_env):
    """Startup recovery checks unfinalized 'recording' rows and completes valid files."""
    svc: NVRService = nvr_test_env["service"]
    rec_dir: Path = nvr_test_env["rec_dir"]

    valid_file = rec_dir / "valid_crash.mp4"
    valid_file.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41\x00\x00\x00\x08mdat")

    empty_file = rec_dir / "empty_crash.mp4"
    empty_file.touch()

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, start_time)
            VALUES ('rec_recov_1', 'cam_nvr_1', 'Driveway', ?, 'recording', '2026-10-08T00:00:00Z'),
                   ('rec_recov_2', 'cam_nvr_1', 'Driveway', ?, 'recording', '2026-10-08T00:00:00Z');
            """,
            (str(valid_file), str(empty_file)),
        )
        await conn.commit()

    await svc.recover_unfinalized_recordings()

    async with get_db() as conn:
        async with conn.execute("SELECT id, status FROM recordings WHERE id IN ('rec_recov_1', 'rec_recov_2');") as cursor:
            rows = {r["id"]: r["status"] for r in await cursor.fetchall()}
            assert rows["rec_recov_1"] == "completed"
            assert rows["rec_recov_2"] == "failed"


# ==============================================================================
# Feature 18: Scheduled & Event-Based Recording
# ==============================================================================

@pytest.mark.asyncio
async def test_event_recording_burst_deduplication(nvr_test_env):
    """Burst of event triggers within 10s cooldown does not spawn duplicate sessions."""
    svc: NVRService = nvr_test_env["service"]
    r1 = await svc.start_recording("cam_nvr_1", trigger_type="event", duration_sec=5)
    r2 = await svc.start_recording("cam_nvr_1", trigger_type="event", duration_sec=10)

    assert r1["recording_id"] == r2["recording_id"]
    assert len(svc._active_sessions) == 1


def test_schedule_evaluation_continuous():
    """Continuous schedule always evaluates to True."""
    cfg = {"enabled": True, "mode": "continuous"}
    assert NVRService.evaluate_schedule(cfg) is True

    cfg_disabled = {"enabled": False, "mode": "continuous"}
    assert NVRService.evaluate_schedule(cfg_disabled) is False


def test_schedule_evaluation_daytime_window():
    """Daytime window (08:00 to 18:00) evaluates correctly."""
    cfg = {"enabled": True, "mode": "time_window", "start_hour": 8, "end_hour": 18}

    t_in = datetime(2026, 10, 8, 14, 0, 0)
    assert NVRService.evaluate_schedule(cfg, current_dt=t_in) is True

    t_out = datetime(2026, 10, 8, 20, 0, 0)
    assert NVRService.evaluate_schedule(cfg, current_dt=t_out) is False


def test_schedule_evaluation_midnight_spanning_window():
    """Midnight-spanning window (22:00 to 06:00) evaluates correctly."""
    cfg = {"enabled": True, "mode": "time_window", "start_hour": 22, "end_hour": 6}

    t_night = datetime(2026, 10, 8, 23, 30, 0)
    assert NVRService.evaluate_schedule(cfg, current_dt=t_night) is True

    t_early = datetime(2026, 10, 8, 3, 15, 0)
    assert NVRService.evaluate_schedule(cfg, current_dt=t_early) is True

    t_noon = datetime(2026, 10, 8, 12, 0, 0)
    assert NVRService.evaluate_schedule(cfg, current_dt=t_noon) is False


# ==============================================================================
# REST API Endpoints Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_nvr_api_routes(nvr_test_env):
    """Verifies REST endpoints for recording start/stop/status/lock."""
    app = create_app()
    client = TestClient(app)

    # 1. Start recording
    res = client.post("/api/cameras/cam_nvr_1/record/start")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "recording_started"
    rec_id = data["recording_id"]

    # 2. Check recording status
    status_res = client.get("/api/cameras/cam_nvr_1/record/status")
    assert status_res.status_code == 200
    assert status_res.json()["is_recording"] is True

    # 3. Stop recording
    stop_res = client.post("/api/cameras/cam_nvr_1/record/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "recording_stopped"

    # 4. List recordings
    list_res = client.get("/api/recordings?camera_id=cam_nvr_1")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # 5. Lock and unlock recording
    lock_res = client.post(f"/api/recordings/{rec_id}/lock")
    assert lock_res.status_code == 200
    assert lock_res.json()["is_locked"] is True

    unlock_res = client.post(f"/api/recordings/{rec_id}/unlock")
    assert unlock_res.status_code == 200
    assert unlock_res.json()["is_locked"] is False

    # 6. Schedule config API
    sched_res = client.post(
        "/api/cameras/cam_nvr_1/schedule",
        json={"enabled": True, "mode": "time_window", "start_hour": 8, "end_hour": 18},
    )
    assert sched_res.status_code == 200
    assert sched_res.json()["schedule"]["start_hour"] == 8
