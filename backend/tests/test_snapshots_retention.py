"""
backend/tests/test_snapshots_retention.py

Unit and integration tests for High-Resolution Snapshot Engine,
Pillow watermarking & thumbnails, and Storage Hierarchy / FIFO Retention.
Milestone 3: Features 19 & 20.
"""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from PIL import Image
from fastapi.testclient import TestClient

from app.database import init_db, get_db, set_database_path
from app.main import create_app
from app.services.nvr_service import CameraNotFoundError
from app.services.storage_service import (
    SnapshotService,
    StorageManager,
    StorageRetentionWorker,
    is_unc_path,
)


@pytest_asyncio.fixture
async def snap_test_env(tmp_path):
    """Sets up an isolated database, snapshot folder, and recordings folder."""
    db_file = tmp_path / "test_storage.db"
    rec_dir = tmp_path / "recordings"
    snap_dir = tmp_path / "snapshots"
    rec_dir.mkdir(parents=True, exist_ok=True)
    snap_dir.mkdir(parents=True, exist_ok=True)

    set_database_path(db_file)
    await init_db(db_file)

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type, live_url, enabled)
            VALUES ('cam_snap_1', 'Porch Cam', 'generic', 'stream_snap_1', 'generic_rtsp', 'rtsp://mock/snap1', 1),
                   ('cam_snap_2', 'Backyard Cam', 'generic', 'stream_snap_2', 'generic_rtsp', 'rtsp://mock/snap2', 1);
            """
        )
        await conn.commit()

    snap_svc = SnapshotService()
    snap_svc.snapshots_dir = snap_dir

    storage_mgr = StorageManager()
    storage_mgr.recordings_dir = rec_dir
    storage_mgr.snapshots_dir = snap_dir

    yield {
        "db_file": db_file,
        "rec_dir": rec_dir,
        "snap_dir": snap_dir,
        "snap_svc": snap_svc,
        "storage_mgr": storage_mgr,
    }


# ==============================================================================
# Feature 19: High-Resolution Snapshot Engine
# ==============================================================================

@pytest.mark.asyncio
async def test_capture_snapshot_success(snap_test_env):
    """Captures snapshot, verifies JPEG format, Pillow thumbnail 320x180, and DB row."""
    svc: SnapshotService = snap_test_env["snap_svc"]
    res = await svc.capture_snapshot("cam_snap_1", watermark=True)

    assert res["status"] == "ok"
    assert "snapshot_id" in res
    assert res["camera_id"] == "cam_snap_1"
    assert res["snapshot_url"].endswith(".jpg")
    assert res["thumbnail_url"].endswith(".jpg")

    # Verify full image on disk
    full_path = Path(res["file_path"])
    assert full_path.is_file()
    img = Image.open(full_path)
    assert img.format == "JPEG"

    # Verify thumbnail on disk
    thumb_path = Path(res["thumbnail_path"])
    assert thumb_path.is_file()
    thumb = Image.open(thumb_path)
    assert thumb.format == "JPEG"
    assert thumb.size == (320, 180)

    # Verify database record
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM recordings WHERE id = ?;", (res["snapshot_id"],)) as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["camera_id"] == "cam_snap_1"
            assert row["record_type"] == "snapshot"
            assert row["status"] == "completed"


@pytest.mark.asyncio
async def test_capture_snapshot_nonexistent_camera_404(snap_test_env):
    """Capturing snapshot on unknown camera raises CameraNotFoundError."""
    svc: SnapshotService = snap_test_env["snap_svc"]
    with pytest.raises(CameraNotFoundError):
        await svc.capture_snapshot("ghost_camera_xyz")


@pytest.mark.asyncio
async def test_snapshot_burst_generates_unique_files(snap_test_env):
    """Rapid consecutive snapshots generate unique timestamps and files."""
    svc: SnapshotService = snap_test_env["snap_svc"]
    urls = set()
    for _ in range(5):
        res = await svc.capture_snapshot("cam_snap_1")
        urls.add(res["snapshot_url"])
        await asyncio.sleep(0.005)

    assert len(urls) == 5


# ==============================================================================
# Feature 20: Storage Hierarchy & FIFO Retention
# ==============================================================================

def test_unc_path_detection():
    """Validates Windows UNC network share path helper."""
    assert is_unc_path("\\\\nas_server\\cameras\\share") is True
    assert is_unc_path("//nas_server/cameras/share") is True
    assert is_unc_path("C:\\recordings") is False
    assert is_unc_path("/mnt/nas/recordings") is False
    assert is_unc_path("") is False


def test_storage_stats_calculation(snap_test_env):
    """Calculates disk usage and managed folder sizes."""
    mgr: StorageManager = snap_test_env["storage_mgr"]
    rec_dir: Path = snap_test_env["rec_dir"]

    # Write a 10KB test file
    test_file = rec_dir / "sample.mp4"
    test_file.write_bytes(b"\x00" * 10240)

    stats = mgr.get_storage_stats()
    assert stats["recordings_bytes"] >= 10240
    assert stats["disk_total_bytes"] > 0
    assert stats["disk_free_bytes"] > 0


@pytest.mark.asyncio
async def test_fifo_purge_deletes_oldest_first(snap_test_env):
    """FIFO purge identifies and purges oldest unlocked recordings first."""
    mgr: StorageManager = snap_test_env["storage_mgr"]
    rec_dir: Path = snap_test_env["rec_dir"]

    now = time.time()
    f1 = rec_dir / "old1.mp4"
    f2 = rec_dir / "new2.mp4"
    f1.write_bytes(b"DATA1")
    f2.write_bytes(b"DATA2")

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, created_at)
            VALUES ('rec_old1', 'cam_snap_1', 'Porch', ?, 'completed', 0, 0, 5, '2026-10-01T00:00:00Z'),
                   ('rec_new2', 'cam_snap_1', 'Porch', ?, 'completed', 0, 0, 5, '2026-10-08T00:00:00Z');
            """,
            (str(f1), str(f2)),
        )
        await conn.commit()

    # Purge 1 file (needed_bytes=5)
    result = await mgr.run_fifo_purge(needed_bytes=5)
    assert result["purged_count"] >= 1
    assert result["freed_bytes"] >= 5

    # Assert old1 deleted from disk and database
    assert not f1.exists()
    assert f2.exists()

    async with get_db() as conn:
        async with conn.execute("SELECT id FROM recordings WHERE id = 'rec_old1';") as cursor:
            assert await cursor.fetchone() is None
        async with conn.execute("SELECT id FROM recordings WHERE id = 'rec_new2';") as cursor:
            assert await cursor.fetchone() is not None


@pytest.mark.asyncio
async def test_fifo_purge_spares_locked_and_protected_recordings(snap_test_env):
    """Protected/locked recordings are spared from FIFO purge even if oldest."""
    mgr: StorageManager = snap_test_env["storage_mgr"]
    rec_dir: Path = snap_test_env["rec_dir"]

    f_locked = rec_dir / "locked.mp4"
    f_unlocked = rec_dir / "unlocked.mp4"
    f_locked.write_bytes(b"LOCKED")
    f_unlocked.write_bytes(b"UNLOCKED")

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, created_at)
            VALUES ('rec_locked', 'cam_snap_1', 'Porch', ?, 'completed', 1, 1, 6, '2026-09-01T00:00:00Z'),
                   ('rec_unlocked', 'cam_snap_1', 'Porch', ?, 'completed', 0, 0, 8, '2026-10-08T00:00:00Z');
            """,
            (str(f_locked), str(f_unlocked)),
        )
        await conn.commit()

    result = await mgr.run_fifo_purge()
    assert result["purged_count"] == 1

    # Locked file remains intact
    assert f_locked.exists()
    assert not f_unlocked.exists()

    async with get_db() as conn:
        async with conn.execute("SELECT id FROM recordings WHERE id = 'rec_locked';") as cursor:
            assert await cursor.fetchone() is not None


@pytest.mark.asyncio
async def test_fifo_purge_missing_file_graceful(snap_test_env):
    """Missing physical file does not throw unhandled error during DB purge."""
    mgr: StorageManager = snap_test_env["storage_mgr"]

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, created_at)
            VALUES ('rec_ghost', 'cam_snap_1', 'Porch', '/non/existent/file.mp4', 'completed', 0, 0, 100, '2026-10-01T00:00:00Z');
            """
        )
        await conn.commit()

    result = await mgr.run_fifo_purge()
    assert result["purged_count"] == 1


# ==============================================================================
# REST API Endpoints Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_snapshot_and_storage_api_routes(snap_test_env):
    """Verifies REST endpoints for snapshot capture, storage stats, and purge."""
    app = create_app()
    client = TestClient(app)

    # 1. Snapshot capture API
    res = client.post("/api/cameras/cam_snap_1/snapshot")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["snapshot_url"].endswith(".jpg")
    snap_id = data["snapshot_id"]

    # 2. Delete recording API
    del_res = client.delete(f"/api/recordings/{snap_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # 3. Create another snapshot for storage tests
    client.post("/api/cameras/cam_snap_1/snapshot")

    # 4. Storage status API
    stats_res = client.get("/api/storage/status")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_managed_bytes" in stats
    assert "max_storage_gb" in stats

    # 5. Manual storage purge API
    purge_res = client.post("/api/storage/purge")
    assert purge_res.status_code == 200
    assert purge_res.json()["status"] == "ok"
