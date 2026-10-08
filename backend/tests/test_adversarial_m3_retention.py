"""
backend/tests/test_adversarial_m3_retention.py

Adversarial Stress Testing & Fuzzing Harness for Milestone 3 (Storage Retention & FIFO Quotas).
Authored by challenger_m3_2 to empirically verify:
1. FIFO retention ordering oracle: oldest unlocked files deleted strictly first.
2. Locked/Protected recordings strict immunity under severe quota exhaustion.
3. In-progress (status='recording') recordings immunity from purge.
4. Physical file and thumbnail filesystem unlink integrity and graceful handling of missing files.
5. Windows UNC paths validation, syntax edge cases, and storage hierarchy statistics.
6. REST API integration for lock, unlock, status, and manual purge triggers.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from app.config import settings
from app.database import init_db, get_db, set_database_path
from app.main import create_app
from app.services.storage_service import (
    SnapshotService,
    StorageManager,
    StorageRetentionWorker,
    is_unc_path,
)


@pytest_asyncio.fixture
async def retention_test_env(tmp_path):
    """Sets up an isolated database, snapshot folder, and recordings folder."""
    db_file = tmp_path / "test_adversarial_retention.db"
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
            VALUES ('cam_adv_1', 'Gate Camera', 'generic', 'stream_adv_1', 'generic_rtsp', 'rtsp://mock/adv1', 1),
                   ('cam_adv_2', 'Perimeter Camera', 'generic', 'stream_adv_2', 'generic_rtsp', 'rtsp://mock/adv2', 1);
            """
        )
        await conn.commit()

    storage_mgr = StorageManager()
    storage_mgr.recordings_dir = rec_dir
    storage_mgr.snapshots_dir = snap_dir

    yield {
        "db_file": db_file,
        "rec_dir": rec_dir,
        "snap_dir": snap_dir,
        "storage_mgr": storage_mgr,
    }


# ==============================================================================
# 1. FIFO Retention Ordering Oracle
# ==============================================================================

@pytest.mark.asyncio
async def test_fifo_ordering_strict_chronological_purge(retention_test_env):
    """
    Stress-tests FIFO deletion ordering:
    Inserts 10 recordings with non-monotonic insertion order and distinct created_at timestamps.
    Verifies that run_fifo_purge deletes them strictly in ascending chronological order.
    """
    mgr: StorageManager = retention_test_env["storage_mgr"]
    rec_dir: Path = retention_test_env["rec_dir"]

    base_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    # Shuffled order of minutes: [7, 2, 9, 0, 4, 1, 8, 3, 6, 5]
    minutes_order = [7, 2, 9, 0, 4, 1, 8, 3, 6, 5]

    for m in minutes_order:
        ts = base_time + timedelta(minutes=m)
        f = rec_dir / f"rec_m{m}.mp4"
        f.write_bytes(b"DATA_" + str(m).encode() * 100)
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO recordings (
                    id, camera_id, camera_name, file_path, status,
                    is_locked, is_protected, file_size, size_bytes, created_at
                ) VALUES (?, 'cam_adv_1', 'Gate', ?, 'completed', 0, 0, 100, 100, ?);
                """,
                (f"rec_id_{m}", str(f), ts.isoformat()),
            )
            await conn.commit()

    # Expected purge sequence: minutes 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
    for expected_minute in range(10):
        res = await mgr.run_fifo_purge(needed_bytes=100)
        assert res["purged_count"] == 1
        assert res["freed_bytes"] == 100

        # Verify that the expected minute's file was deleted from disk and DB
        deleted_file = rec_dir / f"rec_m{expected_minute}.mp4"
        assert not deleted_file.exists(), f"File for minute {expected_minute} should have been unlinked"

        async with get_db() as conn:
            async with conn.execute("SELECT id FROM recordings WHERE id = ?;", (f"rec_id_{expected_minute}",)) as cur:
                assert await cur.fetchone() is None

        # Verify that all newer files still exist
        for remaining_m in range(expected_minute + 1, 10):
            remaining_file = rec_dir / f"rec_m{remaining_m}.mp4"
            assert remaining_file.exists(), f"File for minute {remaining_m} should still exist"


# ==============================================================================
# 2. Strict Immunity of Locked and Protected Recordings
# ==============================================================================

@pytest.mark.asyncio
async def test_locked_and_protected_recordings_strict_immunity(retention_test_env):
    """
    Stress-tests that locked and protected recordings are 100% immune,
    even when they are the oldest files in the entire database.
    """
    mgr: StorageManager = retention_test_env["storage_mgr"]
    rec_dir: Path = retention_test_env["rec_dir"]

    base_time = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # 1. Very old LOCKED recording (is_locked=1, is_protected=0)
    f_locked1 = rec_dir / "ancient_locked1.mp4"
    f_locked1.write_bytes(b"LOCKED_CONTENT_1" * 100)
    # 2. Very old PROTECTED recording (is_locked=0, is_protected=1)
    f_prot2 = rec_dir / "ancient_prot2.mp4"
    f_prot2.write_bytes(b"PROT_CONTENT_2" * 100)
    # 3. Very old DUAL LOCKED recording (is_locked=1, is_protected=1)
    f_dual3 = rec_dir / "ancient_dual3.mp4"
    f_dual3.write_bytes(b"DUAL_CONTENT_3" * 100)
    # 4. Newer UNLOCKED recording (is_locked=0, is_protected=0)
    f_unlocked4 = rec_dir / "newer_unlocked4.mp4"
    f_unlocked4.write_bytes(b"UNLOCKED_CONTENT_4" * 100)

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, size_bytes, created_at)
            VALUES ('rec_l1', 'cam_adv_1', 'Gate', ?, 'completed', 1, 0, 1600, 1600, ?),
                   ('rec_p2', 'cam_adv_1', 'Gate', ?, 'completed', 0, 1, 1400, 1400, ?),
                   ('rec_d3', 'cam_adv_1', 'Gate', ?, 'completed', 1, 1, 1400, 1400, ?),
                   ('rec_u4', 'cam_adv_1', 'Gate', ?, 'completed', 0, 0, 1800, 1800, ?);
            """,
            (
                str(f_locked1), (base_time + timedelta(days=1)).isoformat(),
                str(f_prot2), (base_time + timedelta(days=2)).isoformat(),
                str(f_dual3), (base_time + timedelta(days=3)).isoformat(),
                str(f_unlocked4), (base_time + timedelta(days=10)).isoformat(),
            ),
        )
        await conn.commit()

    # Trigger purge requesting a large amount of bytes (100,000 bytes)
    res = await mgr.run_fifo_purge(needed_bytes=100_000)

    # Only rec_u4 should be purged
    assert res["purged_count"] == 1
    assert res["freed_bytes"] == 1800
    assert not f_unlocked4.exists()

    # All three locked/protected files MUST survive
    assert f_locked1.exists()
    assert f_prot2.exists()
    assert f_dual3.exists()

    async with get_db() as conn:
        async with conn.execute("SELECT id FROM recordings ORDER BY id ASC;") as cur:
            remaining_ids = [row["id"] for row in await cur.fetchall()]
            assert set(remaining_ids) == {"rec_d3", "rec_l1", "rec_p2"}

    # Attempt second purge when only locked files remain
    res_second = await mgr.run_fifo_purge(needed_bytes=50_000)
    assert res_second["purged_count"] == 0
    assert res_second["freed_bytes"] == 0
    assert "No unlocked recordings eligible" in res_second["message"]


# ==============================================================================
# 3. Active (In-Progress) Recording Immunity
# ==============================================================================

@pytest.mark.asyncio
async def test_active_recording_spared_from_purge(retention_test_env):
    """
    Verifies that a recording session currently in progress (status='recording')
    is NEVER purged by the FIFO cleanup, even if it is unlocked and older than completed clips.
    """
    mgr: StorageManager = retention_test_env["storage_mgr"]
    rec_dir: Path = retention_test_env["rec_dir"]

    f_active = rec_dir / "active_stream.mp4"
    f_active.write_bytes(b"STREAMING_CHUNKS")
    f_comp = rec_dir / "completed.mp4"
    f_comp.write_bytes(b"COMPLETED_CLIP")

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, size_bytes, created_at)
            VALUES ('rec_active', 'cam_adv_1', 'Gate', ?, 'recording', 0, 0, 500, 500, '2026-01-01T00:00:00Z'),
                   ('rec_comp', 'cam_adv_1', 'Gate', ?, 'completed', 0, 0, 500, 500, '2026-01-02T00:00:00Z');
            """,
            (str(f_active), str(f_comp)),
        )
        await conn.commit()

    res = await mgr.run_fifo_purge()
    assert res["purged_count"] == 1

    # rec_comp must be purged, rec_active must survive
    assert not f_comp.exists()
    assert f_active.exists()

    async with get_db() as conn:
        async with conn.execute("SELECT id, status FROM recordings WHERE id = 'rec_active';") as cur:
            row = await cur.fetchone()
            assert row is not None
            assert row["status"] == "recording"


# ==============================================================================
# 4. Filesystem Cleanup and Missing File Resilience
# ==============================================================================

@pytest.mark.asyncio
async def test_thumbnail_unlinked_and_missing_file_resilience(retention_test_env):
    """
    Verifies that:
    1. Both recording file and thumbnail file are deleted during purge.
    2. Missing files on disk do not raise unhandled exceptions during DB row purge.
    """
    mgr: StorageManager = retention_test_env["storage_mgr"]
    rec_dir: Path = retention_test_env["rec_dir"]
    snap_dir: Path = retention_test_env["snap_dir"]

    f_video = rec_dir / "video_with_thumb.mp4"
    f_thumb = snap_dir / "video_with_thumb.jpg"
    f_video.write_bytes(b"VIDEO")
    f_thumb.write_bytes(b"THUMBNAIL")

    f_missing = rec_dir / "already_deleted_by_user.mp4"
    if f_missing.exists():
        f_missing.unlink()

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, thumbnail_path, status, is_locked, is_protected, file_size, size_bytes, created_at)
            VALUES ('rec_with_thumb', 'cam_adv_1', 'Gate', ?, ?, 'completed', 0, 0, 10, 10, '2026-01-01T00:00:00Z'),
                   ('rec_ghost_file', 'cam_adv_1', 'Gate', ?, NULL, 'completed', 0, 0, 20, 20, '2026-01-02T00:00:00Z');
            """,
            (str(f_video), str(f_thumb), str(f_missing)),
        )
        await conn.commit()

    res = await mgr.run_fifo_purge()
    assert res["purged_count"] == 2
    assert not f_video.exists()
    assert not f_thumb.exists()

    async with get_db() as conn:
        async with conn.execute("SELECT count(*) FROM recordings;") as cur:
            count = (await cur.fetchone())[0]
            assert count == 0


# ==============================================================================
# 5. Windows UNC Paths Validation & Fuzzing
# ==============================================================================

def test_unc_path_fuzzing_and_boundary_syntax():
    """
    Fuzzes and validates Windows UNC path detection against multiple boundary cases.
    """
    # Valid UNC patterns
    assert is_unc_path("\\\\nas_server\\cameras\\share") is True
    assert is_unc_path("\\\\192.168.1.200\\nvr_storage") is True
    assert is_unc_path("\\\\server\\share\\nested\\subfolder\\file.mp4") is True
    assert is_unc_path("//nas_server/cameras/share") is True
    assert is_unc_path("//10.0.0.5/cams") is True
    assert is_unc_path("\\\\?\\UNC\\server\\share") is True  # Win32 extended-length UNC

    # Invalid UNC patterns
    assert is_unc_path("C:\\recordings") is False
    assert is_unc_path("D:\\nas\\share") is False
    assert is_unc_path("/mnt/nas/recordings") is False
    assert is_unc_path("recordings/cam1") is False
    assert is_unc_path("./nas_share") is False
    assert is_unc_path("") is False
    assert is_unc_path(None) is False
    assert is_unc_path("\\nas\\share") is False  # single backslash is not UNC
    assert is_unc_path("/nas/share") is False    # single forward slash is not UNC


def test_storage_stats_with_nested_folders(retention_test_env):
    """
    Verifies recursive disk usage calculation on nested recordings and snapshots.
    """
    mgr: StorageManager = retention_test_env["storage_mgr"]
    rec_dir: Path = retention_test_env["rec_dir"]
    snap_dir: Path = retention_test_env["snap_dir"]

    sub_rec = rec_dir / "2026" / "10" / "08"
    sub_rec.mkdir(parents=True, exist_ok=True)
    (sub_rec / "clip1.mp4").write_bytes(b"A" * 4096)
    (sub_rec / "clip2.mp4").write_bytes(b"B" * 2048)

    sub_snap = snap_dir / "thumbs"
    sub_snap.mkdir(parents=True, exist_ok=True)
    (sub_snap / "snap1.jpg").write_bytes(b"C" * 1024)

    stats = mgr.get_storage_stats()
    assert stats["recordings_bytes"] == 6144
    assert stats["snapshots_bytes"] == 1024
    assert stats["total_managed_bytes"] == 7168


# ==============================================================================
# 6. REST API End-to-End Lock, Unlock, Status & Purge Integration
# ==============================================================================

@pytest.mark.asyncio
async def test_rest_api_lock_unlock_and_retention_flow(retention_test_env):
    """
    E2E integration test via FastAPI TestClient:
    1. Lock recording via POST /api/recordings/{id}/lock
    2. Verify status and immunity during POST /api/storage/purge
    3. Unlock recording via POST /api/recordings/{id}/unlock
    4. Verify recording is successfully purged after unlock
    """
    rec_dir: Path = retention_test_env["rec_dir"]
    test_file = rec_dir / "api_test_clip.mp4"
    test_file.write_bytes(b"SAMPLE_VIDEO_DATA")

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, size_bytes, created_at)
            VALUES ('rec_api_test', 'cam_adv_1', 'Gate', ?, 'completed', 0, 0, 17, 17, '2026-01-01T00:00:00Z');
            """,
            (str(test_file),),
        )
        await conn.commit()

    app = create_app()
    client = TestClient(app)

    # 1. Lock recording
    lock_res = client.post("/api/recordings/rec_api_test/lock")
    assert lock_res.status_code == 200
    assert lock_res.json()["is_locked"] is True
    assert lock_res.json()["is_protected"] is True

    # 2. Trigger storage purge
    purge_res1 = client.post("/api/storage/purge")
    assert purge_res1.status_code == 200
    assert purge_res1.json()["purged_count"] == 0
    assert test_file.exists()

    # 3. Unlock recording
    unlock_res = client.post("/api/recordings/rec_api_test/unlock")
    assert unlock_res.status_code == 200
    assert unlock_res.json()["is_locked"] is False
    assert unlock_res.json()["is_protected"] is False

    # 4. Trigger storage purge again
    purge_res2 = client.post("/api/storage/purge")
    assert purge_res2.status_code == 200
    assert purge_res2.json()["purged_count"] == 1
    assert not test_file.exists()


# ==============================================================================
# 7. StorageRetentionWorker Background Tick Quota Evaluation
# ==============================================================================

@pytest.mark.asyncio
async def test_storage_retention_worker_tick_enforcement(retention_test_env):
    """
    Tests StorageRetentionWorker logic when managed storage exceeds MAX_STORAGE_GB.
    """
    mgr: StorageManager = retention_test_env["storage_mgr"]
    rec_dir: Path = retention_test_env["rec_dir"]

    # Insert 3 recordings
    for i in range(3):
        f = rec_dir / f"worker_rec_{i}.mp4"
        f.write_bytes(b"W" * 1000)
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO recordings (id, camera_id, camera_name, file_path, status, is_locked, is_protected, file_size, size_bytes, created_at)
                VALUES (?, 'cam_adv_1', 'Gate', ?, 'completed', 0, 0, 1000, 1000, ?);
                """,
                (f"w_rec_{i}", str(f), f"2026-01-0{i+1}T00:00:00Z"),
            )
            await conn.commit()

    worker = StorageRetentionWorker(manager=mgr, check_interval=0.1)

    # Mock get_storage_stats to simulate quota exceedance (total 3000 bytes, max 1000 bytes)
    mock_stats = {
        "recordings_bytes": 3000,
        "snapshots_bytes": 0,
        "total_managed_bytes": 3000,
        "disk_total_bytes": 100_000,
        "disk_free_bytes": 50_000,
        "disk_used_bytes": 50_000,
        "max_storage_gb": 1000 / (1024**3),  # 1000 bytes allowed
        "min_free_space_gb": 10 / (1024**3),
        "retention_days": 30,
    }

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(mgr, "get_storage_stats", lambda: mock_stats)
        await worker.check_and_enforce_retention()

    # Oldest 2 files (w_rec_0, w_rec_1 = 2000 bytes) should be purged to get <= 1000 bytes
    async with get_db() as conn:
        async with conn.execute("SELECT id FROM recordings ORDER BY id ASC;") as cur:
            remaining = [r["id"] for r in await cur.fetchall()]
            assert remaining == ["w_rec_2"]
