"""
Unit Tests for SQLite WAL Database and Data Models (backend/app/database.py and backend/app/models/)
"""

import os
import pytest
import aiosqlite
from pathlib import Path

from app.database import (
    init_db,
    close_db,
    get_db,
    set_database_path,
    get_database_path,
    check_db_health,
    save_camera,
    get_camera_by_id,
    get_camera_by_stream_id,
    DEFAULT_SETTINGS,
)
from app.models import (
    AccountCreate,
    AccountResponse,
    AccountInDB,
    CameraCreate,
    CameraResponse,
    CameraInDB,
    CanonicalEventType,
    EventCreate,
    EventResponse,
    EventQueryFilter,
    RecordingMetadata,
    SettingItem,
)
from app.vault import encrypt_secret, mask_secret


@pytest.fixture
async def isolated_test_db(tmp_path):
    """Setup and teardown a temporary file-backed SQLite database in WAL mode."""
    db_file = tmp_path / "test_nvr.db"
    set_database_path(db_file)
    await init_db(db_file)
    yield db_file
    await close_db()


@pytest.mark.asyncio
async def test_db_schema_initialization(isolated_test_db):
    """Verify all 5 tables exist and default settings are seeded."""
    async with get_db() as conn:
        # Check tables
        async with conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        ) as cursor:
            tables = [row["name"] for row in await cursor.fetchall()]

        expected_tables = ["accounts", "cameras", "event_logs", "recordings", "system_settings"]
        for expected in expected_tables:
            assert expected in tables, f"Expected table '{expected}' not found in database."

        # Check WAL journal mode
        async with conn.execute("PRAGMA journal_mode;") as cursor:
            journal_mode = (await cursor.fetchone())[0]
            assert journal_mode.lower() == "wal"

        # Check seeded system settings
        async with conn.execute("SELECT count(*) FROM system_settings;") as cursor:
            count = (await cursor.fetchone())[0]
            assert count >= len(DEFAULT_SETTINGS)


@pytest.mark.asyncio
async def test_db_foreign_key_account_cascade_set_null(isolated_test_db):
    """Deleting an account sets camera.account_id to NULL (ON DELETE SET NULL)."""
    async with get_db() as conn:
        # Insert account
        await conn.execute(
            """
            INSERT INTO accounts (id, provider, account_name, encrypted_secret, status)
            VALUES ('acc_01', 'ezviz', 'My EZVIZ Account', 'enc_secret_val', 'active');
            """
        )
        # Insert camera linked to account
        await conn.execute(
            """
            INSERT INTO cameras (id, account_id, name, brand, stream_id, stream_type)
            VALUES ('cam_01', 'acc_01', 'Front Door', 'ezviz', 'stream_front', 'ezviz_cloud');
            """
        )
        await conn.commit()

        # Delete account
        await conn.execute("DELETE FROM accounts WHERE id = 'acc_01';")
        await conn.commit()

        # Camera should still exist with account_id NULL
        async with conn.execute("SELECT account_id, name FROM cameras WHERE id = 'cam_01';") as cursor:
            row = await cursor.fetchone()
            assert row is not None
            assert row["account_id"] is None
            assert row["name"] == "Front Door"


@pytest.mark.asyncio
async def test_db_foreign_key_camera_cascade_delete(isolated_test_db):
    """Deleting a camera cascades deletion to associated event_logs and recordings."""
    async with get_db() as conn:
        # Insert camera
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type)
            VALUES ('cam_cascade', 'Garage Cam', 'generic', 'stream_garage', 'rtsp_local');
            """
        )
        # Insert event log
        await conn.execute(
            """
            INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp)
            VALUES ('evt_01', 'cam_cascade', 'Garage Cam', 'Human', '2026-10-08T04:00:00Z');
            """
        )
        # Insert recording
        await conn.execute(
            """
            INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status)
            VALUES ('rec_01', 'cam_cascade', 'Garage Cam', 'manual', 'recordings/rec_01.mp4', 'rec_01.mp4', '2026-10-08T04:00:00Z', 'completed');
            """
        )
        await conn.commit()

        # Delete camera
        await conn.execute("DELETE FROM cameras WHERE id = 'cam_cascade';")
        await conn.commit()

        # Assert event_logs and recordings are deleted
        async with conn.execute("SELECT count(*) FROM event_logs WHERE camera_id = 'cam_cascade';") as cursor:
            assert (await cursor.fetchone())[0] == 0

        async with conn.execute("SELECT count(*) FROM recordings WHERE camera_id = 'cam_cascade';") as cursor:
            assert (await cursor.fetchone())[0] == 0


@pytest.mark.asyncio
async def test_db_camera_crud_helpers(isolated_test_db):
    """Verify save_camera, get_camera_by_id, and get_camera_by_stream_id helpers."""
    cam_data = {
        "id": "cam_helper_01",
        "name": "Backyard Garden",
        "brand": "xiaomi",
        "model": "C300",
        "ip_address": "192.168.1.120",
        "port": 554,
        "stream_id": "stream_backyard",
        "stream_type": "xiaomi_p2p",
        "has_ptz": True,
        "is_online": True,
        "enabled": True,
        "recording_enabled": False,
    }

    saved = await save_camera(cam_data)
    assert saved["id"] == "cam_helper_01"
    assert saved["name"] == "Backyard Garden"
    assert saved["has_ptz"] == 1

    by_id = await get_camera_by_id("cam_helper_01")
    assert by_id is not None
    assert by_id["stream_id"] == "stream_backyard"

    by_stream = await get_camera_by_stream_id("stream_backyard")
    assert by_stream is not None
    assert by_stream["id"] == "cam_helper_01"

    assert await get_camera_by_id("non_existent_id") is None
    assert await get_camera_by_stream_id("non_existent_stream") is None


@pytest.mark.asyncio
async def test_db_query_plan_indexed(isolated_test_db):
    """Confirm compound index is used for multi-filter event queries."""
    async with get_db() as conn:
        async with conn.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT * FROM event_logs
            WHERE timestamp >= '2026-10-08T00:00:00Z'
              AND event_type = 'Human'
              AND camera_id = 'cam_01'
            ORDER BY timestamp DESC;
            """
        ) as cursor:
            plan = " ".join(row[3] for row in await cursor.fetchall())
            # SQLite query plan should mention an index on event_logs
            assert "idx_event_logs" in plan or "INDEX" in plan


@pytest.mark.asyncio
async def test_db_health_check(isolated_test_db):
    """check_db_health returns 'connected' on an active database."""
    status = await check_db_health()
    assert status == "connected"


def test_pydantic_models_and_zero_leakage():
    """Verify zero secret leakage in response DTOs and strict enum typing."""
    # Account
    raw_secret = "ConfidentialPassword123"
    enc_secret = encrypt_secret(raw_secret)
    account_in_db = AccountInDB(
        id="acc_100",
        provider="ezviz",
        account_name="HQ Office",
        username="admin@domain.com",
        encrypted_secret=enc_secret,
        status="active",
        created_at="2026-10-08T00:00:00Z",
        updated_at="2026-10-08T00:00:00Z",
    )

    account_resp = AccountResponse(
        id=account_in_db.id,
        provider=account_in_db.provider,
        account_name=account_in_db.account_name,
        username=account_in_db.username,
        masked_secret=mask_secret(raw_secret),
        status=account_in_db.status,
        created_at=account_in_db.created_at,
        updated_at=account_in_db.updated_at,
    )
    # Ensure raw secret is not present in response model fields
    assert "secret" not in account_resp.model_dump()
    assert "encrypted_secret" not in account_resp.model_dump()
    assert account_resp.masked_secret == "Con...123"

    # Camera
    camera_resp = CameraResponse(
        id="cam_200",
        name="Lobby Camera",
        brand="generic",
        stream_id="stream_lobby",
        stream_type="generic_rtsp",
        is_online=True,
        has_credentials=True,
        masked_username="adm...tor",
        created_at="2026-10-08T00:00:00Z",
        updated_at="2026-10-08T00:00:00Z",
    )
    assert "password" not in camera_resp.model_dump()
    assert "encrypted_password" not in camera_resp.model_dump()

    # Canonical Event Enum validation
    assert CanonicalEventType.HUMAN.value == "Human"
    assert CanonicalEventType.MOVEMENT.value == "Movement"
    assert CanonicalEventType.ABNORMAL_SOUND.value == "Abnormal Sound"

    with pytest.raises(ValueError):
        CanonicalEventType("UnsupportedEventCategory")
