"""
backend/tests/test_camera_sync.py

Unit tests for CameraSyncService (Orchestrator between cloud providers, SQLite DB, and go2rtc).
"""

import os
import tempfile
import time
import pytest
import aiosqlite

from app.database import set_database_path, init_db, close_db, get_camera_by_id
from app.vault import init_vault, encrypt_secret
from app.services.ezviz_service import ezviz_service
from app.services.xiaomi_service import xiaomi_service
from app.services.camera_sync_service import CameraSyncService, camera_sync_service
from app.services.go2rtc_service import Go2rtcClient
from tests_e2e.mocks.mock_camera_server import MockEZVIZPlatform, MockXiaomiPlatform, MockGo2rtcServer


class InMemoryMockGo2rtcClient:
    """Simulates go2rtc client methods in memory for testing."""
    def __init__(self):
        self.streams = {}

    async def add_stream(self, name: str, src: str) -> bool:
        self.streams[name] = src
        return True

    async def update_stream(self, name: str, src: str) -> bool:
        self.streams[name] = src
        return True

    async def delete_stream(self, name: str) -> bool:
        self.streams.pop(name, None)
        return True


@pytest.fixture(autouse=True)
async def setup_test_db_and_vault(tmp_path):
    """Initializes isolated SQLite DB and Vault before each test."""
    db_file = tmp_path / "test_sync.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_salt"
    key_file = tmp_path / ".test_key"
    init_vault(passphrase="TestMasterPassphrase123!", salt_path=salt_file, master_key_file=key_file)

    yield

    await close_db()


@pytest.fixture
def sync_service_with_mocks():
    mock_ezviz = MockEZVIZPlatform()
    mock_xiaomi = MockXiaomiPlatform()
    mock_go2rtc = InMemoryMockGo2rtcClient()

    from tests.conftest import set_current_mocks
    set_current_mocks(ezviz=mock_ezviz, xiaomi=mock_xiaomi)

    sync_svc = CameraSyncService(go2rtc=mock_go2rtc)
    return sync_svc, mock_ezviz, mock_xiaomi, mock_go2rtc


# ==============================================================================
# Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_sync_ezviz_cloud_account(sync_service_with_mocks, tmp_path):
    """Verifies syncing EZVIZ cloud account fetches devices, saves to DB, and registers streams."""
    sync_svc, mock_ezviz, _, mock_go2rtc = sync_service_with_mocks

    # 1. Insert EZVIZ account into DB
    acc_id = "acc_ezviz_1"
    enc_secret = encrypt_secret(mock_ezviz.app_secret)

    from app.database import get_db
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
            VALUES (?, 'ezviz', 'My EZVIZ Cloud', 'cn', ?, ?, 'active');
            """,
            (acc_id, mock_ezviz.app_key, enc_secret),
        )
        await conn.commit()

    # 2. Execute sync
    synced = await sync_svc.sync_account_cameras(acc_id)
    assert len(synced) >= 2

    # 3. Verify SQLite DB records
    cam1 = await get_camera_by_id("ezviz_F12345678_1")
    assert cam1 is not None
    assert cam1["name"] == "Front Door EZVIZ Cam"
    assert cam1["brand"] == "ezviz"
    assert cam1["device_serial"] == "F12345678"

    # 4. Verify streams registered in go2rtc
    assert cam1["stream_id"] in mock_go2rtc.streams


@pytest.mark.asyncio
async def test_sync_xiaomi_cloud_account(sync_service_with_mocks):
    """Verifies syncing Xiaomi account generates xiaomi:// streams and saves to DB."""
    sync_svc, _, mock_xiaomi, mock_go2rtc = sync_service_with_mocks

    # 1. Insert Xiaomi account into DB
    acc_id = "acc_xiaomi_1"
    enc_secret = encrypt_secret("Secr3tP@ss123")

    from app.database import get_db
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
            VALUES (?, 'xiaomi', 'My Xiaomi Home', 'cn', 'user_china@example.com', ?, 'active');
            """,
            (acc_id, enc_secret),
        )
        await conn.commit()

    # 2. Execute sync
    synced = await sync_svc.sync_account_cameras(acc_id)
    assert len(synced) == 2

    # 3. Verify SQLite DB records
    cam = await get_camera_by_id("xiaomi_xiaomi_cam_001")
    assert cam is not None
    assert cam["name"] == "Living Room Chuangmi IPC"
    assert cam["brand"] == "xiaomi"
    assert cam["stream_type"] == "xiaomi_p2p"

    # 4. Verify go2rtc stream registration
    stream_id = cam["stream_id"]
    assert stream_id in mock_go2rtc.streams
    assert mock_go2rtc.streams[stream_id].startswith("xiaomi://")


@pytest.mark.asyncio
async def test_sync_nonexistent_account_raises_error(sync_service_with_mocks):
    """Verifies syncing non-existent account ID raises ValueError."""
    sync_svc, _, _, _ = sync_service_with_mocks
    with pytest.raises(ValueError) as exc_info:
        await sync_svc.sync_account_cameras("ghost_account_id_999")
    assert "not found" in str(exc_info.value)


@pytest.mark.asyncio
async def test_stream_register_and_unregister(sync_service_with_mocks):
    """Verifies manual register and unregister stream lifecycle."""
    sync_svc, _, _, mock_go2rtc = sync_service_with_mocks

    camera = {
        "stream_id": "stream_test_01",
        "live_url": "rtsp://192.168.1.50:554/live",
    }
    ok = await sync_svc.register_camera_stream(camera)
    assert ok is True
    assert "stream_test_01" in mock_go2rtc.streams

    del_ok = await sync_svc.unregister_camera_stream("stream_test_01")
    assert del_ok is True
    assert "stream_test_01" not in mock_go2rtc.streams
