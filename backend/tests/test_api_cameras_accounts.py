"""
backend/tests/test_api_cameras_accounts.py

Unit and integration tests for Camera and Account REST API routers.
"""

import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import set_database_path, init_db, close_db
from app.vault import init_vault
from app.services.ezviz_service import ezviz_service
from app.services.xiaomi_service import xiaomi_service
from app.services.onvif_service import onvif_service
from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
)


@pytest.fixture(autouse=True)
async def setup_test_environment(tmp_path):
    """Sets up isolated SQLite DB and Vault before each test run."""
    db_file = tmp_path / "test_api.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_salt"
    key_file = tmp_path / ".test_key"
    init_vault(passphrase="TestApiMasterPassphrase999!", salt_path=salt_file, master_key_file=key_file)

    mock_ez = MockEZVIZPlatform()
    mock_mi = MockXiaomiPlatform()
    mock_onvif = MockONVIFDevice()

    from tests.conftest import set_current_mocks
    set_current_mocks(ezviz=mock_ez, xiaomi=mock_mi, onvif=mock_onvif)

    yield

    await close_db()


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# Camera Endpoints Tests
# ==============================================================================

def test_add_and_list_cameras(client):
    """Verifies adding a generic RTSP camera and listing it chronologically."""
    payload = {
        "name": "Warehouse North RTSP",
        "platform": "generic_rtsp",
        "stream_url": "rtsp://192.168.1.99:554/live",
        "ptz_supported": False,
    }
    res = client.post("/api/cameras", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "Warehouse North RTSP"
    assert data["stream_url"] == "rtsp://192.168.1.99:554/live"
    cam_id = data["id"]

    # List cameras
    list_res = client.get("/api/cameras")
    assert list_res.status_code == 200
    cams = list_res.json()
    assert len(cams) >= 1
    assert any(c["id"] == cam_id for c in cams)


def test_get_camera_by_id(client):
    """Verifies retrieving single camera details and 404 for missing ID."""
    add_res = client.post("/api/cameras", json={"name": "Front Cam", "stream_url": "rtsp://front"})
    cam_id = add_res.json()["id"]

    get_res = client.get(f"/api/cameras/{cam_id}")
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "Front Cam"

    # 404 for missing
    missing_res = client.get("/api/cameras/non_existent_cam_xyz")
    assert missing_res.status_code == 404


def test_update_camera(client):
    """Verifies updating camera properties."""
    add_res = client.post("/api/cameras", json={"name": "Old Name", "stream_url": "rtsp://old"})
    cam_id = add_res.json()["id"]

    patch_res = client.patch(f"/api/cameras/{cam_id}", json={"name": "New Name", "stream_url": "rtsp://new"})
    assert patch_res.status_code == 200
    assert patch_res.json()["name"] == "New Name"
    assert patch_res.json()["stream_url"] == "rtsp://new"


def test_delete_camera(client):
    """Verifies deleting camera removes it from database."""
    add_res = client.post("/api/cameras", json={"name": "To Delete", "stream_url": "rtsp://del"})
    cam_id = add_res.json()["id"]

    del_res = client.delete(f"/api/cameras/{cam_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # Confirm it no longer exists
    get_res = client.get(f"/api/cameras/{cam_id}")
    assert get_res.status_code == 404


def test_ptz_control_deadman_stop_and_move(client):
    """Verifies PTZ directional movement, deadman stop, and rejection on fixed camera."""
    # 1. Camera with PTZ enabled
    ptz_res = client.post("/api/cameras", json={"name": "PTZ Cam", "ptz_supported": True})
    ptz_id = ptz_res.json()["id"]

    # Direction move
    move_res = client.post(f"/api/cameras/{ptz_id}/ptz", json={"direction": "up", "speed": 5})
    assert move_res.status_code == 200
    assert move_res.json()["status"] == "ok"
    assert move_res.json()["action"] == "move_up"

    # Stop move
    stop_res = client.post(f"/api/cameras/{ptz_id}/ptz", json={"direction": "stop"})
    assert stop_res.status_code == 200
    assert stop_res.json()["action"] == "stop"

    # 2. Camera without PTZ -> 400 Bad Request
    fixed_res = client.post("/api/cameras", json={"name": "Fixed Cam", "ptz_supported": False})
    fixed_id = fixed_res.json()["id"]
    err_res = client.post(f"/api/cameras/{fixed_id}/ptz", json={"direction": "up"})
    assert err_res.status_code == 400

    # 3. Non-existent camera -> 404
    missing_res = client.post("/api/cameras/ghost_camera_xyz/ptz", json={"direction": "up"})
    assert missing_res.status_code == 404


def test_camera_test_connection(client):
    """Verifies testing RTSP format."""
    res_valid = client.post("/api/cameras/test-connection", json={"stream_url": "rtsp://127.0.0.1:554/live"})
    assert res_valid.status_code == 200
    assert res_valid.json()["valid_format"] is True

    res_invalid = client.post("/api/cameras/test-connection", json={"stream_url": "http://invalid-scheme"})
    assert res_invalid.status_code == 200
    assert res_invalid.json()["valid_format"] is False


def test_onvif_discover_endpoint(client):
    """Verifies /api/onvif/discover endpoint discovers LAN ONVIF devices."""
    res = client.post("/api/onvif/discover")
    assert res.status_code == 200
    devices = res.json()
    assert isinstance(devices, list)
    assert len(devices) >= 1
    assert "xaddrs" in devices[0]


# ==============================================================================
# Account Endpoints Tests
# ==============================================================================

def test_add_and_list_accounts(client):
    """Verifies adding cloud accounts and ensuring secrets are masked."""
    # 1. Add EZVIZ account
    ez_res = client.post("/api/accounts", json={
        "provider": "ezviz",
        "account_name": "My EZVIZ Account",
        "username": "mock_ezviz_app_key_999",
        "secret": "mock_ezviz_secret_888",
        "region": "cn",
    })
    assert ez_res.status_code == 200
    ez_data = ez_res.json()
    assert ez_data["provider"] == "ezviz"
    assert "mock_ezviz_secret_888" not in ez_data["masked_secret"]
    assert "..." in ez_data["masked_secret"] or "*" in ez_data["masked_secret"]
    ez_id = ez_data["id"]

    # 2. Add Xiaomi account
    mi_res = client.post("/api/accounts", json={
        "provider": "xiaomi",
        "account_name": "My Mi Home Account",
        "username": "user_china@example.com",
        "secret": "Secr3tP@ss123",
        "region": "cn",
    })
    assert mi_res.status_code == 200
    mi_data = mi_res.json()
    assert mi_data["provider"] == "xiaomi"
    assert mi_data["status"] == "active"

    # 3. List accounts
    list_res = client.get("/api/accounts")
    assert list_res.status_code == 200
    accs = list_res.json()
    assert len(accs) >= 2


def test_add_invalid_provider_rejected(client):
    """Verifies unsupported provider is rejected with 400 Bad Request."""
    res = client.post("/api/accounts", json={
        "provider": "unsupported_cloud",
        "account_name": "Test",
        "secret": "pass",
    })
    assert res.status_code == 400


def test_delete_account(client):
    """Verifies deleting account removes it from database."""
    add_res = client.post("/api/accounts", json={
        "provider": "ezviz",
        "account_name": "To Delete Acc",
        "secret": "secret",
    })
    acc_id = add_res.json()["id"]

    del_res = client.delete(f"/api/accounts/{acc_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    get_res = client.get(f"/api/accounts/{acc_id}")
    assert get_res.status_code == 404


def test_sync_account_endpoint(client):
    """Verifies /api/accounts/{id}/sync triggers device synchronization."""
    add_res = client.post("/api/accounts", json={
        "provider": "ezviz",
        "account_name": "Sync Test EZVIZ",
        "username": "mock_ezviz_app_key_999",
        "secret": "mock_ezviz_secret_888",
        "region": "cn",
    })
    acc_id = add_res.json()["id"]

    sync_res = client.post(f"/api/accounts/{acc_id}/sync")
    assert sync_res.status_code == 200
    data = sync_res.json()
    assert data["status"] == "success"
    assert data["count"] >= 2
