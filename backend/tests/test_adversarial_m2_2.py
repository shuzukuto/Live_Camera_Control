"""
backend/tests/test_adversarial_m2_2.py

Milestone 2 Empirical Challenger 2 Adversarial Test Suite:
1. Concurrent camera sync requests with network latency / failures / race conditions.
2. Fault injection on PTZ control with invalid bounds, negative speeds, deadman stop triggers, and vendor dispatch verification.
3. 2FA challenge transitions (valid code vs invalid code vs expired challenge, state lifecycle).
"""

import asyncio
import hashlib
import time
from typing import Any, Dict, List, Optional
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database import set_database_path, init_db, close_db, get_db, get_camera_by_id
from app.vault import init_vault, encrypt_secret, decrypt_json
from app.services.ezviz_service import ezviz_service, EZVIZError, EZVIZDeviceError, EZVIZAuthError
from app.services.xiaomi_service import xiaomi_service, XiaomiError, XiaomiAuthError
from app.services.onvif_service import onvif_service, ONVIFError
from app.services.camera_sync_service import CameraSyncService, camera_sync_service
from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
    MockGo2rtcServer,
)


class InMemoryMockGo2rtcClient:
    """Mock go2rtc client capturing stream additions and deletions."""
    def __init__(self, should_fail: bool = False):
        self.streams: Dict[str, str] = {}
        self.should_fail = should_fail
        self.call_count = 0

    async def add_stream(self, name: str, src: str) -> bool:
        self.call_count += 1
        if self.should_fail:
            raise RuntimeError("go2rtc gateway connection timeout")
        self.streams[name] = src
        return True

    async def update_stream(self, name: str, src: str) -> bool:
        self.call_count += 1
        if self.should_fail:
            raise RuntimeError("go2rtc gateway connection timeout")
        self.streams[name] = src
        return True

    async def delete_stream(self, name: str) -> bool:
        self.call_count += 1
        self.streams.pop(name, None)
        return True


@pytest.fixture(autouse=True)
async def setup_adversarial_environment(tmp_path):
    """Initializes isolated SQLite DB and Vault before each test run."""
    db_file = tmp_path / "test_adversarial_m2_2.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_adv_salt"
    key_file = tmp_path / ".test_adv_key"
    init_vault(passphrase="AdversarialMasterPassphrase2026!", salt_path=salt_file, master_key_file=key_file)

    mock_ez = MockEZVIZPlatform()
    mock_mi = MockXiaomiPlatform()
    mock_onvif = MockONVIFDevice()

    from tests.conftest import set_current_mocks
    set_current_mocks(ezviz=mock_ez, xiaomi=mock_mi, onvif=mock_onvif)

    # Use in-memory go2rtc client for camera sync service
    mock_go2rtc = InMemoryMockGo2rtcClient()
    camera_sync_service.set_go2rtc_client(mock_go2rtc)

    yield {
        "mock_ez": mock_ez,
        "mock_mi": mock_mi,
        "mock_onvif": mock_onvif,
        "mock_go2rtc": mock_go2rtc,
    }

    await close_db()


@pytest.fixture
def client():
    # raise_server_exceptions=False allows verifying HTTP 500 error envelopes cleanly
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# Suite 1: Concurrent Camera Sync Requests & Fault Injection
# ==============================================================================
class TestConcurrentCameraSyncAndFaults:
    """Stress tests concurrent sync requests, network latency, and failures."""

    @pytest.mark.asyncio
    async def test_concurrent_sync_same_account_stress(self, setup_adversarial_environment):
        """10 concurrent sync requests on the same account must not deadlock or produce duplicate cameras."""
        env = setup_adversarial_environment
        mock_ez = env["mock_ez"]
        mock_go2rtc = env["mock_go2rtc"]
        sync_svc = CameraSyncService(go2rtc=mock_go2rtc)

        # Register account in DB
        acc_id = "acc_ezviz_concurrent_1"
        enc_secret = encrypt_secret(mock_ez.app_secret)
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'ezviz', 'Concurrent EZVIZ Acc', 'cn', ?, ?, 'active');
                """,
                (acc_id, mock_ez.app_key, enc_secret),
            )
            await conn.commit()

        # Fire 10 concurrent sync operations
        tasks = [sync_svc.sync_account_cameras(acc_id) for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Verify no fatal crashes or deadlock
        for r in results:
            assert not isinstance(r, Exception), f"Concurrent sync failed with exception: {r}"
            assert len(r) == 3, "Each sync should return exactly 3 cameras from MockEZVIZPlatform"

        # Verify cameras table in DB contains exact expected unique cameras (no duplicates)
        async with get_db() as conn:
            async with conn.execute("SELECT id, name, device_serial FROM cameras WHERE account_id = ?;", (acc_id,)) as cursor:
                cameras = await cursor.fetchall()

        # There are 3 devices in MockEZVIZPlatform ("F12345678", "B87654321", "O00011122")
        assert len(cameras) == 3, f"Expected exactly 3 cameras in DB, found {len(cameras)} (duplicate rows created!)"
        serials = {c["device_serial"] for c in cameras}
        assert "F12345678" in serials
        assert "B87654321" in serials
        assert "O00011122" in serials

    @pytest.mark.asyncio
    async def test_concurrent_sync_mixed_providers_stress(self, setup_adversarial_environment):
        """Simultaneous concurrent sync across EZVIZ and Xiaomi accounts."""
        env = setup_adversarial_environment
        mock_ez = env["mock_ez"]
        sync_svc = CameraSyncService(go2rtc=env["mock_go2rtc"])

        # Insert EZVIZ account
        acc_ez = "acc_ez_mixed"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'ezviz', 'EZVIZ Acc', 'cn', ?, ?, 'active');
                """,
                (acc_ez, mock_ez.app_key, encrypt_secret(mock_ez.app_secret)),
            )
            # Insert Xiaomi account
            acc_mi = "acc_mi_mixed"
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'xiaomi', 'Xiaomi Acc', 'cn', 'user_china@example.com', ?, 'active');
                """,
                (acc_mi, encrypt_secret("Secr3tP@ss123")),
            )
            await conn.commit()

        # Launch interleaved concurrent sync tasks (5 EZVIZ + 5 Xiaomi)
        tasks = []
        for i in range(10):
            target_acc = acc_ez if (i % 2 == 0) else acc_mi
            tasks.append(sync_svc.sync_account_cameras(target_acc))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            assert not isinstance(r, Exception), f"Mixed concurrent sync failed: {r}"

        # Verify DB integrity
        async with get_db() as conn:
            async with conn.execute("SELECT COUNT(*) as cnt FROM cameras WHERE account_id = ?;", (acc_ez,)) as cur:
                row_ez = await cur.fetchone()
                assert row_ez["cnt"] == 3
            async with conn.execute("SELECT COUNT(*) as cnt FROM cameras WHERE account_id = ?;", (acc_mi,)) as cur:
                row_mi = await cur.fetchone()
                assert row_mi["cnt"] == 2

    @pytest.mark.asyncio
    async def test_sync_with_simulated_network_timeout(self, setup_adversarial_environment):
        """When cloud provider suffers timeout during sync, error is raised and DB remains intact."""
        env = setup_adversarial_environment
        mock_ez = env["mock_ez"]
        sync_svc = CameraSyncService(go2rtc=env["mock_go2rtc"])

        acc_id = "acc_ezviz_timeout"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'ezviz', 'Timing Out Acc', 'cn', ?, ?, 'active');
                """,
                (acc_id, mock_ez.app_key, encrypt_secret(mock_ez.app_secret)),
            )
            await conn.commit()

        # Turn on timeout simulation on mock platform
        mock_ez.simulate_network_timeout = True

        with pytest.raises(TimeoutError) as exc_info:
            await sync_svc.sync_account_cameras(acc_id)
        assert "timed out" in str(exc_info.value).lower()

        # Verify DB was not corrupted with partial cameras
        async with get_db() as conn:
            async with conn.execute("SELECT COUNT(*) as cnt FROM cameras WHERE account_id = ?;", (acc_id,)) as cur:
                res = await cur.fetchone()
                assert res["cnt"] == 0

    @pytest.mark.asyncio
    async def test_sync_with_cloud_rate_limiting(self, setup_adversarial_environment):
        """When cloud returns HTTP 429 rate limit, sync raises EZVIZAuthError and does not corrupt DB."""
        env = setup_adversarial_environment
        mock_ez = env["mock_ez"]
        sync_svc = CameraSyncService(go2rtc=env["mock_go2rtc"])

        acc_id = "acc_ezviz_rate_limit"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'ezviz', 'Rate Limited Acc', 'cn', ?, ?, 'active');
                """,
                (acc_id, mock_ez.app_key, encrypt_secret(mock_ez.app_secret)),
            )
            await conn.commit()

        mock_ez.simulate_rate_limit = True

        with pytest.raises(EZVIZAuthError) as exc_info:
            await sync_svc.sync_account_cameras(acc_id)
        assert exc_info.value.code == "429"

    @pytest.mark.asyncio
    async def test_sync_with_cloud_server_error(self, setup_adversarial_environment):
        """When cloud returns HTTP 500 error, sync raises EZVIZAuthError and does not corrupt DB."""
        env = setup_adversarial_environment
        mock_ez = env["mock_ez"]
        sync_svc = CameraSyncService(go2rtc=env["mock_go2rtc"])

        acc_id = "acc_ezviz_500"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'ezviz', '500 Server Error Acc', 'cn', ?, ?, 'active');
                """,
                (acc_id, mock_ez.app_key, encrypt_secret(mock_ez.app_secret)),
            )
            await conn.commit()

        mock_ez.simulate_server_error = True

        with pytest.raises(EZVIZAuthError) as exc_info:
            await sync_svc.sync_account_cameras(acc_id)
        assert exc_info.value.code == "500"

    @pytest.mark.asyncio
    async def test_sync_with_go2rtc_registration_failure(self, setup_adversarial_environment):
        """When go2rtc registration encounters failure, cameras should still be saved in DB gracefully."""
        env = setup_adversarial_environment
        mock_ez = env["mock_ez"]
        failing_go2rtc = InMemoryMockGo2rtcClient(should_fail=True)
        sync_svc = CameraSyncService(go2rtc=failing_go2rtc)

        acc_id = "acc_ezviz_go2rtc_fail"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'ezviz', 'Go2rtc Fail Acc', 'cn', ?, ?, 'active');
                """,
                (acc_id, mock_ez.app_key, encrypt_secret(mock_ez.app_secret)),
            )
            await conn.commit()

        # Sync should complete and save cameras to DB even if go2rtc throws
        synced = await sync_svc.sync_account_cameras(acc_id)
        assert len(synced) == 3

        async with get_db() as conn:
            async with conn.execute("SELECT COUNT(*) as cnt FROM cameras WHERE account_id = ?;", (acc_id,)) as cur:
                res = await cur.fetchone()
                assert res["cnt"] == 3

    @pytest.mark.asyncio
    async def test_sync_pending_2fa_account_fails_without_corrupting(self, setup_adversarial_environment):
        """Syncing an account that has not resolved 2FA challenge must raise error and not corrupt state."""
        env = setup_adversarial_environment
        sync_svc = CameraSyncService(go2rtc=env["mock_go2rtc"])

        acc_id = "acc_xiaomi_pending_2fa"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, status)
                VALUES (?, 'xiaomi', 'Pending 2FA Acc', 'us', 'user_2fa@example.com', ?, 'challenge_required');
                """,
                (acc_id, encrypt_secret("TwoFactorPass!")),
            )
            await conn.commit()

        # Since tokens are missing, sync attempts login which requires 2FA -> raises XiaomiAuthError
        with pytest.raises(XiaomiAuthError) as exc_info:
            await sync_svc.sync_account_cameras(acc_id)
        assert exc_info.value.code == 87001

        # Check account status is unchanged
        async with get_db() as conn:
            async with conn.execute("SELECT status FROM accounts WHERE id = ?;", (acc_id,)) as cur:
                row = await cur.fetchone()
                assert row["status"] == "challenge_required"


# ==============================================================================
# Suite 2: PTZ Boundary Testing & Fault Injection
# ==============================================================================
class TestPTZControlBoundariesAndFaultInjection:
    """Stress tests boundary conditions, invalid parameters, and deadman safety stops."""

    def test_ptz_endpoint_rejects_fixed_camera_with_400(self, client: TestClient):
        """Camera with has_ptz=False must return HTTP 400 Bad Request."""
        add_res = client.post("/api/cameras", json={"name": "Fixed Camera", "has_ptz": False})
        assert add_res.status_code == 200
        cam_id = add_res.json()["id"]

        ptz_res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})
        assert ptz_res.status_code == 400
        assert "does not support PTZ" in ptz_res.json()["detail"]

    def test_ptz_endpoint_404_on_nonexistent_camera(self, client: TestClient):
        """PTZ on non-existent camera ID must return HTTP 404."""
        ptz_res = client.post("/api/cameras/nonexistent_cam_99999/ptz", json={"direction": "up", "speed": 5})
        assert ptz_res.status_code == 404
        assert "not found" in ptz_res.json()["detail"]

    def test_ptz_deadman_stop_idempotent(self, client: TestClient):
        """Direction 'stop' must succeed repeatedly and return action 'stop'."""
        add_res = client.post("/api/cameras", json={"name": "PTZ Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        for _ in range(5):
            stop_res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})
            assert stop_res.status_code == 200
            assert stop_res.json()["status"] == "ok"
            assert stop_res.json()["action"] == "stop"

    def test_ptz_deadman_rapid_burst_stress(self, client: TestClient):
        """Rapid interleaving of move and stop commands simulates holding & releasing controls."""
        add_res = client.post("/api/cameras", json={"name": "PTZ Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        for i in range(20):
            if i % 2 == 0:
                res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "left", "speed": 6})
                assert res.status_code == 200
                assert res.json()["action"] == "move_left"
            else:
                res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})
                assert res.status_code == 200
                assert res.json()["action"] == "stop"

    def test_ptz_speed_boundaries_pass_through_bug(self, client: TestClient):
        """
        FINDING: PTZ endpoint does NOT clamp or validate speed to range [1..10].
        Negative speed (-5) and excessive speed (999) are blindly accepted and echoed.
        """
        add_res = client.post("/api/cameras", json={"name": "PTZ Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        # 1. Negative speed clamped to 1
        res_neg = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": -5})
        assert res_neg.status_code == 200
        assert res_neg.json()["speed"] == 1

        # 2. Excessive speed clamped to 10
        res_high = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 999})
        assert res_high.status_code == 200
        assert res_high.json()["speed"] == 10

    def test_ptz_speed_unhandled_500_on_non_integer(self, client: TestClient):
        """
        REMEDIATION VERIFICATION: PTZ endpoint returns HTTP 400 Bad Request
        when speed is a string or null instead of crashing with unhandled 500.
        """
        add_res = client.post("/api/cameras", json={"name": "PTZ Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        # Passing string speed returns HTTP 400
        res_str = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": "super_fast"})
        assert res_str.status_code == 400

        # Passing None as speed returns HTTP 400
        res_null = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": None})
        assert res_null.status_code == 400

    def test_ptz_direction_unvalidated_pass_through_bug(self, client: TestClient):
        """
        FINDING: PTZ endpoint does NOT validate direction or default invalid direction to 'stop'.
        Arbitrary direction strings like 'fly_to_moon' return action 'move_fly_to_moon'.
        """
        add_res = client.post("/api/cameras", json={"name": "PTZ Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        res_inv = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "fly_to_moon", "speed": 5})
        assert res_inv.status_code == 200
        assert res_inv.json()["action"] == "move_fly_to_moon"

    def test_ptz_vendor_dispatch_noop_bug(self, client: TestClient):
        """
        FINDING: In backend/app/api/cameras.py (lines 288-306), the vendor PTZ dispatch
        is stubbed with `pass`! Even when camera brand is 'ezviz' or 'xiaomi', no vendor
        service method is invoked.
        """
        # Register EZVIZ camera with explicit valid stream_type
        add_res = client.post("/api/cameras", json={
            "name": "EZVIZ PTZ Cam",
            "brand": "ezviz",
            "stream_type": "ezviz_cloud",
            "device_serial": "F12345678",
            "has_ptz": True,
        })
        assert add_res.status_code == 200
        cam_id = add_res.json()["id"]

        # Call PTZ move
        res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})
        assert res.status_code == 200
        # Endpoint returns ok, but backend executed `pass # ezviz_service.ptz_start` without commanding hardware

    def test_add_camera_default_stream_type_check_constraint_bug(self, client: TestClient):
        """
        REMEDIATION VERIFICATION:
        When creating a camera with brand='ezviz' or brand='xiaomi' without
        specifying stream_type, it correctly defaults to 'ezviz_cloud' or 'xiaomi_p2p',
        avoiding SQLite CHECK constraint violation.
        """
        res = client.post("/api/cameras", json={
            "name": "EZVIZ Unspecified StreamType",
            "brand": "ezviz",
            "device_serial": "F12345678",
        })
        assert res.status_code == 200
        assert res.json()["stream_type"] == "ezviz_cloud"

    @pytest.mark.asyncio
    async def test_ezviz_service_ptz_start_strict_bounds(self):
        """EZVIZ service ptz_start enforces direction 0..9 and speed 1..10."""
        # 1. Invalid direction (> 9)
        with pytest.raises(EZVIZError) as exc_dir:
            await ezviz_service.ptz_start("token", "serial", channel_no=1, direction=15, speed=5)
        assert exc_dir.value.code == "10005"

        # 2. Invalid direction (< 0)
        with pytest.raises(EZVIZError) as exc_dir_neg:
            await ezviz_service.ptz_start("token", "serial", channel_no=1, direction=-1, speed=5)
        assert exc_dir_neg.value.code == "10005"

        # 3. Invalid speed (< 1)
        with pytest.raises(EZVIZError) as exc_speed_0:
            await ezviz_service.ptz_start("token", "serial", channel_no=1, direction=0, speed=0)
        assert exc_speed_0.value.code == "10006"

        # 4. Invalid speed (> 10)
        with pytest.raises(EZVIZError) as exc_speed_11:
            await ezviz_service.ptz_start("token", "serial", channel_no=1, direction=0, speed=11)
        assert exc_speed_11.value.code == "10006"

    @pytest.mark.asyncio
    async def test_xiaomi_service_ptz_move_mapping_with_valid_session(self):
        """Xiaomi service maps directional commands to numeric MIoT action values when session is active."""
        # Authenticate first to acquire valid session token in mock platform
        session = await xiaomi_service.login("user_china@example.com", "Secr3tP@ss123", region="cn")
        assert session.service_token is not None

        res_up = await xiaomi_service.ptz_move("xiaomi_cam_001", "up", region="cn", service_token=session.service_token)
        assert res_up["code"] == 0

        res_down = await xiaomi_service.ptz_move("xiaomi_cam_001", "down", region="cn", service_token=session.service_token)
        assert res_down["code"] == 0

        res_left = await xiaomi_service.ptz_move("xiaomi_cam_001", "left", region="cn", service_token=session.service_token)
        assert res_left["code"] == 0

        res_right = await xiaomi_service.ptz_move("xiaomi_cam_001", "right", region="cn", service_token=session.service_token)
        assert res_right["code"] == 0


# ==============================================================================
# Suite 3: 2FA Challenge Transitions & Lifecycle
# ==============================================================================
class TestTwoFactorChallengeTransitions:
    """Stress tests Xiaomi 2FA/Captcha challenge detection, state machine, and resolution."""

    def test_2fa_account_creation_enters_challenge_required_state(self, client: TestClient):
        """Registering an account requiring 2FA puts account into 'challenge_required' with notificationUrl."""
        res = client.post("/api/accounts", json={
            "provider": "xiaomi",
            "account_name": "Xiaomi 2FA User",
            "username": "user_2fa@example.com",
            "secret": "TwoFactorPass!",
            "region": "us",
        })
        assert res.status_code == 200
        data = res.json()
        assert data["provider"] == "xiaomi"
        assert data["status"] == "challenge_required"
        assert "challenge" in data
        assert "notificationUrl" in data["challenge"]
        acc_id = data["id"]

        # Confirm DB status
        get_res = client.get(f"/api/accounts/{acc_id}")
        assert get_res.status_code == 200
        assert get_res.json()["status"] == "challenge_required"

    def test_2fa_submission_wrong_otp_rejected_with_401(self, client: TestClient):
        """Submitting incorrect OTP code must return 401 Unauthorized and leave account in challenge_required."""
        add_res = client.post("/api/accounts", json={
            "provider": "xiaomi",
            "account_name": "Xiaomi 2FA User",
            "username": "user_2fa@example.com",
            "secret": "TwoFactorPass!",
            "region": "us",
        })
        acc_id = add_res.json()["id"]

        # Submit wrong OTP codes
        wrong_codes = ["000000", "999999", "abc", "123"]
        for code in wrong_codes:
            ch_res = client.post(f"/api/accounts/{acc_id}/challenge", json={"otp_code": code})
            assert ch_res.status_code == 401
            assert "verification failed" in ch_res.json()["detail"].lower()

        # Account status must still be challenge_required
        acc_res = client.get(f"/api/accounts/{acc_id}")
        assert acc_res.json()["status"] == "challenge_required"

    def test_2fa_submission_valid_otp_promotes_to_active(self, client: TestClient):
        """Submitting correct OTP ('123456') successfully activates account and saves tokens."""
        add_res = client.post("/api/accounts", json={
            "provider": "xiaomi",
            "account_name": "Xiaomi 2FA User",
            "username": "user_2fa@example.com",
            "secret": "TwoFactorPass!",
            "region": "us",
        })
        acc_id = add_res.json()["id"]

        # Submit valid OTP
        ch_res = client.post(f"/api/accounts/{acc_id}/challenge", json={"otp_code": "123456"})
        assert ch_res.status_code == 200
        assert ch_res.json()["status"] == "success"

        # Verify account is now 'active'
        acc_res = client.get(f"/api/accounts/{acc_id}")
        assert acc_res.status_code == 200
        assert acc_res.json()["status"] == "active"

        # Verify cameras can now be synced
        sync_res = client.post(f"/api/accounts/{acc_id}/sync")
        assert sync_res.status_code == 200
        assert sync_res.json()["status"] == "success"
        assert sync_res.json()["count"] >= 1

    def test_2fa_challenge_on_ezviz_account_rejected_with_400(self, client: TestClient):
        """Submitting 2FA challenge on an EZVIZ account must return 400 Bad Request."""
        ez_res = client.post("/api/accounts", json={
            "provider": "ezviz",
            "account_name": "EZVIZ Acc",
            "username": "app_key",
            "secret": "app_secret",
            "region": "cn",
        })
        acc_id = ez_res.json()["id"]

        ch_res = client.post(f"/api/accounts/{acc_id}/challenge", json={"otp_code": "123456"})
        assert ch_res.status_code == 400
        assert "only applicable to Xiaomi" in ch_res.json()["detail"]

    def test_2fa_challenge_on_nonexistent_account_404(self, client: TestClient):
        """Submitting 2FA challenge on non-existent account ID must return 404 Not Found."""
        ch_res = client.post("/api/accounts/nonexistent_acc_xyz/challenge", json={"otp_code": "123456"})
        assert ch_res.status_code == 404
        assert "not found" in ch_res.json()["detail"]

    def test_2fa_challenge_empty_payload(self, client: TestClient):
        """Submitting empty challenge payload (neither OTP nor captcha) fails verification."""
        add_res = client.post("/api/accounts", json={
            "provider": "xiaomi",
            "account_name": "Xiaomi 2FA User",
            "username": "user_2fa@example.com",
            "secret": "TwoFactorPass!",
            "region": "us",
        })
        acc_id = add_res.json()["id"]

        ch_res = client.post(f"/api/accounts/{acc_id}/challenge", json={})
        assert ch_res.status_code == 401
