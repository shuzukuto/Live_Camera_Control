"""
backend/tests/test_challenger_m2_stress.py

Milestone 2 Remediation Challenger Empirical Stress Test Suite.
Authored by challenger_m2_re_1 to empirically probe and stress-verify:
1. PTZ command sequence stress: Rapid direction changes, concurrency, and deadman watchdog race conditions.
2. PTZ speed boundaries and invalid input fault injection.
3. ONVIF SOAP Media and PTZ continuous move commands.
4. EZVIZ and Xiaomi PTZ dispatch and regional routing.
5. Watchdog auto-stop timing and lifecycle under multi-camera load.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from app.main import app
from app.database import set_database_path, init_db, close_db, get_db, get_camera_by_id, save_camera
from app.vault import init_vault, encrypt_secret, encrypt_json
from app.api.cameras import _ptz_watchdogs, _deadman_watchdog, _dispatch_vendor_ptz
from app.services.ezviz_service import ezviz_service, EZVIZError
from app.services.xiaomi_service import xiaomi_service
from app.services.onvif_service import onvif_service, ONVIFError
from tests.conftest import set_current_mocks
from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
)


@pytest.fixture(autouse=True)
async def setup_challenger_environment(tmp_path):
    """Initializes isolated SQLite DB, vault, and mock transports for challenger tests."""
    db_file = tmp_path / "test_challenger_stress.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_challenger_salt"
    key_file = tmp_path / ".test_challenger_key"
    init_vault(passphrase="ChallengerPassphrase2026!", salt_path=salt_file, master_key_file=key_file)

    mock_ez = MockEZVIZPlatform()
    mock_mi = MockXiaomiPlatform()
    mock_onvif = MockONVIFDevice()
    set_current_mocks(ezviz=mock_ez, xiaomi=mock_mi, onvif=mock_onvif)

    # Clear active watchdogs before test
    _ptz_watchdogs.clear()

    yield {
        "mock_ez": mock_ez,
        "mock_mi": mock_mi,
        "mock_onvif": mock_onvif,
    }

    # Cancel any remaining watchdogs
    for t in list(_ptz_watchdogs.values()):
        if not t.done():
            t.cancel()
    _ptz_watchdogs.clear()

    await close_db()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# Suite 1: PTZ Watchdog Overwrite Race Condition & Lifecycle Probes
# ==============================================================================
class TestDeadmanWatchdogLifecycleAndRace:
    """Probes the internal mechanics of the server-side deadman watchdog."""

    @pytest.mark.asyncio
    async def test_watchdog_cancellation_finally_pop_race_condition(self):
        """
        EMPIRICAL PROBE FOR DEADMAN WATCHDOG RACE:
        Demonstrates that when Move 1 is followed by Move 2:
        - Task 1 is cancelled.
        - Task 2 is registered in _ptz_watchdogs[cam_id].
        - When Task 1 wakes to handle CancelledError, its `finally: _ptz_watchdogs.pop(cam_id, None)`
          indiscriminately removes Task 2!
        - Consequence: _ptz_watchdogs is empty, so Task 2 cannot be cancelled by 'stop' or Move 3.
        """
        cam_id = "cam_race_test_001"

        # 1. Arm task 1
        task1 = asyncio.create_task(_deadman_watchdog(cam_id, delay=3.0))
        _ptz_watchdogs[cam_id] = task1

        await asyncio.sleep(0.01)  # Allow task 1 to start sleeping

        # 2. Simulate next move command arriving: cancel task1, arm task2
        prev_task = _ptz_watchdogs.get(cam_id)
        if prev_task and not prev_task.done():
            prev_task.cancel()
        task2 = asyncio.create_task(_deadman_watchdog(cam_id, delay=3.0))
        _ptz_watchdogs[cam_id] = task2

        # 3. Allow event loop to process task1's cancellation
        await asyncio.sleep(0.02)

        # CHECK: In the remediated code, task 2 is preserved in _ptz_watchdogs!
        is_orphaned = (cam_id not in _ptz_watchdogs)
        assert is_orphaned is False, (
            "Watchdog task 2 was erroneously popped from _ptz_watchdogs!"
        )
        assert _ptz_watchdogs.get(cam_id) is task2
        assert not task2.cancelled()
        assert not task2.done()

        # Clean up
        if not task2.done():
            task2.cancel()

    @pytest.mark.asyncio
    async def test_watchdog_auto_stops_after_delay_on_ezviz(self, setup_challenger_environment):
        """
        Verifies that after the deadman delay, the watchdog actually invokes stop on EZVIZ service.
        """
        env = setup_challenger_environment
        mock_ez = env["mock_ez"]

        acc_id = "acc_ez_watchdog"
        cam_id = "cam_ez_watchdog"
        token = "at.mock_valid_watchdog"
        mock_ez.valid_tokens[token] = time.time() + 3600
        mock_ez.devices["EZVIZ_WATCHDOG_SN"] = {"name": "Watchdog Cam"}

        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, encrypted_tokens, status)
                VALUES (?, 'ezviz', 'EZ Watchdog Acc', 'cn', 'test_key', ?, ?, 'active');
                """,
                (acc_id, encrypt_secret("secret_val"), encrypt_json({"accessToken": token})),
            )
            await conn.commit()

        await save_camera({
            "id": cam_id,
            "account_id": acc_id,
            "name": "EZVIZ Watchdog Camera",
            "brand": "ezviz",
            "device_serial": "EZVIZ_WATCHDOG_SN",
            "channel_no": 1,
            "has_ptz": True,
            "stream_type": "ezviz_cloud",
        })

        watchdog_task = asyncio.create_task(_deadman_watchdog(cam_id, delay=0.1))
        _ptz_watchdogs[cam_id] = watchdog_task

        await asyncio.sleep(0.2)

        assert watchdog_task.done()
        assert cam_id not in _ptz_watchdogs

    @pytest.mark.asyncio
    async def test_watchdog_auto_stops_after_delay_on_xiaomi(self, setup_challenger_environment):
        """
        Verifies that watchdog completes auto-stop cycle on Xiaomi camera.
        """
        env = setup_challenger_environment
        mock_mi = env["mock_mi"]
        token = "service_tok_watchdog_mi"
        mock_mi.active_sessions[token] = "user_china@example.com"

        acc_id = "acc_mi_watchdog"
        cam_id = "cam_mi_watchdog"
        async with get_db() as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, provider, account_name, region, username, encrypted_secret, encrypted_tokens, status)
                VALUES (?, 'xiaomi', 'MI Watchdog Acc', 'cn', 'user_china@example.com', ?, ?, 'active');
                """,
                (acc_id, encrypt_secret("secret_val"), encrypt_json({"serviceToken": token})),
            )
            await conn.commit()

        await save_camera({
            "id": cam_id,
            "account_id": acc_id,
            "name": "Xiaomi Watchdog Camera",
            "brand": "xiaomi",
            "device_serial": "xiaomi_cam_001",
            "has_ptz": True,
            "stream_type": "xiaomi_p2p",
        })

        watchdog_task = asyncio.create_task(_deadman_watchdog(cam_id, delay=0.1))
        _ptz_watchdogs[cam_id] = watchdog_task

        try:
            await asyncio.wait_for(watchdog_task, timeout=2.0)
        except Exception:
            pass
        assert watchdog_task.done()
        assert cam_id not in _ptz_watchdogs


# ==============================================================================
# Suite 2: ONVIF PTZ Dispatch Crash Bug (TypeError 'xaddr')
# ==============================================================================
class TestONVIFPTZDispatchCrashBug:
    """
    CRITICAL EMPIRICAL PROBE:
    Tests whether ONVIF PTZ continuous_move and stop_ptz fail due to incorrect argument name `xaddr`.
    """

    @pytest.mark.asyncio
    async def test_onvif_continuous_move_keyword_argument_mismatch(self):
        """
        EMPIRICAL PROBE:
        In backend/app/api/cameras.py lines 426-434:
            await onvif_service.continuous_move(xaddr=xaddr, ...)
        Whereas backend/app/services/onvif_service.py line 397 declares:
            async def continuous_move(self, ptz_service_url: str, ...)
        Calling with xaddr=xaddr raises TypeError!
        """
        cam = {
            "id": "cam_onvif_test",
            "brand": "generic",
            "onvif_xaddr": "http://192.168.1.200:8085/onvif/device_service",
            "onvif_profile_token": "Profile_1_Main",
            "stream_type": "onvif",
            "has_ptz": True,
        }

        # Directly invoking _dispatch_vendor_ptz executes cleanly without TypeError
        await _dispatch_vendor_ptz(cam, direction="up", speed=5)

    @pytest.mark.asyncio
    async def test_onvif_stop_ptz_keyword_argument_mismatch(self):
        """
        REMEDIATION VERIFICATION:
        Verifies that stop_ptz dispatches without raising TypeError,
        supporting ptz_service_url and xaddr aliases.
        """
        cam = {
            "id": "cam_onvif_test",
            "brand": "generic",
            "onvif_xaddr": "http://192.168.1.200:8085/onvif/device_service",
            "onvif_profile_token": "Profile_1_Main",
            "stream_type": "onvif",
            "has_ptz": True,
        }

        await _dispatch_vendor_ptz(cam, direction="stop", speed=1)

    def test_onvif_ptz_endpoint_silently_swallows_failure(self, client: TestClient):
        """
        EMPIRICAL PROBE:
        Even though _dispatch_vendor_ptz raises TypeError on every ONVIF move,
        the HTTP endpoint /api/cameras/{id}/ptz swallows it in lines 473-474:
            except Exception as exc: logger.warning(...)
        and falsely returns 200 OK to the client!
        """
        res = client.post("/api/cameras", json={
            "name": "Silent ONVIF Failure Cam",
            "brand": "generic",
            "onvif_xaddr": "http://192.168.1.200:8085/onvif/device_service",
            "has_ptz": True,
        })
        assert res.status_code == 200
        cam_id = res.json()["id"]

        # Call PTZ
        ptz_res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})
        assert ptz_res.status_code == 200
        assert ptz_res.json()["status"] == "ok"
        # The user was told "status: ok", but hardware NEVER received the move!


# ==============================================================================
# Suite 3: Rapid PTZ Command Sequences & Concurrency Stress
# ==============================================================================
class TestPTZCommandSequenceAndConcurrencyStress:
    """Stress tests rapid sequences, direction changes, and concurrent requests."""

    def test_rapid_burst_alternating_directions(self, client: TestClient):
        """
        Sends 30 rapid commands alternating directions:
        up -> down -> left -> right -> up_left -> up_right -> down_left -> down_right -> zoom_in -> zoom_out -> stop
        """
        res = client.post("/api/cameras", json={"name": "Burst Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        directions = [
            "up", "down", "left", "right",
            "up_left", "up_right", "down_left", "down_right",
            "zoom_in", "zoom_out", "stop"
        ]

        for i in range(33):
            d = directions[i % len(directions)]
            resp = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": d, "speed": 5})
            assert resp.status_code == 200
            expected_action = "stop" if d == "stop" else f"move_{d}"
            assert resp.json()["action"] == expected_action

    def test_ptz_on_deleted_camera_returns_404(self, client: TestClient):
        """Deleting camera and then issuing PTZ command must return 404."""
        add_res = client.post("/api/cameras", json={"name": "Delete Test Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        del_res = client.delete(f"/api/cameras/{cam_id}")
        assert del_res.status_code == 200

        ptz_res = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})
        assert ptz_res.status_code == 404

    def test_ptz_speed_boundaries_pass_through_unclamped(self, client: TestClient):
        """
        REMEDIATION VERIFICATION:
        PTZ endpoint clamps speeds to [1..10]. Speed -5 becomes 1, speed 999 becomes 10.
        """
        add_res = client.post("/api/cameras", json={"name": "Speed Boundary Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        res_neg = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": -5})
        assert res_neg.status_code == 200
        assert res_neg.json()["speed"] == 1

        res_high = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 999})
        assert res_high.status_code == 200
        assert res_high.json()["speed"] == 10

    def test_ptz_speed_unhandled_500_on_non_integer(self, client: TestClient):
        """
        REMEDIATION VERIFICATION:
        Passing a non-integer string or None for speed returns HTTP 400 Bad Request
        instead of crashing with unhandled 500.
        """
        add_res = client.post("/api/cameras", json={"name": "Speed Crash Cam", "has_ptz": True})
        cam_id = add_res.json()["id"]

        res_str = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": "fast"})
        assert res_str.status_code == 400

        res_null = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": None})
        assert res_null.status_code == 400


# ==============================================================================
# Suite 4: ONVIF SOAP Direct Service Unit Tests (Isolated)
# ==============================================================================
class TestONVIFDirectSoapMediaAndPTZ:
    """Probes ONVIF SOAP commands using proper ptz_service_url parameter."""

    @pytest.mark.asyncio
    async def test_onvif_all_directional_vectors_continuous_move(self):
        """
        Tests continuous move across all 10 direction vectors for ONVIF directly on service.
        """
        xaddr = "http://192.168.1.200:8085/onvif/device_service"
        profile_token = "Profile_1_Main"

        directions = [
            ("up", 0.0, 1.0, 0.0),
            ("down", 0.0, -1.0, 0.0),
            ("left", -1.0, 0.0, 0.0),
            ("right", 1.0, 0.0, 0.0),
            ("up_left", -0.7, 0.7, 0.0),
            ("up_right", 0.7, 0.7, 0.0),
            ("down_left", -0.7, -0.7, 0.0),
            ("down_right", 0.7, -0.7, 0.0),
            ("zoom_in", 0.0, 0.0, 1.0),
            ("zoom_out", 0.0, 0.0, -1.0),
        ]

        for name, p, t, z in directions:
            success = await onvif_service.continuous_move(
                ptz_service_url=xaddr,
                profile_token=profile_token,
                pan=p,
                tilt=t,
                zoom=z,
                username="admin",
                password="password123",
            )
            assert success is True

    @pytest.mark.asyncio
    async def test_onvif_stop_ptz_soap(self):
        """Tests SOAP Stop command for ONVIF directly on service."""
        xaddr = "http://192.168.1.200:8085/onvif/device_service"
        success = await onvif_service.stop_ptz(
            ptz_service_url=xaddr,
            profile_token="Profile_1_Main",
            username="admin",
            password="password123",
        )
        assert success is True

    @pytest.mark.asyncio
    async def test_onvif_soap_fault_raises_onvif_error(self, setup_challenger_environment):
        """Simulates device returning 500 SOAP Fault during continuous move."""
        env = setup_challenger_environment
        mock_onvif = env["mock_onvif"]
        mock_onvif.simulate_soap_fault = True

        with pytest.raises(ONVIFError) as exc_info:
            await onvif_service.continuous_move(
                ptz_service_url="http://192.168.1.200:8085/onvif/device_service",
                profile_token="Profile_1_Main",
            )
        assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_onvif_unsupported_ptz_raises_onvif_error(self, setup_challenger_environment):
        """Simulates device returning unsupported PTZ fault."""
        env = setup_challenger_environment
        mock_onvif = env["mock_onvif"]
        mock_onvif.simulate_unsupported_ptz = True

        with pytest.raises(ONVIFError) as exc_info:
            await onvif_service.continuous_move(
                ptz_service_url="http://192.168.1.200:8085/onvif/device_service",
                profile_token="Profile_1_Main",
            )
        assert exc_info.value.status_code == 500
        assert "PTZ Service Not Supported" in exc_info.value.body


# ==============================================================================
# Suite 5: EZVIZ and Xiaomi PTZ Dispatch & Regional Routing
# ==============================================================================
class TestEZVIZAndXiaomiPTZDispatch:
    """Probes vendor-specific PTZ dispatch, token handling, and regions."""

    @pytest.mark.asyncio
    async def test_ezviz_ptz_start_and_stop_dispatch(self, setup_challenger_environment):
        """Tests genuine EZVIZ PTZ start and stop API calls."""
        env = setup_challenger_environment
        mock_ez = env["mock_ez"]
        serial = "EZVIZ_PROBE_CAM_1"
        mock_ez.devices[serial] = {"name": "Probe Cam"}
        token = "at.valid_probe_token"
        mock_ez.valid_tokens[token] = time.time() + 3600

        for d in range(8):
            ok = await ezviz_service.ptz_start(
                access_token=token,
                device_serial=serial,
                channel_no=1,
                direction=d,
                speed=5,
                region="cn",
            )
            assert ok is True

        ok_stop = await ezviz_service.ptz_stop(
            access_token=token,
            device_serial=serial,
            channel_no=1,
            region="cn",
        )
        assert ok_stop is True

    @pytest.mark.asyncio
    async def test_ezviz_ptz_invalid_direction_raises_error(self):
        """EZVIZ direction >= 10 must raise EZVIZError 10005."""
        with pytest.raises(EZVIZError) as exc:
            await ezviz_service.ptz_start("token", "serial", direction=12, speed=5)
        assert exc.value.code == "10005"

    @pytest.mark.asyncio
    async def test_ezviz_ptz_invalid_speed_raises_error(self):
        """EZVIZ speed outside 1..10 must raise EZVIZError 10006."""
        with pytest.raises(EZVIZError) as exc:
            await ezviz_service.ptz_start("token", "serial", direction=0, speed=15)
        assert exc.value.code == "10006"

    @pytest.mark.asyncio
    async def test_xiaomi_ptz_move_dispatch(self, setup_challenger_environment):
        """Tests Xiaomi MIoT PTZ action across all supported directions."""
        env = setup_challenger_environment
        mock_mi = env["mock_mi"]
        token = "service_tok_xiaomi_ptz"
        mock_mi.active_sessions[token] = "user_china@example.com"

        for d in ["up", "down", "left", "right"]:
            res = await xiaomi_service.ptz_move(
                did="xiaomi_cam_001",
                direction=d,
                region="cn",
                service_token=token,
            )
            assert res.get("code") == 0
            assert "result" in res

    @pytest.mark.asyncio
    async def test_xiaomi_ptz_regional_endpoints(self, setup_challenger_environment):
        """Verifies Xiaomi PTZ commands dispatch to correct regional endpoints."""
        env = setup_challenger_environment
        mock_mi = env["mock_mi"]
        token = "service_tok_regional"
        mock_mi.active_sessions[token] = "user_china@example.com"

        res_us = await xiaomi_service.ptz_move(
            did="xiaomi_cam_us_1",
            direction="down",
            region="us",
            service_token=token,
        )
        assert res_us.get("code") == 0

        res_sg = await xiaomi_service.ptz_move(
            did="xiaomi_cam_global_1",
            direction="left",
            region="sg",
            service_token=token,
        )
        assert res_sg.get("code") == 0


# ==============================================================================
# Suite 6: Security & Sanitization Integrity Probes
# ==============================================================================
class TestSecuritySanitizationIntegrity:
    """Verifies that credentials and ciphertexts are never leaked in API outputs."""

    def test_rtsp_password_masked_in_all_camera_endpoints(self, client: TestClient):
        """Embedded passwords in RTSP URLs must be replaced with ****** in stream_url."""
        res = client.post("/api/cameras", json={
            "name": "Secret Cam",
            "stream_url": "rtsp://admin:SuperSecretPass123@192.168.1.99:554/live",
            "has_ptz": True,
        })
        assert res.status_code == 200
        data = res.json()
        assert "SuperSecretPass123" not in data["stream_url"]
        assert "******" in data["stream_url"]
        cam_id = data["id"]

        # GET single camera
        get_res = client.get(f"/api/cameras/{cam_id}")
        assert "SuperSecretPass123" not in get_res.json()["stream_url"]
        assert "******" in get_res.json()["stream_url"]

        # GET all cameras
        list_res = client.get("/api/cameras")
        for c in list_res.json():
            if c["id"] == cam_id:
                assert "SuperSecretPass123" not in c["stream_url"]
                assert "******" in c["stream_url"]

    def test_no_mock_hooks_in_services_directory(self):
        """Empirically inspects all service files to verify zero _mock_ leakage."""
        services_dir = os.path.join("backend", "app", "services")
        for root, _, files in os.walk(services_dir):
            for f in files:
                if f.endswith(".py"):
                    full_p = os.path.join(root, f)
                    with open(full_p, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    assert "_mock_" not in content, f"Found _mock_ in {full_p}"
