"""
backend/tests/test_challenger_m2_it3_deep.py

Adversarial Stress & Empirical Challenge Suite for Milestone 2 Iteration 3.
Authored by challenger_m2_it3_1.

Empirical verification scope:
1. ONVIF PTZ SOAP dispatch under `ptz_service_url`, `xaddr`, dual, and absent parameters.
2. Deadman safety watchdog task preservation during rapid bursts (100 sequential moves).
3. Deadman watchdog auto-stop lifecycle, multi-camera isolation, camera deletion resilience, and error handling.
4. Comprehensive PTZ speed validation matrix: non-integers, booleans, strings, nulls, and boundary clamping [1..10].
5. Live PTZ HTTP API invocations across all 10 directions, stop action, and vendor dispatch routing.
6. Re-raising of programming errors (TypeError, AttributeError) to prevent silent swallowing.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List
import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from app.main import app
from app.database import (
    set_database_path,
    init_db,
    close_db,
    get_db,
    get_camera_by_id,
    save_camera,
)
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
async def setup_it3_challenger_env(tmp_path):
    """Sets up completely isolated DB, vault, and mock platforms."""
    db_file = tmp_path / "test_challenger_it3.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_it3_salt"
    key_file = tmp_path / ".test_it3_key"
    init_vault(
        passphrase="ChallengerIt3Passphrase2026!",
        salt_path=salt_file,
        master_key_file=key_file,
    )

    mock_ez = MockEZVIZPlatform()
    mock_mi = MockXiaomiPlatform()
    mock_onvif = MockONVIFDevice()
    set_current_mocks(ezviz=mock_ez, xiaomi=mock_mi, onvif=mock_onvif)

    _ptz_watchdogs.clear()

    yield {
        "mock_ez": mock_ez,
        "mock_mi": mock_mi,
        "mock_onvif": mock_onvif,
    }

    for t in list(_ptz_watchdogs.values()):
        if not t.done():
            t.cancel()
    _ptz_watchdogs.clear()

    await close_db()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# Suite 1: ONVIF SOAP Parameter Polymorphism & Robustness
# ==============================================================================
class TestONVIFParameterPolymorphismAndRobustness:
    """Stress-probes ONVIF continuous_move and stop_ptz signatures."""

    @pytest.mark.asyncio
    async def test_continuous_move_with_ptz_service_url(self):
        """Verifies continuous_move works when passing ptz_service_url."""
        url = "http://192.168.1.200:8085/onvif/ptz_service"
        res = await onvif_service.continuous_move(
            ptz_service_url=url,
            profile_token="Profile_1",
            pan=0.5,
            tilt=0.5,
            zoom=0.0,
        )
        assert res is True

    @pytest.mark.asyncio
    async def test_continuous_move_with_xaddr(self):
        """Verifies continuous_move works when passing xaddr."""
        url = "http://192.168.1.200:8085/onvif/ptz_service"
        res = await onvif_service.continuous_move(
            xaddr=url,
            profile_token="Profile_1",
            pan=-0.5,
            tilt=-0.5,
            zoom=0.0,
        )
        assert res is True

    @pytest.mark.asyncio
    async def test_continuous_move_with_both_parameters(self):
        """Verifies continuous_move prioritizes ptz_service_url or xaddr gracefully."""
        url1 = "http://192.168.1.200:8085/onvif/ptz_service_primary"
        url2 = "http://192.168.1.200:8085/onvif/ptz_service_secondary"
        res = await onvif_service.continuous_move(
            ptz_service_url=url1,
            xaddr=url2,
            profile_token="Profile_1",
            pan=0.0,
            tilt=1.0,
            zoom=0.0,
        )
        assert res is True

    @pytest.mark.asyncio
    async def test_continuous_move_missing_both_raises_error(self):
        """continuous_move with neither URL must raise ONVIFError."""
        with pytest.raises(ONVIFError) as exc_info:
            await onvif_service.continuous_move(
                profile_token="Profile_1",
                pan=0.1,
            )
        assert "ptz_service_url or xaddr is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_stop_ptz_with_ptz_service_url(self):
        """Verifies stop_ptz works when passing ptz_service_url."""
        url = "http://192.168.1.200:8085/onvif/ptz_service"
        res = await onvif_service.stop_ptz(
            ptz_service_url=url,
            profile_token="Profile_1",
        )
        assert res is True

    @pytest.mark.asyncio
    async def test_stop_ptz_with_xaddr(self):
        """Verifies stop_ptz works when passing xaddr."""
        url = "http://192.168.1.200:8085/onvif/ptz_service"
        res = await onvif_service.stop_ptz(
            xaddr=url,
            profile_token="Profile_1",
        )
        assert res is True

    @pytest.mark.asyncio
    async def test_stop_ptz_missing_both_raises_error(self):
        """stop_ptz with neither URL must raise ONVIFError."""
        with pytest.raises(ONVIFError) as exc_info:
            await onvif_service.stop_ptz(
                profile_token="Profile_1",
            )
        assert "ptz_service_url or xaddr is required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_dispatch_vendor_ptz_onvif_move_and_stop_clean(self):
        """Tests that _dispatch_vendor_ptz dispatches ONVIF move and stop without any TypeError."""
        cam = {
            "id": "cam_onvif_it3",
            "brand": "onvif",
            "onvif_xaddr": "http://192.168.1.200:8085/onvif/device_service",
            "onvif_profile_token": "Profile_Token_Main",
            "stream_type": "onvif",
            "has_ptz": True,
        }
        # Continuous move
        await _dispatch_vendor_ptz(cam, direction="down_right", speed=7)
        # Stop
        await _dispatch_vendor_ptz(cam, direction="stop", speed=1)


# ==============================================================================
# Suite 2: Deadman Watchdog Rapid Burst & Task Preservation Stress
# ==============================================================================
class TestDeadmanWatchdogRapidBurstAndPreservation:
    """Stress tests server-side deadman watchdog under rapid burst conditions."""

    @pytest.mark.asyncio
    async def test_watchdog_100_rapid_sequential_move_burst(self):
        """
        Simulates 100 rapid direction changes arriving at ~1ms intervals.
        Verifies that after all cancellations process:
        1. Only the 100th task is stored in _ptz_watchdogs[cam_id].
        2. No previous task's finally block prematurely popped the 100th task.
        3. The 100th task is active and not done.
        """
        cam_id = "cam_burst_100"
        tasks: List[asyncio.Task] = []

        for i in range(100):
            prev = _ptz_watchdogs.get(cam_id)
            if prev and not prev.done():
                prev.cancel()
            t = asyncio.create_task(_deadman_watchdog(cam_id, delay=1.0))
            _ptz_watchdogs[cam_id] = t
            tasks.append(t)
            await asyncio.sleep(0.001)

        # Allow all cancelled tasks to process their cancellation handlers
        await asyncio.sleep(0.05)

        # Assert 100th task is preserved and not cancelled
        active_task = _ptz_watchdogs.get(cam_id)
        assert active_task is not None, "Watchdog task was erroneously popped from dictionary!"
        assert active_task is tasks[-1], "Active watchdog task is not the latest scheduled task!"
        assert not active_task.cancelled(), "Active watchdog task was unexpectedly cancelled!"
        assert not active_task.done(), "Active watchdog task finished prematurely!"

        # Assert all 99 prior tasks are done and cancelled
        for prior_t in tasks[:-1]:
            assert prior_t.done()
            assert prior_t.cancelled()

        # Clean up
        active_task.cancel()

    @pytest.mark.asyncio
    async def test_multi_camera_watchdog_isolation(self):
        """
        Tests 5 concurrent cameras receiving watchdogs.
        Cancelling watchdog for camera 3 must not affect cameras 1, 2, 4, 5.
        """
        cams = [f"cam_iso_{i}" for i in range(5)]
        for c in cams:
            _ptz_watchdogs[c] = asyncio.create_task(_deadman_watchdog(c, delay=0.5))

        assert len(_ptz_watchdogs) == 5

        # Stop camera 2
        task_2 = _ptz_watchdogs.pop(cams[2], None)
        assert task_2 is not None
        task_2.cancel()

        await asyncio.sleep(0.02)

        # Check remaining 4 are intact
        for idx, c in enumerate(cams):
            if idx == 2:
                assert c not in _ptz_watchdogs
            else:
                assert c in _ptz_watchdogs
                assert not _ptz_watchdogs[c].done()

        # Clean up
        for c in cams:
            t = _ptz_watchdogs.pop(c, None)
            if t and not t.done():
                t.cancel()

    @pytest.mark.asyncio
    async def test_watchdog_auto_stop_resilience_on_deleted_camera(self):
        """
        Tests that when watchdog auto-stop triggers on a camera that was deleted in the interim,
        it completes gracefully without crashing the server and unregisters itself.
        """
        cam_id = "cam_deleted_before_autostop"
        # Schedule watchdog with short delay
        t = asyncio.create_task(_deadman_watchdog(cam_id, delay=0.05))
        _ptz_watchdogs[cam_id] = t

        # Wait for watchdog to trigger
        await asyncio.sleep(0.1)

        assert t.done()
        assert cam_id not in _ptz_watchdogs

    @pytest.mark.asyncio
    async def test_watchdog_auto_stop_resilience_on_dispatch_error(self, setup_it3_challenger_env):
        """
        Tests that if _dispatch_vendor_ptz raises during auto-stop,
        watchdog catches it, logs a warning, and still cleans up _ptz_watchdogs.
        """
        env = setup_it3_challenger_env
        mock_ez = env["mock_ez"]

        cam_id = "cam_fault_on_autostop"
        # Save camera with has_ptz=True
        await save_camera({
            "id": cam_id,
            "name": "Fault Cam",
            "brand": "ezviz",
            "device_serial": "FAULTY_SERIAL",
            "has_ptz": True,
            "stream_type": "ezviz_cloud",
        })

        t = asyncio.create_task(_deadman_watchdog(cam_id, delay=0.05))
        _ptz_watchdogs[cam_id] = t

        await asyncio.sleep(0.1)

        assert t.done()
        assert cam_id not in _ptz_watchdogs


# ==============================================================================
# Suite 3: PTZ Speed Parameter Validation & Clamping Matrix
# ==============================================================================
class TestPTZSpeedValidationAndClampingMatrix:
    """Probes all combinations of valid, boundary, and malformed speed inputs."""

    def test_speed_rejections_return_http_400(self, client: TestClient):
        """Verifies non-integer speeds return HTTP 400."""
        res = client.post("/api/cameras", json={"name": "Speed Matrix Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        invalid_speeds = [
            "fast",
            "slow",
            None,
            True,        # Boolean True must NOT be treated as int 1
            False,       # Boolean False must NOT be treated as int 0
            "",
            [],
            {},
            [5],
            "5.5",       # String float cannot be converted via int("5.5")
            "abc",
        ]

        for bad in invalid_speeds:
            r = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": bad})
            assert r.status_code == 400, f"Expected 400 for speed={bad!r}, got {r.status_code}: {r.text}"
            assert "Speed must be an integer between 1 and 10" in r.json()["detail"]

    def test_speed_clamping_matrix(self, client: TestClient):
        """Verifies integer speeds are clamped to range [1..10]."""
        res = client.post("/api/cameras", json={"name": "Clamp Matrix Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        test_cases = [
            (-9999, 1),
            (-1, 1),
            (0, 1),
            (1, 1),
            (2, 2),
            (5, 5),
            (9, 9),
            (10, 10),
            (11, 10),
            (9999, 10),
            ("1", 1),    # Valid integer string
            ("5", 5),
            ("10", 10),
            ("-5", 1),   # Negative integer string clamped
            ("50", 10),  # High integer string clamped
        ]

        for input_spd, expected_clamped in test_cases:
            r = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "right", "speed": input_spd})
            assert r.status_code == 200, f"Failed on input_spd={input_spd!r}: {r.text}"
            assert r.json()["speed"] == expected_clamped, (
                f"Expected speed {expected_clamped} for input {input_spd!r}, got {r.json()['speed']}"
            )


# ==============================================================================
# Suite 4: Live PTZ Direction Matrix & Vendor Dispatch
# ==============================================================================
class TestLivePTZDirectionMatrixAndVendorDispatch:
    """Verifies live PTZ requests for all 10 directions, stop, and error handling."""

    def test_all_10_ptz_directions_live_invocation(self, client: TestClient):
        """Tests all 10 movement directions return expected action and status."""
        res = client.post("/api/cameras", json={
            "name": "Live PTZ Cam",
            "has_ptz": True,
            "brand": "generic",
            "onvif_xaddr": "http://192.168.1.200:8085/onvif/device_service",
            "stream_type": "onvif",
        })
        assert res.status_code == 200
        cam_id = res.json()["id"]

        directions = [
            "up",
            "down",
            "left",
            "right",
            "up_left",
            "up_right",
            "down_left",
            "down_right",
            "zoom_in",
            "zoom_out",
        ]

        for d in directions:
            r = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": d, "speed": 6})
            assert r.status_code == 200
            data = r.json()
            assert data["status"] == "ok"
            assert data["action"] == f"move_{d}"
            assert data["speed"] == 6

        # Stop action
        stop_r = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})
        assert stop_r.status_code == 200
        assert stop_r.json() == {"status": "ok", "action": "stop"}

    def test_ptz_on_non_ptz_camera_rejected_with_400(self, client: TestClient):
        """PTZ control on camera with has_ptz=False returns HTTP 400."""
        res = client.post("/api/cameras", json={"name": "Fixed Dome Cam", "has_ptz": False})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        r = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})
        assert r.status_code == 400
        assert "Camera does not support PTZ" in r.json()["detail"]

    def test_ptz_on_nonexistent_camera_returns_404(self, client: TestClient):
        """PTZ control on nonexistent camera returns HTTP 404."""
        r = client.post("/api/cameras/nonexistent-cam-id-12345/ptz", json={"direction": "up", "speed": 5})
        assert r.status_code == 404


# ==============================================================================
# Suite 5: Exception Propagation Probe (No Silent Swallowing)
# ==============================================================================
class TestPTZExceptionPropagation:
    """Verifies that internal programming errors are not swallowed into false 200 OKs."""

    def test_type_error_in_dispatch_is_reraised(self, client: TestClient, monkeypatch):
        """
        Simulates a TypeError in _dispatch_vendor_ptz to verify lines 520 & 534
        re-raise TypeError rather than masking it as HTTP 200.
        """
        from app.api import cameras

        async def broken_dispatch(cam, direction, speed):
            raise TypeError("Simulated internal argument error")

        monkeypatch.setattr(cameras, "_dispatch_vendor_ptz", broken_dispatch)

        res = client.post("/api/cameras", json={"name": "Crash Probe Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        # When raise_server_exceptions=True, error is propagated out of endpoint as TypeError/ExceptionGroup
        strict_client = TestClient(app, raise_server_exceptions=True)
        with pytest.raises((TypeError, ExceptionGroup)):
            strict_client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})

        with pytest.raises((TypeError, ExceptionGroup)):
            strict_client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})

        # When raise_server_exceptions=False, must result in HTTP 500 (not swallowed into 200)
        resp_move = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 5})
        assert resp_move.status_code == 500

        # Stop command: must result in HTTP 500 (not swallowed into 200)
        resp_stop = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})
        assert resp_stop.status_code == 500
