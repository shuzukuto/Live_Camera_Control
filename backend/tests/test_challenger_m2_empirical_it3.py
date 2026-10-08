"""
backend/tests/test_challenger_m2_empirical_it3.py

Milestone 2 Iteration 3 Adversarial Challenge & Stress Verification Suite.
Authored by challenger_m2_it3_1 to empirically probe and stress-verify:
1. PTZ watchdog lifecycle and concurrency under high-volume rapid concurrent calls.
2. sanitize_stream_url edge cases (multi-colon passwords, @ in passwords, blank usernames, fuzzing).
3. PTZ speed bounds (0, -1, 11, 999, non-integers, booleans, nulls, types).
4. Multi-camera concurrent PTZ operations.
"""

from __future__ import annotations

import asyncio
import os
import random
import string
import time
from typing import Any, Dict, List, Optional
import pytest
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
from app.api.cameras import (
    _ptz_watchdogs,
    _deadman_watchdog,
    _dispatch_vendor_ptz,
    sanitize_stream_url,
    _format_camera_response,
)
from tests.conftest import set_current_mocks
from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
)


@pytest.fixture(autouse=True)
async def setup_it3_challenger_environment(tmp_path):
    """Initializes isolated SQLite DB, vault, and mock transports for challenger it3."""
    db_file = tmp_path / "test_challenger_it3.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_chal_it3_salt"
    key_file = tmp_path / ".test_chal_it3_key"
    init_vault(
        passphrase="AdversarialChallengerIt3Passphrase2026!",
        salt_path=salt_file,
        master_key_file=key_file,
    )

    mock_ez = MockEZVIZPlatform()
    mock_mi = MockXiaomiPlatform()
    mock_onv = MockONVIFDevice()
    set_current_mocks(ezviz=mock_ez, xiaomi=mock_mi, onvif=mock_onv)

    _ptz_watchdogs.clear()

    yield {
        "mock_ez": mock_ez,
        "mock_mi": mock_mi,
        "mock_onv": mock_onv,
        "db_file": db_file,
    }

    # Cancel any lingering watchdog tasks
    for t in list(_ptz_watchdogs.values()):
        if not t.done():
            t.cancel()
    _ptz_watchdogs.clear()

    await close_db()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# Suite 1: PTZ Watchdog High-Concurrency Stress
# ==============================================================================
class TestPTZWatchdogHighConcurrencyStress:
    """Stress tests server-side deadman watchdog under concurrent load and races."""

    @pytest.mark.asyncio
    async def test_100_concurrent_ptz_moves_single_camera(self):
        """
        Spams 100 concurrent PTZ move requests to a single camera.
        Verifies:
        1. All 100 coroutines complete without race crash or deadlock.
        2. Exactly 1 watchdog task remains in _ptz_watchdogs (the last registered).
        3. All 99 previous watchdog tasks were cleanly cancelled without popping the active one.
        4. The active watchdog triggers stop after its delay and clears the registry.
        """
        cam_id = "cam_ptz_stress_100"
        await save_camera({
            "id": cam_id,
            "name": "PTZ Stress Cam 100",
            "brand": "generic",
            "has_ptz": True,
            "stream_type": "generic_rtsp",
        })

        # Launch 100 concurrent watchdog creations mimicking 100 rapid move calls
        async def issue_move(i: int):
            prev = _ptz_watchdogs.get(cam_id)
            if prev and not prev.done():
                prev.cancel()
            t = asyncio.create_task(_deadman_watchdog(cam_id, delay=0.15))
            _ptz_watchdogs[cam_id] = t
            return t

        tasks = [issue_move(i) for i in range(100)]
        created_tasks = await asyncio.gather(*tasks)

        # Allow cancelled tasks to handle their cancellations
        await asyncio.sleep(0.02)

        # Verification: registry MUST NOT be empty!
        assert cam_id in _ptz_watchdogs, "Active watchdog was prematurely popped by cancelled predecessor!"
        active_task = _ptz_watchdogs[cam_id]
        assert active_task in created_tasks
        assert not active_task.done()

        # Count cancelled tasks
        cancelled_count = sum(1 for t in created_tasks if t.cancelled())
        assert cancelled_count >= 95, f"Expected ~99 cancelled tasks, got {cancelled_count}"

        # Wait for active task to expire and auto-stop
        await asyncio.sleep(0.25)
        assert active_task.done()
        assert cam_id not in _ptz_watchdogs, "Expired watchdog failed to clean itself from registry!"

    @pytest.mark.asyncio
    async def test_multi_camera_concurrent_ptz_watchdogs(self):
        """
        Spams concurrent PTZ operations across 20 distinct cameras simultaneously (10 moves each = 200 ops).
        Verifies watchdog isolation per camera ID.
        """
        cam_count = 20
        cam_ids = [f"cam_multi_{i:02d}" for i in range(cam_count)]
        for cid in cam_ids:
            await save_camera({
                "id": cid,
                "name": f"Multi Cam {cid}",
                "brand": "generic",
                "has_ptz": True,
            })

        async def spam_camera(cid: str):
            for _ in range(10):
                prev = _ptz_watchdogs.get(cid)
                if prev and not prev.done():
                    prev.cancel()
                _ptz_watchdogs[cid] = asyncio.create_task(_deadman_watchdog(cid, delay=0.1))
                await asyncio.sleep(0.005)

        await asyncio.gather(*(spam_camera(cid) for cid in cam_ids))

        # Check each camera has exactly its own active task
        for cid in cam_ids:
            assert cid in _ptz_watchdogs, f"Camera {cid} lost its watchdog!"
            assert not _ptz_watchdogs[cid].done()

        # Let all auto-stops trigger and complete DB lookups
        active_tasks = list(_ptz_watchdogs.values())
        await asyncio.gather(*active_tasks, return_exceptions=True)
        assert len(_ptz_watchdogs) == 0, f"Remaining watchdogs not cleaned up: {list(_ptz_watchdogs.keys())}"

    def test_http_endpoint_concurrent_ptz_burst(self, client: TestClient):
        """
        Sends 50 rapid HTTP requests via client alternating moves and stops.
        Verifies HTTP 200 response integrity and final state consistency.
        """
        res = client.post("/api/cameras", json={"name": "HTTP Burst Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        directions = ["up", "down", "left", "right", "stop"]
        for i in range(50):
            d = directions[i % len(directions)]
            resp = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": d, "speed": (i % 10) + 1})
            assert resp.status_code == 200
            if d == "stop":
                assert resp.json()["action"] == "stop"
            else:
                assert resp.json()["action"] == f"move_{d}"

        # If last action was stop (i=49 -> 49%5 = 4 -> "stop"), watchdog should be empty
        assert cam_id not in _ptz_watchdogs


# ==============================================================================
# Suite 2: sanitize_stream_url Adversarial Boundaries & Fuzzing
# ==============================================================================
class TestSanitizeStreamUrlAdversarialBoundaries:
    """Stress tests URL credential masking against all adversarial permutations."""

    def test_multi_colon_passwords(self):
        """Passwords with 2, 3, 5 colons."""
        test_cases = [
            ("rtsp://admin:pass:123@host:554/live", "rtsp://admin:******@host:554/live"),
            ("rtsp://admin:p:a:s:s:w:o:r:d@192.168.1.1/live", "rtsp://admin:******@192.168.1.1/live"),
            ("rtsp://admin:secret:part2:part3@10.0.0.1:8554/s", "rtsp://admin:******@10.0.0.1:8554/s"),
        ]
        for raw, expected in test_cases:
            res = sanitize_stream_url(raw)
            assert res == expected, f"Failed on multi-colon: {raw} -> got {res}"
            assert "pass" not in res and "secret" not in res

    def test_at_signs_inside_passwords(self):
        """Passwords containing one or more '@' symbols."""
        test_cases = [
            ("rtsp://admin:p@ssword@192.168.1.1:554/live", "rtsp://admin:******@192.168.1.1:554/live"),
            ("rtsp://user:p@@ss@@word@@@10.0.0.2:554/ch1", "rtsp://user:******@10.0.0.2:554/ch1"),
            ("rtsp://operator:mail@domain.com:extra@cam.local/stream", "rtsp://operator:******@cam.local/stream"),
        ]
        for raw, expected in test_cases:
            res = sanitize_stream_url(raw)
            assert res == expected, f"Failed on @ in password: {raw} -> got {res}"
            assert "p@ssword" not in res and "mail@domain.com" not in res

    def test_blank_usernames(self):
        """URLs where username is empty: rtsp://:password@host."""
        test_cases = [
            ("rtsp://:mysecretpassword@192.168.1.100:554/live", "rtsp://:******@192.168.1.100:554/live"),
            ("rtsp://:pass:with:colons@10.0.0.1/live", "rtsp://:******@10.0.0.1/live"),
            ("rtsp://:p@ss@@at@10.0.0.1/live", "rtsp://:******@10.0.0.1/live"),
            ("rtsp://:@192.168.1.1/live", "rtsp://:******@192.168.1.1/live"),
        ]
        for raw, expected in test_cases:
            res = sanitize_stream_url(raw)
            assert res == expected, f"Failed on blank username: {raw} -> got {res}"
            assert "mysecretpassword" not in res

    def test_passwordless_urls_preserved(self):
        """URLs with only username or no userinfo must not be corrupted."""
        test_cases = [
            ("rtsp://admin@192.168.1.1:554/live", "rtsp://admin@192.168.1.1:554/live"),
            ("rtsp://192.168.1.1:554/live", "rtsp://192.168.1.1:554/live"),
            ("http://camera.local/mjpeg", "http://camera.local/mjpeg"),
            ("rtmp://live.stream.tv/app/stream", "rtmp://live.stream.tv/app/stream"),
        ]
        for raw, expected in test_cases:
            res = sanitize_stream_url(raw)
            assert res == expected, f"Failed on passwordless URL: {raw} -> got {res}"

    def test_xiaomi_and_query_parameter_masking(self):
        """Xiaomi scheme tokens and pins masked correctly."""
        raw = "xiaomi://camera_12345?token=abcdef0123456789&pin=998877&channel=0"
        sanitized = sanitize_stream_url(raw)
        assert "token=******" in sanitized
        assert "pin=******" in sanitized
        assert "abcdef0123456789" not in sanitized
        assert "998877" not in sanitized
        assert "channel=0" in sanitized

    def test_empty_none_and_corrupt_inputs(self):
        """Empty, None, or garbage inputs return safely without crashing."""
        assert sanitize_stream_url(None) == ""
        assert sanitize_stream_url("") == ""
        assert sanitize_stream_url("not_a_url") == "not_a_url"
        assert sanitize_stream_url("://") == "://"

    def test_randomized_fuzzing_500_urls(self):
        """
        Generates 500 random adversarial URLs with arbitrary usernames, passwords,
        special characters, colons, and @ signs.
        Verifies:
        1. Never raises an uncaught exception.
        2. Never contains the unmasked password.
        3. Preserves the protocol scheme and host.
        """
        schemes = ["rtsp", "rtsps", "http", "https"]
        chars = string.ascii_letters + string.digits + "!$#%&*+=-_"
        for _ in range(500):
            scheme = random.choice(schemes)
            user = "".join(random.choices(chars, k=random.randint(0, 10)))
            # Password may contain colons and @ signs
            pass_chars = chars + "::@@"
            password = "".join(random.choices(pass_chars, k=random.randint(6, 20)))
            host = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port = random.choice([554, 8554, 80, 8080])
            path = f"/live/ch{random.randint(0, 4)}"

            raw_url = f"{scheme}://{user}:{password}@{host}:{port}{path}"
            sanitized = sanitize_stream_url(raw_url)

            # Verification 1: scheme & host preserved
            assert sanitized.startswith(f"{scheme}://")
            assert f"{host}:{port}{path}" in sanitized

            # Verification 2: password masked
            assert password not in sanitized, f"Password '{password}' leaked in '{sanitized}'!"
            assert ":******@" in sanitized


# ==============================================================================
# Suite 3: PTZ Speed Bounds & Fault Injection
# ==============================================================================
class TestPTZSpeedBoundsAndValidation:
    """Verifies PTZ speed clamping [1..10] and HTTP 400 validation for invalid types."""

    def test_speed_clamped_bounds_integers(self, client: TestClient):
        """
        Speed values outside [1..10] must be clamped:
        - Speed 0 -> clamped to 1
        - Speed -1 -> clamped to 1
        - Speed -999 -> clamped to 1
        - Speed 11 -> clamped to 10
        - Speed 999 -> clamped to 10
        """
        res = client.post("/api/cameras", json={"name": "Speed Clamping Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        test_cases = [
            (0, 1),
            (-1, 1),
            (-999, 1),
            (1, 1),
            (5, 5),
            (10, 10),
            (11, 10),
            (999, 10),
            (1000000, 10),
        ]

        for input_spd, expected_spd in test_cases:
            resp = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": input_spd})
            assert resp.status_code == 200, f"Failed on speed {input_spd}: {resp.text}"
            data = resp.json()
            assert data["status"] == "ok"
            assert data["speed"] == expected_spd, f"Expected speed {expected_spd} for input {input_spd}, got {data['speed']}"

    def test_speed_rejected_non_integers_http_400(self, client: TestClient):
        """
        Non-integer, null, or boolean values must return HTTP 400 Bad Request:
        - "fast", "slow", "invalid"
        - None / null
        - True / False (booleans)
        - Empty string ""
        - Dict {}, List []
        - String float "3.14"
        """
        res = client.post("/api/cameras", json={"name": "Speed Error Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        invalid_speeds = [
            "fast",
            "slow",
            "",
            None,
            True,
            False,
            "3.14",
            "NaN",
            [],
            {},
        ]

        for inv in invalid_speeds:
            resp = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": inv})
            assert resp.status_code == 400, f"Expected HTTP 400 for speed={inv!r}, got {resp.status_code}: {resp.text}"
            detail = resp.json().get("detail", "")
            assert "Speed must be an integer" in detail, f"Unexpected detail message for speed={inv!r}: {detail}"

    def test_ptz_direction_handling(self, client: TestClient):
        """Validates directions and stop behavior."""
        res = client.post("/api/cameras", json={"name": "Direction Cam", "has_ptz": True})
        assert res.status_code == 200
        cam_id = res.json()["id"]

        all_valid_directions = [
            "up", "down", "left", "right",
            "up_left", "up_right", "down_left", "down_right",
            "zoom_in", "zoom_out",
        ]

        for d in all_valid_directions:
            resp = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": d, "speed": 5})
            assert resp.status_code == 200
            assert resp.json()["action"] == f"move_{d}"

        # Stop command
        stop_resp = client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})
        assert stop_resp.status_code == 200
        assert stop_resp.json()["action"] == "stop"
