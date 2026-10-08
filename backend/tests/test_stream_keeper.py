"""
backend/tests/test_stream_keeper.py

Unit and integration tests for StreamKeeper 24/7 daemon and zero-timeout LAN routing.
Milestone 3: Features 15 & 16.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from app.database import init_db, get_db, set_database_path
from app.services.ezviz_service import StreamLease, EZVIZError
from app.services.go2rtc_service import Go2rtcClient
from app.services.stream_keeper import StreamKeeper, StreamKeeperStats
from app.vault import encrypt_secret, encrypt_json


@pytest_asyncio.fixture
async def keeper_db(tmp_path):
    """Sets up an isolated SQLite database for StreamKeeper testing."""
    db_file = tmp_path / "test_keeper.db"
    set_database_path(db_file)
    await init_db(db_file)
    yield db_file


@pytest.fixture
def mock_go2rtc():
    """Mock Go2rtcClient tracking stream updates."""
    client = AsyncMock(spec=Go2rtcClient)
    client.streams = {}

    async def mock_update(name: str, src: Any) -> bool:
        client.streams[name] = src
        return True

    async def mock_add(name: str, src: Any) -> bool:
        client.streams[name] = src
        return True

    client.update_stream.side_effect = mock_update
    client.add_stream.side_effect = mock_add
    return client


# ==============================================================================
# Category 1: Lifecycle & Configuration
# ==============================================================================

def test_streamkeeper_init_and_config(mock_go2rtc):
    """Confirms defaults and configuration initialization."""
    sk = StreamKeeper(
        go2rtc=mock_go2rtc,
        renew_lead_sec=30.0,
        check_interval=5.0,
        max_concurrent_renewals=5,
        max_retries=3,
    )
    assert sk.renew_lead_sec == 30.0
    assert sk.check_interval == 5.0
    assert sk.max_retries == 3
    assert sk.is_running() is False
    assert isinstance(sk.stats, StreamKeeperStats)


@pytest.mark.asyncio
async def test_streamkeeper_start_stop_idempotent(mock_go2rtc):
    """Calling start() activates daemon, subsequent start() is idempotent, stop() cancels cleanly."""
    sk = StreamKeeper(go2rtc=mock_go2rtc, check_interval=0.1)
    sk.start()
    assert sk.is_running() is True

    # Idempotent second call
    task1 = sk._worker_task
    sk.start()
    assert sk._worker_task is task1

    await asyncio.sleep(0.05)
    await sk.stop()
    assert sk.is_running() is False


@pytest.mark.asyncio
async def test_streamkeeper_reads_system_settings_lead_sec(keeper_db, mock_go2rtc):
    """Dynamically reads renewal lead time from system_settings."""
    async with get_db() as conn:
        await conn.execute(
            "UPDATE system_settings SET value = '45' WHERE key = 'streaming.streamkeeper_renew_lead_sec';"
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc, renew_lead_sec=30.0)
    await sk.check_and_renew_leases()
    assert sk.renew_lead_sec == 45.0


# ==============================================================================
# Category 2: Proactive Lease Renewal & Hot-Swap (Feature 15)
# ==============================================================================

@pytest.mark.asyncio
async def test_proactive_renewal_at_t_minus_30s(keeper_db, mock_go2rtc):
    """Camera with lease within T-30s is detected and renewed via hot-swap."""
    now = time.time()
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type, live_url, url_expires_at, enabled)
            VALUES ('cam_t30', 'Front Gate', 'ezviz', 'stream_t30', 'ezviz_cloud', 'rtsp://old/url', ?, 1);
            """,
            (int(now + 20),),  # 20s left -> within 30s threshold
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc, renew_lead_sec=30.0)

    # Mock ezviz_service returning fresh lease
    fresh_lease = StreamLease(stream_url="rtsp://new/cloud/url", expires_at=now + 300.0, is_local_rtsp=False)
    with patch("app.services.stream_keeper.ezviz_service.refresh_stream_url", new=AsyncMock(return_value=fresh_lease)):
        results = await sk.check_and_renew_leases()

    assert len(results) == 1
    assert results[0]["action"] == "renewed"
    mock_go2rtc.update_stream.assert_called_with("stream_t30", "rtsp://new/cloud/url")

    # Verify DB update
    async with get_db() as conn:
        async with conn.execute("SELECT live_url, url_expires_at FROM cameras WHERE id = 'cam_t30';") as cursor:
            row = await cursor.fetchone()
            assert row["live_url"] == "rtsp://new/cloud/url"
            assert row["url_expires_at"] == int(now + 300.0)


@pytest.mark.asyncio
async def test_unexpired_camera_skipped(keeper_db, mock_go2rtc):
    """Camera with lease outside T-30s window is not renewed."""
    now = time.time()
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type, live_url, url_expires_at, enabled)
            VALUES ('cam_unexp', 'Lobby', 'ezviz', 'stream_unexp', 'ezviz_cloud', 'rtsp://valid/url', ?, 1);
            """,
            (int(now + 120),),  # 120s left -> outside 30s lead
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc, renew_lead_sec=30.0)
    with patch("app.services.stream_keeper.ezviz_service.refresh_stream_url") as mock_refresh:
        results = await sk.check_and_renew_leases()
        mock_refresh.assert_not_called()

    assert len(results) == 0
    mock_go2rtc.update_stream.assert_not_called()


@pytest.mark.asyncio
async def test_in_flight_deduplication(keeper_db, mock_go2rtc):
    """Concurrent calls to renew the same camera ID execute only once."""
    now = time.time()
    cam = {
        "id": "cam_dedup",
        "brand": "ezviz",
        "stream_id": "stream_dedup",
        "stream_type": "ezviz_cloud",
        "url_expires_at": int(now + 10),
    }

    sk = StreamKeeper(go2rtc=mock_go2rtc)
    fresh_lease = StreamLease(stream_url="rtsp://fresh", expires_at=now + 300)

    async def slow_refresh(*args, **kwargs):
        await asyncio.sleep(0.05)
        return fresh_lease

    with patch.object(sk, "_renew_ezviz_lease", side_effect=slow_refresh):
        r1, r2 = await asyncio.gather(
            sk.renew_camera_lease(cam),
            sk.renew_camera_lease(cam),
        )

    # One succeeds, the other returns None because it was deduplicated
    assert (r1 is not None and r2 is None) or (r2 is not None and r1 is None)


@pytest.mark.asyncio
async def test_reactive_10002_reauthentication(keeper_db, mock_go2rtc):
    """Token invalidation error 10002 triggers force_refresh re-auth and second renewal."""
    now = time.time()
    enc_secret = encrypt_secret("my_app_secret")
    enc_tokens = encrypt_json({"accessToken": "old_token"})

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, provider, account_name, username, encrypted_secret, encrypted_tokens, token_expire_time, status)
            VALUES ('acc_ez', 'ezviz', 'My EZVIZ Account', 'my_app_key', ?, ?, ?, 'active');
            """,
            (enc_secret, enc_tokens, int((now + 3600) * 1000)),
        )
        await conn.execute(
            """
            INSERT INTO cameras (id, account_id, name, brand, stream_id, stream_type, url_expires_at, enabled)
            VALUES ('cam_10002', 'acc_ez', 'Yard', 'ezviz', 'stream_10002', 'ezviz_cloud', ?, 1);
            """,
            (int(now + 10),),
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc)

    from app.services.ezviz_service import EZVIZToken
    mock_new_token = EZVIZToken(access_token="new_valid_token", expire_time=int((now + 7200) * 1000), area_domain="open.ys7.com")
    valid_lease = StreamLease(stream_url="rtsp://valid/cloud", expires_at=now + 300)

    # First call raises EZVIZError 10002, second call returns valid_lease
    call_count = 0

    async def mock_refresh(cam, access_token=None, region=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise EZVIZError("Invalid token", code="10002")
        return valid_lease

    with patch("app.services.stream_keeper.ezviz_service.refresh_stream_url", side_effect=mock_refresh), \
         patch("app.services.stream_keeper.ezviz_service.get_token", new=AsyncMock(return_value=mock_new_token)):
        lease = await sk._renew_ezviz_lease({"id": "cam_10002", "account_id": "acc_ez", "brand": "ezviz"})

    assert lease.stream_url == "rtsp://valid/cloud"
    assert call_count == 2


# ==============================================================================
# Category 3: Error Recovery & Circuit Breaker
# ==============================================================================

@pytest.mark.asyncio
async def test_repeated_failure_marks_camera_offline(keeper_db, mock_go2rtc):
    """Exceeding max_retries past expiration marks the camera offline."""
    past_exp = time.time() - 10  # Already expired
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type, url_expires_at, is_online, enabled)
            VALUES ('cam_fail', 'Roof', 'ezviz', 'stream_fail', 'ezviz_cloud', ?, 1, 1);
            """,
            (int(past_exp),),
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc, max_retries=2)
    cam = {"id": "cam_fail", "brand": "ezviz", "stream_id": "stream_fail", "url_expires_at": past_exp}

    with patch.object(sk, "_renew_ezviz_lease", side_effect=RuntimeError("Connection refused")):
        # Attempt 1
        await sk.renew_camera_lease(cam)
        # Attempt 2 (reaches max_retries)
        await sk.renew_camera_lease(cam)

    async with get_db() as conn:
        async with conn.execute("SELECT is_online FROM cameras WHERE id = 'cam_fail';") as cursor:
            row = await cursor.fetchone()
            assert row["is_online"] == 0


@pytest.mark.asyncio
async def test_circuit_breaker_camera_isolation(keeper_db, mock_go2rtc):
    """One failing camera does not prevent other cameras from renewing successfully."""
    now = time.time()
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (id, name, brand, stream_id, stream_type, url_expires_at, enabled)
            VALUES ('cam_ok_1', 'C1', 'ezviz', 's_ok1', 'ezviz_cloud', ?, 1),
                   ('cam_err', 'CE', 'ezviz', 's_err', 'ezviz_cloud', ?, 1),
                   ('cam_ok_2', 'C2', 'ezviz', 's_ok2', 'ezviz_cloud', ?, 1);
            """,
            (int(now + 10), int(now + 10), int(now + 10)),
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc)

    async def selective_renew(cam):
        if cam["id"] == "cam_err":
            raise RuntimeError("Cloud 500 Server Error")
        return StreamLease(stream_url=f"rtsp://{cam['id']}/new", expires_at=now + 300)

    with patch.object(sk, "_renew_ezviz_lease", side_effect=selective_renew):
        results = await sk.check_and_renew_leases()

    renewed_ids = {r["camera_id"] for r in results}
    assert "cam_ok_1" in renewed_ids
    assert "cam_ok_2" in renewed_ids
    assert "cam_err" not in renewed_ids


# ==============================================================================
# Category 4: Concurrency & Semaphore Bounding
# ==============================================================================

@pytest.mark.asyncio
async def test_concurrent_renewals_bounded_by_semaphore(keeper_db, mock_go2rtc):
    """Concurrent renewals respect max_concurrent_renewals limit."""
    now = time.time()
    async with get_db() as conn:
        for i in range(6):
            await conn.execute(
                """
                INSERT INTO cameras (id, name, brand, stream_id, stream_type, url_expires_at, enabled)
                VALUES (?, ?, 'ezviz', ?, 'ezviz_cloud', ?, 1);
                """,
                (f"cam_sem_{i}", f"Cam {i}", f"stream_sem_{i}", int(now + 10)),
            )
        await conn.commit()

    max_concurrent = 2
    sk = StreamKeeper(go2rtc=mock_go2rtc, max_concurrent_renewals=max_concurrent)

    current_concurrent = 0
    max_observed_concurrent = 0

    async def tracked_renew(cam):
        nonlocal current_concurrent, max_observed_concurrent
        current_concurrent += 1
        max_observed_concurrent = max(max_observed_concurrent, current_concurrent)
        await asyncio.sleep(0.02)
        current_concurrent -= 1
        return StreamLease(stream_url="rtsp://ok", expires_at=now + 300)

    with patch.object(sk, "_renew_ezviz_lease", side_effect=tracked_renew):
        results = await sk.check_and_renew_leases()

    assert len(results) == 6
    assert max_observed_concurrent <= max_concurrent


# ==============================================================================
# Category 5: Zero-Timeout LAN RTSP Routing (Feature 16)
# ==============================================================================

@pytest.mark.asyncio
async def test_lan_reachability_probe_open_port():
    """probe_lan_reachability returns True on an open TCP socket."""
    sk = StreamKeeper()

    # Start a temporary local TCP server
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        is_up = await sk.probe_lan_reachability("127.0.0.1", port=port, timeout=0.5)
        assert is_up is True
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_lan_reachability_probe_closed_port():
    """probe_lan_reachability returns False when connection refused without hanging."""
    sk = StreamKeeper()
    # Choose unused port
    is_up = await sk.probe_lan_reachability("127.0.0.1", port=59999, timeout=0.1)
    assert is_up is False


@pytest.mark.asyncio
async def test_cloud_to_lan_auto_promotion(keeper_db, mock_go2rtc):
    """Camera on cloud stream is promoted to zero-timeout LAN RTSP when LAN port is reachable."""
    enc_vcode = encrypt_secret("SECRET123")
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (
                id, name, brand, stream_id, stream_type, ip_address, port,
                encrypted_verification_code, live_url, url_expires_at, enabled
            ) VALUES (
                'cam_lan_promo', 'Driveway', 'ezviz', 'stream_promo', 'ezviz_cloud',
                '192.168.1.100', 554, ?, 'rtsp://cloud/live', 9999999999, 1
            );
            """,
            (enc_vcode,),
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc, lan_probe_interval=0.0)

    # Mock reachability probe as True
    with patch.object(sk, "probe_lan_reachability", new=AsyncMock(return_value=True)):
        results = await sk.check_and_renew_leases()

    assert len(results) == 1
    assert results[0]["action"] == "promoted_to_lan"
    assert "rtsp://admin:SECRET123@192.168.1.100:554" in results[0]["stream_url"]

    # Verify DB update: stream_type = rtsp_local, url_expires_at = NULL (zero timeout)
    async with get_db() as conn:
        async with conn.execute("SELECT stream_type, url_expires_at FROM cameras WHERE id = 'cam_lan_promo';") as cursor:
            row = await cursor.fetchone()
            assert row["stream_type"] == "rtsp_local"
            assert row["url_expires_at"] is None


@pytest.mark.asyncio
async def test_lan_to_cloud_failover(keeper_db, mock_go2rtc):
    """Camera on LAN RTSP whose port 554 becomes unreachable fails over to cloud stream."""
    now = time.time()
    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO accounts (id, provider, account_name, username, encrypted_secret, status)
            VALUES ('acc_fo', 'ezviz', 'Failover Acc', 'key', 'sec', 'active');
            """
        )
        await conn.execute(
            """
            INSERT INTO cameras (
                id, account_id, name, brand, stream_id, stream_type, ip_address, port,
                live_url, url_expires_at, enabled
            ) VALUES (
                'cam_fo', 'acc_fo', 'Garage', 'ezviz', 'stream_fo', 'rtsp_local',
                '192.168.1.200', 554, 'rtsp://192.168.1.200/local', NULL, 1
            );
            """
        )
        await conn.commit()

    sk = StreamKeeper(go2rtc=mock_go2rtc, lan_probe_interval=0.0)

    cloud_lease = StreamLease(stream_url="rtsp://cloud/failover", expires_at=now + 300)

    # Mock reachability as False (LAN down), cloud renew as valid
    with patch.object(sk, "probe_lan_reachability", new=AsyncMock(return_value=False)), \
         patch.object(sk, "_renew_ezviz_lease", new=AsyncMock(return_value=cloud_lease)):
        results = await sk.check_and_renew_leases()

    assert len(results) == 1
    assert results[0]["action"] == "renewed"
    assert results[0]["stream_url"] == "rtsp://cloud/failover"
    assert sk.stats.total_lan_fallbacks >= 1
