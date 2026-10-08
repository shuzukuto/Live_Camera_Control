"""
backend/tests/test_ezviz_service.py

Unit tests for EZVIZ OpenAPI Client & Local RTSP Resolver (Feature 7 & Feature 8).
"""

import time
import pytest
from app.services.ezviz_service import (
    EZVIZService,
    EZVIZToken,
    StreamLease,
    EZVIZError,
    EZVIZAuthError,
    EZVIZDeviceError,
    EZVIZ_REGIONAL_ENDPOINTS,
)
from tests_e2e.mocks.mock_camera_server import MockEZVIZPlatform
from tests.conftest import set_current_mocks


@pytest.fixture
def mock_ezviz_platform():
    plat = MockEZVIZPlatform()
    set_current_mocks(ezviz=plat)
    return plat


@pytest.fixture
def ezviz_svc(mock_ezviz_platform):
    return EZVIZService()


# ==============================================================================
# Regional Endpoints & Resolution
# ==============================================================================

def test_regional_endpoint_resolution(ezviz_svc):
    """Verifies all defined regional gateways map to valid HTTPS URLs."""
    for region, expected_url in EZVIZ_REGIONAL_ENDPOINTS.items():
        resolved = ezviz_svc.resolve_endpoint(region=region)
        assert resolved == expected_url.rstrip("/")

    # Default fallback to cn
    assert ezviz_svc.resolve_endpoint(region="unknown_region") == EZVIZ_REGIONAL_ENDPOINTS["cn"]

    # Explicit area_domain override
    custom_area = "https://custom-area.ezvizlife.com"
    assert ezviz_svc.resolve_endpoint(area_domain=custom_area) == custom_area


# ==============================================================================
# Token Acquisition & Lifecycle (Feature 7)
# ==============================================================================

@pytest.mark.asyncio
async def test_token_acquisition_success(ezviz_svc, mock_ezviz_platform):
    """Verifies exchanging valid AppKey/Secret returns a valid EZVIZToken."""
    token = await ezviz_svc.get_token(
        app_key=mock_ezviz_platform.app_key,
        app_secret=mock_ezviz_platform.app_secret,
    )
    assert isinstance(token, EZVIZToken)
    assert token.access_token.startswith("at.ezviz_live_")
    assert token.expire_time > int(time.time() * 1000)
    assert not token.is_expired


@pytest.mark.asyncio
async def test_token_acquisition_caching(ezviz_svc, mock_ezviz_platform):
    """Verifies token is cached and force_refresh bypasses cache."""
    t1 = await ezviz_svc.get_token(
        app_key=mock_ezviz_platform.app_key,
        app_secret=mock_ezviz_platform.app_secret,
    )
    t2 = await ezviz_svc.get_token(
        app_key=mock_ezviz_platform.app_key,
        app_secret=mock_ezviz_platform.app_secret,
    )
    assert t1.access_token == t2.access_token

    # Force refresh
    t3 = await ezviz_svc.get_token(
        app_key=mock_ezviz_platform.app_key,
        app_secret=mock_ezviz_platform.app_secret,
        force_refresh=True,
    )
    assert isinstance(t3, EZVIZToken)


@pytest.mark.asyncio
async def test_token_acquisition_invalid_credentials_rejected(ezviz_svc):
    """Verifies invalid AppKey/Secret raises EZVIZAuthError with code 10001."""
    with pytest.raises(EZVIZAuthError) as exc_info:
        await ezviz_svc.get_token(app_key="wrong_key", app_secret="wrong_secret")
    assert exc_info.value.code == "10001"


# ==============================================================================
# Camera Listing (Feature 7)
# ==============================================================================

@pytest.mark.asyncio
async def test_camera_listing_success(ezviz_svc, mock_ezviz_platform):
    """Verifies listing cameras with valid access token."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    cams = await ezviz_svc.list_cameras(access_token=token.access_token)
    assert len(cams) >= 2
    serials = [c["deviceSerial"] for c in cams]
    assert "F12345678" in serials
    assert "B87654321" in serials


@pytest.mark.asyncio
async def test_camera_listing_online_offline_status(ezviz_svc, mock_ezviz_platform):
    """Verifies distinguishing online (status=1) from offline (status=0) cameras."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    cams = await ezviz_svc.list_cameras(access_token=token.access_token)
    online = [c for c in cams if c["status"] == 1]
    offline = [c for c in cams if c["status"] == 0]
    assert len(online) >= 2
    assert len(offline) >= 1
    assert any(c["deviceSerial"] == "O00011122" for c in offline)


@pytest.mark.asyncio
async def test_camera_listing_invalid_token_rejected(ezviz_svc):
    """Verifies invalid or expired token raises EZVIZError with code 10002."""
    with pytest.raises(EZVIZError) as exc_info:
        await ezviz_svc.list_cameras(access_token="invalid_token_xyz")
    assert exc_info.value.code == "10002"


# ==============================================================================
# Live URL Extraction & Leases (Feature 7)
# ==============================================================================

@pytest.mark.asyncio
async def test_live_address_extraction_with_lease(ezviz_svc, mock_ezviz_platform):
    """Verifies live stream URL extraction and lease expiration."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    lease = await ezviz_svc.get_live_address(
        access_token=token.access_token,
        device_serial="F12345678",
        channel_no=1,
        expire_time_sec=600,
    )
    assert isinstance(lease, StreamLease)
    assert "rtsp://" in lease.stream_url
    assert lease.expires_at > time.time()
    assert lease.is_local_rtsp is False
    assert lease.is_encrypt == 1


@pytest.mark.asyncio
async def test_live_address_offline_device_rejected(ezviz_svc, mock_ezviz_platform):
    """Verifies offline camera live address request raises EZVIZDeviceError 20007."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    with pytest.raises(EZVIZDeviceError) as exc_info:
        await ezviz_svc.get_live_address(token.access_token, device_serial="O00011122")
    assert exc_info.value.code == "20007"


# ==============================================================================
# Encryption Toggle Off (Feature 8)
# ==============================================================================

@pytest.mark.asyncio
async def test_disable_encryption_with_valid_code(ezviz_svc, mock_ezviz_platform):
    """Verifies turning off device encryption with verification code."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    ok = await ezviz_svc.set_encryption_off(
        access_token=token.access_token,
        device_serial="F12345678",
        validate_code="VERIFY123",
    )
    assert ok is True
    assert mock_ezviz_platform.devices["F12345678"]["isEncrypt"] == 0


@pytest.mark.asyncio
async def test_disable_encryption_wrong_code_rejected(ezviz_svc, mock_ezviz_platform):
    """Verifies wrong verification code raises EZVIZDeviceError 20014."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    with pytest.raises(EZVIZDeviceError) as exc_info:
        await ezviz_svc.set_encryption_off(
            access_token=token.access_token,
            device_serial="F12345678",
            validate_code="WRONG_CODE_99",
        )
    assert exc_info.value.code == "20014"


# ==============================================================================
# PTZ Control (Feature 8)
# ==============================================================================

@pytest.mark.asyncio
async def test_ptz_start_valid_direction_and_speed(ezviz_svc, mock_ezviz_platform):
    """Verifies PTZ start with directions (0..7) and speed (1..10)."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    ok = await ezviz_svc.ptz_start(
        access_token=token.access_token,
        device_serial="B87654321",
        channel_no=1,
        direction=2,  # Left
        speed=5,
    )
    assert ok is True


@pytest.mark.asyncio
async def test_ptz_speed_bounds_enforced(ezviz_svc, mock_ezviz_platform):
    """Verifies speed outside [1, 10] raises EZVIZError 10006."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    with pytest.raises(EZVIZError) as exc_info:
        await ezviz_svc.ptz_start(
            access_token=token.access_token,
            device_serial="B87654321",
            channel_no=1,
            direction=0,
            speed=15,
        )
    assert exc_info.value.code == "10006"


@pytest.mark.asyncio
async def test_ptz_stop(ezviz_svc, mock_ezviz_platform):
    """Verifies PTZ stop successfully halts movement."""
    token = await ezviz_svc.get_token(mock_ezviz_platform.app_key, mock_ezviz_platform.app_secret)
    ok = await ezviz_svc.ptz_stop(
        access_token=token.access_token,
        device_serial="B87654321",
        channel_no=1,
    )
    assert ok is True


# ==============================================================================
# Local LAN RTSP Resolver
# ==============================================================================

def test_resolve_local_rtsp_url():
    """Verifies generating direct zero-timeout LAN RTSP URL."""
    url = EZVIZService.resolve_local_rtsp_url(
        ip="192.168.1.101",
        verification_code="VERIFY123",
        port=554,
        channel_no=1,
        stream_type="main",
    )
    assert url == "rtsp://admin:VERIFY123@192.168.1.101:554/h264/ch1/main/av_stream"

    sub_url = EZVIZService.resolve_local_rtsp_url(
        ip="192.168.1.101",
        verification_code="VERIFY123",
        port=554,
        channel_no=1,
        stream_type="sub",
    )
    assert sub_url == "rtsp://admin:VERIFY123@192.168.1.101:554/h264/ch1/sub/av_stream"


@pytest.mark.asyncio
async def test_refresh_stream_url_prefers_local_rtsp(ezviz_svc):
    """Verifies refresh_stream_url gives priority to local RTSP when IP and verification code are present."""
    camera = {
        "ip_address": "192.168.1.105",
        "verification_code": "SEC123",
        "port": 554,
        "channel_no": 1,
    }
    lease = await ezviz_svc.refresh_stream_url(camera)
    assert lease.is_local_rtsp is True
    assert "192.168.1.105" in lease.stream_url
    assert lease.expires_at > time.time() + 86400 * 30
