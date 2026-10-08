"""
backend/tests/test_xiaomi_service.py

Unit tests for Xiaomi Mi Home Cloud & MIoT Protocol Client (Features 9, 10, 11).
"""

import hashlib
import time
import pytest
from app.services.xiaomi_service import (
    XiaomiService,
    XiaomiSession,
    XiaomiError,
    XiaomiAuthError,
    sign_miio_request,
    XIAOMI_REGIONS,
    XIAOMI_REGIONAL_ENDPOINTS,
)
from tests_e2e.mocks.mock_camera_server import MockXiaomiPlatform
from tests.conftest import set_current_mocks


@pytest.fixture
def mock_xiaomi_platform():
    plat = MockXiaomiPlatform()
    set_current_mocks(xiaomi=plat)
    return plat


@pytest.fixture
def xiaomi_svc(mock_xiaomi_platform):
    return XiaomiService()


# ==============================================================================
# Regional Endpoints & Cryptographic Signing
# ==============================================================================

def test_xiaomi_regions_endpoints(xiaomi_svc):
    """Verifies all 6 regional endpoints are defined and resolvable."""
    for reg in ["cn", "de", "i2", "ru", "sg", "us"]:
        endpoint = xiaomi_svc.resolve_endpoint(reg)
        assert endpoint.startswith("https://")
        assert "api.io.mi.com" in endpoint

    with pytest.raises(XiaomiError) as exc_info:
        xiaomi_svc.resolve_endpoint("invalid_region_mars")
    assert exc_info.value.code == -1


def test_sign_miio_request_algorithm():
    """Verifies HMAC-SHA256 signature generation and nonce extraction."""
    ssecurity = "yK47d2nCg7f3Q6Wk+eR8jQ=="
    uri = "/home/device_list"
    data = '{"getVirtualModel": false}'

    signed = sign_miio_request(uri=uri, data_json=data, ssecurity=ssecurity)
    assert "_nonce" in signed
    assert "signature" in signed
    assert signed["data"] == data
    assert len(signed["_nonce"]) > 10
    assert len(signed["signature"]) > 10


# ==============================================================================
# Passport Authentication (Feature 9)
# ==============================================================================

@pytest.mark.asyncio
async def test_passport_step1_service_login(xiaomi_svc):
    """Verifies Step 1 login returns _sign, qs, and callback."""
    step1 = await xiaomi_svc.passport_step1()
    assert "_sign" in step1
    assert "qs" in step1
    assert "callback" in step1


@pytest.mark.asyncio
async def test_passport_step2_auth_success(xiaomi_svc):
    """Verifies Step 2 authentication with valid MD5 password hash."""
    s1 = await xiaomi_svc.passport_step1()
    pwd_md5 = hashlib.md5("Secr3tP@ss123".encode()).hexdigest()
    s2 = await xiaomi_svc.passport_step2(
        username="user_china@example.com",
        password_or_md5=pwd_md5,
        sign=s1["_sign"],
        qs=s1["qs"],
        callback=s1["callback"],
    )
    assert s2["code"] == 0
    assert "serviceToken" in s2
    assert "ssecurity" in s2
    assert s2["userId"] == "100982341"


@pytest.mark.asyncio
async def test_passport_invalid_password_rejected(xiaomi_svc):
    """Verifies invalid password returns non-zero error code."""
    s1 = await xiaomi_svc.passport_step1()
    s2 = await xiaomi_svc.passport_step2(
        username="user_china@example.com",
        password_or_md5="wrong_password_md5",
        sign=s1["_sign"],
        qs=s1["qs"],
        callback=s1["callback"],
    )
    assert s2["code"] != 0


@pytest.mark.asyncio
async def test_passport_two_factor_auth_challenge(xiaomi_svc):
    """Verifies 2FA challenge is flagged when OTP is missing."""
    s1 = await xiaomi_svc.passport_step1()
    pwd_md5 = hashlib.md5("TwoFactorPass!".encode()).hexdigest()
    s2 = await xiaomi_svc.passport_step2(
        username="user_2fa@example.com",
        password_or_md5=pwd_md5,
        sign=s1["_sign"],
        qs=s1["qs"],
        callback=s1["callback"],
    )
    assert s2["code"] == 87001
    assert "notificationUrl" in s2


@pytest.mark.asyncio
async def test_passport_two_factor_auth_resolved_with_otp(xiaomi_svc):
    """Verifies providing valid OTP resolves 2FA challenge."""
    s1 = await xiaomi_svc.passport_step1()
    pwd_md5 = hashlib.md5("TwoFactorPass!".encode()).hexdigest()
    s2 = await xiaomi_svc.passport_step2(
        username="user_2fa@example.com",
        password_or_md5=pwd_md5,
        sign=s1["_sign"],
        qs=s1["qs"],
        callback=s1["callback"],
        otp_code="123456",
    )
    assert s2["code"] == 0
    assert "serviceToken" in s2


@pytest.mark.asyncio
async def test_full_login_flow(xiaomi_svc):
    """Verifies full login helper returns populated XiaomiSession."""
    session = await xiaomi_svc.login(
        username="user_china@example.com",
        password="Secr3tP@ss123",
        region="cn",
    )
    assert isinstance(session, XiaomiSession)
    assert session.user_id == "100982341"
    assert session.service_token.startswith("st_xiaomi_")
    assert session.region == "cn"


# ==============================================================================
# Device Synchronization (Feature 10)
# ==============================================================================

@pytest.mark.asyncio
async def test_device_sync_cn(xiaomi_svc):
    """Verifies camera device retrieval for Mainland China (cn) regional gateway."""
    session = await xiaomi_svc.login("user_china@example.com", "Secr3tP@ss123", region="cn")
    devices = await xiaomi_svc.get_devices(region="cn", service_token=session.service_token)
    assert len(devices) == 2
    assert devices[0]["did"] == "xiaomi_cam_001"
    assert devices[0]["model"] == "chuangmi.camera.ipc009"
    assert devices[0]["isOnline"] is True
    assert "localip" in devices[0]
    assert "token" in devices[0]


@pytest.mark.asyncio
async def test_device_sync_global_sg(xiaomi_svc):
    """Verifies camera device retrieval for Global Singapore (sg) gateway."""
    session = await xiaomi_svc.login("user_global@example.com", "GlobalPass2026!", region="sg")
    devices = await xiaomi_svc.get_devices(region="sg", service_token=session.service_token)
    assert len(devices) == 1
    assert devices[0]["did"] == "xiaomi_cam_global_1"


@pytest.mark.asyncio
async def test_device_sync_unauthorized_token_rejected(xiaomi_svc):
    """Verifies invalid or expired serviceToken raises XiaomiError code 2."""
    with pytest.raises(XiaomiError) as exc_info:
        await xiaomi_svc.get_devices(region="cn", service_token="unauthenticated_token_999")
    assert exc_info.value.code == 2


# ==============================================================================
# Stream Descriptor & PTZ Control (Feature 11)
# ==============================================================================

@pytest.mark.asyncio
async def test_xiaomi_stream_uri_generation(xiaomi_svc):
    """Verifies resolving xiaomi:// stream descriptor for go2rtc ingestion."""
    session = await xiaomi_svc.login("user_china@example.com", "Secr3tP@ss123", region="cn")
    desc = await xiaomi_svc.get_stream_descriptor(
        did="xiaomi_cam_001",
        region="cn",
        service_token=session.service_token,
    )
    assert desc["code"] == 0
    assert desc["stream_url"].startswith("xiaomi://192.168.1.150")


@pytest.mark.asyncio
async def test_miot_ptz_action_execution(xiaomi_svc):
    """Verifies MIoT-Spec action RPC for camera motor PTZ movement."""
    session = await xiaomi_svc.login("user_china@example.com", "Secr3tP@ss123", region="cn")
    res = await xiaomi_svc.miot_action(
        region="cn",
        service_token=session.service_token,
        did="xiaomi_cam_001",
        siid=5,
        aiid=1,
        in_params=[1],  # Move Up
    )
    assert res["code"] == 0
    assert res["result"]["code"] == 0
    assert res["result"]["did"] == "xiaomi_cam_001"


@pytest.mark.asyncio
async def test_unknown_device_ptz_fails(xiaomi_svc):
    """Verifies PTZ fails gracefully on unknown device ID."""
    session = await xiaomi_svc.login("user_china@example.com", "Secr3tP@ss123", region="cn")
    with pytest.raises(XiaomiError) as exc_info:
        await xiaomi_svc.miot_action(
            region="cn",
            service_token=session.service_token,
            did="non_existent_did_xyz",
            siid=5,
            aiid=1,
            in_params=[1],
        )
    assert exc_info.value.code != 0


@pytest.mark.asyncio
async def test_ptz_move_helper(xiaomi_svc):
    """Verifies ptz_move helper translates named directions ('up', 'down', 'left', 'right')."""
    session = await xiaomi_svc.login("user_china@example.com", "Secr3tP@ss123", region="cn")
    res = await xiaomi_svc.ptz_move(
        did="xiaomi_cam_002",
        direction="left",
        region="cn",
        service_token=session.service_token,
    )
    assert res["code"] == 0
    assert res["result"]["did"] == "xiaomi_cam_002"
