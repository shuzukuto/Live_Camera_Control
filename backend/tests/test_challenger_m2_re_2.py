"""
backend/tests/test_challenger_m2_re_2.py

Milestone 2 Remediation Adversarial & Stress Testing Suite (Challenger 2):
1. Credential extraction and sanitization across malformed URL schemes and API endpoints.
2. Dual-stream concurrency: 50 cameras with substream_url under high-concurrency read/write.
3. Fault injection on regional token endpoints (EZVIZ & Xiaomi).
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from typing import Any, Dict, List, Optional
import httpx
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
from app.vault import (
    init_vault,
    encrypt_secret,
    decrypt_secret,
    encrypt_json,
    decrypt_json,
)
from app.api.cameras import _format_camera_response
from app.services.ezviz_service import (
    ezviz_service,
    EZVIZService,
    EZVIZError,
    EZVIZAuthError,
    EZVIZ_REGIONAL_ENDPOINTS,
)
from app.services.xiaomi_service import (
    xiaomi_service,
    XiaomiService,
    XiaomiError,
    XiaomiAuthError,
    sign_miio_request,
    XIAOMI_REGIONS,
    XIAOMI_REGIONAL_ENDPOINTS,
)
from app.services.camera_sync_service import camera_sync_service
from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
)
from tests.conftest import set_current_mocks


# ==============================================================================
# In-memory Mock go2rtc for testing
# ==============================================================================
class InMemoryGo2rtcClient:
    def __init__(self):
        self.streams: Dict[str, str] = {}

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
async def setup_test_env(tmp_path):
    """Isolate DB, Vault, and Mocks for each test."""
    db_file = tmp_path / "test_challenger_m2_re_2.db"
    set_database_path(db_file)
    await init_db(db_file)

    salt_file = tmp_path / ".test_chal_salt"
    key_file = tmp_path / ".test_chal_key"
    init_vault(
        passphrase="AdversarialChallenger2SecretKey2026!",
        salt_path=salt_file,
        master_key_file=key_file,
    )

    mock_ez = MockEZVIZPlatform()
    mock_mi = MockXiaomiPlatform()
    mock_onv = MockONVIFDevice()
    set_current_mocks(ezviz=mock_ez, xiaomi=mock_mi, onvif=mock_onv)

    mock_go2rtc = InMemoryGo2rtcClient()
    camera_sync_service.set_go2rtc_client(mock_go2rtc)

    yield {
        "mock_ez": mock_ez,
        "mock_mi": mock_mi,
        "mock_onv": mock_onv,
        "mock_go2rtc": mock_go2rtc,
        "db_file": db_file,
    }

    await close_db()


@pytest.fixture
def client():
    return TestClient(app, raise_server_exceptions=False)


# ==============================================================================
# SUITE 1: Credential Extraction & URL Scheme Sanitization
# ==============================================================================
class TestCredentialExtractionAndSanitization:
    """
    Empirically attempts to extract credentials from camera serialization,
    account listing, and account sync endpoints across diverse URL schemes.
    """

    def test_standard_rtsp_password_masked(self, client):
        """Standard RTSP with user:pass is masked to user:******@."""
        secret_pass = "SuperSecretP@ss123"
        payload = {
            "name": "Front Yard Cam",
            "brand": "generic",
            "stream_url": f"rtsp://admin:{secret_pass}@192.168.1.100:554/stream1",
            "substream_url": f"rtsp://admin:{secret_pass}@192.168.1.100:554/sub",
        }
        res = client.post("/api/cameras", json=payload)
        assert res.status_code == 200, res.text
        data = res.json()

        # Sensitive password MUST NOT appear in API response
        assert secret_pass not in data["stream_url"]
        assert "******" in data["stream_url"]
        assert secret_pass not in (data.get("substream_url") or "")

    def test_xiaomi_stream_tokens_and_pins_masked(self, client):
        """Xiaomi stream URLs mask token and pin parameters."""
        raw_token = "998877665544332211aabbccddeeff"
        raw_pin = "123456"
        url = f"xiaomi://xiaomi_cam_001?token={raw_token}&pin={raw_pin}"
        sub_url = f"xiaomi://xiaomi_cam_001_sub?token={raw_token}&pin={raw_pin}"

        payload = {
            "name": "Xiaomi Cam",
            "brand": "xiaomi",
            "stream_url": url,
            "substream_url": sub_url,
        }
        res = client.post("/api/cameras", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert raw_token not in data["stream_url"]
        assert raw_pin not in data["stream_url"]
        assert "token=******" in data["stream_url"]
        assert "pin=******" in data["stream_url"]

        if data.get("substream_url"):
            assert raw_token not in data["substream_url"]
            assert raw_pin not in data["substream_url"]

    def test_camera_serialization_never_leaks_vault_ciphertexts(self, client):
        """Verifies GET /api/cameras and GET /api/cameras/{id} omit internal vault fields."""
        payload = {
            "name": "Internal Vault Test Cam",
            "brand": "generic",
            "username": "secret_user",
            "password": "secret_password",
            "verification_code": "VERIF123",
            "stream_url": "rtsp://192.168.1.200:554/live",
            "substream_url": "rtsp://192.168.1.200:554/sub",
        }
        res = client.post("/api/cameras", json=payload)
        assert res.status_code == 200
        cam_id = res.json()["id"]

        # 1. Inspect direct POST response
        post_data = res.json()
        forbidden_keys = [
            "encrypted_password",
            "encrypted_username",
            "encrypted_verification_code",
            "password",
            "verification_code",
        ]
        for key in forbidden_keys:
            assert key not in post_data, f"Key {key} leaked in POST /api/cameras"

        # 2. Inspect GET /api/cameras/{id}
        res_get = client.get(f"/api/cameras/{cam_id}")
        assert res_get.status_code == 200
        get_data = res_get.json()
        for key in forbidden_keys:
            assert key not in get_data, f"Key {key} leaked in GET /api/cameras/{{id}}"
        assert get_data.get("masked_username") is not None
        assert get_data.get("has_credentials") is True

        # 3. Inspect GET /api/cameras
        res_list = client.get("/api/cameras")
        assert res_list.status_code == 200
        list_cams = res_list.json()
        matching = [c for c in list_cams if c["id"] == cam_id]
        assert len(matching) == 1
        for key in forbidden_keys:
            assert key not in matching[0], f"Key {key} leaked in GET /api/cameras list"

    def test_account_endpoints_never_leak_raw_secrets_or_vault_bundles(self, client):
        """
        Verifies GET /api/accounts, GET /api/accounts/{id}, and POST /api/accounts
        mask secrets and never expose encrypted_secret or encrypted_tokens bundles.
        """
        raw_secret = "VerySecretAppSecret999"
        res = client.post(
            "/api/accounts",
            json={
                "provider": "ezviz",
                "account_name": "EZVIZ Main",
                "username": "my_app_key",
                "secret": raw_secret,
                "region": "cn",
            },
        )
        assert res.status_code == 200
        acc_data = res.json()
        acc_id = acc_data["id"]

        # Ensure raw secret is NOT leaked
        assert raw_secret not in json.dumps(acc_data)
        assert "encrypted_secret" not in acc_data
        assert "encrypted_tokens" not in acc_data
        assert acc_data.get("masked_secret") is not None
        assert "..." in acc_data["masked_secret"] or "******" in acc_data["masked_secret"]

        # Verify GET /api/accounts/{id}
        res_get = client.get(f"/api/accounts/{acc_id}")
        assert res_get.status_code == 200
        get_acc = res_get.json()
        assert raw_secret not in json.dumps(get_acc)
        assert "encrypted_secret" not in get_acc
        assert "encrypted_tokens" not in get_acc

        # Verify GET /api/accounts
        res_list = client.get("/api/accounts")
        assert res_list.status_code == 200
        acc_list = res_list.json()
        assert raw_secret not in json.dumps(acc_list)

    def test_account_sync_endpoint_masks_all_synced_camera_credentials(self, client):
        """Verifies POST /api/accounts/{id}/sync returns sanitized camera payloads."""
        # 1. Create account using valid mock credentials
        acc_res = client.post(
            "/api/accounts",
            json={
                "provider": "ezviz",
                "account_name": "EZVIZ Sync Test",
                "username": "mock_ezviz_app_key_999",
                "secret": "mock_ezviz_secret_888",
                "region": "cn",
            },
        )
        assert acc_res.status_code == 200
        acc_id = acc_res.json()["id"]

        # 2. Sync cameras
        sync_res = client.post(f"/api/accounts/{acc_id}/sync")
        assert sync_res.status_code == 200
        sync_data = sync_res.json()
        assert sync_data["status"] == "success"
        cams = sync_data["cameras"]
        assert len(cams) > 0

        for cam in cams:
            assert "encrypted_password" not in cam
            assert "encrypted_secret" not in cam
            assert "encrypted_tokens" not in cam
            # Live stream URL should be sanitized
            url = cam.get("stream_url", "")
            if "@" in url:
                assert ":******@" in url


    def test_malformed_url_schemes_and_extraction_boundaries(self):
        """
        Adversarial probe testing regex and url parser boundaries:
        - URL with multiple colons in password: rtsp://user:pass:extra@host
        - URL with @ inside password: rtsp://user:p@ss@host
        - URL with no username: rtsp://:secret@host
        - URL with credentials in HTTP basic auth: http://admin:pass@host/video
        """
        # Test Case 1: Empty username rtsp://:secret@192.168.1.1/live
        url1 = "rtsp://:mysecret@192.168.1.1:554/live"
        row1 = {"id": "c1", "live_url": url1, "substream_url": None}
        formatted1 = _format_camera_response(row1)
        assert "mysecret" not in formatted1["stream_url"]

        # Test Case 2: HTTP stream with credentials http://admin:pass@192.168.1.10/mjpg
        url2 = "http://admin:http_pass123@192.168.1.10:8080/mjpg"
        row2 = {"id": "c2", "live_url": url2, "substream_url": None}
        formatted2 = _format_camera_response(row2)
        assert "http_pass123" not in formatted2["stream_url"]

        # Test Case 3: Multiple colons in password rtsp://admin:secret:part2@192.168.1.1/live
        url3 = "rtsp://admin:secret:part2@192.168.1.1:554/live"
        row3 = {"id": "c3", "live_url": url3, "substream_url": None}
        formatted3 = _format_camera_response(row3)
        sanitized3 = formatted3["stream_url"]
        assert "secret" not in sanitized3, f"Password substring 'secret' leaked in sanitized URL: {sanitized3}"

        # Test Case 4: Password containing '@' symbol
        url4 = "rtsp://admin:p@ssword@192.168.1.1:554/live"
        row4 = {"id": "c4", "live_url": url4, "substream_url": None}
        formatted4 = _format_camera_response(row4)
        sanitized4 = formatted4["stream_url"]
        assert "ssword" not in sanitized4, f"Password suffix 'ssword' leaked in sanitized URL: {sanitized4}"

        # Test Case 5: Substream URL sanitization
        sub_url = "rtsp://admin:sub_secret_password@192.168.1.1:554/sub"
        row5 = {"id": "c5", "live_url": "rtsp://192.168.1.1/live", "substream_url": sub_url}
        formatted5 = _format_camera_response(row5)
        assert "sub_secret_password" not in formatted5["substream_url"]
        assert ":******@" in formatted5["substream_url"]


    def test_camera_update_substream_url_persistence(self, client):
        """
        Tests whether updating a camera's substream_url via PUT or PATCH persists.
        Identifies if update_camera drops substream_url.
        """
        # 1. Create camera with initial substream_url
        create_res = client.post(
            "/api/cameras",
            json={
                "name": "Cam For Update Test",
                "brand": "generic",
                "stream_url": "rtsp://192.168.1.50/live",
                "substream_url": "rtsp://192.168.1.50/sub1",
            },
        )
        assert create_res.status_code == 200
        cam_id = create_res.json()["id"]
        assert create_res.json()["substream_url"] == "rtsp://192.168.1.50/sub1"

        # 2. Update substream_url via PATCH
        new_substream = "rtsp://192.168.1.50/sub2_updated"
        patch_res = client.patch(
            f"/api/cameras/{cam_id}",
            json={"substream_url": new_substream},
        )
        assert patch_res.status_code == 200
        patch_data = patch_res.json()

        # 3. Verify via GET /api/cameras/{id}
        get_res = client.get(f"/api/cameras/{cam_id}")
        assert get_res.status_code == 200
        get_data = get_res.json()

        # Check if update persisted or was dropped
        substream_persisted = (get_data.get("substream_url") == new_substream)
        assert substream_persisted, (
            f"substream_url was NOT updated! Expected '{new_substream}', "
            f"but got '{get_data.get('substream_url')}'"
        )


# ==============================================================================
# SUITE 2: Dual-Stream Concurrency & Substream URL Persistence (50 Cameras)
# ==============================================================================
class TestDualStreamConcurrencyAndPersistence:
    """
    Stress-tests dual-stream concurrency: adds 50 cameras with substream_url
    under high concurrency and verifies persistence and retrieval.
    """

    @pytest.mark.asyncio
    async def test_concurrent_add_and_retrieve_50_cameras_with_substream(self, setup_test_env):
        """
        Adds 50 cameras with substream_url concurrently via asyncio.gather,
        then retrieves all 50 cameras concurrently, verifying 100% data integrity.
        """
        num_cameras = 50

        # 1. Concurrent Camera Addition
        async def add_single_camera(i: int) -> Dict[str, Any]:
            cam_payload = {
                "id": f"cam_concurrent_{i:03d}",
                "name": f"Concurrent Camera {i:03d}",
                "brand": "generic",
                "stream_url": f"rtsp://admin:pass{i}@192.168.1.{100 + (i % 100)}:554/live",
                "substream_url": f"rtsp://admin:subpass{i}@192.168.1.{100 + (i % 100)}:554/sub",
                "stream_id": f"stream_conc_{i:03d}",
                "has_ptz": (i % 2 == 0),
                "recording_enabled": False,
            }
            # Simulate direct API database write
            saved = await save_camera(cam_payload)
            return saved

        # Run 50 additions concurrently
        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*(add_single_camera(i) for i in range(num_cameras)))
        elapsed_add = asyncio.get_event_loop().time() - start_time

        assert len(results) == num_cameras, f"Expected {num_cameras} saved cameras"

        # 2. Concurrent Retrieval of all 50 cameras
        async def get_single_camera(cam_id: str) -> Optional[Dict[str, Any]]:
            return await get_camera_by_id(cam_id)

        start_time = asyncio.get_event_loop().time()
        retrieved_results = await asyncio.gather(
            *(get_single_camera(f"cam_concurrent_{i:03d}") for i in range(num_cameras))
        )
        elapsed_get = asyncio.get_event_loop().time() - start_time

        assert len(retrieved_results) == num_cameras

        # 3. Verify substream_url persistence for all 50 cameras
        missing_substream = []
        corrupted_substream = []
        for i, cam in enumerate(retrieved_results):
            assert cam is not None, f"Camera {i} returned None from database"
            expected_sub = f"rtsp://admin:subpass{i}@192.168.1.{100 + (i % 100)}:554/sub"
            actual_sub = cam.get("substream_url")
            if not actual_sub:
                missing_substream.append(cam.get("id"))
            elif actual_sub != expected_sub:
                corrupted_substream.append((cam.get("id"), actual_sub, expected_sub))

        assert len(missing_substream) == 0, f"Cameras missing substream_url: {missing_substream}"
        assert len(corrupted_substream) == 0, f"Cameras with corrupted substream_url: {corrupted_substream}"

        # 4. Verify API serialization of all 50 cameras
        async with get_db() as conn:
            async with conn.execute("SELECT * FROM cameras WHERE id LIKE 'cam_concurrent_%';") as cursor:
                rows = await cursor.fetchall()
                formatted_list = [_format_camera_response(dict(r)) for r in rows]

        assert len(formatted_list) == num_cameras
        for item in formatted_list:
            assert item["substream_url"] is not None
            # Sensitive subpass password must be masked in API output
            assert ":******@" in item["substream_url"]

    @pytest.mark.asyncio
    async def test_concurrent_mixed_read_write_stress(self, setup_test_env):
        """
        Stress test: 25 simultaneous writes and 25 simultaneous reads on the same DB connection pool.
        Verifies SQLite WAL concurrency and absence of 'database is locked' errors.
        """
        async def writer(i: int):
            data = {
                "id": f"cam_rw_{i}",
                "name": f"RW Cam {i}",
                "brand": "generic",
                "stream_id": f"stream_rw_{i}",
                "substream_url": f"rtsp://10.0.0.{i}/sub",
            }
            return await save_camera(data)

        async def reader(i: int):
            await asyncio.sleep(0.005 * (i % 5))
            async with get_db() as conn:
                async with conn.execute("SELECT count(*) FROM cameras;") as cursor:
                    row = await cursor.fetchone()
                    return row[0] if row else 0

        tasks = [writer(i) for i in range(25)] + [reader(i) for i in range(25)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        exceptions = [r for r in results if isinstance(r, Exception)]
        assert len(exceptions) == 0, f"Encountered concurrency exceptions: {exceptions}"


# ==============================================================================
# SUITE 3: Fault Injection on Regional Token Endpoints
# ==============================================================================
class TestRegionalTokenEndpointsFaultInjection:
    """
    Fault injection testing on regional token endpoints:
    - EZVIZ 9 regional gateways (cn, us, eu, de, sg, ap, ru, sa, i2)
    - Xiaomi 6 regional gateways (cn, de, i2, ru, sg, us)
    - Network timeout, HTTP 500, corrupt JSON, auth errors, rate limiting
    """

    def test_ezviz_all_nine_regional_endpoints_resolution(self):
        """Verifies EZVIZService resolves all 9 regional codes without errors."""
        service = EZVIZService()
        expected_regions = ["cn", "us", "eu", "de", "sg", "ap", "ru", "sa", "i2"]

        for reg in expected_regions:
            resolved = service.resolve_endpoint(reg)
            assert resolved.startswith("https://"), f"Region {reg} resolved to invalid URL: {resolved}"
            assert resolved == EZVIZ_REGIONAL_ENDPOINTS[reg]

        # Verify default fallback for unknown region is 'cn'
        fallback = service.resolve_endpoint("unknown_region")
        assert fallback == EZVIZ_REGIONAL_ENDPOINTS["cn"]

    @pytest.mark.asyncio
    async def test_ezviz_token_endpoint_network_timeout(self, monkeypatch):
        """Simulates network timeout on EZVIZ token endpoint."""
        service = EZVIZService()

        async def timeout_post(*args, **kwargs):
            raise httpx.ConnectTimeout("Connection timed out to EZVIZ regional endpoint")

        monkeypatch.setattr(httpx.AsyncClient, "post", timeout_post)

        with pytest.raises((httpx.ConnectTimeout, httpx.RequestError)):
            await service.get_token(app_key="test_key", app_secret="test_secret", region="eu")

    @pytest.mark.asyncio
    async def test_ezviz_token_endpoint_server_500(self, monkeypatch):
        """Simulates HTTP 500 Internal Server Error from regional OpenAPI gateway."""
        service = EZVIZService()

        async def server_error_post(*args, **kwargs):
            req = httpx.Request("POST", "https://open.ys7.com/api/lapp/token/get")
            return httpx.Response(500, text="Internal Server Error", request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", server_error_post)

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await service.get_token(app_key="test_key", app_secret="test_secret", region="de")
        assert exc_info.value.response.status_code == 500

    @pytest.mark.asyncio
    async def test_ezviz_token_endpoint_error_code_envelope(self, monkeypatch):
        """Simulates EZVIZ JSON error envelope with non-200 code (e.g. 10001: invalid appKey)."""
        service = EZVIZService()

        async def error_code_post(*args, **kwargs):
            req = httpx.Request("POST", "https://open.ys7.com/api/lapp/token/get")
            return httpx.Response(200, json={"code": "10001", "msg": "appKey or appSecret is incorrect"}, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", error_code_post)

        with pytest.raises(EZVIZAuthError) as exc_info:
            await service.get_token(app_key="wrong_key", app_secret="wrong_secret", region="sg")
        assert exc_info.value.code == "10001"
        assert "appKey or appSecret is incorrect" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_ezviz_token_endpoint_corrupt_json(self, monkeypatch):
        """Simulates corrupt/non-JSON response from regional endpoint."""
        service = EZVIZService()

        async def corrupt_post(*args, **kwargs):
            req = httpx.Request("POST", "https://open.ys7.com/api/lapp/token/get")
            return httpx.Response(200, text="<HTML><HEAD><TITLE>Gateway Error</TITLE></HEAD></HTML>", request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", corrupt_post)

        with pytest.raises(json.JSONDecodeError):
            await service.get_token(app_key="test_key", app_secret="test_secret", region="ru")

    def test_xiaomi_all_six_regional_endpoints_resolution(self):
        """Verifies XiaomiService resolves all 6 regional endpoints correctly."""
        service = XiaomiService()
        for reg in XIAOMI_REGIONS:
            endpoint = service.resolve_endpoint(reg)
            assert endpoint == XIAOMI_REGIONAL_ENDPOINTS[reg]
            assert endpoint.startswith("https://")

        # Invalid region must raise XiaomiError with code -1
        with pytest.raises(XiaomiError) as exc_info:
            service.resolve_endpoint("invalid_region")
        assert exc_info.value.code == -1

    @pytest.mark.asyncio
    async def test_xiaomi_passport_step1_timeout(self, monkeypatch):
        """Simulates network timeout during Xiaomi Passport step 1."""
        service = XiaomiService()

        async def timeout_get(*args, **kwargs):
            raise httpx.ReadTimeout("Read timed out waiting for Xiaomi Passport")

        monkeypatch.setattr(httpx.AsyncClient, "get", timeout_get)

        with pytest.raises((httpx.ReadTimeout, httpx.RequestError)):
            await service.passport_step1()

    @pytest.mark.asyncio
    async def test_xiaomi_passport_step2_auth_failure_70016(self, monkeypatch):
        """Simulates Xiaomi code 70016 (invalid username or password)."""
        service = XiaomiService()

        # Step 1 succeeds
        async def step1_mock(*args, **kwargs):
            req = httpx.Request("GET", "https://account.xiaomi.com/pass/serviceLogin")
            return httpx.Response(
                200,
                text='&&&START&&&{"_sign": "mock_sign", "qs": "mock_qs", "callback": "mock_cb"}',
                request=req,
            )

        # Step 2 fails with code 70016
        async def step2_mock(*args, **kwargs):
            req = httpx.Request("POST", "https://account.xiaomi.com/pass/serviceLoginAuth2")
            return httpx.Response(
                200,
                text='&&&START&&&{"code": 70016, "description": "Invalid password"}',
                request=req,
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", step1_mock)
        monkeypatch.setattr(httpx.AsyncClient, "post", step2_mock)

        with pytest.raises(XiaomiAuthError) as exc_info:
            await service.login("user@example.com", "wrong_password", region="de")
        assert exc_info.value.code == 70016

    @pytest.mark.asyncio
    async def test_xiaomi_passport_2fa_challenge_code_87001(self, monkeypatch):
        """Simulates Xiaomi 2FA verification challenge (code 87001)."""
        service = XiaomiService()

        async def step1_mock(*args, **kwargs):
            req = httpx.Request("GET", "https://account.xiaomi.com/pass/serviceLogin")
            return httpx.Response(
                200,
                text='&&&START&&&{"_sign": "mock_sign", "qs": "mock_qs", "callback": "mock_cb"}',
                request=req,
            )

        challenge_data = {
            "code": 87001,
            "description": "2FA verification required",
            "notificationUrl": "https://account.xiaomi.com/identity/auth",
            "sign": "sign_123",
            "qs": "qs_123",
        }

        async def step2_mock(*args, **kwargs):
            req = httpx.Request("POST", "https://account.xiaomi.com/pass/serviceLoginAuth2")
            return httpx.Response(
                200,
                text=f"&&&START&&&{json.dumps(challenge_data)}",
                request=req,
            )

        monkeypatch.setattr(httpx.AsyncClient, "get", step1_mock)
        monkeypatch.setattr(httpx.AsyncClient, "post", step2_mock)

        with pytest.raises(XiaomiAuthError) as exc_info:
            await service.login("user@example.com", "pass123", region="i2")
        assert exc_info.value.code == 87001
        assert exc_info.value.data is not None


    def test_xiaomi_hmac_sha256_cryptographic_signing_resilience(self):
        """
        Tests sign_miio_request cryptographic signing with diverse data payloads,
        ensuring proper nonce generation, valid base64 output, and signature formatting.
        """
        uri = "/home/device_list"
        data_json = json.dumps({"getVirtualModel": True, "getHuamiDevices": 1})
        # 16-byte base64-encoded secret
        ssecurity = "dGVzdF9zc2VjdXJpdHlfMTIzNA=="

        signed = sign_miio_request(uri, data_json, ssecurity)

        assert "_nonce" in signed
        assert "data" in signed
        assert "signature" in signed
        assert signed["data"] == data_json

        # Nonce must be valid base64 and 16 bytes decoded (12 random/epoch bytes)
        import base64
        nonce_bytes = base64.b64decode(signed["_nonce"])
        assert len(nonce_bytes) == 12

        # Signature must be valid base64-encoded SHA-256 (32 bytes)
        sig_bytes = base64.b64decode(signed["signature"])
        assert len(sig_bytes) == 32
