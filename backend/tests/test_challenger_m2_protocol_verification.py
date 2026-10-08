"""
backend/tests/test_challenger_m2_protocol_verification.py

Empirical Challenge & Protocol Verification Suite for Milestone 2 Iteration 3.
Authored by Challenger M2.2.

Target Systems under Verification:
1. ONVIF:
   - continuous_move and stop_ptz signature polymorphism (ptz_service_url, xaddr, both, neither).
   - SOAP envelope and WS-Security PasswordDigest payload generation.
   - XML structure correctness for ContinuousMove and Stop actions.
   - Vector boundary float ranges (-1.0 to 1.0) and boolean PanTilt / Zoom flags.
2. Xiaomi MIoT:
   - Regional cloud gateway endpoints across all 6 regions (cn, de, i2, ru, sg, us).
   - HMAC-SHA256 signature generation (sign_miio_request) with dynamic 12-byte nonce.
   - MIoT Spec RPC structure (/miotspec/action with siid, aiid, in parameters).
   - Motor PTZ action mapping (directions up/down/left/right -> 1/2/3/4).
   - Stream descriptor generation (xiaomi:// URL format and token/pin parameters).
3. EZVIZ OpenAPI:
   - Regional OpenAPI endpoint mapping (cn, us, eu, de, sg, ap, ru, sa, i2).
   - Access token acquisition, 7-day expiration handling, and caching lifecycle.
   - Live stream URL retrieval (StreamLease expiration epoch and local RTSP resolution).
   - Stream encryption off toggling with 6-character verification code.
   - Cloud PTZ start/stop direction (0-9) and speed bounds (1-10).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
import pytest
import httpx

from app.services.onvif_service import (
    ONVIFService,
    ONVIFError,
    create_ws_security_header,
    wrap_soap_envelope,
    SOAP_NAMESPACES,
)
from app.services.xiaomi_service import (
    XiaomiService,
    XiaomiError,
    XIAOMI_REGIONS,
    XIAOMI_REGIONAL_ENDPOINTS,
    sign_miio_request,
)
from app.services.ezviz_service import (
    EZVIZService,
    EZVIZError,
    EZVIZAuthError,
    EZVIZDeviceError,
    EZVIZ_REGIONAL_ENDPOINTS,
    StreamLease,
)
from app.api.cameras import sanitize_stream_url


# ==============================================================================
# Suite 1: ONVIF Protocol Signatures & SOAP Payload Generation
# ==============================================================================
class TestONVIFProtocolAndPayloads:
    """Verifies ONVIF continuous_move / stop_ptz signatures and SOAP XML payload."""

    def test_ws_security_header_structure_and_digest(self):
        """WS-Security header must contain Username, PasswordDigest, Nonce, and Created."""
        username = "admin"
        password = "ComplexPassword#2026!"
        hdr = create_ws_security_header(username, password)
        assert hdr, "WS-Security header is empty!"

        # Wrap in temporary root for XML parsing
        root = ET.fromstring(f"<root>{hdr}</root>")
        ns = {
            "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
        }
        user_elem = root.find(".//wsse:Username", ns)
        assert user_elem is not None
        assert user_elem.text == username

        pass_elem = root.find(".//wsse:Password", ns)
        assert pass_elem is not None
        assert pass_elem.attrib.get("Type") == (
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
        )
        assert len(pass_elem.text) > 20  # Base64 SHA1 digest

        nonce_elem = root.find(".//wsse:Nonce", ns)
        assert nonce_elem is not None
        raw_nonce = base64.b64decode(nonce_elem.text)
        assert len(raw_nonce) == 16  # 16-byte random nonce

        created_elem = root.find(".//wsu:Created", ns)
        assert created_elem is not None
        assert "T" in created_elem.text and created_elem.text.endswith("Z")

    def test_wrap_soap_envelope_validity(self):
        """wrap_soap_envelope must generate well-formed XML with standard namespaces."""
        body = "<tptz:ContinuousMove><tptz:ProfileToken>prof_1</tptz:ProfileToken></tptz:ContinuousMove>"
        xml = wrap_soap_envelope(body, username="user1", password="pw1")
        root = ET.fromstring(xml)
        assert root.tag.endswith("Envelope")

        # Must have Header and Body
        header = root.find("{http://www.w3.org/2003/05/soap-envelope}Header")
        body_elem = root.find("{http://www.w3.org/2003/05/soap-envelope}Body")
        assert header is not None
        assert body_elem is not None

    @pytest.mark.asyncio
    async def test_continuous_move_payload_structure(self, monkeypatch):
        """ContinuousMove SOAP body must include ProfileToken and PanTilt/Zoom velocities."""
        captured: Dict[str, Any] = {}

        async def fake_send_soap(endpoint_url, action_name, body_xml, username=None, password=None):
            captured["url"] = endpoint_url
            captured["action"] = action_name
            captured["body"] = body_xml
            return "<soap:Envelope/>"

        svc = ONVIFService()
        monkeypatch.setattr(svc, "_send_soap_request", fake_send_soap)

        # 1. Test using ptz_service_url
        res = await svc.continuous_move(
            ptz_service_url="http://192.168.1.100:8080/onvif/ptz",
            profile_token="MainProfile_01",
            pan=0.75,
            tilt=-0.50,
            zoom=1.0,
            username="admin",
            password="pwd",
        )
        assert res is True
        assert captured["url"] == "http://192.168.1.100:8080/onvif/ptz"
        assert captured["action"] == "ContinuousMove"

        # Verify XML body elements
        body_root = ET.fromstring(f"<root xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">{captured['body']}</root>")
        pt_elem = body_root.find(".//{http://www.onvif.org/ver20/ptz/wsdl}ProfileToken")
        assert pt_elem is not None and pt_elem.text == "MainProfile_01"

        pantilt = body_root.find(".//{http://www.onvif.org/ver10/schema}PanTilt")
        assert pantilt is not None
        assert float(pantilt.attrib["x"]) == 0.75
        assert float(pantilt.attrib["y"]) == -0.50

        zoom_elem = body_root.find(".//{http://www.onvif.org/ver10/schema}Zoom")
        assert zoom_elem is not None
        assert float(zoom_elem.attrib["x"]) == 1.0

        # 2. Test using xaddr keyword argument
        res2 = await svc.continuous_move(
            xaddr="http://192.168.1.101:8080/onvif/ptz",
            profile_token="SubProfile_02",
            pan=-1.0,
            tilt=1.0,
            zoom=-0.5,
        )
        assert res2 is True
        assert captured["url"] == "http://192.168.1.101:8080/onvif/ptz"

    @pytest.mark.asyncio
    async def test_stop_ptz_payload_structure(self, monkeypatch):
        """Stop SOAP body must include ProfileToken, PanTilt (boolean) and Zoom (boolean)."""
        captured: Dict[str, Any] = {}

        async def fake_send_soap(endpoint_url, action_name, body_xml, username=None, password=None):
            captured["url"] = endpoint_url
            captured["action"] = action_name
            captured["body"] = body_xml
            return "<soap:Envelope/>"

        svc = ONVIFService()
        monkeypatch.setattr(svc, "_send_soap_request", fake_send_soap)

        # PanTilt True, Zoom False
        await svc.stop_ptz(
            ptz_service_url="http://192.168.1.100:8080/onvif/ptz",
            profile_token="Profile_Stop",
            pan_tilt=True,
            zoom=False,
        )
        assert captured["action"] == "Stop"
        body_root = ET.fromstring(f"<root xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\">{captured['body']}</root>")
        pt = body_root.find(".//{http://www.onvif.org/ver20/ptz/wsdl}PanTilt")
        zm = body_root.find(".//{http://www.onvif.org/ver20/ptz/wsdl}Zoom")
        assert pt is not None and pt.text == "true"
        assert zm is not None and zm.text == "false"

        # PanTilt False, Zoom True via xaddr
        await svc.stop_ptz(
            xaddr="http://192.168.1.102:8080/onvif/ptz",
            pan_tilt=False,
            zoom=True,
        )
        assert captured["url"] == "http://192.168.1.102:8080/onvif/ptz"
        body_root2 = ET.fromstring(f"<root xmlns:tptz=\"http://www.onvif.org/ver20/ptz/wsdl\">{captured['body']}</root>")
        pt2 = body_root2.find(".//{http://www.onvif.org/ver20/ptz/wsdl}PanTilt")
        zm2 = body_root2.find(".//{http://www.onvif.org/ver20/ptz/wsdl}Zoom")
        assert pt2.text == "false"
        assert zm2.text == "true"

    @pytest.mark.asyncio
    async def test_onvif_missing_url_raises_onvif_error(self):
        """Calling continuous_move or stop_ptz without any URL raises ONVIFError."""
        svc = ONVIFService()
        with pytest.raises(ONVIFError, match="ptz_service_url or xaddr is required"):
            await svc.continuous_move()

        with pytest.raises(ONVIFError, match="ptz_service_url or xaddr is required"):
            await svc.stop_ptz()


# ==============================================================================
# Suite 2: Xiaomi MIoT RPC Formatting Across Regions
# ==============================================================================
class TestXiaomiMIoTAcrossRegions:
    """Verifies Xiaomi MIoT RPC formatting, HMAC signing, and regional routing."""

    def test_all_6_regions_resolve_correct_endpoints(self):
        """Verifies regional gateway URLs for cn, de, i2, ru, sg, us."""
        svc = XiaomiService()
        expected = {
            "cn": "https://api.io.mi.com/app",
            "de": "https://de.api.io.mi.com/app",
            "i2": "https://i2.api.io.mi.com/app",
            "ru": "https://ru.api.io.mi.com/app",
            "sg": "https://sg.api.io.mi.com/app",
            "us": "https://us.api.io.mi.com/app",
        }
        for reg, url in expected.items():
            assert svc.resolve_endpoint(reg) == url
            assert svc.resolve_endpoint(reg.upper()) == url  # Case-insensitivity

        with pytest.raises(XiaomiError, match="Invalid Xiaomi region"):
            svc.resolve_endpoint("jp")

        with pytest.raises(XiaomiError, match="Invalid Xiaomi region"):
            svc.resolve_endpoint("uk")

    def test_sign_miio_request_hmac_and_nonce_format(self):
        """Verifies HMAC-SHA256 signature and 12-byte nonce generation."""
        ssecurity = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("utf-8")
        uri = "/miotspec/action"
        payload = json.dumps({"params": {"did": "12345", "siid": 5, "aiid": 1, "in": [1]}})

        signed = sign_miio_request(uri, payload, ssecurity)
        assert "_nonce" in signed
        assert "data" in signed and signed["data"] == payload
        assert "signature" in signed

        # Verify nonce format: 12 bytes decoded
        raw_nonce = base64.b64decode(signed["_nonce"])
        assert len(raw_nonce) == 12

        # Verify signature length
        raw_sig = base64.b64decode(signed["signature"])
        assert len(raw_sig) == 32  # SHA-256 is 32 bytes

    @pytest.mark.asyncio
    async def test_miot_action_payload_across_all_regions(self, monkeypatch):
        """Verifies /miotspec/action RPC structure across every supported region."""
        svc = XiaomiService()
        sent_requests: List[Dict[str, Any]] = []

        async def mock_post(self, url, **kwargs):
            sent_requests.append({
                "url": str(url),
                "data": kwargs.get("data"),
                "headers": kwargs.get("headers"),
            })
            req = httpx.Request("POST", str(url))
            return httpx.Response(200, json={"code": 0, "message": "ok", "result": {"out": []}}, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        ssec = base64.b64encode(b"ssecurity_test_key_32bytes_long!").decode("utf-8")

        for reg in XIAOMI_REGIONS:
            sent_requests.clear()
            res = await svc.miot_action(
                region=reg,
                service_token=f"token_{reg}",
                did="cam_did_999",
                siid=5,
                aiid=1,
                in_params=[3],  # Move left
                ssecurity=ssec,
            )
            assert res["code"] == 0
            assert len(sent_requests) == 1
            req = sent_requests[0]

            expected_endpoint = f"{XIAOMI_REGIONAL_ENDPOINTS[reg]}/miotspec/action"
            assert req["url"] == expected_endpoint
            assert req["headers"]["Cookie"] == f"serviceToken=token_{reg}"

            # Check signed payload
            data_dict = req["data"]
            assert "_nonce" in data_dict
            assert "signature" in data_dict
            inner_data = json.loads(data_dict["data"])
            assert inner_data["params"]["did"] == "cam_did_999"
            assert inner_data["params"]["siid"] == 5
            assert inner_data["params"]["aiid"] == 1
            assert inner_data["params"]["in"] == [3]

    @pytest.mark.asyncio
    async def test_ptz_move_direction_mapping(self, monkeypatch):
        """Verifies ptz_move maps directions up=1, down=2, left=3, right=4."""
        svc = XiaomiService()
        actions_called: List[Dict[str, Any]] = []

        async def fake_miot_action(region, service_token, did, siid, aiid, in_params, ssecurity=None):
            actions_called.append({
                "region": region,
                "did": did,
                "siid": siid,
                "aiid": aiid,
                "in": in_params,
            })
            return {"code": 0, "message": "ok"}

        monkeypatch.setattr(svc, "miot_action", fake_miot_action)

        directions = [("up", 1), ("down", 2), ("left", 3), ("right", 4), (1, 1), (4, 4), ("unknown", 1)]
        for d, expected_val in directions:
            actions_called.clear()
            await svc.ptz_move(did="did_ptz", direction=d, region="cn", service_token="tok")
            assert len(actions_called) == 1
            assert actions_called[0]["siid"] == 5
            assert actions_called[0]["aiid"] == 1
            assert actions_called[0]["in"] == [expected_val]

    def test_xiaomi_stream_descriptor_and_sanitization(self):
        """Verifies xiaomi:// URI formatting and password masking."""
        svc = XiaomiService()
        loop = asyncio.new_event_loop()
        desc = loop.run_until_complete(svc.get_stream_descriptor(
            did="did123",
            region="cn",
            service_token="tok",
            device_ip="192.168.1.88",
            device_token="devicetokenhex123",
            pin="1234",
        ))
        loop.close()
        raw_url = desc["stream_url"]
        assert raw_url == "xiaomi://192.168.1.88?token=devicetokenhex123&pin=1234"

        # Masking
        masked = sanitize_stream_url(raw_url)
        assert "devicetokenhex123" not in masked
        assert "1234" not in masked
        assert masked == "xiaomi://192.168.1.88?token=******&pin=******"


# ==============================================================================
# Suite 3: EZVIZ Token Acquisition & Live Stream Retrieval
# ==============================================================================
class TestEZVIZTokenAndStreamRetrieval:
    """Verifies EZVIZ OpenAPI token acquisition, cache lifecycle, and live stream extraction."""

    def test_all_ezviz_regional_endpoints(self):
        """Verifies regional endpoint resolution for cn, us, eu, de, sg, ap, ru, sa, i2."""
        svc = EZVIZService()
        expected = {
            "cn": "https://open.ys7.com",
            "us": "https://iusopen.ezvizlife.com",
            "eu": "https://ieuopen.ezvizlife.com",
            "de": "https://ieuopen.ezvizlife.com",
            "sg": "https://isgpopen.ezvizlife.com",
            "ap": "https://isgpopen.ezvizlife.com",
            "ru": "https://iruopen.ezvizlife.com",
            "sa": "https://isaopen.ezvizlife.com",
            "i2": "https://isgpopen.ezvizlife.com",
        }
        for reg, url in expected.items():
            assert svc.resolve_endpoint(reg) == url

        # Custom area_domain overrides regional code
        custom = "https://custom.openapi.ezvizlife.com"
        assert svc.resolve_endpoint("us", area_domain=custom) == custom

    @pytest.mark.asyncio
    async def test_token_acquisition_and_caching_lifecycle(self, monkeypatch):
        """Verifies /api/lapp/token/get exchange, caching, and forced refresh."""
        svc = EZVIZService()
        call_count = 0

        async def fake_post(self, url, **kwargs):
            nonlocal call_count
            call_count += 1
            now_ms = int(time.time() * 1000)
            req = httpx.Request("POST", str(url))
            return httpx.Response(200, json={
                "code": "200",
                "msg": "success",
                "data": {
                    "accessToken": f"at.live_{call_count}",
                    "expireTime": now_ms + (7 * 24 * 3600 * 1000),  # 7 days
                    "areaDomain": "https://open.ys7.com",
                }
            }, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        # First call: hits API
        t1 = await svc.get_token("app_k1", "app_s1", region="cn")
        assert t1.access_token == "at.live_1"
        assert call_count == 1
        assert not t1.is_expired

        # Second call: uses cache (call_count unchanged)
        t2 = await svc.get_token("app_k1", "app_s1", region="cn")
        assert t2.access_token == "at.live_1"
        assert call_count == 1

        # Third call: force_refresh bypasses cache
        t3 = await svc.get_token("app_k1", "app_s1", region="cn", force_refresh=True)
        assert t3.access_token == "at.live_2"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_token_acquisition_invalid_credentials_raises_auth_error(self, monkeypatch):
        """EZVIZAuthError raised on invalid appKey / appSecret."""
        svc = EZVIZService()

        async def fake_post(self, url, **kwargs):
            req = httpx.Request("POST", str(url))
            return httpx.Response(200, json={
                "code": "10001",
                "msg": "appKey does not exist",
            }, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        with pytest.raises(EZVIZAuthError, match="appKey does not exist"):
            await svc.get_token("invalid_key", "invalid_secret")

    @pytest.mark.asyncio
    async def test_live_stream_retrieval_and_lease(self, monkeypatch):
        """Verifies get_live_address parses stream URL, expiration lease, and encryption state."""
        svc = EZVIZService()
        captured_data: Dict[str, Any] = {}

        async def fake_post(self, url, **kwargs):
            captured_data.update(kwargs.get("data", {}))
            now_sec = time.time()
            req = httpx.Request("POST", str(url))
            return httpx.Response(200, json={
                "code": "200",
                "msg": "success",
                "data": {
                    "url": "rtsp://open.ezvizlife.com:554/live/G12345678",
                    "expireTime": int((now_sec + 600) * 1000),  # 10 minutes in ms
                    "isEncrypt": 0,
                    "hls": "https://open.ezvizlife.com/hls/live.m3u8",
                }
            }, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        lease: StreamLease = await svc.get_live_address(
            access_token="at.valid_tok",
            device_serial="G12345678",
            channel_no=1,
            protocol=1,  # RTSP
            quality=1,
            expire_time_sec=600,
        )

        assert lease.stream_url == "rtsp://open.ezvizlife.com:554/live/G12345678"
        assert lease.is_encrypt == 0
        assert lease.is_local_rtsp is False
        assert lease.hls_url == "https://open.ezvizlife.com/hls/live.m3u8"
        assert lease.expires_at > time.time() + 500

        # Verify POST payload parameters
        assert captured_data["accessToken"] == "at.valid_tok"
        assert captured_data["deviceSerial"] == "G12345678"
        assert captured_data["channelNo"] == 1
        assert captured_data["protocol"] == 1

    @pytest.mark.asyncio
    async def test_set_encryption_off_with_verification_code(self, monkeypatch):
        """Verifies /api/lapp/device/encrypt/off payload and error handling."""
        svc = EZVIZService()
        captured_data: Dict[str, Any] = {}

        async def fake_post(self, url, **kwargs):
            captured_data.update(kwargs.get("data", {}))
            req = httpx.Request("POST", str(url))
            if kwargs.get("data", {}).get("validateCode") == "CORRECT":
                return httpx.Response(200, json={"code": "200", "msg": "success"}, request=req)
            return httpx.Response(200, json={"code": "20014", "msg": "verification code error"}, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        # Successful disable
        res = await svc.set_encryption_off("at.tok", "DEV001", "CORRECT")
        assert res is True
        assert captured_data["validateCode"] == "CORRECT"

        # Failed verification code
        with pytest.raises(EZVIZDeviceError, match="verification code error"):
            await svc.set_encryption_off("at.tok", "DEV001", "WRONG!")

    @pytest.mark.asyncio
    async def test_ezviz_cloud_ptz_direction_and_speed_matrix(self, monkeypatch):
        """Verifies direction 0-9 and speed 1-10 bounds enforcement for cloud PTZ."""
        svc = EZVIZService()

        async def fake_post(self, url, **kwargs):
            req = httpx.Request("POST", str(url))
            return httpx.Response(200, json={"code": "200", "msg": "success"}, request=req)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        # Valid directions (0-9) and valid speeds (1-10)
        for d in range(10):
            res = await svc.ptz_start("at.tok", "DEV_PTZ", direction=d, speed=5)
            assert res is True

        stop_res = await svc.ptz_stop("at.tok", "DEV_PTZ")
        assert stop_res is True

        # Out-of-bounds directions
        with pytest.raises(EZVIZError, match="Invalid PTZ direction"):
            await svc.ptz_start("at.tok", "DEV_PTZ", direction=-1)

        with pytest.raises(EZVIZError, match="Invalid PTZ direction"):
            await svc.ptz_start("at.tok", "DEV_PTZ", direction=10)

        # Out-of-bounds speeds
        with pytest.raises(EZVIZError, match="Invalid PTZ speed"):
            await svc.ptz_start("at.tok", "DEV_PTZ", direction=0, speed=0)

        with pytest.raises(EZVIZError, match="Invalid PTZ speed"):
            await svc.ptz_start("at.tok", "DEV_PTZ", direction=0, speed=11)

    def test_local_rtsp_resolution_zero_timeout_format(self):
        """Verifies local RTSP URI format: rtsp://admin:{verification_code}@{ip}:{port}/h264/ch{channel_no}/main/av_stream."""
        svc = EZVIZService()
        url = svc.resolve_local_rtsp_url(
            ip="192.168.1.150",
            verification_code="ABCDEF",
            port=554,
            channel_no=1,
            stream_type="main",
        )
        assert url == "rtsp://admin:ABCDEF@192.168.1.150:554/h264/ch1/main/av_stream"

        # Verify password sanitization masks the verification code
        masked = sanitize_stream_url(url)
        assert "ABCDEF" not in masked
        assert masked == "rtsp://admin:******@192.168.1.150:554/h264/ch1/main/av_stream"
