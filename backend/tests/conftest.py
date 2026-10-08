"""
backend/tests/conftest.py

Test fixtures and mock cloud transport for backend unit & adversarial tests.
Zero mock hooks in production code: intercepts HTTP calls at the httpx transport level
and UDP discovery via asyncio datagram endpoint patching.
"""

from __future__ import annotations

import asyncio
import json
import socket
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import httpx
import pytest

from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
)

# Registry of active mock instances for the current test
_current_mocks: Dict[str, Any] = {
    "ezviz": MockEZVIZPlatform(),
    "xiaomi": MockXiaomiPlatform(),
    "onvif": MockONVIFDevice(),
}


def get_current_mocks() -> Dict[str, Any]:
    return _current_mocks


def set_current_mocks(
    ezviz: Optional[MockEZVIZPlatform] = None,
    xiaomi: Optional[MockXiaomiPlatform] = None,
    onvif: Optional[MockONVIFDevice] = None,
) -> None:
    if ezviz is not None:
        _current_mocks["ezviz"] = ezviz
    if xiaomi is not None:
        _current_mocks["xiaomi"] = xiaomi
    if onvif is not None:
        _current_mocks["onvif"] = onvif


class UnifiedMockCloudTransport(httpx.AsyncBaseTransport):
    """
    HTTP transport that routes requests to the active mock platforms without
    requiring mock hooks in production service classes.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        content_bytes = await request.aread()
        content_text = content_bytes.decode("utf-8", errors="ignore")

        ezviz: MockEZVIZPlatform = _current_mocks["ezviz"]
        xiaomi: MockXiaomiPlatform = _current_mocks["xiaomi"]
        onvif: MockONVIFDevice = _current_mocks["onvif"]

        # 1. EZVIZ Endpoints
        if "/api/lapp/token/get" in url_str:
            data = dict(urllib.parse.parse_qsl(content_text))
            res = ezviz.get_token(data.get("appKey", ""), data.get("appSecret", ""))
            return httpx.Response(200, json=res)

        if "/api/lapp/camera/list" in url_str:
            data = dict(urllib.parse.parse_qsl(content_text))
            res = ezviz.list_cameras(
                data.get("accessToken", ""),
                page_start=int(data.get("pageStart", 0)),
                page_size=int(data.get("pageSize", 10)),
            )
            return httpx.Response(200, json=res)

        if "/api/lapp/live/address/get" in url_str or "/api/lapp/v2/live/address/get" in url_str:
            data = dict(urllib.parse.parse_qsl(content_text))
            res = ezviz.get_live_address(
                data.get("accessToken", ""),
                data.get("deviceSerial", ""),
                channel_no=int(data.get("channelNo", 1)),
                expire_time=int(data.get("expireTime", 300)),
            )
            return httpx.Response(200, json=res)

        if "/api/lapp/device/encrypt/off" in url_str:
            data = dict(urllib.parse.parse_qsl(content_text))
            res = ezviz.set_encryption_off(
                data.get("accessToken", ""),
                data.get("deviceSerial", ""),
                data.get("validateCode", ""),
            )
            return httpx.Response(200, json=res)

        if "/api/lapp/device/ptz/start" in url_str:
            data = dict(urllib.parse.parse_qsl(content_text))
            res = ezviz.ptz_start(
                data.get("accessToken", ""),
                data.get("deviceSerial", ""),
                channel_no=int(data.get("channelNo", 1)),
                direction=int(data.get("direction", 0)),
                speed=int(data.get("speed", 1)),
            )
            return httpx.Response(200, json=res)

        if "/api/lapp/device/ptz/stop" in url_str:
            data = dict(urllib.parse.parse_qsl(content_text))
            res = ezviz.ptz_stop(
                data.get("accessToken", ""),
                data.get("deviceSerial", ""),
                channel_no=int(data.get("channelNo", 1)),
            )
            return httpx.Response(200, json=res)

        # 2. Xiaomi Endpoints
        if "pass/serviceLogin" in url_str or "serviceLoginAuth2" in url_str:
            if request.method == "POST" or "Auth2" in url_str:
                data = dict(urllib.parse.parse_qsl(content_text))
                res = xiaomi.passport_step2_auth(
                    data.get("user", ""),
                    data.get("hash", ""),
                    data.get("_sign", ""),
                    data.get("qs", ""),
                    data.get("callback", ""),
                    otp_code=data.get("ticket") or data.get("otp_code"),
                )
            else:
                res = xiaomi.passport_step1_service_login()
            return httpx.Response(200, text="&&&START&&&" + json.dumps(res))

        if "/home/device_list" in url_str:
            cookie = request.headers.get("cookie", "")
            token = cookie.split("serviceToken=")[-1].split(";")[0] if "serviceToken=" in cookie else ""
            reg = "cn"
            for r in ["de", "us", "ru", "sg", "i2", "cn"]:
                if f"{r}.api.io.mi.com" in url_str:
                    reg = r
                    break
            res = xiaomi.get_devices(region=reg, service_token=token)
            return httpx.Response(200, json=res)

        if "/home/get_stream" in url_str:
            cookie = request.headers.get("cookie", "")
            token = cookie.split("serviceToken=")[-1].split(";")[0] if "serviceToken=" in cookie else ""
            res = xiaomi.get_stream_descriptor(did="xiaomi_cam_001", region="cn", service_token=token)
            return httpx.Response(200, json=res)

        if "/miotspec/action" in url_str:
            cookie = request.headers.get("cookie", "")
            token = cookie.split("serviceToken=")[-1].split(";")[0] if "serviceToken=" in cookie else ""
            data = dict(urllib.parse.parse_qsl(content_text))
            if "data" in data:
                payload = json.loads(data["data"]).get("params", {})
            else:
                payload = json.loads(content_text or "{}").get("params", {})
            reg = "cn"
            for r in ["de", "us", "ru", "sg", "i2", "cn"]:
                if f"{r}.api.io.mi.com" in url_str:
                    reg = r
                    break
            res = xiaomi.miot_action(
                region=reg,
                service_token=token,
                did=payload.get("did", ""),
                siid=payload.get("siid", 0),
                aiid=payload.get("aiid", 0),
                in_params=payload.get("in", []),
            )
            return httpx.Response(200, json=res)

        # 3. ONVIF SOAP
        if "onvif" in url_str or request.headers.get("SOAPAction"):
            soap_action = request.headers.get("SOAPAction", "")
            res = onvif.handle_soap_request(soap_action, content_text)
            return httpx.Response(
                res.get("status_code", 200),
                content=res.get("body", "").encode("utf-8"),
                headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            )

        # 4. go2rtc mock
        if "127.0.0.1:1984" in url_str or ":1984" in url_str:
            if "/api/frame" in url_str:
                from PIL import Image
                import io
                img = Image.new("RGB", (640, 360), color=(30, 40, 50))
                buf = io.BytesIO()
                img.save(buf, format="JPEG")
                return httpx.Response(200, content=buf.getvalue(), headers={"Content-Type": "image/jpeg"})
            if "/api/streams" in url_str:
                return httpx.Response(200, json={})
            if "/api" in url_str:
                return httpx.Response(200, json={"version": "1.8.5"})

        return httpx.Response(404, text=f"Mock transport: Unhandled endpoint {url_str}")


class MockDatagramTransport(asyncio.DatagramTransport):
    def close(self):
        pass


@pytest.fixture(autouse=True)
def patch_cloud_environment(monkeypatch):
    """
    Automatically redirects httpx.AsyncClient requests to UnifiedMockCloudTransport
    and mocks UDP multicast for ONVIF WS-Discovery.
    """
    ez = MockEZVIZPlatform()
    mi = MockXiaomiPlatform()
    onv = MockONVIFDevice()
    set_current_mocks(ezviz=ez, xiaomi=mi, onvif=onv)

    transport = UnifiedMockCloudTransport()
    orig_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        if "transport" not in kwargs:
            kwargs["transport"] = transport
        orig_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)

    # Patch create_datagram_endpoint on the event loop for ONVIF WS-Discovery
    async def mock_create_datagram(self, protocol_factory, **kwargs):
        protocol = protocol_factory()
        datagram_transport = MockDatagramTransport()
        loop = asyncio.get_running_loop()
        curr_onvif = _current_mocks["onvif"]
        # Deliver response packet shortly
        loop.call_soon(
            protocol.datagram_received,
            curr_onvif.get_ws_discovery_response_xml().encode("utf-8"),
            (curr_onvif.ip, 3702),
        )
        return datagram_transport, protocol

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_datagram_endpoint", mock_create_datagram)
    monkeypatch.setattr(asyncio.AbstractEventLoop, "create_datagram_endpoint", mock_create_datagram)
    monkeypatch.setattr(socket.socket, "sendto", lambda self, data, addr: len(data))

    yield {
        "mock_ezviz": ez,
        "mock_xiaomi": mi,
        "mock_onvif": onv,
    }
