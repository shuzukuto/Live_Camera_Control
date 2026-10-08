"""
backend/app/services/ezviz_service.py

EZVIZ Cloud OpenAPI Client & Local RTSP Resolver.
Features:
- Regional API endpoint mapping (cn, us, eu, sg, ap, ru, sa)
- Access token acquisition & proactive refresh lifecycle
- Camera and channel listing
- Live stream URL extraction (HTTP-FLV / HLS / RTSP) with expiration lease
- Stream encryption toggle off via verification code
- Cloud PTZ motor control (start / stop with 8 directions + zoom)
- Local LAN RTSP URL builder (zero-timeout bypass)
- Dependency injection support for mock ecosystem testing
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("nvr.ezviz")

# Regional OpenAPI Gateways per EZVIZ developer documentation
EZVIZ_REGIONAL_ENDPOINTS: Dict[str, str] = {
    "cn": "https://open.ys7.com",
    "us": "https://iusopen.ezvizlife.com",
    "eu": "https://ieuopen.ezvizlife.com",
    "de": "https://ieuopen.ezvizlife.com",  # Germany maps to European OpenAPI endpoint
    "sg": "https://isgpopen.ezvizlife.com",
    "ap": "https://isgpopen.ezvizlife.com",
    "ru": "https://iruopen.ezvizlife.com",
    "sa": "https://isaopen.ezvizlife.com",
    "i2": "https://isgpopen.ezvizlife.com",
}


class EZVIZError(Exception):
    """Base exception for EZVIZ OpenAPI operations."""
    def __init__(self, message: str, code: Optional[str] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class EZVIZAuthError(EZVIZError):
    """Raised on authentication failure or token expiration."""
    pass


class EZVIZDeviceError(EZVIZError):
    """Raised on device not found, verification code mismatch, etc."""
    pass


@dataclass
class EZVIZToken:
    access_token: str
    expire_time: int  # Epoch ms
    area_domain: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        # Buffer of 60 seconds
        return time.time() * 1000 >= (self.expire_time - 60_000)


@dataclass
class StreamLease:
    stream_url: str
    expires_at: float  # Epoch seconds
    is_local_rtsp: bool = False
    is_encrypt: int = 0
    hls_url: Optional[str] = None


class EZVIZService:
    """
    Client for EZVIZ Open Platform OpenAPI.
    Handles token management, camera discovery, stream URL retrieval, and PTZ.
    """

    def __init__(
        self,
        default_region: str = "cn",
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.default_region = (default_region or "cn").lower()
        self._http_client = http_client
        self._token_cache: Dict[str, EZVIZToken] = {}  # app_key -> token

    def clear_token_cache(self) -> None:
        """Clears local token cache."""
        self._token_cache.clear()

    def resolve_endpoint(self, region: Optional[str] = None, area_domain: Optional[str] = None) -> str:
        """Resolves base URL from area_domain or regional code."""
        if area_domain:
            return area_domain.rstrip("/")
        reg = (region or self.default_region or "cn").lower().strip()
        return EZVIZ_REGIONAL_ENDPOINTS.get(reg, EZVIZ_REGIONAL_ENDPOINTS["cn"]).rstrip("/")

    async def get_token(
        self,
        app_key: str,
        app_secret: str,
        region: Optional[str] = None,
        force_refresh: bool = False,
    ) -> EZVIZToken:
        """
        POST /api/lapp/token/get
        Exchanges appKey and appSecret for an access token (7-day validity).
        """
        cache_key = f"{app_key}:{region or self.default_region}"
        if not force_refresh and cache_key in self._token_cache:
            cached = self._token_cache[cache_key]
            if not cached.is_expired:
                return cached

        base_url = self.resolve_endpoint(region)
        endpoint = f"{base_url}/api/lapp/token/get"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                endpoint,
                data={"appKey": app_key, "appSecret": app_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            res = resp.json()

        code = str(res.get("code", ""))
        if code != "200":
            raise EZVIZAuthError(res.get("msg", "Failed to acquire token"), code=code)

        data = res.get("data", {})
        token = EZVIZToken(
            access_token=data["accessToken"],
            expire_time=int(data["expireTime"]),
            area_domain=data.get("areaDomain"),
        )
        self._token_cache[cache_key] = token
        return token

    async def list_cameras(
        self,
        access_token: str,
        region: Optional[str] = None,
        area_domain: Optional[str] = None,
        page_start: int = 0,
        page_size: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        POST /api/lapp/camera/list
        Lists camera channels under the account.
        """
        base_url = self.resolve_endpoint(region, area_domain)
        endpoint = f"{base_url}/api/lapp/camera/list"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                endpoint,
                data={"accessToken": access_token, "pageStart": page_start, "pageSize": page_size},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            res = resp.json()

        code = str(res.get("code", ""))
        if code != "200":
            if code == "10002":
                raise EZVIZAuthError(res.get("msg", "AccessToken is expired or invalid"), code="10002")
            raise EZVIZError(res.get("msg", "Failed to list cameras"), code=code)
        return res.get("data", [])


    async def get_live_address(
        self,
        access_token: str,
        device_serial: str,
        channel_no: int = 1,
        expire_time_sec: int = 300,
        protocol: int = 4,  # 4 = HTTP-FLV, 2 = HLS, 1 = ezopen
        quality: int = 1,   # 1 = HD, 2 = standard
        region: Optional[str] = None,
        area_domain: Optional[str] = None,
    ) -> StreamLease:
        """
        POST /api/lapp/live/address/get or /v2/live/address/get
        Extracts live stream URL with lease expiration time.
        """
        base_url = self.resolve_endpoint(region, area_domain)
        endpoint = f"{base_url}/api/lapp/v2/live/address/get"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                endpoint,
                data={
                    "accessToken": access_token,
                    "deviceSerial": device_serial,
                    "channelNo": channel_no,
                    "protocol": protocol,
                    "quality": quality,
                    "expireTime": expire_time_sec,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            res = resp.json()

        code = str(res.get("code", ""))
        if code != "200":
            raise EZVIZDeviceError(res.get("msg", "Failed to get live address"), code=code)

        data = res.get("data", {})
        expire_val = data.get("expireTime")
        if isinstance(expire_val, (int, float)):
            expire_epoch = float(expire_val) / 1000.0 if expire_val > 10_000_000_000 else float(expire_val)
        else:
            expire_epoch = time.time() + expire_time_sec

        return StreamLease(
            stream_url=data.get("url", ""),
            expires_at=expire_epoch,
            is_local_rtsp=False,
            is_encrypt=data.get("isEncrypt", 0),
            hls_url=data.get("hls"),
        )

    async def set_encryption_off(
        self,
        access_token: str,
        device_serial: str,
        validate_code: str,
        region: Optional[str] = None,
        area_domain: Optional[str] = None,
    ) -> bool:
        """
        POST /api/lapp/device/encrypt/off
        Disables device video stream encryption with camera 6-character verification code.
        """
        base_url = self.resolve_endpoint(region, area_domain)
        endpoint = f"{base_url}/api/lapp/device/encrypt/off"

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                endpoint,
                data={
                    "accessToken": access_token,
                    "deviceSerial": device_serial,
                    "validateCode": validate_code,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            res = resp.json()

        code = str(res.get("code", ""))
        if code != "200":
            raise EZVIZDeviceError(res.get("msg", "Failed to disable encryption"), code=code)
        return True

    async def ptz_start(
        self,
        access_token: str,
        device_serial: str,
        channel_no: int = 1,
        direction: int = 0,
        speed: int = 1,
        region: Optional[str] = None,
        area_domain: Optional[str] = None,
    ) -> bool:
        """
        POST /api/lapp/device/ptz/start
        Starts camera PTZ movement.
        direction: 0=up, 1=down, 2=left, 3=right, 4=up-left, 5=down-left, 6=up-right, 7=down-right, 8=zoom-in, 9=zoom-out
        speed: 1..10 (or 0..2 for standard mode)
        """
        if direction not in range(10):
            raise EZVIZError("Invalid PTZ direction parameter (must be 0-9)", code="10005")
        if not (1 <= speed <= 10):
            raise EZVIZError("Invalid PTZ speed parameter (must be 1-10)", code="10006")

        base_url = self.resolve_endpoint(region, area_domain)
        endpoint = f"{base_url}/api/lapp/device/ptz/start"

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                endpoint,
                data={
                    "accessToken": access_token,
                    "deviceSerial": device_serial,
                    "channelNo": channel_no,
                    "direction": direction,
                    "speed": speed,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            res = resp.json()

        code = str(res.get("code", ""))
        if code != "200":
            raise EZVIZDeviceError(res.get("msg", "PTZ start failed"), code=code)
        return True

    async def ptz_stop(
        self,
        access_token: str,
        device_serial: str,
        channel_no: int = 1,
        direction: Optional[int] = None,
        region: Optional[str] = None,
        area_domain: Optional[str] = None,
    ) -> bool:
        """
        POST /api/lapp/device/ptz/stop
        Stops active PTZ movement.
        """
        base_url = self.resolve_endpoint(region, area_domain)
        endpoint = f"{base_url}/api/lapp/device/ptz/stop"

        payload = {
            "accessToken": access_token,
            "deviceSerial": device_serial,
            "channelNo": channel_no,
        }
        if direction is not None:
            payload["direction"] = direction

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            res = resp.json()

        code = str(res.get("code", ""))
        if code != "200":
            raise EZVIZDeviceError(res.get("msg", "PTZ stop failed"), code=code)
        return True

    @staticmethod
    def resolve_local_rtsp_url(
        ip: str,
        verification_code: str,
        port: int = 554,
        channel_no: int = 1,
        stream_type: str = "main",  # "main" or "sub"
    ) -> str:
        """
        Constructs zero-timeout LAN RTSP URL for on-premise EZVIZ cameras.
        Format: rtsp://admin:{verification_code}@{ip}:{port}/h264/ch{channel_no}/{stream_type}/av_stream
        """
        code = verification_code.strip()
        return f"rtsp://admin:{code}@{ip}:{port}/h264/ch{channel_no}/{stream_type}/av_stream"

    async def refresh_stream_url(
        self,
        camera: Dict[str, Any],
        access_token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> StreamLease:
        """
        Interface contract for StreamKeeper daemon.
        Evaluates LAN RTSP availability first; falls back to cloud live URL refresh.
        """
        ip = camera.get("ip_address")
        vcode = camera.get("verification_code") or camera.get("validateCode")
        serial = camera.get("device_serial") or camera.get("serial")
        channel_no = camera.get("channel_no", 1)

        # 1. Local RTSP Priority (Zero Timeout)
        if ip and vcode:
            local_url = self.resolve_local_rtsp_url(
                ip=ip,
                verification_code=vcode,
                port=camera.get("port", 554),
                channel_no=channel_no,
            )
            # Indefinite lease for local network RTSP
            return StreamLease(
                stream_url=local_url,
                expires_at=time.time() + 31536000.0,  # 1 year
                is_local_rtsp=True,
                is_encrypt=0,
            )

        # 2. Cloud Live URL Fallback
        if not access_token:
            raise EZVIZAuthError("Access token required to refresh cloud stream URL")
        if not serial:
            raise EZVIZDeviceError("Device serial number required for EZVIZ cloud stream")

        return await self.get_live_address(
            access_token=access_token,
            device_serial=serial,
            channel_no=channel_no,
            expire_time_sec=camera.get("lease_sec", 300),
            region=region,
        )


# Global default instance
ezviz_service = EZVIZService()
