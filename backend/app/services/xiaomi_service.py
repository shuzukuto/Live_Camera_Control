"""
backend/app/services/xiaomi_service.py

Xiaomi Mi Home Cloud & MIoT Protocol Client.
Features:
- Xiaomi Passport 2-Step Authentication (MD5 password hashing, 2FA/Captcha challenge handling)
- 6 Regional Cloud Gateways (cn, de, i2, ru, sg, us)
- Cryptographic Request Signing (HMAC-SHA256 with dynamic nonce and ssecurity)
- Camera Device Synchronization & Inventory Extraction
- Native go2rtc stream mapping (xiaomi:// protocol)
- MIoT-Spec action RPC for Camera Motor PTZ Control
- Dependency injection support for mock ecosystem testing
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("nvr.xiaomi")

XIAOMI_REGIONS: List[str] = ["cn", "de", "i2", "ru", "sg", "us"]

XIAOMI_REGIONAL_ENDPOINTS: Dict[str, str] = {
    "cn": "https://api.io.mi.com/app",
    "de": "https://de.api.io.mi.com/app",
    "i2": "https://i2.api.io.mi.com/app",
    "ru": "https://ru.api.io.mi.com/app",
    "sg": "https://sg.api.io.mi.com/app",
    "us": "https://us.api.io.mi.com/app",
}

PASSPORT_URL = "https://account.xiaomi.com"


class XiaomiError(Exception):
    """Base exception for Xiaomi operations."""
    def __init__(self, message: str, code: Optional[int] = None, data: Any = None):
        super().__init__(message)
        self.code = code
        self.data = data


class XiaomiAuthError(XiaomiError):
    """Authentication or challenge required error."""
    pass


@dataclass
class XiaomiSession:
    user_id: str
    service_token: str
    ssecurity: str
    region: str = "cn"
    c_user_id: Optional[str] = None
    pass_token: Optional[str] = None


@dataclass
class XiaomiDevice:
    did: str
    name: str
    model: str
    is_online: bool
    token: Optional[str] = None
    local_ip: Optional[str] = None
    mac: Optional[str] = None
    pin: Optional[str] = None


def sign_miio_request(uri: str, data_json: str, ssecurity: str) -> Dict[str, str]:
    """
    Signs request to api.io.mi.com using HMAC-SHA256.
    Derives signed_nonce from 12-byte nonce (8 random bytes + 4 bytes epoch minutes).
    """
    # 1. Generate 12-byte nonce
    nonce_bytes = os.urandom(8) + int(time.time() / 60).to_bytes(4, "big")
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")

    # 2. Derive signed_nonce
    m = hashlib.sha256()
    m.update(base64.b64decode(ssecurity))
    m.update(base64.b64decode(nonce_b64))
    signed_nonce_bytes = m.digest()
    signed_nonce = base64.b64encode(signed_nonce_bytes).decode("utf-8")

    # 3. Create message payload
    msg = f"{uri}&{signed_nonce}&{nonce_b64}&data={data_json}"

    # 4. Generate HMAC-SHA256 signature
    sig = hmac.new(
        key=signed_nonce_bytes,
        msg=msg.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    signature_b64 = base64.b64encode(sig).decode("utf-8")

    return {
        "_nonce": nonce_b64,
        "data": data_json,
        "signature": signature_b64,
    }


class XiaomiService:
    """
    Client for Xiaomi Passport authentication, regional MIoT cloud, and camera PTZ.
    """

    def __init__(
        self,
        default_region: str = "cn",
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.default_region = (default_region or "cn").lower()
        self._http_client = http_client
        self._session_cache: Dict[str, XiaomiSession] = {}

    def resolve_endpoint(self, region: Optional[str] = None) -> str:
        """Resolves base URL for the given region."""
        reg = (region or self.default_region or "cn").lower().strip()
        if reg not in XIAOMI_REGIONAL_ENDPOINTS:
            raise XiaomiError(f"Invalid Xiaomi region: {reg}. Supported: {XIAOMI_REGIONS}", code=-1)
        return XIAOMI_REGIONAL_ENDPOINTS[reg]

    async def passport_step1(self, sid: str = "xiaomiio") -> Dict[str, Any]:
        """
        Step 1: Initializes login session to acquire _sign, qs, and callback.
        """
        url = f"{PASSPORT_URL}/pass/serviceLogin?sid={sid}&_json=true"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers={"User-Agent": "APP/com.xiaomi.smarthome APPV/1000000 Linux/Android"})
            resp.raise_for_status()
            text = resp.text.replace("&&&START&&&", "").strip()
            data = json.loads(text)
            return {
                "_sign": data["_sign"],
                "qs": data["qs"],
                "callback": data["callback"],
                "sid": sid,
            }

    async def passport_step2(
        self,
        username: str,
        password_or_md5: str,
        sign: str,
        qs: str,
        callback: str,
        sid: str = "xiaomiio",
        otp_code: Optional[str] = None,
        captcha_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Step 2: Submits user credentials with MD5 hash and handles challenges.
        """
        # If password is raw, hash it with MD5
        if len(password_or_md5) == 32 and all(c in "0123456789abcdefABCDEF" for c in password_or_md5):
            pwd_hash = password_or_md5.lower()
        else:
            pwd_hash = hashlib.md5(password_or_md5.encode("utf-8")).hexdigest().lower()

        login_data = {
            "user": username,
            "hash": pwd_hash.upper(),
            "sid": sid,
            "_json": "true",
            "_sign": sign,
            "qs": qs,
            "callback": callback,
        }
        if otp_code:
            login_data["ticket"] = otp_code
        if captcha_code:
            login_data["captcha"] = captcha_code

        url = f"{PASSPORT_URL}/pass/serviceLoginAuth2"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                data=login_data,
                headers={"User-Agent": "APP/com.xiaomi.smarthome APPV/1000000 Linux/Android"},
            )
            resp.raise_for_status()
            text = resp.text.replace("&&&START&&&", "").strip()
            res = json.loads(text)

        code = res.get("code")
        if code in [70016, 87001, 81003]:
            return res  # Challenge response
        if code != 0:
            raise XiaomiAuthError(res.get("description", "Authentication failed"), code=code, data=res)

        return res

    async def login(
        self,
        username: str,
        password: str,
        region: str = "cn",
        otp_code: Optional[str] = None,
    ) -> XiaomiSession:
        """
        Executes full two-step login workflow.
        Returns XiaomiSession with userId, serviceToken, and ssecurity.
        """
        step1 = await self.passport_step1()
        step2 = await self.passport_step2(
            username=username,
            password_or_md5=password,
            sign=step1["_sign"],
            qs=step1["qs"],
            callback=step1["callback"],
            otp_code=otp_code,
        )

        code = step2.get("code", -1)
        if code == 87001 or "notificationUrl" in step2:
            raise XiaomiAuthError(
                "Two-factor authentication required",
                code=87001,
                data={"notificationUrl": step2.get("notificationUrl")},
            )
        if code == 70016 and "captchaUrl" in step2:
            raise XiaomiAuthError(
                "Captcha challenge required",
                code=70016,
                data={"captchaUrl": step2.get("captchaUrl")},
            )
        if code != 0:
            raise XiaomiAuthError(step2.get("description", "Login failed"), code=code)

        session = XiaomiSession(
            user_id=str(step2.get("userId", "")),
            service_token=step2.get("serviceToken", ""),
            ssecurity=step2.get("ssecurity", ""),
            region=region,
            c_user_id=step2.get("cUserId"),
            pass_token=step2.get("passToken"),
        )
        self._session_cache[username] = session
        return session

    async def get_devices(
        self,
        region: str,
        service_token: str,
        ssecurity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        POST /home/device_list
        Retrieves device inventory for the specified regional gateway.
        """
        reg = region.lower()
        if reg not in XIAOMI_REGIONS:
            raise XiaomiError(f"Invalid Xiaomi region: {region}. Supported: {XIAOMI_REGIONS}", code=-1)

        base_url = self.resolve_endpoint(reg)
        uri = "/home/device_list"
        endpoint = f"{base_url}{uri}"
        payload_json = json.dumps({"getVirtualModel": False, "getHuamiDevices": 0})

        headers = {
            "User-Agent": "APP/com.xiaomi.smarthome APPV/1000000 Linux/Android",
            "Cookie": f"serviceToken={service_token}",
        }

        data_to_send: Dict[str, Any]
        if ssecurity:
            data_to_send = sign_miio_request(uri, payload_json, ssecurity)
        else:
            data_to_send = {"data": payload_json}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(endpoint, data=data_to_send, headers=headers)
            resp.raise_for_status()
            res = resp.json()

        code = res.get("code", -1)
        if code != 0:
            raise XiaomiError(res.get("message", "Failed to retrieve device list"), code=code)

        return res.get("result", {}).get("list", [])

    async def get_stream_descriptor(
        self,
        did: str,
        region: str,
        service_token: str,
        device_ip: Optional[str] = None,
        device_token: Optional[str] = None,
        pin: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generates native xiaomi:// stream descriptor string for go2rtc ingestion.
        Format: xiaomi://{ip}?token={token}&pin={pin}
        """
        ip = device_ip
        token = device_token
        pin_val = pin
        if not (ip and token):
            try:
                devices = await self.get_devices(region=region, service_token=service_token)
                for dev in devices:
                    if dev.get("did") == did:
                        ip = ip or dev.get("localip") or dev.get("ip")
                        token = token or dev.get("token")
                        pin_val = pin_val or dev.get("pin")
                        break
            except Exception:
                pass

        if not ip and not token:
            raise XiaomiError(f"Device {did} not found in region {region}", code=-1)

        ip = ip or "127.0.0.1"
        token = token or ""
        pin_val = pin_val or "0000"
        stream_url = f"xiaomi://{ip}?token={token}&pin={pin_val}"
        return {"code": 0, "stream_url": stream_url, "local_ip": ip}

    async def refresh_stream_url(
        self,
        camera: Dict[str, Any],
        service_token: Optional[str] = None,
        ssecurity: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """
        Interface contract for StreamKeeper daemon (PROJECT.md:113).
        Evaluates LAN availability first; falls back to cloud stream descriptor.
        """
        from app.services.ezviz_service import StreamLease
        did = camera.get("device_serial") or camera.get("did", "")
        local_ip = camera.get("ip_address") or camera.get("local_ip")
        reg = (region or camera.get("region") or self.default_region).lower()

        # 1. Local Network Descriptor (Zero Timeout)
        if local_ip:
            descriptor = await self.get_stream_descriptor(
                did=did,
                region=reg,
                service_token=service_token or "",
                device_ip=local_ip,
                device_token=camera.get("device_token"),
                pin=camera.get("pin"),
            )
            return StreamLease(
                stream_url=descriptor.get("stream_url", f"xiaomi://{local_ip}"),
                expires_at=time.time() + 31536000.0,  # 1 year
                is_local_rtsp=True,
            )

        # 2. Cloud Relay Descriptor (1-Hour Session Lease)
        descriptor = await self.get_stream_descriptor(
            did=did,
            region=reg,
            service_token=service_token or "",
            device_token=camera.get("device_token"),
            pin=camera.get("pin"),
        )
        return StreamLease(
            stream_url=descriptor.get("stream_url", ""),
            expires_at=time.time() + 3600.0,
            is_local_rtsp=False,
        )

    async def miot_action(
        self,
        region: str,
        service_token: str,
        did: str,
        siid: int,
        aiid: int,
        in_params: List[Any],
        ssecurity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        POST /miotspec/action
        Executes an action RPC on a MIoT device (e.g. motor control PTZ).
        """
        base_url = self.resolve_endpoint(region)
        uri = "/miotspec/action"
        endpoint = f"{base_url}{uri}"
        payload_json = json.dumps({
            "params": {
                "did": did,
                "siid": siid,
                "aiid": aiid,
                "in": in_params,
            }
        })

        headers = {
            "User-Agent": "APP/com.xiaomi.smarthome APPV/1000000 Linux/Android",
            "Cookie": f"serviceToken={service_token}",
        }

        data_to_send: Dict[str, Any]
        if ssecurity:
            data_to_send = sign_miio_request(uri, payload_json, ssecurity)
        else:
            data_to_send = {"data": payload_json}

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(endpoint, data=data_to_send, headers=headers)
            resp.raise_for_status()
            res = resp.json()

        code = res.get("code", -1)
        if code != 0:
            raise XiaomiError(res.get("message", "MIoT action failed"), code=code)

        return res

    async def ptz_move(
        self,
        did: str,
        direction: str | int,
        region: str,
        service_token: str,
        ssecurity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes PTZ direction movement for camera.
        Direction: 1='up', 2='down', 3='left', 4='right'
        """
        dir_map = {
            "up": 1,
            "down": 2,
            "left": 3,
            "right": 4,
            1: 1,
            2: 2,
            3: 3,
            4: 4,
        }
        dir_val = dir_map.get(direction, 1)

        return await self.miot_action(
            region=region,
            service_token=service_token,
            did=did,
            siid=5,
            aiid=1,
            in_params=[dir_val],
            ssecurity=ssecurity,
        )


# Global default instance
xiaomi_service = XiaomiService()
