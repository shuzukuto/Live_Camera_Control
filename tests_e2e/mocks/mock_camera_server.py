"""
Deterministic Mock Camera and Streaming Infrastructure for E2E Testing.
Simulates EZVIZ Open Platform, Xiaomi Mi Home Cloud & MIoT, ONVIF WS-Discovery & SOAP,
go2rtc Media Gateway, and FFmpeg execution with zero external hardware or network dependencies.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from PIL import Image, ImageDraw


# ==============================================================================
# 1. Mock EZVIZ Open Platform Cloud Engine
# ==============================================================================
class MockEZVIZPlatform:
    """Simulates EZVIZ Open Platform OpenAPI endpoints and device management."""

    def __init__(self):
        self.app_key = "mock_ezviz_app_key_999"
        self.app_secret = "mock_ezviz_secret_888"
        self.valid_tokens: Dict[str, float] = {}  # token -> expires_at
        self.devices: Dict[str, Dict[str, Any]] = {
            "F12345678": {
                "deviceSerial": "F12345678",
                "channelNo": 1,
                "cameraName": "Front Door EZVIZ Cam",
                "status": 1,  # 1=online, 0=offline
                "isEncrypt": 1,  # 1=encrypted, 0=plain
                "validateCode": "VERIFY123",
                "videoLevel": 2,  # 0=smooth, 1=balanced, 2=HD
                "local_rtsp": "rtsp://admin:VERIFY123@192.168.1.101:554/h264/ch1/main",
            },
            "B87654321": {
                "deviceSerial": "B87654321",
                "channelNo": 1,
                "cameraName": "Backyard PTZ Cam",
                "status": 1,
                "isEncrypt": 0,
                "validateCode": "BACKYARD88",
                "videoLevel": 2,
                "local_rtsp": "rtsp://admin:BACKYARD88@192.168.1.102:554/h264/ch1/main",
            },
            "O00011122": {
                "deviceSerial": "O00011122",
                "channelNo": 1,
                "cameraName": "Garage Offline Cam",
                "status": 0,  # offline
                "isEncrypt": 0,
                "validateCode": "GARAGE00",
                "videoLevel": 1,
                "local_rtsp": None,
            },
        }
        # Fault injection toggles
        self.simulate_network_timeout = False
        self.simulate_rate_limit = False
        self.simulate_server_error = False

    def get_token(self, app_key: str, app_secret: str) -> Dict[str, Any]:
        """POST /api/lapp/token/get"""
        if self.simulate_network_timeout:
            raise TimeoutError("EZVIZ cloud connection timed out")
        if self.simulate_rate_limit:
            return {"code": "429", "msg": "Too Many Requests - Rate limit exceeded", "data": None}
        if self.simulate_server_error:
            return {"code": "500", "msg": "EZVIZ Cloud internal error", "data": None}

        if app_key == self.app_key and app_secret == self.app_secret:
            token = f"at.ezviz_live_{hashlib.sha256(f'{app_key}:{time.time()}'.encode()).hexdigest()[:24]}"
            expires_at = time.time() + (7 * 86400)  # 7-day token
            self.valid_tokens[token] = expires_at
            return {
                "code": "200",
                "msg": "Success",
                "data": {
                    "accessToken": token,
                    "expireTime": int(expires_at * 1000),
                },
            }
        return {"code": "10001", "msg": "AppKey or AppSecret is invalid", "data": None}

    def list_cameras(self, access_token: str, page_start: int = 0, page_size: int = 10) -> Dict[str, Any]:
        """POST /api/lapp/camera/list"""
        if not self._is_token_valid(access_token):
            return {"code": "10002", "msg": "AccessToken is expired or invalid", "data": None}

        device_list = list(self.devices.values())
        paginated = device_list[page_start : page_start + page_size]
        return {
            "code": "200",
            "msg": "Success",
            "page": {"page": page_start, "size": page_size, "total": len(device_list)},
            "data": paginated,
        }

    def get_live_address(self, access_token: str, device_serial: str, channel_no: int = 1, expire_time: int = 300) -> Dict[str, Any]:
        """POST /api/lapp/live/address/get"""
        if not self._is_token_valid(access_token):
            return {"code": "10002", "msg": "AccessToken is expired or invalid", "data": None}
        if device_serial not in self.devices:
            return {"code": "20002", "msg": "Device does not exist", "data": None}

        dev = self.devices[device_serial]
        if dev["status"] == 0:
            return {"code": "20007", "msg": "Device is offline", "data": None}

        # Generate live URL with lease
        lease_expires = time.time() + expire_time
        live_url = f"rtsp://open.ezvizlife.com/live/{device_serial}/{channel_no}?lease={int(lease_expires)}"
        hls_url = f"https://open.ezvizlife.com/live/{device_serial}/{channel_no}.m3u8"
        return {
            "code": "200",
            "msg": "Success",
            "data": {
                "url": live_url,
                "hls": hls_url,
                "expireTime": int(lease_expires * 1000),
                "isEncrypt": dev["isEncrypt"],
            },
        }

    def set_encryption_off(self, access_token: str, device_serial: str, validate_code: str) -> Dict[str, Any]:
        """POST /api/lapp/device/encrypt/off"""
        if not self._is_token_valid(access_token):
            return {"code": "10002", "msg": "AccessToken is expired or invalid", "data": None}
        if device_serial not in self.devices:
            return {"code": "20002", "msg": "Device not found", "data": None}

        dev = self.devices[device_serial]
        if dev["validateCode"] != validate_code:
            return {"code": "20014", "msg": "Device verification code is incorrect", "data": None}

        dev["isEncrypt"] = 0
        return {"code": "200", "msg": "Device stream encryption successfully disabled", "data": None}

    def ptz_start(self, access_token: str, device_serial: str, channel_no: int, direction: int, speed: int = 1) -> Dict[str, Any]:
        """POST /api/lapp/device/ptz/start"""
        if not self._is_token_valid(access_token):
            return {"code": "10002", "msg": "AccessToken is expired or invalid", "data": None}
        if device_serial not in self.devices:
            return {"code": "20002", "msg": "Device not found", "data": None}
        if direction not in range(8):  # 0..7 (up, down, left, right, up-left, up-right, down-left, down-right)
            return {"code": "10005", "msg": "Invalid PTZ direction parameter (must be 0-7)", "data": None}
        if speed not in range(1, 11):
            return {"code": "10006", "msg": "Invalid PTZ speed parameter (must be 1-10)", "data": None}

        return {"code": "200", "msg": f"PTZ direction {direction} speed {speed} started", "data": None}

    def ptz_stop(self, access_token: str, device_serial: str, channel_no: int) -> Dict[str, Any]:
        """POST /api/lapp/device/ptz/stop"""
        if not self._is_token_valid(access_token):
            return {"code": "10002", "msg": "AccessToken is expired or invalid", "data": None}
        if device_serial not in self.devices:
            return {"code": "20002", "msg": "Device not found", "data": None}

        return {"code": "200", "msg": "PTZ movement stopped", "data": None}

    def _is_token_valid(self, token: str) -> bool:
        if token not in self.valid_tokens:
            return False
        return time.time() < self.valid_tokens[token]


# ==============================================================================
# 2. Mock Xiaomi Mi Home Cloud & MIoT Platform
# ==============================================================================
class MockXiaomiPlatform:
    """Simulates Xiaomi Passport 2-Step Authentication & Regional MIoT Cloud."""

    REGIONS = ["cn", "de", "i2", "ru", "sg", "us"]

    def __init__(self):
        self.users: Dict[str, Dict[str, Any]] = {
            "user_china@example.com": {
                "password_hash": hashlib.md5("Secr3tP@ss123".encode()).hexdigest(),
                "user_id": "100982341",
                "region": "cn",
                "two_factor_required": False,
            },
            "user_global@example.com": {
                "password_hash": hashlib.md5("GlobalPass2026!".encode()).hexdigest(),
                "user_id": "200876543",
                "region": "sg",
                "two_factor_required": False,
            },
            "user_2fa@example.com": {
                "password_hash": hashlib.md5("TwoFactorPass!".encode()).hexdigest(),
                "user_id": "300123999",
                "region": "us",
                "two_factor_required": True,
            },
        }

        self.devices_by_region: Dict[str, List[Dict[str, Any]]] = {
            "cn": [
                {
                    "did": "xiaomi_cam_001",
                    "name": "Living Room Chuangmi IPC",
                    "model": "chuangmi.camera.ipc009",
                    "isOnline": True,
                    "token": "4a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d",
                    "localip": "192.168.1.150",
                    "mac": "64:90:C1:22:33:44",
                    "pin": "1234",
                },
                {
                    "did": "xiaomi_cam_002",
                    "name": "Balcony PTZ Camera 2K",
                    "model": "isa.camera.hlc7",
                    "isOnline": True,
                    "token": "5b8c0d2e3f4a5b6c7d8e9f0a1b2c3d4e",
                    "localip": "192.168.1.151",
                    "mac": "64:90:C1:55:66:77",
                    "pin": "0000",
                },
            ],
            "sg": [
                {
                    "did": "xiaomi_cam_global_1",
                    "name": "Office Security Camera 360",
                    "model": "mijia.camera.v3",
                    "isOnline": True,
                    "token": "6c9d1e2f3a4b5c6d7e8f9a0b1c2d3e4f",
                    "localip": "192.168.1.160",
                    "mac": "64:90:C1:88:99:AA",
                    "pin": "9999",
                }
            ],
            "us": [
                {
                    "did": "xiaomi_cam_us_1",
                    "name": "Warehouse North Cam",
                    "model": "chuangmi.camera.021a04",
                    "isOnline": True,
                    "token": "7d0e2f3a4b5c6d7e8f9a0b1c2d3e4f5a",
                    "localip": "192.168.1.170",
                    "mac": "64:90:C1:BB:CC:DD",
                    "pin": "1111",
                }
            ],
            "de": [],
            "ru": [],
            "i2": [],
        }

        self.active_sessions: Dict[str, Dict[str, Any]] = {}  # service_token -> session_info
        self.simulate_captcha = False
        self.simulate_network_fail = False

    def passport_step1_service_login(self, sid: str = "xiaomiio") -> Dict[str, Any]:
        """GET /pass/serviceLogin"""
        if self.simulate_network_fail:
            raise ConnectionError("Xiaomi Passport connection failed")
        nonce = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        return {
            "_sign": f"mock_sign_{nonce}",
            "qs": f"%3Fsid%3D{sid}%26_json%3Dtrue",
            "callback": "https://sts.api.io.mi.com/sts",
            "sid": sid,
        }

    def passport_step2_auth(self, user: str, pwd_md5: str, sign: str, qs: str, callback: str, otp_code: Optional[str] = None) -> Dict[str, Any]:
        """POST /pass/serviceLoginAuth2"""
        if self.simulate_captcha:
            return {"code": 70016, "description": "Captcha required", "notificationUrl": "https://account.xiaomi.com/captcha"}

        if user not in self.users:
            return {"code": 70016, "description": "Invalid Xiaomi username or password"}

        account = self.users[user]
        if account["password_hash"].lower() != pwd_md5.lower():
            return {"code": 70016, "description": "Invalid Xiaomi username or password"}

        if account["two_factor_required"] and otp_code != "123456":
            return {"code": 87001, "description": "2FA verification required", "notificationUrl": "https://account.xiaomi.com/identity/auth"}

        user_id = account["user_id"]
        service_token = f"st_xiaomi_{hashlib.sha256(f'{user}:{time.time()}'.encode()).hexdigest()[:32]}"
        ssecurity = base64.b64encode(hashlib.sha256(f"ssec:{user}:{time.time()}".encode()).digest()).decode()

        self.active_sessions[service_token] = {
            "user_id": user_id,
            "user": user,
            "region": account["region"],
            "ssecurity": ssecurity,
            "created_at": time.time(),
        }

        return {
            "code": 0,
            "description": "Success",
            "userId": user_id,
            "cUserId": f"c_{user_id}",
            "serviceToken": service_token,
            "ssecurity": ssecurity,
            "location": callback,
        }

    def get_devices(self, region: str, service_token: str, signature: Optional[str] = None) -> Dict[str, Any]:
        """POST /home/device_list via regional gateway"""
        if region not in self.REGIONS:
            return {"code": -1, "message": f"Invalid Xiaomi region: {region}. Supported: {self.REGIONS}"}
        if service_token not in self.active_sessions:
            return {"code": 2, "message": "Invalid or expired serviceToken"}

        devs = self.devices_by_region.get(region, [])
        return {"code": 0, "message": "ok", "result": {"list": devs}}

    def miot_action(self, region: str, service_token: str, did: str, siid: int, aiid: int, in_params: List[Any]) -> Dict[str, Any]:
        """POST /miotspec/action (e.g. PTZ control)"""
        if service_token not in self.active_sessions:
            return {"code": 2, "message": "Invalid serviceToken"}

        # Validate did exists in region
        found = False
        for dev in self.devices_by_region.get(region, []):
            if dev["did"] == did:
                found = True
                break

        if not found:
            return {"code": -1, "message": f"Device {did} not found in region {region}"}

        # Check PTZ action (siid=5, aiid=1 is typical camera PTZ motor move)
        if siid == 5 and aiid == 1:
            direction = in_params[0] if in_params else 1
            return {"code": 0, "message": "ok", "result": {"did": did, "siid": siid, "aiid": aiid, "code": 0, "out": [f"Moved {direction}"]}}

        return {"code": 0, "message": "ok", "result": {"did": did, "siid": siid, "aiid": aiid, "code": 0, "out": []}}

    def get_stream_descriptor(self, did: str, region: str, service_token: str) -> Dict[str, Any]:
        """Resolves xiaomi:// stream descriptor for go2rtc"""
        if service_token not in self.active_sessions:
            return {"code": 2, "message": "Invalid serviceToken"}

        for dev in self.devices_by_region.get(region, []):
            if dev["did"] == did:
                stream_url = f"xiaomi://{dev['localip']}?token={dev['token']}&pin={dev['pin']}"
                return {"code": 0, "message": "ok", "stream_url": stream_url, "local_ip": dev["localip"]}

        return {"code": -1, "message": "Device not found"}


# ==============================================================================
# 3. Mock ONVIF WS-Discovery & SOAP Services
# ==============================================================================
class MockONVIFDevice:
    """Simulates ONVIF WS-Discovery UDP Multicast Probe and SOAP Media/PTZ Services."""

    def __init__(self, ip: str = "192.168.1.200", port: int = 8085):
        self.ip = ip
        self.port = port
        self.device_uuid = "urn:uuid:550e8400-e29b-41d4-a716-446655440000"
        self.xaddrs = f"http://{self.ip}:{self.port}/onvif/device_service"
        self.rtsp_url = f"rtsp://{self.ip}:554/live/main"
        self.profiles = ["Profile_1_Main", "Profile_2_Sub"]
        self.simulate_soap_fault = False
        self.simulate_unsupported_ptz = False

    def get_ws_discovery_response_xml(self) -> str:
        """Returns standard ONVIF WS-Discovery ProbeMatches SOAP XML"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:MessageID>urn:uuid:{hashlib.md5(str(time.time()).encode()).hexdigest()}</wsa:MessageID>
    <wsa:RelatesTo>urn:uuid:client_probe_request</wsa:RelatesTo>
    <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
  </soap:Header>
  <soap:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>{self.device_uuid}</wsa:Address>
        </wsa:EndpointReference>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/location/office</d:Scopes>
        <d:XAddrs>{self.xaddrs}</d:XAddrs>
        <d:MetadataVersion>1</d:MetadataVersion>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </soap:Body>
</soap:Envelope>"""

    def handle_soap_request(self, action: str, body: str) -> Dict[str, Any]:
        """Simulates ONVIF SOAP Media and PTZ service responses"""
        if self.simulate_soap_fault:
            return {
                "status_code": 500,
                "body": "<soap:Fault><faultcode>soap:Server</faultcode><faultstring>Internal Device Fault</faultstring></soap:Fault>",
            }

        if "GetDeviceInformation" in action or "GetDeviceInformation" in body:
            return {
                "status_code": 200,
                "body": """<GetDeviceInformationResponse xmlns="http://www.onvif.org/ver10/device/wsdl">
  <Manufacturer>GenericSecurityCorp</Manufacturer>
  <Model>GSC-IPC-4K-PRO</Model>
  <FirmwareVersion>v2.4.12-build2026</FirmwareVersion>
  <SerialNumber>GSC9988776655</SerialNumber>
  <HardwareId>HW-REV-3</HardwareId>
</GetDeviceInformationResponse>""",
            }

        if "GetProfiles" in action or "GetProfiles" in body:
            return {
                "status_code": 200,
                "body": f"""<GetProfilesResponse xmlns="http://www.onvif.org/ver10/media/wsdl">
  <Profiles token="{self.profiles[0]}" fixed="true">
    <Name>MainStreamProfile</Name>
    <VideoEncoderConfiguration>
      <Encoding>H264</Encoding>
      <Resolution><Width>1920</Width><Height>1080</Height></Resolution>
    </VideoEncoderConfiguration>
  </Profiles>
  <Profiles token="{self.profiles[1]}" fixed="true">
    <Name>SubStreamProfile</Name>
    <VideoEncoderConfiguration>
      <Encoding>H264</Encoding>
      <Resolution><Width>640</Width><Height>360</Height></Resolution>
    </VideoEncoderConfiguration>
  </Profiles>
</GetProfilesResponse>""",
            }

        if "GetStreamUri" in action or "GetStreamUri" in body:
            return {
                "status_code": 200,
                "body": f"""<GetStreamUriResponse xmlns="http://www.onvif.org/ver10/media/wsdl">
  <MediaUri>
    <Uri>{self.rtsp_url}</Uri>
    <InvalidAfterConnect>false</InvalidAfterConnect>
    <InvalidAfterReboot>false</InvalidAfterReboot>
    <Timeout>PT60S</Timeout>
  </MediaUri>
</GetStreamUriResponse>""",
            }

        if "ContinuousMove" in action or "ContinuousMove" in body:
            if self.simulate_unsupported_ptz:
                return {
                    "status_code": 500,
                    "body": "<soap:Fault><faultcode>soap:Client</faultcode><faultstring>PTZ Service Not Supported</faultstring></soap:Fault>",
                }
            return {
                "status_code": 200,
                "body": '<ContinuousMoveResponse xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
            }

        if "Stop" in action or "Stop" in body:
            return {
                "status_code": 200,
                "body": '<StopResponse xmlns="http://www.onvif.org/ver20/ptz/wsdl"/>',
            }

        return {"status_code": 404, "body": "<soap:Fault><faultcode>soap:Client</faultcode><faultstring>Action not recognized</faultstring></soap:Fault>"}


# ==============================================================================
# 4. Mock go2rtc Media Gateway Engine (REST API & WebRTC)
# ==============================================================================
class MockGo2rtcServer:
    """Simulates go2rtc binary media gateway on port 1984."""

    def __init__(self, port: int = 1984):
        self.port = port
        self.is_running = True
        self.streams: Dict[str, Dict[str, Any]] = {}
        self.consumers_count: Dict[str, int] = {}
        self.simulate_api_error = False

    def add_stream(self, name: str, src: str) -> bool:
        """PUT /api/streams?name={name}&src={src}"""
        if not self.is_running or self.simulate_api_error:
            return False
        if not name or not src:
            return False
        self.streams[name] = {
            "name": name,
            "src": src,
            "added_at": time.time(),
            "updated_at": time.time(),
            "status": "online",
        }
        self.consumers_count.setdefault(name, 0)
        return True

    def update_stream(self, name: str, src: str) -> bool:
        """PATCH /api/streams?name={name}&src={src} (Hot-swap upstream lease)"""
        if not self.is_running or self.simulate_api_error:
            return False
        if name not in self.streams:
            return False
        self.streams[name]["src"] = src
        self.streams[name]["updated_at"] = time.time()
        return True

    def delete_stream(self, name: str) -> bool:
        """DELETE /api/streams?name={name}"""
        if not self.is_running or self.simulate_api_error:
            return False
        if name in self.streams:
            del self.streams[name]
            self.consumers_count.pop(name, None)
            return True
        return False

    def get_streams(self) -> Dict[str, Any]:
        """GET /api/streams"""
        if not self.is_running:
            raise ConnectionRefusedError(f"go2rtc not running on port {self.port}")
        return {
            name: {
                "producers": [{"url": info["src"], "medias": ["video, sendonly, H.264", "audio, sendonly, AAC"]}],
                "consumers": [{"url": "webrtc", "user_agent": "Mozilla/5.0"} for _ in range(self.consumers_count.get(name, 0))],
            }
            for name, info in self.streams.items()
        }

    def get_frame(self, stream_name: str, width: int = 640, height: int = 360) -> bytes:
        """GET /api/frame.jpeg?src={stream_name}"""
        if not self.is_running:
            raise ConnectionRefusedError(f"go2rtc not running on port {self.port}")
        if stream_name not in self.streams:
            raise FileNotFoundError(f"Stream '{stream_name}' not found in go2rtc")

        # Generate a deterministic valid JPEG with text watermark using Pillow
        img = Image.new("RGB", (width, height), color=(15, 23, 42))
        draw = ImageDraw.Draw(img)
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        draw.rectangle([10, 10, width - 10, height - 10], outline=(56, 189, 248), width=3)
        draw.text((25, 25), f"STREAM: {stream_name}", fill=(255, 255, 255))
        draw.text((25, 55), f"TIME: {timestamp_str}", fill=(148, 163, 184))
        draw.text((25, 85), f"CODEC: H.264 PASSTHROUGH", fill=(74, 222, 128))

        buffer = io.BytesIO()
        img.save(buffer, format="JPEG", quality=85)
        return buffer.getvalue()

    def webrtc_handshake(self, stream_name: str, sdp_offer: str) -> Dict[str, Any]:
        """POST /api/webrtc?src={stream_name}"""
        if not self.is_running or stream_name not in self.streams:
            return {"status": "error", "message": f"Stream '{stream_name}' unavailable"}
        if "v=0" not in sdp_offer:
            return {"status": "error", "message": "Invalid SDP offer format"}

        # Increment consumer count
        self.consumers_count[stream_name] = self.consumers_count.get(stream_name, 0) + 1

        # Synthesize standard SDP answer
        sdp_answer = (
            "v=0\r\n"
            "o=go2rtc 1000 2000 IN IP4 127.0.0.1\r\n"
            "s=go2rtc WebRTC Gateway\r\n"
            "t=0 0\r\n"
            "a=group:BUNDLE 0 1\r\n"
            "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
            "c=IN IP4 127.0.0.1\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=sendonly\r\n"
            "m=audio 9 UDP/TLS/RTP/SAVPF 97\r\n"
            "c=IN IP4 127.0.0.1\r\n"
            "a=rtpmap:97 PCMU/8000\r\n"
            "a=sendonly\r\n"
        )
        return {"status": "success", "type": "answer", "sdp": sdp_answer}

    def stop_consumer(self, stream_name: str):
        if stream_name in self.consumers_count and self.consumers_count[stream_name] > 0:
            self.consumers_count[stream_name] -= 1


# ==============================================================================
# 5. Mock FFmpeg 7.1 Muxer & Recording Simulator
# ==============================================================================
class MockFFmpegSimulator:
    """Simulates FFmpeg 7.1 fMP4 capture and faststart finalization."""

    @staticmethod
    def verify_movflags(cmd_args: List[str]) -> bool:
        """Verifies crash-resilient fMP4 flags are present"""
        joined = " ".join(cmd_args)
        required = ["+frag_keyframe", "+empty_moov", "+default_base_moof"]
        return all(req in joined for req in required)

    @staticmethod
    def create_mock_mp4_file(output_path: str, duration_sec: int = 5, has_faststart: bool = True):
        """Generates a small valid MP4/fMP4 binary file with ftyp/moov/mdat atoms for testing"""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        # Construct minimal ISO Base Media File Format (MP4) binary chunks
        # ftyp atom (isom / mp42)
        ftyp_data = b"isom\x00\x00\x02\x00isomiso2mp41"
        ftyp_box = len(ftyp_data + b"12345678").to_bytes(4, "big") + b"ftyp" + ftyp_data

        # mdat atom with mock media bytes
        media_payload = b"\x00" * (duration_sec * 1024)
        mdat_box = (len(media_payload) + 8).to_bytes(4, "big") + b"mdat" + media_payload

        # moov atom (contains mvhd and trak headers)
        moov_payload = b"\x00" * 256
        moov_box = (len(moov_payload) + 8).to_bytes(4, "big") + b"moov" + moov_payload

        with open(output_path, "wb") as f:
            if has_faststart:
                # moov comes BEFORE mdat in faststart MP4
                f.write(ftyp_box + moov_box + mdat_box)
            else:
                # moov comes AFTER mdat in unfinalized fMP4
                f.write(ftyp_box + mdat_box + moov_box)


# ==============================================================================
# Global Mock Suite Container
# ==============================================================================
class MockSurveillanceEcosystem:
    """Aggregates all mocks into a unified deterministic testing environment."""

    def __init__(self):
        self.ezviz = MockEZVIZPlatform()
        self.xiaomi = MockXiaomiPlatform()
        self.onvif = MockONVIFDevice()
        self.go2rtc = MockGo2rtcServer()
        self.ffmpeg = MockFFmpegSimulator()

    def reset(self):
        """Resets all mock states between test cases."""
        self.__init__()


# Singleton instance accessible across tests
mock_ecosystem = MockSurveillanceEcosystem()
