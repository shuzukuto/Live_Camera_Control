"""
backend/app/services/onvif_service.py

ONVIF WS-Discovery Probe, SOAP Media & PTZ Client, and RTSP URL Validator.
Features:
- Async UDP Multicast WS-Discovery probe on 239.255.255.250:3702
- Deduplication of discovered cameras by device UUID
- SOAP Client with WS-Security UsernameToken (PasswordDigest)
- SOAP GetDeviceInformation, GetProfiles, GetStreamUri
- SOAP ContinuousMove & Stop PTZ Controller
- RTSP URL validation and socket reachability tester
- Dependency injection support for mock ecosystem testing
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import logging
import os
import re
import socket
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("nvr.onvif")

WS_DISCOVERY_MULTICAST_IP = "239.255.255.250"
WS_DISCOVERY_MULTICAST_PORT = 3702

SOAP_NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "s11": "http://schemas.xmlsoap.org/soap/envelope/",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "d": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "dn": "http://www.onvif.org/ver10/network/wsdl",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
    "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
}


class ONVIFError(Exception):
    """Base exception for ONVIF protocol operations."""
    def __init__(self, message: str, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


@dataclass
class DiscoveredCamera:
    uuid: str
    ip: str
    xaddrs: List[str]
    scopes: List[str]


@dataclass
class ONVIFProfile:
    token: str
    name: str
    encoding: Optional[str] = "H264"
    width: Optional[int] = 1920
    height: Optional[int] = 1080


def create_ws_security_header(username: Optional[str], password: Optional[str]) -> str:
    """
    Constructs standard WS-Security UsernameToken with SHA1 PasswordDigest.
    Digest = Base64(SHA1(Nonce + Created + Password))
    """
    if not username or not password:
        return ""

    raw_nonce = os.urandom(16)
    nonce_b64 = base64.b64encode(raw_nonce).decode("utf-8")
    now_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    hasher = hashlib.sha1()
    hasher.update(raw_nonce)
    hasher.update(now_utc.encode("utf-8"))
    hasher.update(password.encode("utf-8"))
    password_digest = base64.b64encode(hasher.digest()).decode("utf-8")

    return f"""
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{now_utc}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
    """


def wrap_soap_envelope(body_content: str, username: Optional[str] = None, password: Optional[str] = None) -> str:
    """Envelopes SOAP body with WS-Security header."""
    security_hdr = create_ws_security_header(username, password)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
               xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
               xmlns:tt="http://www.onvif.org/ver10/schema">
  <soap:Header>
    {security_hdr}
  </soap:Header>
  <soap:Body>
    {body_content}
  </soap:Body>
</soap:Envelope>"""


class ONVIFService:
    """
    ONVIF Protocol Service for discovery, device inspection, media URI extraction, and PTZ.
    """

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        self._http_client = http_client

    # --------------------------------------------------------------------------
    # 1. WS-Discovery Probe
    # --------------------------------------------------------------------------
    async def discover_devices(self, timeout: float = 2.0) -> List[Dict[str, Any]]:
        """
        Sends WS-Discovery Probe over UDP multicast (239.255.255.250:3702).
        Returns deduplicated list of discovered ONVIF cameras.
        """
        msg_id = f"urn:uuid:{uuid.uuid4()}"
        probe_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:MessageID>{msg_id}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
  </soap:Header>
  <soap:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </soap:Body>
</soap:Envelope>"""

        discovered_dict: Dict[str, Dict[str, Any]] = {}

        class ProbeProtocol(asyncio.DatagramProtocol):
            def __init__(self, parser_fn):
                self.parser_fn = parser_fn

            def datagram_received(self, data: bytes, addr: Tuple[str, int]):
                try:
                    text = data.decode("utf-8", errors="ignore")
                    matches = self.parser_fn(text, sender_ip=addr[0])
                    for m in matches:
                        uid = m.get("uuid") or m.get("ip")
                        if uid and uid not in discovered_dict:
                            discovered_dict[uid] = m
                except Exception as exc:
                    logger.debug("Failed to parse probe datagram: %s", exc)

        loop = asyncio.get_running_loop()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)

            transport, _ = await loop.create_datagram_endpoint(
                lambda: ProbeProtocol(self.parse_probe_matches_xml),
                sock=sock,
            )

            # Transmit multicast probe
            sock.sendto(probe_xml.encode("utf-8"), (WS_DISCOVERY_MULTICAST_IP, WS_DISCOVERY_MULTICAST_PORT))
            await asyncio.sleep(timeout)
            transport.close()
        except Exception as exc:
            logger.warning("WS-Discovery socket probe error: %s", exc)

        return list(discovered_dict.values())

    @staticmethod
    def parse_probe_matches_xml(xml_content: str, sender_ip: str = "127.0.0.1") -> List[Dict[str, Any]]:
        """Parses WS-Discovery ProbeMatches SOAP XML and extracts endpoints."""
        results: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_content)
        except Exception:
            return results

        # Support namespaces
        for match in root.iter():
            if match.tag.endswith("ProbeMatch"):
                device_uuid = ""
                xaddrs: List[str] = []
                scopes: List[str] = []

                for child in match.iter():
                    if child.tag.endswith("Address") and child.text:
                        device_uuid = child.text.strip()
                    elif child.tag.endswith("XAddrs") and child.text:
                        xaddrs = child.text.strip().split()
                    elif child.tag.endswith("Scopes") and child.text:
                        scopes = child.text.strip().split()

                if not device_uuid:
                    device_uuid = f"urn:uuid:{uuid.uuid4()}"

                results.append({
                    "uuid": device_uuid,
                    "ip": sender_ip,
                    "xaddrs": xaddrs[0] if len(xaddrs) == 1 else xaddrs,
                    "scopes": scopes,
                })

        return results

    # --------------------------------------------------------------------------
    # 2. SOAP Dispatcher
    # --------------------------------------------------------------------------
    async def _send_soap_request(
        self,
        endpoint_url: str,
        action_name: str,
        body_xml: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> str:
        """Dispatches SOAP POST request via HTTP client."""
        envelope = wrap_soap_envelope(body_xml, username=username, password=password)
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "SOAPAction": action_name,
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(endpoint_url, content=envelope, headers=headers)
            if resp.status_code != 200:
                raise ONVIFError(
                    f"ONVIF SOAP HTTP error ({resp.status_code}): {resp.text}",
                    status_code=resp.status_code,
                    body=resp.text,
                )
            return resp.text

    # --------------------------------------------------------------------------
    # 3. ONVIF Core Device & Media Services
    # --------------------------------------------------------------------------
    async def get_device_information(
        self,
        device_service_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        SOAP GetDeviceInformation: retrieves Manufacturer, Model, FirmwareVersion, SerialNumber.
        """
        body = "<tds:GetDeviceInformation/>"
        resp_xml = await self._send_soap_request(
            device_service_url,
            action_name="GetDeviceInformation",
            body_xml=body,
            username=username,
            password=password,
        )

        info: Dict[str, str] = {}
        try:
            root = ET.fromstring(resp_xml)
            for elem in root.iter():
                tag = elem.tag.split("}")[-1]
                if tag in ["Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"] and elem.text:
                    info[tag] = elem.text.strip()
        except Exception as exc:
            logger.warning("Error parsing GetDeviceInformation XML: %s", exc)

        return info

    async def get_profiles(
        self,
        media_service_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> List[ONVIFProfile]:
        """
        SOAP GetProfiles: lists video encoding profiles supported by the camera.
        """
        body = "<trt:GetProfiles/>"
        resp_xml = await self._send_soap_request(
            media_service_url,
            action_name="GetProfiles",
            body_xml=body,
            username=username,
            password=password,
        )

        profiles: List[ONVIFProfile] = []
        try:
            root = ET.fromstring(resp_xml)
            for elem in root.iter():
                if elem.tag.endswith("Profiles"):
                    token = elem.attrib.get("token", "")
                    name = ""
                    width, height = 1920, 1080
                    encoding = "H264"

                    for child in elem.iter():
                        tag = child.tag.split("}")[-1]
                        if tag == "Name" and child.text and not name:
                            name = child.text.strip()
                        elif tag == "Encoding" and child.text:
                            encoding = child.text.strip()
                        elif tag == "Width" and child.text:
                            try:
                                width = int(child.text.strip())
                            except ValueError:
                                pass
                        elif tag == "Height" and child.text:
                            try:
                                height = int(child.text.strip())
                            except ValueError:
                                pass

                    if token:
                        profiles.append(ONVIFProfile(
                            token=token,
                            name=name or token,
                            encoding=encoding,
                            width=width,
                            height=height,
                        ))
        except Exception as exc:
            logger.warning("Error parsing GetProfiles XML: %s", exc)

        return profiles

    async def get_stream_uri(
        self,
        media_service_url: str,
        profile_token: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> str:
        """
        SOAP GetStreamUri: retrieves exact RTSP stream URL for the designated media profile.
        """
        body = f"""<trt:GetStreamUri>
  <trt:StreamSetup>
    <tt:Stream>RTP-Unicast</tt:Stream>
    <tt:Transport>
      <tt:Protocol>RTSP</tt:Protocol>
    </tt:Transport>
  </trt:StreamSetup>
  <trt:ProfileToken>{profile_token}</trt:ProfileToken>
</trt:GetStreamUri>"""

        resp_xml = await self._send_soap_request(
            media_service_url,
            action_name="GetStreamUri",
            body_xml=body,
            username=username,
            password=password,
        )

        try:
            root = ET.fromstring(resp_xml)
            for elem in root.iter():
                tag = elem.tag.split("}")[-1]
                if tag == "Uri" and elem.text and elem.text.strip():
                    return elem.text.strip()
        except Exception as exc:
            logger.warning("Error parsing GetStreamUri XML: %s", exc)

        raise ONVIFError("Could not extract stream URI from GetStreamUri response")

    # --------------------------------------------------------------------------
    # 4. ONVIF PTZ ContinuousMove & Stop
    # --------------------------------------------------------------------------
    async def continuous_move(
        self,
        ptz_service_url: Optional[str] = None,
        profile_token: str = "Profile_1",
        pan: float = 0.0,
        tilt: float = 0.0,
        zoom: float = 0.0,
        username: Optional[str] = None,
        password: Optional[str] = None,
        xaddr: Optional[str] = None,
    ) -> bool:
        """
        SOAP ContinuousMove: initiates PTZ movement velocity (-1.0 to 1.0).
        Supports either ptz_service_url or xaddr parameter.
        """
        target_url = ptz_service_url or xaddr
        if not target_url:
            raise ONVIFError("ptz_service_url or xaddr is required for continuous_move")
        body = f"""<tptz:ContinuousMove>
  <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
  <tptz:Velocity>
    <tt:PanTilt x="{pan}" y="{tilt}"/>
    <tt:Zoom x="{zoom}"/>
  </tptz:Velocity>
</tptz:ContinuousMove>"""

        await self._send_soap_request(
            target_url,
            action_name="ContinuousMove",
            body_xml=body,
            username=username,
            password=password,
        )
        return True

    async def stop_ptz(
        self,
        ptz_service_url: Optional[str] = None,
        profile_token: str = "Profile_1",
        pan_tilt: bool = True,
        zoom: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        xaddr: Optional[str] = None,
    ) -> bool:
        """
        SOAP Stop: halts active PTZ motor movement.
        Supports either ptz_service_url or xaddr parameter.
        """
        target_url = ptz_service_url or xaddr
        if not target_url:
            raise ONVIFError("ptz_service_url or xaddr is required for stop_ptz")
        pt_str = "true" if pan_tilt else "false"
        zm_str = "true" if zoom else "false"
        body = f"""<tptz:Stop>
  <tptz:ProfileToken>{profile_token}</tptz:ProfileToken>
  <tptz:PanTilt>{pt_str}</tptz:PanTilt>
  <tptz:Zoom>{zm_str}</tptz:Zoom>
</tptz:Stop>"""

        await self._send_soap_request(
            target_url,
            action_name="Stop",
            body_xml=body,
            username=username,
            password=password,
        )
        return True

    # --------------------------------------------------------------------------
    # 5. RTSP URL Validator & Socket Probe
    # --------------------------------------------------------------------------
    @staticmethod
    def validate_rtsp_url(url: str) -> Dict[str, Any]:
        """
        Validates RTSP URL format, extracts components, and produces safe masked representation.
        """
        if not url or not (url.startswith("rtsp://") or url.startswith("rtsps://")):
            raise ValueError("URL must start with rtsp:// or rtsps://")

        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        port = parsed.port or 554
        username = parsed.username
        password = parsed.password
        path = parsed.path or "/"

        # Create sanitized URL without plaintext password
        masked_user_info = ""
        if username:
            masked_pass = "******" if password else ""
            masked_user_info = f"{username}:{masked_pass}@" if password else f"{username}@"

        masked_url = f"{parsed.scheme}://{masked_user_info}{hostname}:{port}{path}"

        return {
            "valid": True,
            "scheme": parsed.scheme,
            "hostname": hostname,
            "port": port,
            "username": username,
            "password": password,
            "path": path,
            "masked_url": masked_url,
        }

    @staticmethod
    def check_rtsp_reachability(host: str, port: int = 554, timeout: float = 3.0) -> bool:
        """
        Performs quick TCP socket connectivity probe against camera host and port.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


# Global default instance
onvif_service = ONVIFService()
