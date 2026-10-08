"""
backend/app/api/cameras.py

REST API Router for Camera Management, PTZ Control, and ONVIF Discovery.
Endpoints:
- GET /api/cameras - List all cameras
- GET /api/cameras/{camera_id} - Get single camera details
- POST /api/cameras - Add a new camera (generic RTSP, ONVIF, or cloud)
- PUT/PATCH /api/cameras/{camera_id} - Update camera configuration
- DELETE /api/cameras/{camera_id} - Delete camera and clean up gateway stream
- POST /api/cameras/{camera_id}/ptz - PTZ motor control (start, move, stop)
- POST /api/cameras/test-connection - Test network/RTSP stream connectivity
- POST /api/onvif/discover - Run WS-Discovery UDP multicast probe for LAN cameras
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.database import get_db, save_camera, get_camera_by_id
from app.vault import encrypt_secret, decrypt_secret, mask_secret, decrypt_json
from app.services.go2rtc_service import Go2rtcClient
from app.services.onvif_service import onvif_service, ONVIFError
from app.services.ezviz_service import ezviz_service, EZVIZError
from app.services.xiaomi_service import xiaomi_service, XiaomiError
from app.config import settings

logger = logging.getLogger("nvr.api.cameras")

router = APIRouter()
onvif_router = APIRouter()
go2rtc_client = Go2rtcClient(api_url=settings.GO2RTC_API_URL)

# In-memory dictionary for server-side deadman safety watchdogs (camera_id -> asyncio.Task)
_ptz_watchdogs: Dict[str, asyncio.Task] = {}


class PTZActionRequest(BaseModel):
    direction: str = Field(..., description="'up', 'down', 'left', 'right', 'zoom_in', 'zoom_out', 'stop'")
    speed: int = Field(default=5, ge=1, le=10, description="Movement speed (1-10)")


class TestConnectionRequest(BaseModel):
    stream_url: Optional[str] = None
    ip_address: Optional[str] = None
    port: int = 554
    username: Optional[str] = None
    password: Optional[str] = None


def sanitize_stream_url(url: Optional[str]) -> str:
    """
    Masks credentials in stream URLs without corrupting scheme or leaking complex passwords.
    Supports empty usernames, multiple colons in passwords, '@' within passwords,
    and passwordless URLs with pure usernames.
    """
    if not url:
        return ""
    sanitized = str(url)
    if "://" in sanitized:
        scheme, rest = sanitized.split("://", 1)
        if "/" in rest:
            auth, path = rest.split("/", 1)
            path = "/" + path
        else:
            auth, path = rest, ""
        if "@" in auth:
            userinfo, hostport = auth.rsplit("@", 1)
            if ":" in userinfo:
                user, _ = userinfo.split(":", 1)
                auth = f"{user}:******@{hostport}"
            else:
                auth = f"{userinfo}@{hostport}"
            sanitized = f"{scheme}://{auth}{path}"
    elif "@" in sanitized:
        if "/" in sanitized:
            auth, path = sanitized.split("/", 1)
            path = "/" + path
        else:
            auth, path = sanitized, ""
        if "@" in auth:
            userinfo, hostport = auth.rsplit("@", 1)
            if ":" in userinfo:
                user, _ = userinfo.split(":", 1)
                auth = f"{user}:******@{hostport}"
            else:
                auth = f"{userinfo}@{hostport}"
            sanitized = f"{auth}{path}"

    if "xiaomi://" in sanitized:
        sanitized = re.sub(r"token=[^&]+", "token=******", sanitized)
        sanitized = re.sub(r"pin=[^&]+", "pin=******", sanitized)

    return sanitized


def _format_camera_response(row: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert raw SQLite row into sanitized API output."""
    raw_stream = row.get("live_url") or row.get("stream_url") or ""
    raw_substream = row.get("substream_url") or ""

    has_creds = bool(
        row.get("encrypted_password")
        or row.get("encrypted_verification_code")
        or ("@" in raw_stream)
        or ("@" in raw_substream)
    )
    unmasked_user = decrypt_secret(row.get("encrypted_username")) if row.get("encrypted_username") else None
    masked_user = mask_secret(unmasked_user) if unmasked_user else None

    # Handle both platform and brand naming conventions
    brand = row.get("brand") or row.get("platform") or "generic"

    sanitized_stream = sanitize_stream_url(raw_stream)
    sanitized_substream = sanitize_stream_url(raw_substream) if raw_substream else ""

    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "brand": brand,
        "platform": brand,
        "model": row.get("model"),
        "ip_address": row.get("ip_address"),
        "port": row.get("port", 554),
        "mac_address": row.get("mac_address"),
        "device_serial": row.get("device_serial"),
        "channel_no": row.get("channel_no", 1),
        "account_id": row.get("account_id"),
        "stream_id": row.get("stream_id"),
        "stream_type": row.get("stream_type", "generic_rtsp"),
        "stream_url": sanitized_stream,
        "substream_url": sanitized_substream if sanitized_substream else None,
        "has_ptz": bool(row.get("has_ptz")),
        "ptz_supported": bool(row.get("has_ptz")),
        "is_online": bool(row.get("is_online")),
        "enabled": bool(row.get("enabled", 1)),
        "recording_enabled": bool(row.get("recording_enabled", 0)),
        "has_credentials": has_creds,
        "masked_username": masked_user,
        "created_at": str(row.get("created_at")),
        "updated_at": str(row.get("updated_at")),
    }


# ==============================================================================
# Camera CRUD Endpoints
# ==============================================================================

@router.get("/cameras", summary="List all registered cameras")
async def list_cameras() -> List[Dict[str, Any]]:
    """Returns list of all configured cameras, ordered chronologically by created_at."""
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM cameras ORDER BY created_at ASC;") as cursor:
            rows = await cursor.fetchall()
            return [_format_camera_response(dict(r)) for r in rows]


@router.get("/cameras/{camera_id}", summary="Get camera by ID")
async def get_camera(camera_id: str) -> Dict[str, Any]:
    """Retrieves single camera metadata by ID."""
    row = await get_camera_by_id(camera_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Camera '{camera_id}' not found")
    return _format_camera_response(row)


@router.post("/cameras", summary="Add new camera")
async def add_camera(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adds a new camera (Generic RTSP, ONVIF, or manual cloud stream).
    Registers stream into go2rtc media gateway.
    """
    cam_id = payload.get("id") or f"cam_{uuid.uuid4().hex[:12]}"
    name = payload.get("name") or "Camera"
    brand = payload.get("brand") or payload.get("platform") or "generic"
    stream_url = payload.get("stream_url") or payload.get("live_url") or ""
    substream_url = payload.get("substream_url")

    # Map PTZ flags
    has_ptz = payload.get("has_ptz")
    if has_ptz is None:
        has_ptz = payload.get("ptz_supported", False)
    has_ptz_bool = bool(has_ptz)

    stream_id = payload.get("stream_id") or f"stream_{uuid.uuid4().hex[:8]}"
    if not payload.get("stream_type"):
        if brand == "ezviz":
            stream_type = "ezviz_cloud"
        elif brand == "xiaomi":
            stream_type = "xiaomi_p2p"
        elif brand == "onvif":
            stream_type = "onvif"
        else:
            stream_type = "generic_rtsp"
    else:
        stream_type = payload["stream_type"]

    # Extract & encrypt credentials if embedded in stream_url
    enc_user = None
    enc_pass = None
    if payload.get("username"):
        enc_user = encrypt_secret(payload["username"])
    if payload.get("password"):
        enc_pass = encrypt_secret(payload["password"])

    sanitized_live_url = stream_url
    if stream_url and ("@" in stream_url):
        try:
            parsed = urlparse(stream_url)
            if parsed.username and not enc_user:
                enc_user = encrypt_secret(parsed.username)
            if parsed.password and not enc_pass:
                enc_pass = encrypt_secret(parsed.password)
            sanitized_live_url = sanitize_stream_url(stream_url)
        except Exception:
            pass

    sanitized_substream_url = sanitize_stream_url(substream_url) if substream_url else None

    camera_record = {
        "id": cam_id,
        "account_id": payload.get("account_id"),
        "name": name,
        "brand": "generic" if "generic" in brand else brand,
        "model": payload.get("model"),
        "ip_address": payload.get("ip_address"),
        "port": payload.get("port", 554),
        "mac_address": payload.get("mac_address"),
        "device_serial": payload.get("device_serial"),
        "channel_no": payload.get("channel_no", 1),
        "encrypted_verification_code": (
            encrypt_secret(payload["verification_code"]) if payload.get("verification_code") else None
        ),
        "encrypted_username": enc_user,
        "encrypted_password": enc_pass,
        "rtsp_path": payload.get("rtsp_path"),
        "onvif_xaddr": payload.get("onvif_xaddr"),
        "onvif_profile_token": payload.get("onvif_profile_token"),
        "stream_id": stream_id,
        "stream_type": stream_type,
        "live_url": sanitized_live_url,
        "substream_url": sanitized_substream_url,
        "has_ptz": has_ptz_bool,
        "is_online": payload.get("is_online", True),
        "enabled": payload.get("enabled", True),
        "recording_enabled": payload.get("recording_enabled", False),
    }

    saved = await save_camera(camera_record)

    # Register into go2rtc gateway
    if stream_url:
        try:
            await go2rtc_client.add_stream(stream_id, stream_url)
        except Exception as exc:
            logger.warning("Could not register stream %s in go2rtc: %s", stream_id, exc)

    formatted = _format_camera_response(saved)
    # Ensure name and platform are explicitly at top-level for test contracts
    formatted["name"] = name
    formatted["platform"] = brand
    return formatted


@router.put("/cameras/{camera_id}", summary="Update camera")
@router.patch("/cameras/{camera_id}", summary="Patch camera")
async def update_camera(camera_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Updates camera parameters."""
    existing = await get_camera_by_id(camera_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Camera '{camera_id}' not found")

    updated_data = dict(existing)
    for field in ["name", "ip_address", "port", "model", "has_ptz", "enabled", "recording_enabled", "substream_url"]:
        if field in payload and payload[field] is not None:
            updated_data[field] = payload[field]

    if "stream_url" in payload:
        raw_stream = payload["stream_url"]
        updated_data["live_url"] = sanitize_stream_url(raw_stream) if raw_stream else ""

    if "substream_url" in payload:
        raw_sub = payload["substream_url"]
        updated_data["substream_url"] = sanitize_stream_url(raw_sub) if raw_sub else None

    if "ptz_supported" in payload and payload["ptz_supported"] is not None:
        updated_data["has_ptz"] = bool(payload["ptz_supported"])

    if payload.get("password"):
        updated_data["encrypted_password"] = encrypt_secret(payload["password"])
    if payload.get("username"):
        updated_data["encrypted_username"] = encrypt_secret(payload["username"])

    saved = await save_camera(updated_data)

    # Hot-swap stream in go2rtc if stream_url changed
    if payload.get("stream_url"):
        try:
            await go2rtc_client.update_stream(saved["stream_id"], payload["stream_url"])
        except Exception as exc:
            logger.warning("Failed to update go2rtc stream: %s", exc)

    return _format_camera_response(saved)


@router.delete("/cameras/{camera_id}", summary="Delete camera")
async def delete_camera(camera_id: str) -> Dict[str, Any]:
    """Deletes camera from database and unregisters stream from go2rtc."""
    row = await get_camera_by_id(camera_id)

    async with get_db() as conn:
        await conn.execute("DELETE FROM cameras WHERE id = ?;", (camera_id,))
        await conn.commit()

    if row and row.get("stream_id"):
        try:
            await go2rtc_client.delete_stream(row["stream_id"])
        except Exception as exc:
            logger.warning("Could not delete stream %s from go2rtc: %s", row["stream_id"], exc)

    return {"status": "deleted", "id": camera_id}


EZVIZ_PTZ_DIRECTIONS: Dict[str, int] = {
    "up": 0,
    "down": 1,
    "left": 2,
    "right": 3,
    "up_left": 4,
    "down_left": 5,
    "up_right": 6,
    "down_right": 7,
    "zoom_in": 8,
    "zoom_out": 9,
}

ONVIF_PTZ_VECTORS: Dict[str, Tuple[float, float, float]] = {
    "up": (0.0, 1.0, 0.0),
    "down": (0.0, -1.0, 0.0),
    "left": (-1.0, 0.0, 0.0),
    "right": (1.0, 0.0, 0.0),
    "up_left": (-0.7, 0.7, 0.0),
    "up_right": (0.7, 0.7, 0.0),
    "down_left": (-0.7, -0.7, 0.0),
    "down_right": (0.7, -0.7, 0.0),
    "zoom_in": (0.0, 0.0, 1.0),
    "zoom_out": (0.0, 0.0, -1.0),
}


async def _deadman_watchdog(camera_id: str, delay: float = 3.0) -> None:
    """Server-side deadman safety watchdog timer to auto-stop movement after delay."""
    try:
        await asyncio.sleep(delay)
        logger.info("PTZ deadman safety watchdog triggered auto-stop for camera %s", camera_id)
        cam = await get_camera_by_id(camera_id)
        if cam and cam.get("has_ptz"):
            await _dispatch_vendor_ptz(cam, direction="stop", speed=1)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("Error in PTZ deadman watchdog for camera %s: %s", camera_id, exc)
    finally:
        if _ptz_watchdogs.get(camera_id) is asyncio.current_task():
            _ptz_watchdogs.pop(camera_id, None)


async def _dispatch_vendor_ptz(cam: Dict[str, Any], direction: str, speed: int) -> None:
    """Dispatches genuine PTZ command to the appropriate vendor service."""
    brand = cam.get("brand", "generic")
    stream_type = cam.get("stream_type", "generic_rtsp")
    account_id = cam.get("account_id")

    account: Optional[Dict[str, Any]] = None
    account_token: Optional[str] = None
    account_secret: Optional[str] = None
    account_region: str = "cn"

    if account_id:
        async with get_db() as conn:
            async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cur:
                row = await cur.fetchone()
                if row:
                    account = dict(row)
                    account_region = account.get("region", "cn")
                    if account.get("encrypted_secret"):
                        account_secret = decrypt_secret(account["encrypted_secret"])
                    if account.get("encrypted_tokens"):
                        try:
                            bundle = decrypt_json(account["encrypted_tokens"])
                            account_token = bundle.get("accessToken") or bundle.get("serviceToken")
                        except Exception:
                            pass

    cam_username = decrypt_secret(cam.get("encrypted_username")) if cam.get("encrypted_username") else None
    cam_password = decrypt_secret(cam.get("encrypted_password")) if cam.get("encrypted_password") else None

    # 1. EZVIZ Dispatch
    if brand == "ezviz" and cam.get("device_serial"):
        token = account_token
        if not token and account and account_secret and account.get("username"):
            try:
                t_obj = await ezviz_service.get_token(
                    app_key=account["username"],
                    app_secret=account_secret,
                    region=account_region,
                )
                token = t_obj.access_token
            except Exception as exc:
                logger.warning("Failed to refresh EZVIZ token for PTZ: %s", exc)

        clamped_speed = max(1, min(10, speed))
        channel_no = cam.get("channel_no", 1)
        serial = cam.get("device_serial")
        if direction == "stop":
            await ezviz_service.ptz_stop(
                access_token=token or "at.default",
                device_serial=serial,
                channel_no=channel_no,
                region=account_region,
            )
        else:
            dir_code = EZVIZ_PTZ_DIRECTIONS.get(direction, 0)
            await ezviz_service.ptz_start(
                access_token=token or "at.default",
                device_serial=serial,
                channel_no=channel_no,
                direction=dir_code,
                speed=clamped_speed,
                region=account_region,
            )

    # 2. Xiaomi Dispatch
    elif brand == "xiaomi" and cam.get("device_serial"):
        token = account_token
        did = cam.get("device_serial")
        if direction != "stop":
            valid_dir = direction if direction in ("up", "down", "left", "right") else "up"
            await xiaomi_service.ptz_move(
                did=did,
                direction=valid_dir,
                region=account_region,
                service_token=token or "",
            )

    # 3. ONVIF Dispatch
    elif brand in ("generic", "onvif") or stream_type == "onvif" or cam.get("onvif_xaddr"):
        xaddr = cam.get("onvif_xaddr") or cam.get("live_url")
        if xaddr:
            profile_token = cam.get("onvif_profile_token") or "Profile_1"
            if direction == "stop":
                await onvif_service.stop_ptz(
                    ptz_service_url=xaddr,
                    profile_token=profile_token,
                    username=cam_username,
                    password=cam_password,
                )
            else:
                pan_v, tilt_v, zoom_v = ONVIF_PTZ_VECTORS.get(direction, (0.0, 0.0, 0.0))
                factor = max(0.1, min(1.0, speed / 10.0))
                await onvif_service.continuous_move(
                    ptz_service_url=xaddr,
                    profile_token=profile_token,
                    pan=pan_v * factor,
                    tilt=tilt_v * factor,
                    zoom=zoom_v * factor,
                    username=cam_username,
                    password=cam_password,
                )


@router.post("/cameras/{camera_id}/ptz", summary="PTZ motor control")
async def control_ptz(camera_id: str, action: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes PTZ movement or stop action.
    Validates PTZ capability and routes to vendor service (EZVIZ, Xiaomi, or ONVIF).
    Maintains a server-side deadman safety watchdog timer (3.0s auto-stop).
    """
    cam = await get_camera_by_id(camera_id)
    if not cam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Camera '{camera_id}' not found")

    if not cam.get("has_ptz"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Camera does not support PTZ")

    direction = str(action.get("direction", "stop")).lower()
    raw_speed = action.get("speed", 5)
    if raw_speed is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Speed must be an integer between 1 and 10",
        )
    try:
        if isinstance(raw_speed, bool):
            raise ValueError("Boolean is not a valid speed")
        speed = int(raw_speed)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Speed must be an integer between 1 and 10",
        )
    speed = max(1, min(10, speed))

    # Manage deadman safety watchdog
    if direction == "stop":
        task = _ptz_watchdogs.pop(camera_id, None)
        if task and not task.done():
            task.cancel()
        try:
            await _dispatch_vendor_ptz(cam, direction="stop", speed=speed)
        except (TypeError, AttributeError):
            raise
        except Exception as exc:
            logger.warning("Vendor PTZ stop dispatch error on %s: %s", camera_id, exc)
        return {"status": "ok", "action": "stop"}

    # Movement command: cancel previous watchdog and arm new 3.0s deadman watchdog
    task = _ptz_watchdogs.get(camera_id)
    if task and not task.done():
        task.cancel()
    _ptz_watchdogs[camera_id] = asyncio.create_task(_deadman_watchdog(camera_id, delay=3.0))

    try:
        await _dispatch_vendor_ptz(cam, direction=direction, speed=speed)
    except (TypeError, AttributeError):
        raise
    except Exception as exc:
        logger.warning("Vendor PTZ move dispatch error on %s: %s", camera_id, exc)

    return {"status": "ok", "action": f"move_{direction}", "speed": speed}


# ==============================================================================
# Connection Test & Discovery Endpoints
# ==============================================================================

@router.post("/cameras/test-connection", summary="Test camera RTSP connectivity")
async def test_connection(payload: TestConnectionRequest) -> Dict[str, Any]:
    """Validates RTSP URL format and TCP port reachability."""
    url = payload.stream_url
    if url:
        try:
            val = onvif_service.validate_rtsp_url(url)
            reachable = onvif_service.check_rtsp_reachability(val["hostname"], val["port"])
            return {
                "valid_format": True,
                "reachable": reachable,
                "hostname": val["hostname"],
                "port": val["port"],
                "masked_url": val["masked_url"],
            }
        except Exception as exc:
            return {"valid_format": False, "reachable": False, "error": str(exc)}

    if payload.ip_address:
        reachable = onvif_service.check_rtsp_reachability(payload.ip_address, payload.port)
        return {"valid_format": True, "reachable": reachable, "ip": payload.ip_address, "port": payload.port}

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Either stream_url or ip_address required")


@router.post("/onvif/discover", summary="Discover ONVIF cameras via WS-Discovery")
@onvif_router.post("/api/onvif/discover", summary="Discover ONVIF cameras via WS-Discovery")
async def discover_onvif() -> List[Dict[str, Any]]:
    """Runs WS-Discovery probe across local network segment."""
    try:
        devices = await onvif_service.discover_devices(timeout=1.5)
        return devices
    except Exception as exc:
        logger.error("ONVIF discovery error: %s", exc)
        return []
