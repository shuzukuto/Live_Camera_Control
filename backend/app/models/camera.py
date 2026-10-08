from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict


class CameraBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="User-assigned camera display name")
    brand: Literal["ezviz", "xiaomi", "generic"] = Field(..., description="Camera brand / category")
    model: Optional[str] = Field(None, max_length=50)
    ip_address: Optional[str] = Field(None, description="Local IP address on LAN")
    port: int = Field(default=554, ge=1, le=65535, description="RTSP or ONVIF port")
    mac_address: Optional[str] = Field(None, max_length=20)
    device_serial: Optional[str] = Field(None, max_length=50, description="EZVIZ serial number or Xiaomi DID")
    channel_no: int = Field(default=1, ge=1, description="Camera channel index")
    has_ptz: bool = Field(default=False, description="Whether camera supports Pan/Tilt/Zoom control")
    enabled: bool = Field(default=True, description="Whether the camera stream is actively enabled")
    recording_enabled: bool = Field(default=False, description="Whether automated recording is enabled")
    substream_url: Optional[str] = Field(None, description="Optional secondary substream RTSP URL for grid view")


class CameraCreate(CameraBase):
    account_id: Optional[str] = Field(None, description="Linked cloud account ID, if applicable")
    stream_type: Literal["rtsp_local", "ezviz_cloud", "xiaomi_p2p", "onvif", "generic_rtsp"] = Field(
        default="rtsp_local", description="Ingestion protocol type"
    )
    # Sensitive input fields (encrypted before database storage):
    verification_code: Optional[str] = Field(
        None, max_length=20, description="EZVIZ 6-character camera verification code"
    )
    username: Optional[str] = Field(None, max_length=50, description="RTSP / ONVIF username")
    password: Optional[str] = Field(None, description="RTSP / ONVIF password")
    rtsp_path: Optional[str] = Field(None, description="Custom RTSP URL path suffix")
    onvif_xaddr: Optional[str] = Field(None, description="ONVIF device service SOAP URL")
    onvif_profile_token: Optional[str] = Field(None, description="Selected ONVIF media profile token")


class CameraUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    ip_address: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    verification_code: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    rtsp_path: Optional[str] = None
    stream_type: Optional[Literal["rtsp_local", "ezviz_cloud", "xiaomi_p2p", "onvif", "generic_rtsp"]] = None
    substream_url: Optional[str] = None
    has_ptz: Optional[bool] = None
    enabled: Optional[bool] = None
    recording_enabled: Optional[bool] = None


class CameraResponse(CameraBase):
    """
    Public representation for browser consumption.
    CRITICAL: Never exposes raw passwords, tokens, or credential-embedded RTSP URLs.
    """
    id: str
    account_id: Optional[str] = None
    stream_id: str = Field(..., description="Opaque stream identifier used for WebRTC / MSE playback")
    stream_type: Literal["rtsp_local", "ezviz_cloud", "xiaomi_p2p", "onvif", "generic_rtsp"]
    is_online: bool = Field(default=False, description="Real-time online status")
    has_credentials: bool = Field(default=False, description="Indicates if valid credentials are saved without exposing them")
    masked_username: Optional[str] = None
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class CameraInDB(CameraBase):
    """Full internal representation loaded from SQLite."""
    id: str
    account_id: Optional[str] = None
    encrypted_verification_code: Optional[str] = None
    encrypted_username: Optional[str] = None
    encrypted_password: Optional[str] = None
    rtsp_path: Optional[str] = None
    onvif_xaddr: Optional[str] = None
    onvif_profile_token: Optional[str] = None
    stream_id: str
    stream_type: str
    live_url: Optional[str] = None
    url_expires_at: Optional[int] = None
    is_online: bool = False
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)
