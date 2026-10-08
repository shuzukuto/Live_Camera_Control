from typing import Optional, Literal, List
from pydantic import BaseModel, Field, ConfigDict


class RecordingMetadata(BaseModel):
    id: str
    camera_id: str
    camera_name: str
    record_type: Literal["manual", "scheduled", "event", "snapshot"]
    file_path: str
    file_name: str
    file_size: int = Field(..., description="File size in bytes")
    duration: float = Field(default=0.0, description="Video duration in seconds")
    start_time: str
    end_time: Optional[str] = None
    status: Literal["recording", "completed", "failed", "purged"]
    thumbnail_path: Optional[str] = None
    event_id: Optional[str] = None
    is_locked: bool = Field(default=False, description="Protected from FIFO quota cleanup")
    storage_location: Literal["local", "nas"] = "local"
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class RecordingStartRequest(BaseModel):
    camera_id: str = Field(..., description="Camera ID to begin recording")
    record_type: Literal["manual", "scheduled", "event"] = Field(default="manual")
    event_id: Optional[str] = Field(None, description="Associated event ID if triggered by event")


class RecordingStopResponse(BaseModel):
    recording_id: str
    camera_id: str
    file_path: str
    file_size: int
    duration: float
    status: str


class RecordingSession(BaseModel):
    """Active in-memory / live recording state."""
    session_id: str
    camera_id: str
    camera_name: str
    record_type: str
    start_time: str
    status: Literal["recording", "finalizing", "completed", "error"]
    file_path: str
    is_locked: bool = False


class SnapshotCaptureResponse(BaseModel):
    snapshot_id: str
    camera_id: str
    file_path: str
    thumbnail_path: str
    timestamp: str
    width: Optional[int] = None
    height: Optional[int] = None
