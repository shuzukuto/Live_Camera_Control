"""
backend/app/models/event.py

Pydantic domain models for AI Events, Search Filtering, and Exporting.
Milestone 4: Features 21, 22, 23, 24.
"""

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class CanonicalEventType(str, Enum):
    HUMAN = "Human"
    MOVEMENT = "Movement"
    ABNORMAL_SOUND = "Abnormal Sound"


class EventCreate(BaseModel):
    id: Optional[Union[str, int]] = Field(None, description="Optional custom ID")
    event_id: Optional[str] = Field(None, description="UUID or cloud alarm identifier")
    camera_id: str = Field(..., description="Target camera identifier")
    camera_name: Optional[str] = Field(None, description="Camera name snapshot at time of event")
    event_type: Optional[str] = Field("Movement", description="Raw vendor alert type or canonical event category")
    vendor_raw_type: Optional[str] = Field(None, description="Original vendor alarm type code")
    severity: Optional[str] = Field("medium", description="Event severity: low, medium, high, critical, info, warning")
    description: Optional[str] = Field("", description="Human-readable event description")
    timestamp: Optional[Union[str, float, int]] = Field(None, description="ISO-8601 UTC timestamp or epoch")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence score")
    snapshot_path: Optional[str] = Field(None, description="Local filesystem path to snapshot")
    snapshot_url: Optional[str] = Field(None, description="Web-accessible URL to snapshot")
    clip_path: Optional[str] = Field(None, description="Local filesystem path to recorded MP4")
    clip_url: Optional[str] = Field(None, description="Web-accessible URL to clip")
    metadata: Optional[Union[Dict[str, Any], str]] = Field(None, description="JSON metadata: bounding boxes, decibels")


class EventResponse(BaseModel):
    id: Union[str, int]
    event_id: str
    camera_id: str
    camera_name: str
    event_type: str
    vendor_raw_type: Optional[str] = None
    severity: str = "medium"
    description: Optional[str] = ""
    timestamp: Union[str, float, int]
    confidence: float = 1.0
    snapshot_path: Optional[str] = None
    snapshot_url: Optional[str] = ""
    clip_path: Optional[str] = None
    clip_url: Optional[str] = ""
    metadata: Optional[Any] = None
    is_read: bool = False
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EventQueryFilter(BaseModel):
    """Filter parameters for universal search and dashboard listing."""
    query: Optional[str] = Field(None, description="Universal keyword searched across all event fields")
    camera_id: Optional[str] = Field(None, description="Filter by specific camera ID")
    event_type: Optional[str] = Field(None, description="Filter by event category")
    severity: Optional[str] = Field(None, description="Filter by severity level")
    start_time: Optional[Union[str, float, int]] = Field(None, description="Start timestamp")
    end_time: Optional[Union[str, float, int]] = Field(None, description="End timestamp")
    is_read: Optional[bool] = Field(None, description="Filter by read/unread status")
    page: int = Field(default=1, ge=1, description="Page index (1-based)")
    page_size: int = Field(default=50, ge=1, le=500, description="Records per page")


class EventExportFilter(BaseModel):
    """Specification for 3-mode export (Template, Filtered, All)."""
    mode: Literal["template", "filtered", "all"] = Field("all", description="Export mode per project rules")
    format: Literal["csv", "xlsx"] = Field(default="csv", description="Output file format")
    query: Optional[str] = None
    camera_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[Union[str, float, int]] = None
    end_time: Optional[Union[str, float, int]] = None


class EventPaginatedList(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[EventResponse]
