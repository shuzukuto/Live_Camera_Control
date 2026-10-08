"""
backend/app/api/events.py

REST API Router for AI Event Logging, Universal Search, Filter, and 3-Mode Export.
Milestone 4: Features 21, 22, 23, 24.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Response, status
from app.models.event import EventCreate
from app.services.event_service import event_service

logger = logging.getLogger("nvr.api.events")
router = APIRouter(tags=["AI Events"])


@router.post("/events", summary="Record a new AI event log")
async def create_event(payload: EventCreate) -> Dict[str, Any]:
    """
    Ingest a new event:
    Automatically applies canonical 3-class normalization (Human, Movement, Abnormal Sound),
    resolves camera metadata, persists to SQLite, and broadcasts via WebSocket & SSE.
    """
    try:
        saved = await event_service.record_event(payload)
        return saved
    except Exception as e:
        logger.exception("Failed to record event: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record event: {e}",
        )


@router.get("/events", summary="List events with universal search, filtering, and pagination")
async def list_events(
    response: Response,
    query: Optional[str] = Query(None, description="Universal search term across all columns"),
    camera_id: Optional[str] = Query(None, description="Filter by camera ID"),
    event_type: Optional[str] = Query(None, description="Filter by event category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    start_time: Optional[str] = Query(None, description="Filter >= start timestamp"),
    end_time: Optional[str] = Query(None, description="Filter <= end timestamp"),
    is_read: Optional[bool] = Query(None, description="Filter read status"),
    page: int = Query(1, ge=1, description="Page index (1-based)"),
    page_size: int = Query(50, ge=1, le=500, description="Page size (max 500)"),
    envelope: bool = Query(False, description="Return wrapped object with pagination telemetry"),
) -> Any:
    """
    Query event logs with multi-column text search and column filtering.
    Defaults to returning List[Dict] with pagination headers.
    """
    records, total = await event_service.list_events(
        query=query,
        camera_id=camera_id,
        event_type=event_type,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        is_read=is_read,
        page=page,
        page_size=page_size,
    )

    # Attach pagination telemetry headers
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Page"] = str(page)
    response.headers["X-Page-Size"] = str(page_size)

    if envelope:
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": records,
        }

    return records


@router.get("/events/export", summary="Export event records in 3 modes (Template, Filtered, All)")
async def export_events(
    mode: str = Query("all", description="Export mode: 'template', 'filtered', or 'all'"),
    format: str = Query("csv", description="Output format: 'csv' or 'xlsx'"),
    query: Optional[str] = Query(None, description="Universal search keyword filter"),
    camera_id: Optional[str] = Query(None, description="Camera ID filter"),
    event_type: Optional[str] = Query(None, description="Event type filter"),
    severity: Optional[str] = Query(None, description="Severity filter"),
    start_time: Optional[str] = Query(None, description="Start timestamp filter"),
    end_time: Optional[str] = Query(None, description="End timestamp filter"),
) -> Response:
    """
    3-Mode event log export conforming to user rules:
    - Mode 1: template (header row only)
    - Mode 2: filtered (matching records without pagination truncation)
    - Mode 3: all (all records, fallback for unknown modes)
    Sanitizes spreadsheet formula injections for Excel and CSV.
    """
    content, media_type, filename = await event_service.export_events(
        mode=mode,
        fmt=format,
        query=query,
        camera_id=camera_id,
        event_type=event_type,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
    )

    encoded_filename = quote(filename)
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"; filename*=UTF-8\'\'{encoded_filename}',
    }
    return Response(content=content, media_type=media_type, headers=headers)
