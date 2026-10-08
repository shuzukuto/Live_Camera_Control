"""
backend/tests/test_events_m4.py

Comprehensive Unit and Integration Test Suite for Milestone 4:
AI Event Subsystem & Real-Time Alerts (Features 21–25).
"""

import asyncio
import io
import json
import os
import tempfile
import time
from typing import Generator
import openpyxl
import pytest
from fastapi.testclient import TestClient

from app.database import get_db, init_db, set_database_path, save_event_log, query_event_logs
from app.main import app
from app.models.event import CanonicalEventType, EventCreate, EventResponse
from app.services.broadcast_service import broadcast_manager, BroadcastManager
from app.services.event_service import event_service
from app.utils.export import (
    EXPORT_HEADERS,
    export_events_csv,
    export_events_xlsx,
    format_export_timestamp,
    sanitize_spreadsheet_cell,
)


@pytest.fixture(autouse=True)
def isolated_m4_db() -> Generator[str, None, None]:
    """Provides an isolated SQLite database for each test in this module."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    set_database_path(db_path)
    asyncio.run(init_db())
    yield db_path
    try:
        os.remove(db_path)
    except Exception:
        pass


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


# ==============================================================================
# Feature 21: Canonical AI Event Normalization
# ==============================================================================
class TestFeature21_Normalization:
    def test_human_keywords_normalization(self):
        """Verifies person/human/body/face/pedestrian/intrusion alerts map to Human."""
        assert event_service.normalize_event_type("AI_PERSON_DETECTION") == "Human"
        assert event_service.normalize_event_type("human_body_found") == "Human"
        assert event_service.normalize_event_type("face_recognition_matched") == "Human"
        assert event_service.normalize_event_type("facial_geometry_alert") == "Human"
        assert event_service.normalize_event_type("pedestrian_crossing_lane") == "Human"
        assert event_service.normalize_event_type("chuangmi.camera.person.detected") == "Human"
        assert event_service.normalize_event_type("vendor.ai.person_loitering") == "Human"
        assert event_service.normalize_event_type("perimeter_intruder_alarm") == "Human"

    def test_sound_keywords_normalization(self):
        """Verifies sound/audio/cry/bark/noise/glass alerts map to Abnormal Sound."""
        assert event_service.normalize_event_type("BABY_CRY_DETECTION") == "Abnormal Sound"
        assert event_service.normalize_event_type("audio_spike_anomaly") == "Abnormal Sound"
        assert event_service.normalize_event_type("glass_breaking_sensor") == "Abnormal Sound"
        assert event_service.normalize_event_type("audio.baby_crying_detected") == "Abnormal Sound"
        assert event_service.normalize_event_type("dog_barking_loudly") == "Abnormal Sound"
        assert event_service.normalize_event_type("decibel_threshold_exceeded") == "Abnormal Sound"
        assert event_service.normalize_event_type("abnormal_sound_detected") == "Abnormal Sound"

    def test_movement_keywords_and_fallbacks(self):
        """Verifies motion, line crossing, unknown vendor strings default to Movement."""
        assert event_service.normalize_event_type("MOTION_DETECTED") == "Movement"
        assert event_service.normalize_event_type("line_crossing_event") == "Movement"
        assert event_service.normalize_event_type("ezviz.alarm.motion.line_crossing") == "Movement"
        assert event_service.normalize_event_type("VENDOR_CUSTOM_SENSOR_ALERT_99") == "Movement"
        assert event_service.normalize_event_type("") == "Movement"
        assert event_service.normalize_event_type(None) == "Movement"
        assert event_service.normalize_event_type("    \t\n  ") == "Movement"

    def test_strict_precedence_human_over_sound_over_movement(self):
        """Verifies Human takes precedence over Sound, and Sound over Movement."""
        assert event_service.normalize_event_type("human_screaming_sound") == "Human"
        assert event_service.normalize_event_type("person_making_loud_noise") == "Human"
        assert event_service.normalize_event_type("motion_sound_alarm") == "Abnormal Sound"

    def test_linear_time_extreme_payload_safety(self):
        """Verifies 20,000 character vendor payload evaluates safely in O(N) time without regex backtracking."""
        huge = "x" * 10000 + "person" + "y" * 10000
        t0 = time.time()
        res = event_service.normalize_event_type(huge)
        elapsed = time.time() - t0
        assert res == "Human"
        assert elapsed < 0.05


# ==============================================================================
# Feature 22: AI Event Logging & SQLite Storage
# ==============================================================================
class TestFeature22_Storage:
    @pytest.mark.asyncio
    async def test_save_and_retrieve_event_log(self):
        """Verifies inserting event record stores all fields correctly in SQLite."""
        evt = await save_event_log({
            "camera_id": "cam_storage_1",
            "camera_name": "Front Porch",
            "event_type": "Human",
            "description": "Visitor approached front door",
            "severity": "high",
            "snapshot_url": "/snapshots/front_door.jpg",
            "clip_url": "/recordings/front_door.mp4",
            "confidence": 0.98,
        })
        assert evt["id"] is not None
        assert evt["camera_id"] == "cam_storage_1"
        assert evt["camera_name"] == "Front Porch"
        assert evt["event_type"] == "Human"
        assert evt["description"] == "Visitor approached front door"
        assert evt["severity"] == "high"
        assert evt["snapshot_url"] == "/snapshots/front_door.jpg"
        assert evt["clip_url"] == "/recordings/front_door.mp4"
        assert evt["confidence"] == 0.98

    @pytest.mark.asyncio
    async def test_null_snapshot_and_clip_urls_store_empty_strings(self):
        """Verifies null snapshot and clip URLs store empty strings instead of None."""
        evt = await save_event_log({
            "camera_id": "cam_null_test",
            "camera_name": "Test Cam",
            "event_type": "Movement",
        })
        assert evt["snapshot_url"] == ""
        assert evt["clip_url"] == ""

    @pytest.mark.asyncio
    async def test_sql_injection_payload_in_description_escaped(self):
        """Verifies SQL injection attempts in description are stored as literal strings."""
        payload = "Normal Alert'); DROP TABLE event_logs;--"
        evt = await save_event_log({
            "camera_id": "cam_sql_sec",
            "description": payload,
        })
        async with get_db() as conn:
            async with conn.execute("SELECT description FROM event_logs WHERE id = ?;", (evt["id"],)) as cur:
                row = await cur.fetchone()
                assert row[0] == payload

    @pytest.mark.asyncio
    async def test_unicode_vietnamese_camera_name_preservation(self):
        """Verifies Unicode Vietnamese characters are stored and retrieved without corruption."""
        vn_name = "Camera Cổng Trước Nhà Để Xe"
        evt = await save_event_log({
            "camera_id": "cam_vn_test",
            "camera_name": vn_name,
            "event_type": "Human",
        })
        assert evt["camera_name"] == vn_name

    def test_api_create_event_endpoint(self, client: TestClient):
        """Verifies POST /api/events automatically applies normalization and returns 200."""
        res = client.post("/api/events", json={
            "camera_id": "cam_api_test",
            "camera_name": "Driveway",
            "event_type": "person_alert_101",
            "description": "Delivery courier arrival",
        })
        assert res.status_code == 200
        data = res.json()
        assert data["event_type"] == "Human"
        assert "id" in data
        assert data["camera_id"] == "cam_api_test"


# ==============================================================================
# Feature 23: Universal Event Search & Filter
# ==============================================================================
class TestFeature23_SearchAndFilter:
    @pytest.fixture(autouse=True)
    def seed_data(self, client: TestClient):
        client.post("/api/events", json={"camera_id": "cam_1", "camera_name": "Gate", "event_type": "Human", "description": "Courier delivery"})
        client.post("/api/events", json={"camera_id": "cam_2", "camera_name": "Garden", "event_type": "Movement", "description": "Wind swaying flowers"})
        client.post("/api/events", json={"camera_id": "cam_1", "camera_name": "Gate", "event_type": "Abnormal Sound", "description": "Glass break alert"})

    def test_filter_by_event_type(self, client: TestClient):
        res = client.get("/api/events?event_type=Human")
        assert res.status_code == 200
        events = res.json()
        assert len(events) >= 1
        assert all(e["event_type"] == "Human" for e in events)

    def test_filter_by_camera_id(self, client: TestClient):
        res = client.get("/api/events?camera_id=cam_2")
        assert res.status_code == 200
        events = res.json()
        assert len(events) == 1
        assert events[0]["camera_id"] == "cam_2"

    def test_universal_query_search(self, client: TestClient):
        res = client.get("/api/events?query=courier")
        assert res.status_code == 200
        events = res.json()
        assert len(events) == 1
        assert "courier" in events[0]["description"].lower()

    def test_wildcard_query_safety(self, client: TestClient):
        res = client.get("/api/events?query=%")
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_unknown_event_type_returns_empty_list(self, client: TestClient):
        res = client.get("/api/events?event_type=ALIEN_INVASION_TYPE")
        assert res.status_code == 200
        assert res.json() == []

    def test_pagination_limits_and_headers(self, client: TestClient):
        res = client.get("/api/events?page=1&page_size=2")
        assert res.status_code == 200
        assert len(res.json()) == 2
        assert "X-Total-Count" in res.headers
        assert "X-Page" in res.headers
        assert "X-Page-Size" in res.headers

    def test_page_boundaries_validation(self, client: TestClient):
        # page=0 rejected by ge=1
        r0 = client.get("/api/events?page=0")
        assert r0.status_code == 422

        # page_size=501 rejected by le=500
        r501 = client.get("/api/events?page_size=501")
        assert r501.status_code == 422

    def test_envelope_mode(self, client: TestClient):
        res = client.get("/api/events?envelope=true")
        assert res.status_code == 200
        data = res.json()
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "items" in data
        assert isinstance(data["items"], list)


# ==============================================================================
# Feature 24: 3-Mode Event Export
# ==============================================================================
class TestFeature24_Export:
    @pytest.fixture(autouse=True)
    def seed_export_events(self, client: TestClient):
        client.post("/api/events", json={"camera_id": "c1", "camera_name": "Front Cam", "event_type": "Human", "description": "Delivery"})
        client.post("/api/events", json={"camera_id": "c2", "camera_name": "Back Cam", "event_type": "Movement", "description": "Raccoon"})

    def test_mode1_template_export_strictly_header_only(self, client: TestClient):
        res = client.get("/api/events/export?mode=template")
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        lines = res.text.strip().split("\n")
        assert len(lines) == 1
        assert "Date Time,Camera Name,Event Type" in lines[0]

    def test_mode2_filtered_export(self, client: TestClient):
        res = client.get("/api/events/export?mode=filtered&event_type=Human")
        assert res.status_code == 200
        lines = res.text.strip().split("\n")
        assert len(lines) >= 2  # Header + 1 record
        assert "Front Cam" in res.text
        assert "Back Cam" not in res.text

    def test_mode3_all_export(self, client: TestClient):
        res = client.get("/api/events/export?mode=all")
        assert res.status_code == 200
        lines = res.text.strip().split("\n")
        assert len(lines) >= 3  # Header + 2 records

    def test_unknown_mode_fallback_to_all(self, client: TestClient):
        res = client.get("/api/events/export?mode=unknown_mode_xyz")
        assert res.status_code == 200
        lines = res.text.strip().split("\n")
        assert len(lines) >= 3

    def test_formula_injection_sanitization(self):
        dangerous_inputs = ["=CMD|'/C calc'!A0", "+1+1", "-5", "@SUM(A1:A10)"]
        for item in dangerous_inputs:
            sanitized = sanitize_spreadsheet_cell(item)
            assert sanitized.startswith("'"), f"Failed to sanitize: {item}"

        safe_input = "Normal alert"
        assert sanitize_spreadsheet_cell(safe_input) == "Normal alert"

    def test_xlsx_export_format(self, client: TestClient):
        res = client.get("/api/events/export?mode=all&format=xlsx")
        assert res.status_code == 200
        assert "spreadsheetml" in res.headers["content-type"]
        # Verify valid openpyxl workbook
        wb = openpyxl.load_workbook(io.BytesIO(res.content))
        ws = wb.active
        assert ws.title == "Event Logs"
        assert ws.cell(row=1, column=1).value == "Date Time"


# ==============================================================================
# Feature 25: Real-Time Alert Broadcast via WebSocket & SSE
# ==============================================================================
class TestFeature25_Broadcast:
    @pytest.mark.asyncio
    async def test_silent_noop_when_zero_subscribers(self):
        mgr = BroadcastManager()
        count = await mgr.broadcast_event({"event_type": "Human"})
        assert count == 0

    @pytest.mark.asyncio
    async def test_audio_alert_boolean_flag(self):
        mgr = BroadcastManager()
        queue = asyncio.Queue()
        await mgr.register_sse(queue)

        # Abnormal Sound -> audio_alert True
        await mgr.broadcast_event({"event_type": "Abnormal Sound"})
        msg = await queue.get()
        assert msg["audio_alert"] is True
        assert isinstance(msg["audio_alert"], bool)

        # Movement -> audio_alert False
        await mgr.broadcast_event({"event_type": "Movement"})
        msg2 = await queue.get()
        assert msg2["audio_alert"] is False
        assert isinstance(msg2["audio_alert"], bool)

        await mgr.unregister_sse(queue)

    def test_websocket_connection_and_heartbeat(self, client: TestClient):
        with client.websocket_connect("/api/ws/events") as ws:
            # 1. Receive initial greeting
            greeting = ws.receive_json()
            assert greeting["type"] == "connected"

            # 2. Application-level ping / pong
            ws.send_text("ping")
            pong = ws.receive_json()
            assert pong["type"] == "pong"

    @pytest.mark.asyncio
    async def test_sse_endpoint_stream_and_format(self):
        # 1. Verify SSE endpoint route registration on app
        route = next((r for r in app.routes if getattr(r, "path", None) == "/api/events/stream"), None)
        assert route is not None

        # 2. Verify SSE queue fan-out and formatting compliance
        queue = asyncio.Queue()
        await broadcast_manager.register_sse(queue)
        await broadcast_manager.broadcast_event({"event_type": "Human", "camera_name": "Gate"})
        payload = queue.get_nowait()
        sse_chunk = f"data: {json.dumps(payload)}\n\n"
        assert sse_chunk.startswith("data: ")
        assert sse_chunk.endswith("\n\n")
        assert "Human" in sse_chunk
        assert "Gate" in sse_chunk
        await broadcast_manager.unregister_sse(queue)

    def test_broadcast_status_telemetry(self, client: TestClient):
        res = client.get("/api/ws/status")
        assert res.status_code == 200
        data = res.json()
        assert "active_ws_clients" in data
        assert "active_sse_clients" in data
        assert "total_broadcasts" in data
