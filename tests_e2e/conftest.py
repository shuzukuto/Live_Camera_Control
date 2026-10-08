"""
Pytest configuration and fixtures for Web-based NVR/VMS E2E Test Suite.
Provides isolated test environments, temporary SQLite databases, mock cloud engines,
and contract-compliant test clients.
"""

import asyncio
import hashlib
import os
import shutil
import sqlite3
import tempfile
import time
from typing import AsyncGenerator, Dict, Generator, Any, List

import pytest
try:
    import pytest_asyncio
except ImportError:
    pytest_asyncio = None
from fastapi import FastAPI, HTTPException, Query, WebSocket, status
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
    MockGo2rtcServer,
    MockFFmpegSimulator,
    MockSurveillanceEcosystem,
    mock_ecosystem,
)


# ==============================================================================
# 1. Environment & Storage Fixtures
# ==============================================================================
@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_storage_env() -> Generator[Dict[str, str], None, None]:
    """Creates isolated temporary storage folders for DB, recordings, snapshots, and NAS UNC mount."""
    temp_dir = tempfile.mkdtemp(prefix="nvr_e2e_")
    db_path = os.path.join(temp_dir, "data", "nvr_test.db")
    recordings_dir = os.path.join(temp_dir, "recordings")
    snapshots_dir = os.path.join(temp_dir, "snapshots")
    nas_mount_dir = os.path.join(temp_dir, "nas_share")

    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    os.makedirs(recordings_dir, exist_ok=True)
    os.makedirs(snapshots_dir, exist_ok=True)
    os.makedirs(nas_mount_dir, exist_ok=True)

    env_paths = {
        "root": temp_dir,
        "db_path": db_path,
        "recordings": recordings_dir,
        "snapshots": snapshots_dir,
        "nas_mount": nas_mount_dir,
    }

    yield env_paths

    # Teardown: clean up temporary test files
    try:
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


# ==============================================================================
# 2. SQLite Database Schema Fixture
# ==============================================================================
@pytest.fixture
def test_db_conn(temp_storage_env: Dict[str, str]) -> Generator[sqlite3.Connection, None, None]:
    """Initializes SQLite database with WAL PRAGMA and core NVR tables per PROJECT.md Feature 1."""
    conn = sqlite3.connect(temp_storage_env["db_path"], check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Enable WAL mode and foreign keys
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA foreign_keys=ON;")

    # Table 1: accounts (cloud auth credentials)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        platform TEXT NOT NULL,
        username TEXT NOT NULL,
        encrypted_credentials TEXT NOT NULL,
        region TEXT,
        is_active INTEGER DEFAULT 1,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    );
    """)

    # Table 2: cameras
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cameras (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        platform TEXT NOT NULL,
        account_id TEXT,
        device_serial TEXT,
        stream_url TEXT NOT NULL,
        local_rtsp_url TEXT,
        is_online INTEGER DEFAULT 1,
        is_encrypted INTEGER DEFAULT 0,
        ptz_supported INTEGER DEFAULT 0,
        substream_url TEXT,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE SET NULL
    );
    """)

    # Table 3: recordings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recordings (
        id TEXT PRIMARY KEY,
        camera_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        duration_sec REAL DEFAULT 0,
        size_bytes INTEGER DEFAULT 0,
        trigger_type TEXT DEFAULT 'manual',
        is_protected INTEGER DEFAULT 0,
        created_at REAL NOT NULL,
        FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE
    );
    """)

    # Table 4: event_logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS event_logs (
        id TEXT PRIMARY KEY,
        camera_id TEXT NOT NULL,
        camera_name TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT,
        snapshot_url TEXT,
        clip_url TEXT,
        timestamp REAL NOT NULL,
        FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE
    );
    """)

    # Table 5: system_settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL
    );
    """)

    conn.commit()
    yield conn
    conn.close()


# ==============================================================================
# 3. Deterministic Mock Ecosystem Fixture
# ==============================================================================
@pytest.fixture
def mock_ecosystem_fixture() -> Generator[MockSurveillanceEcosystem, None, None]:
    """Provides a cleanly reset mock ecosystem for each test case."""
    mock_ecosystem.reset()
    yield mock_ecosystem


# ==============================================================================
# 4. Reference FastAPI Application Implementing PROJECT.md Contracts
# ==============================================================================
def create_test_nvr_app(db_conn: sqlite3.Connection, eco: MockSurveillanceEcosystem, storage_paths: Dict[str, str]) -> FastAPI:
    """Creates a lightweight, contract-conforming FastAPI test instance wired to mock infrastructure."""
    app = FastAPI(title="Web-based NVR/VMS Test API", version="0.1.0")

    active_recordings: Dict[str, Dict[str, Any]] = {}

    @app.get("/health")
    async def health():
        return {"status": "ok", "go2rtc_healthy": eco.go2rtc.is_running}

    # --- CAMERAS ---
    @app.get("/api/cameras")
    async def list_cameras():
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM cameras ORDER BY created_at ASC")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    @app.post("/api/cameras")
    async def add_camera(data: Dict[str, Any]):
        cam_id = data.get("id") or f"cam_{int(time.time()*1000)}"
        name = data.get("name", "Camera")
        platform = data.get("platform", "generic_rtsp")
        stream_url = data.get("stream_url", "")
        ptz_supported = 1 if data.get("ptz_supported") else 0

        cursor = db_conn.cursor()
        now = time.time()
        cursor.execute(
            """INSERT INTO cameras (id, name, platform, stream_url, is_online, ptz_supported, created_at, updated_at)
               VALUES (?, ?, ?, ?, 1, ?, ?, ?)""",
            (cam_id, name, platform, stream_url, ptz_supported, now, now),
        )
        db_conn.commit()

        # Register into go2rtc
        eco.go2rtc.add_stream(cam_id, stream_url)

        return {"id": cam_id, "name": name, "platform": platform, "stream_url": stream_url}

    @app.delete("/api/cameras/{camera_id}")
    async def delete_camera(camera_id: str):
        cursor = db_conn.cursor()
        cursor.execute("DELETE FROM cameras WHERE id = ?", (camera_id,))
        db_conn.commit()
        eco.go2rtc.delete_stream(camera_id)
        return {"status": "deleted", "id": camera_id}

    # --- PTZ ---
    @app.post("/api/cameras/{camera_id}/ptz")
    async def control_ptz(camera_id: str, action: Dict[str, Any]):
        direction = action.get("direction", "stop")
        speed = action.get("speed", 5)

        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM cameras WHERE id = ?", (camera_id,))
        cam = cursor.fetchone()
        if not cam:
            raise HTTPException(status_code=404, detail="Camera not found")
        if not cam["ptz_supported"]:
            raise HTTPException(status_code=400, detail="Camera does not support PTZ")

        if direction == "stop":
            return {"status": "ok", "action": "stop"}
        return {"status": "ok", "action": f"move_{direction}", "speed": speed}

    # --- RECORDING ---
    @app.post("/api/cameras/{camera_id}/record/start")
    async def start_recording(camera_id: str, trigger_type: str = Query("manual")):
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM cameras WHERE id = ?", (camera_id,))
        cam = cursor.fetchone()
        if not cam:
            raise HTTPException(status_code=404, detail="Camera not found")

        rec_id = f"rec_{int(time.time()*1000)}"
        output_file = os.path.join(storage_paths["recordings"], f"{camera_id}_{rec_id}.mp4")

        active_recordings[camera_id] = {
            "rec_id": rec_id,
            "output_file": output_file,
            "start_time": time.time(),
            "trigger_type": trigger_type,
        }
        # Simulate initial fMP4 write
        eco.ffmpeg.create_mock_mp4_file(output_file, duration_sec=1, has_faststart=False)

        return {"status": "recording_started", "recording_id": rec_id, "file_path": output_file}

    @app.post("/api/cameras/{camera_id}/record/stop")
    async def stop_recording(camera_id: str):
        if camera_id not in active_recordings:
            raise HTTPException(status_code=400, detail="No active recording for this camera")

        rec_info = active_recordings.pop(camera_id)
        duration = time.time() - rec_info["start_time"]
        file_path = rec_info["output_file"]

        # Finalize faststart
        eco.ffmpeg.create_mock_mp4_file(file_path, duration_sec=max(1, int(duration)), has_faststart=True)
        size = os.path.getsize(file_path)

        cursor = db_conn.cursor()
        cursor.execute(
            """INSERT INTO recordings (id, camera_id, file_path, duration_sec, size_bytes, trigger_type, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (rec_info["rec_id"], camera_id, file_path, duration, size, rec_info["trigger_type"], time.time()),
        )
        db_conn.commit()

        return {"status": "recording_stopped", "recording_id": rec_info["rec_id"], "duration_sec": duration, "size_bytes": size}

    # --- SNAPSHOT ---
    @app.post("/api/cameras/{camera_id}/snapshot")
    async def take_snapshot(camera_id: str):
        cursor = db_conn.cursor()
        cursor.execute("SELECT * FROM cameras WHERE id = ?", (camera_id,))
        cam = cursor.fetchone()
        if not cam:
            raise HTTPException(status_code=404, detail="Camera not found")

        frame_bytes = eco.go2rtc.get_frame(camera_id)
        snap_id = f"snap_{int(time.time()*1000)}.jpg"
        snap_path = os.path.join(storage_paths["snapshots"], snap_id)

        with open(snap_path, "wb") as f:
            f.write(frame_bytes)

        return {"status": "ok", "snapshot_url": f"/snapshots/{snap_id}", "timestamp": time.time()}

    # --- EVENTS ---
    @app.get("/api/events")
    async def list_events(
        event_type: str = Query(None),
        camera_id: str = Query(None),
        query: str = Query(None),
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=500),
    ):
        cursor = db_conn.cursor()
        sql = "SELECT * FROM event_logs WHERE 1=1"
        params: List[Any] = []

        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        if camera_id:
            sql += " AND camera_id = ?"
            params.append(camera_id)
        if query:
            sql += " AND (description LIKE ? OR camera_name LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        offset = (page - 1) * page_size
        params.extend([page_size, offset])

        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    @app.post("/api/events")
    async def create_event(event_data: Dict[str, Any]):
        event_id = f"evt_{int(time.time()*1000)}"
        camera_id = event_data.get("camera_id", "unknown")
        camera_name = event_data.get("camera_name", "Unknown Cam")
        raw_type = event_data.get("event_type", "Movement")

        # Canonical 3-Class Normalization (Feature 21)
        canonical = "Movement"
        if "human" in raw_type.lower() or "person" in raw_type.lower():
            canonical = "Human"
        elif "sound" in raw_type.lower() or "audio" in raw_type.lower() or "cry" in raw_type.lower():
            canonical = "Abnormal Sound"

        now = time.time()
        cursor = db_conn.cursor()
        cursor.execute("SELECT 1 FROM cameras WHERE id = ?", (camera_id,))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO cameras (id, name, platform, stream_url, is_online, created_at, updated_at) VALUES (?, ?, 'generic_rtsp', 'rtsp://mock', 1, ?, ?)",
                (camera_id, camera_name, now, now),
            )
        cursor.execute(
            """INSERT INTO event_logs (id, camera_id, camera_name, event_type, description, snapshot_url, clip_url, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                camera_id,
                camera_name,
                canonical,
                event_data.get("description", ""),
                event_data.get("snapshot_url", ""),
                event_data.get("clip_url", ""),
                now,
            ),
        )
        db_conn.commit()
        return {"id": event_id, "event_type": canonical, "timestamp": now}

    @app.get("/api/events/export")
    async def export_events(mode: str = Query("all"), format: str = Query("csv")):
        cursor = db_conn.cursor()
        if mode == "template":
            # Header only
            csv_data = "Date Time,Camera Name,Event Type,Description,Snapshot Link\n"
        elif mode == "filtered":
            cursor.execute("SELECT timestamp, camera_name, event_type, description, snapshot_url FROM event_logs LIMIT 10")
            rows = cursor.fetchall()
            lines = ["Date Time,Camera Name,Event Type,Description,Snapshot Link"]
            for r in rows:
                dt = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["timestamp"]))
                lines.append(f"{dt},{r['camera_name']},{r['event_type']},{r['description']},{r['snapshot_url']}")
            csv_data = "\n".join(lines)
        else:  # all
            cursor.execute("SELECT timestamp, camera_name, event_type, description, snapshot_url FROM event_logs")
            rows = cursor.fetchall()
            lines = ["Date Time,Camera Name,Event Type,Description,Snapshot Link"]
            for r in rows:
                dt = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(r["timestamp"]))
                lines.append(f"{dt},{r['camera_name']},{r['event_type']},{r['description']},{r['snapshot_url']}")
            csv_data = "\n".join(lines)

        return Response(content=csv_data, media_type="text/csv")

    # --- CLOUD ACCOUNTS ---
    @app.post("/api/accounts/ezviz/login")
    async def ezviz_login(data: Dict[str, Any]):
        app_key = data.get("app_key", "")
        app_secret = data.get("app_secret", "")
        res = eco.ezviz.get_token(app_key, app_secret)
        if res["code"] != "200":
            raise HTTPException(status_code=400, detail=res["msg"])
        return res

    @app.post("/api/accounts/xiaomi/login")
    async def xiaomi_login(data: Dict[str, Any]):
        user = data.get("username", "")
        password = data.get("password", "")
        otp = data.get("otp")
        pwd_md5 = hashlib.md5(password.encode()).hexdigest()

        step1 = eco.xiaomi.passport_step1_service_login()
        step2 = eco.xiaomi.passport_step2_auth(user, pwd_md5, step1["_sign"], step1["qs"], step1["callback"], otp_code=otp)
        if step2["code"] != 0:
            raise HTTPException(status_code=400, detail=step2["description"])
        return step2

    # --- ONVIF DISCOVERY ---
    @app.post("/api/onvif/discover")
    async def discover_onvif():
        # Returns simulated discovered devices on subnet
        return [
            {
                "ip": eco.onvif.ip,
                "port": eco.onvif.port,
                "xaddrs": eco.onvif.xaddrs,
                "device_uuid": eco.onvif.device_uuid,
            }
        ]

    return app


@pytest.fixture
def test_app_client(test_db_conn: sqlite3.Connection, mock_ecosystem_fixture: MockSurveillanceEcosystem, temp_storage_env: Dict[str, str]) -> TestClient:
    """Provides synchronous TestClient fixture wired to test DB and mocks."""
    app = create_test_nvr_app(test_db_conn, mock_ecosystem_fixture, temp_storage_env)
    return TestClient(app)


if pytest_asyncio is not None:
    @pytest_asyncio.fixture
    async def async_test_client(
        test_db_conn: sqlite3.Connection, mock_ecosystem_fixture: MockSurveillanceEcosystem, temp_storage_env: Dict[str, str]
    ) -> AsyncGenerator[AsyncClient, None]:
        """Provides asynchronous httpx client fixture for testing."""
        app = create_test_nvr_app(test_db_conn, mock_ecosystem_fixture, temp_storage_env)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client

