"""
Database Engine & Connection Management for Web-based NVR/VMS.
SQLite with aiosqlite in WAL mode.
"""

import os
import json
import time
import uuid
import logging
from pathlib import Path
from typing import AsyncIterator, Optional, List, Dict, Any, Tuple, Union
from contextlib import asynccontextmanager
import aiosqlite

logger = logging.getLogger("nvr.database")

# Default database location relative to project root
DEFAULT_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "surveillance.db"

# SQL DDL Script
SCHEMA_DDL = """
-- 1. Accounts
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL CHECK(provider IN ('ezviz', 'xiaomi')),
    account_name TEXT NOT NULL,
    region TEXT NOT NULL DEFAULT 'cn',
    username TEXT,
    encrypted_secret TEXT NOT NULL,
    encrypted_tokens TEXT,
    token_expire_time INTEGER,
    area_domain TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'expired', 'error', 'challenge_required')),
    last_sync_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

-- 2. Cameras
CREATE TABLE IF NOT EXISTS cameras (
    id TEXT PRIMARY KEY,
    account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    brand TEXT NOT NULL CHECK(brand IN ('ezviz', 'xiaomi', 'generic')),
    model TEXT,
    ip_address TEXT,
    port INTEGER DEFAULT 554,
    mac_address TEXT,
    device_serial TEXT,
    channel_no INTEGER DEFAULT 1,
    encrypted_verification_code TEXT,
    encrypted_username TEXT,
    encrypted_password TEXT,
    rtsp_path TEXT,
    onvif_xaddr TEXT,
    onvif_profile_token TEXT,
    stream_id TEXT UNIQUE NOT NULL,
    stream_type TEXT NOT NULL CHECK(stream_type IN ('rtsp_local', 'ezviz_cloud', 'xiaomi_p2p', 'onvif', 'generic_rtsp')),
    live_url TEXT,
    substream_url TEXT,
    url_expires_at INTEGER,
    has_ptz INTEGER NOT NULL DEFAULT 0,
    is_online INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    recording_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_cameras_stream_id ON cameras(stream_id);
CREATE INDEX IF NOT EXISTS idx_cameras_account_id ON cameras(account_id);
CREATE INDEX IF NOT EXISTS idx_cameras_brand ON cameras(brand);
CREATE INDEX IF NOT EXISTS idx_cameras_is_online ON cameras(is_online);

-- 3. AI Event Logs
CREATE TABLE IF NOT EXISTS event_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
    camera_name TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN ('Human', 'Movement', 'Abnormal Sound')),
    timestamp TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    snapshot_path TEXT,
    clip_path TEXT,
    metadata TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    vendor_raw_type TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    description TEXT DEFAULT '',
    snapshot_url TEXT DEFAULT '',
    clip_url TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_camera_timestamp ON event_logs(camera_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON event_logs(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_timestamp ON event_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_camera_ts ON event_logs(camera_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_type_ts ON event_logs(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_event_logs_compound ON event_logs(timestamp DESC, event_type, camera_id);
CREATE INDEX IF NOT EXISTS idx_event_logs_unread ON event_logs(is_read) WHERE is_read = 0;

-- 4. Recordings
CREATE TABLE IF NOT EXISTS recordings (
    id TEXT PRIMARY KEY,
    camera_id TEXT NOT NULL REFERENCES cameras(id) ON DELETE CASCADE,
    camera_name TEXT NOT NULL DEFAULT 'Camera',
    record_type TEXT NOT NULL DEFAULT 'manual' CHECK(record_type IN ('manual', 'scheduled', 'event', 'snapshot')),
    trigger_type TEXT DEFAULT 'manual',
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    duration REAL DEFAULT 0.0,
    duration_sec REAL DEFAULT 0.0,
    start_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    end_time TEXT,
    status TEXT NOT NULL DEFAULT 'completed' CHECK(status IN ('recording', 'completed', 'failed', 'purged')),
    thumbnail_path TEXT,
    event_id TEXT REFERENCES event_logs(event_id) ON DELETE SET NULL,
    is_locked INTEGER NOT NULL DEFAULT 0,
    is_protected INTEGER NOT NULL DEFAULT 0,
    storage_location TEXT NOT NULL DEFAULT 'local' CHECK(storage_location IN ('local', 'nas')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_recordings_camera_start ON recordings(camera_id, start_time DESC);
CREATE INDEX IF NOT EXISTS idx_recordings_start_time ON recordings(start_time DESC);
CREATE INDEX IF NOT EXISTS idx_recordings_type ON recordings(record_type);
CREATE INDEX IF NOT EXISTS idx_recordings_status ON recordings(status);
CREATE INDEX IF NOT EXISTS idx_recordings_fifo ON recordings(is_locked, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_recordings_protected ON recordings(is_protected, created_at ASC);

-- 5. System Settings
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'general' CHECK(category IN ('general', 'storage', 'streaming', 'security', 'notification')),
    description TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_system_settings_category ON system_settings(category);
"""

# Default system settings seeded on database initialization
DEFAULT_SETTINGS = [
    ("storage.recordings_path", "recordings", "storage", "Directory path for recorded MP4 files"),
    ("storage.snapshots_path", "snapshots", "storage", "Directory path for snapshot images"),
    ("storage.nas_path", "", "storage", "Optional network UNC path or mount point"),
    ("storage.max_storage_gb", "500", "storage", "Maximum disk quota in GB before FIFO purge"),
    ("storage.min_free_space_gb", "20", "storage", "Minimum required free disk space in GB"),
    ("storage.retention_days", "30", "storage", "Retention lifespan for non-locked recordings"),
    ("storage.auto_purge_enabled", "true", "storage", "Enable automated FIFO disk quota pruner"),
    ("streaming.go2rtc_api_url", "http://127.0.0.1:1984", "streaming", "go2rtc media gateway REST API endpoint"),
    ("streaming.default_protocol", "webrtc", "streaming", "Primary live player protocol (webrtc or mse)"),
    ("streaming.streamkeeper_renew_lead_sec", "30", "streaming", "Lease refresh lead time before cloud expiration"),
    ("general.app_name", "Web-based Surveillance NVR/VMS", "general", "Application title"),
    ("general.grid_layout", "2x2", "general", "Default surveillance dashboard grid layout"),
    ("general.theme", "dark-glassmorphism", "general", "UI color scheme theme"),
]

_db_path: Path = DEFAULT_DB_PATH


def set_database_path(path: Path | str) -> None:
    """Override database location (useful for testing)."""
    global _db_path
    _db_path = Path(path)


def get_database_path() -> Path:
    """Returns current active database file path."""
    return _db_path


async def configure_connection(conn: aiosqlite.Connection) -> None:
    """Applies mandatory high-performance PRAGMAs to an active connection."""
    # PRAGMA journal_mode=WAL is not applicable to :memory:
    db_p = str(get_database_path())
    if ":memory:" not in db_p:
        await conn.execute("PRAGMA journal_mode = WAL;")
    await conn.execute("PRAGMA synchronous = NORMAL;")
    await conn.execute("PRAGMA foreign_keys = ON;")
    await conn.execute("PRAGMA busy_timeout = 5000;")
    await conn.execute("PRAGMA temp_store = MEMORY;")
    await conn.execute("PRAGMA cache_size = -64000;")
    if ":memory:" not in db_p:
        await conn.execute("PRAGMA mmap_size = 268435456;")
    conn.row_factory = aiosqlite.Row


@asynccontextmanager
async def get_db() -> AsyncIterator[aiosqlite.Connection]:
    """
    FastAPI dependency / async context manager for database connections.
    Usage:
        async with get_db() as db:
            async with db.execute(...) as cursor:
                ...
    """
    db_path = get_database_path()
    if ":memory:" not in str(db_path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(db_path) as conn:
        await configure_connection(conn)
        yield conn


async def init_db(custom_path: Optional[Path | str] = None) -> None:
    """
    Initializes SQLite database idempotently:
    Creates directories, applies PRAGMAs, executes table DDL, and seeds default settings.
    """
    if custom_path:
        set_database_path(custom_path)

    db_path = get_database_path()
    if ":memory:" not in str(db_path):
        db_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("Initializing SQLite WAL database at %s", db_path)
    async with aiosqlite.connect(db_path) as conn:
        await configure_connection(conn)

        # Execute schema DDL
        await conn.executescript(SCHEMA_DDL)

        # Migration check: ensure substream_url exists in existing cameras table
        async with conn.execute("PRAGMA table_info(cameras);") as cursor:
            existing_cols = [row["name"] if isinstance(row, aiosqlite.Row) else row[1] for row in await cursor.fetchall()]
            if "substream_url" not in existing_cols:
                await conn.execute("ALTER TABLE cameras ADD COLUMN substream_url TEXT;")

        # Migration check: ensure alias columns exist in existing recordings table
        async with conn.execute("PRAGMA table_info(recordings);") as cursor:
            rec_cols = [row["name"] if isinstance(row, aiosqlite.Row) else row[1] for row in await cursor.fetchall()]
            if "trigger_type" not in rec_cols:
                await conn.execute("ALTER TABLE recordings ADD COLUMN trigger_type TEXT DEFAULT 'manual';")
            if "size_bytes" not in rec_cols:
                await conn.execute("ALTER TABLE recordings ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0;")
            if "duration_sec" not in rec_cols:
                await conn.execute("ALTER TABLE recordings ADD COLUMN duration_sec REAL DEFAULT 0.0;")
            if "is_protected" not in rec_cols:
                await conn.execute("ALTER TABLE recordings ADD COLUMN is_protected INTEGER NOT NULL DEFAULT 0;")

        # Migration check: ensure M4 columns and indexes exist in existing event_logs table
        async with conn.execute("PRAGMA table_info(event_logs);") as cursor:
            evt_cols = [row["name"] if isinstance(row, aiosqlite.Row) else row[1] for row in await cursor.fetchall()]
            if "vendor_raw_type" not in evt_cols:
                await conn.execute("ALTER TABLE event_logs ADD COLUMN vendor_raw_type TEXT;")
            if "severity" not in evt_cols:
                await conn.execute("ALTER TABLE event_logs ADD COLUMN severity TEXT NOT NULL DEFAULT 'medium';")
            if "description" not in evt_cols:
                await conn.execute("ALTER TABLE event_logs ADD COLUMN description TEXT DEFAULT '';")
            if "snapshot_url" not in evt_cols:
                await conn.execute("ALTER TABLE event_logs ADD COLUMN snapshot_url TEXT DEFAULT '';")
            if "clip_url" not in evt_cols:
                await conn.execute("ALTER TABLE event_logs ADD COLUMN clip_url TEXT DEFAULT '';")

        await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_camera_timestamp ON event_logs(camera_id, timestamp DESC);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type_timestamp ON event_logs(event_type, timestamp DESC);")

        # Seed default settings idempotently
        for key, value, category, desc in DEFAULT_SETTINGS:
            await conn.execute(
                """
                INSERT INTO system_settings (key, value, category, description)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO NOTHING;
                """,
                (key, value, category, desc),
            )

        await conn.commit()
    logger.info("SQLite WAL database initialization completed successfully.")


async def close_db() -> None:
    """Clean up resources on application shutdown."""
    logger.info("Database connection shutdown hook executed.")


async def check_db_health() -> str:
    """Checks database connectivity for /api/health."""
    try:
        async with get_db() as conn:
            async with conn.execute("SELECT 1;") as cursor:
                row = await cursor.fetchone()
                if row and row[0] == 1:
                    return "connected"
        return "unhealthy"
    except Exception as e:
        logger.warning("Database health check failed: %s", e)
        return f"error: {e}"


# ------------------------------------------------------------------------------
# High-Level Helper Functions (Interface Contracts with M2 / M3)
# ------------------------------------------------------------------------------

async def get_camera_by_id(camera_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve camera record by its primary key ID."""
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM cameras WHERE id = ?;", (camera_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
    return None


async def get_camera_by_stream_id(stream_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve camera record by its unique stream_id."""
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM cameras WHERE stream_id = ?;", (stream_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
    return None


async def save_camera(camera_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Insert or update a camera record.
    Returns the saved record as a dict.
    """
    cam_id = camera_data.get("id") or f"cam_{uuid.uuid4().hex[:12]}"
    stream_id = camera_data.get("stream_id") or f"stream_{uuid.uuid4().hex[:8]}"

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO cameras (
                id, account_id, name, brand, model, ip_address, port, mac_address,
                device_serial, channel_no, encrypted_verification_code,
                encrypted_username, encrypted_password, rtsp_path, onvif_xaddr,
                onvif_profile_token, stream_id, stream_type, live_url, substream_url,
                url_expires_at, has_ptz, is_online, enabled, recording_enabled
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(id) DO UPDATE SET
                account_id = excluded.account_id,
                name = excluded.name,
                brand = excluded.brand,
                model = excluded.model,
                ip_address = excluded.ip_address,
                port = excluded.port,
                mac_address = excluded.mac_address,
                device_serial = excluded.device_serial,
                channel_no = excluded.channel_no,
                encrypted_verification_code = excluded.encrypted_verification_code,
                encrypted_username = excluded.encrypted_username,
                encrypted_password = excluded.encrypted_password,
                rtsp_path = excluded.rtsp_path,
                onvif_xaddr = excluded.onvif_xaddr,
                onvif_profile_token = excluded.onvif_profile_token,
                stream_type = excluded.stream_type,
                live_url = excluded.live_url,
                substream_url = excluded.substream_url,
                url_expires_at = excluded.url_expires_at,
                has_ptz = excluded.has_ptz,
                is_online = excluded.is_online,
                enabled = excluded.enabled,
                recording_enabled = excluded.recording_enabled,
                updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            """,
            (
                cam_id,
                camera_data.get("account_id"),
                camera_data.get("name", "Unnamed Camera"),
                camera_data.get("brand", "generic"),
                camera_data.get("model"),
                camera_data.get("ip_address"),
                camera_data.get("port", 554),
                camera_data.get("mac_address"),
                camera_data.get("device_serial"),
                camera_data.get("channel_no", 1),
                camera_data.get("encrypted_verification_code"),
                camera_data.get("encrypted_username"),
                camera_data.get("encrypted_password"),
                camera_data.get("rtsp_path"),
                camera_data.get("onvif_xaddr"),
                camera_data.get("onvif_profile_token"),
                stream_id,
                camera_data.get("stream_type", "rtsp_local"),
                camera_data.get("live_url"),
                camera_data.get("substream_url"),
                camera_data.get("url_expires_at"),
                1 if camera_data.get("has_ptz") else 0,
                1 if camera_data.get("is_online") else 0,
                1 if camera_data.get("enabled", True) else 0,
                1 if camera_data.get("recording_enabled", False) else 0,
            ),
        )
        await conn.commit()

    saved = await get_camera_by_id(cam_id)
    assert saved is not None
    return saved


async def save_event_log(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Persist event record into SQLite event_logs table.
    Ensures camera existence (inserts stub if missing), handles column dual-writes,
    and returns dict representation.
    """
    evt_id = event_data.get("event_id") or f"evt_{uuid.uuid4().hex[:12]}"
    cam_id = str(event_data.get("camera_id", "unknown"))
    cam_name = event_data.get("camera_name") or f"Camera {cam_id}"
    event_type = event_data.get("event_type", "Movement")
    timestamp = event_data.get("timestamp")
    if timestamp is None:
        timestamp = time.time()
    confidence = float(event_data.get("confidence", 1.0))
    desc = event_data.get("description", "") or ""
    snap = event_data.get("snapshot_url") or event_data.get("snapshot_path") or ""
    clip = event_data.get("clip_url") or event_data.get("clip_path") or ""
    severity = event_data.get("severity", "medium") or "medium"
    vendor_raw = event_data.get("vendor_raw_type") or ""

    metadata_val = event_data.get("metadata")
    if isinstance(metadata_val, dict):
        metadata_str = json.dumps(metadata_val)
    elif metadata_val is not None:
        metadata_str = str(metadata_val)
    else:
        metadata_str = "{}"

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    async with get_db() as conn:
        # Guarantee camera exists for foreign key constraint
        async with conn.execute("SELECT 1 FROM cameras WHERE id = ?;", (cam_id,)) as cur:
            if not await cur.fetchone():
                stream_id = f"stream_{cam_id}"
                await conn.execute(
                    """
                    INSERT OR IGNORE INTO cameras (id, name, brand, stream_id, stream_type, live_url, created_at, updated_at)
                    VALUES (?, ?, 'generic', ?, 'generic_rtsp', 'rtsp://localhost', ?, ?);
                    """,
                    (cam_id, cam_name, stream_id, now_iso, now_iso),
                )

        cursor = await conn.execute(
            """
            INSERT INTO event_logs (
                event_id, camera_id, camera_name, event_type, timestamp,
                confidence, snapshot_path, clip_path, metadata, is_read,
                vendor_raw_type, severity, description, snapshot_url, clip_url, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?);
            """,
            (
                evt_id, cam_id, cam_name, event_type, timestamp,
                confidence, snap, clip, metadata_str,
                vendor_raw, severity, desc, snap, clip, now_iso
            ),
        )
        row_id = cursor.lastrowid
        await conn.commit()

        async with conn.execute("SELECT * FROM event_logs WHERE id = ?;", (row_id,)) as cur:
            row = await cur.fetchone()
            d = dict(row)
            d["id"] = row_id
            d["event_id"] = evt_id
            d["snapshot_url"] = snap
            d["clip_url"] = clip
            d["snapshot_path"] = snap
            d["clip_path"] = clip
            d["is_read"] = bool(d.get("is_read", 0))
            return d


async def query_event_logs(
    query: Optional[str] = None,
    camera_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    start_time: Optional[Union[str, float, int]] = None,
    end_time: Optional[Union[str, float, int]] = None,
    is_read: Optional[bool] = None,
    page: int = 1,
    page_size: int = 50,
    fetch_all: bool = False,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Universal multi-column search, filter, and pagination query.
    Complies with DTCS2 Rule 6: query searches across all columns.
    """
    async with get_db() as conn:
        conditions: List[str] = ["1=1"]
        params: List[Any] = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(str(event_type))

        if camera_id:
            conditions.append("camera_id = ?")
            params.append(str(camera_id))

        if severity:
            conditions.append("severity = ?")
            params.append(str(severity))

        if start_time is not None:
            conditions.append("timestamp >= ?")
            params.append(start_time)

        if end_time is not None:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        if is_read is not None:
            conditions.append("is_read = ?")
            params.append(1 if is_read else 0)

        # Universal search across ALL columns
        if query is not None and query != "":
            kw = f"%{query}%"
            conditions.append(
                """(
                    camera_name LIKE ? OR
                    event_type LIKE ? OR
                    description LIKE ? OR
                    camera_id LIKE ? OR
                    event_id LIKE ? OR
                    severity LIKE ? OR
                    metadata LIKE ? OR
                    snapshot_url LIKE ? OR
                    clip_url LIKE ?
                )"""
            )
            params.extend([kw, kw, kw, kw, kw, kw, kw, kw, kw])

        where_clause = " AND ".join(conditions)

        # 1. Total count query
        count_sql = f"SELECT COUNT(*) FROM event_logs WHERE {where_clause};"
        async with conn.execute(count_sql, params) as cur:
            row = await cur.fetchone()
            total = row[0] if row else 0

        # 2. Data records query
        if fetch_all:
            data_sql = f"SELECT * FROM event_logs WHERE {where_clause} ORDER BY timestamp DESC, id DESC;"
            async with conn.execute(data_sql, params) as cur:
                rows = await cur.fetchall()
        else:
            offset = max(0, (page - 1) * page_size)
            data_sql = f"SELECT * FROM event_logs WHERE {where_clause} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?;"
            query_params = list(params) + [page_size, offset]
            async with conn.execute(data_sql, query_params) as cur:
                rows = await cur.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            snap = d.get("snapshot_url") or d.get("snapshot_path") or ""
            clip = d.get("clip_url") or d.get("clip_path") or ""
            d["snapshot_url"] = snap
            d["snapshot_path"] = snap
            d["clip_url"] = clip
            d["clip_path"] = clip
            d["is_read"] = bool(d.get("is_read", 0))
            results.append(d)

        return results, total
