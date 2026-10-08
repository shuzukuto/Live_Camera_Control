"""
Adversarial Stress Test Suite: Milestone 1 Validation
Agent: challenger_m1_2

Probes:
1. Secret leakage boundaries on CameraResponse & AccountResponse (model_dump, model_dump_json, dict, str, repr).
2. Database constraint fault injection (Foreign keys, cascades, unique constraints, CHECK constraints, save_camera faults).
3. Rate limit boundary stress testing on /api/health (exact boundary, 429 payload/headers, concurrent burst, IP isolation).
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, Any
import aiosqlite
import pytest
from httpx import AsyncClient, ASGITransport

from app.models.camera import CameraResponse, CameraInDB, CameraBase
from app.models.account import AccountResponse, AccountInDB, AccountBase
from app.vault import mask_secret
from app.database import (
    init_db,
    get_db,
    set_database_path,
    save_camera,
    get_camera_by_id,
    SCHEMA_DDL,
)
from app.main import create_app, limiter
from app.config import settings


# ==============================================================================
# Domain 1: Secret Leakage Probe
# ==============================================================================

class TestSecretLeakageBoundaries:
    """Adversarial probe targeting accidental secret exposure during serialization."""

    def test_camera_response_rejects_and_never_leaks_plaintext_passwords(self):
        """Probe CameraResponse against direct injection of sensitive credential fields."""
        sensitive_payload = {
            "id": "cam_adv_01",
            "name": "Perimeter Cam",
            "brand": "ezviz",
            "model": "C6N",
            "ip_address": "192.168.1.150",
            "port": 554,
            "mac_address": "00:11:22:33:44:55",
            "device_serial": "EZ123456789",
            "channel_no": 1,
            "has_ptz": True,
            "enabled": True,
            "recording_enabled": False,
            "account_id": "acc_01",
            "stream_id": "stream_perim_01",
            "stream_type": "ezviz_cloud",
            "is_online": True,
            "has_credentials": True,
            "masked_username": "adm...tor",
            "created_at": "2026-10-08T00:00:00Z",
            "updated_at": "2026-10-08T00:00:00Z",
            # Adversarial injections
            "password": "SUPER_SECRET_PLAINTEXT_PASSWORD",
            "encrypted_password": "vault:v1:aes256:fake_cipher_pwd",
            "verification_code": "SEC999",
            "encrypted_verification_code": "vault:v1:aes256:fake_cipher_code",
            "live_url": "rtsp://admin:SUPER_SECRET_PLAINTEXT_PASSWORD@192.168.1.150:554/live",
            "rtsp_path": "/h264/ch1/main/av_stream",
            "onvif_xaddr": "http://192.168.1.150/onvif/device_service",
            "onvif_profile_token": "PROFILE_TOKEN_TOKEN",
        }

        # 1. Validation & construction
        resp = CameraResponse.model_validate(sensitive_payload)

        # 2. model_dump() inspection
        dumped_dict = resp.model_dump()
        dumped_str = json.dumps(dumped_dict)

        # 3. model_dump_json() inspection
        json_str = resp.model_dump_json()

        # 4. dict() cast inspection
        raw_dict = dict(resp)

        # 5. String representations inspection
        str_repr = str(resp)
        repr_str = repr(resp)

        forbidden_strings = [
            "SUPER_SECRET_PLAINTEXT_PASSWORD",
            "vault:v1:aes256:fake_cipher_pwd",
            "SEC999",
            "vault:v1:aes256:fake_cipher_code",
            "rtsp://admin",
            "onvif/device_service",
            "PROFILE_TOKEN_TOKEN",
        ]

        for secret in forbidden_strings:
            assert secret not in dumped_str, f"Secret '{secret}' found in model_dump() output!"
            assert secret not in json_str, f"Secret '{secret}' found in model_dump_json() output!"
            assert secret not in str(raw_dict), f"Secret '{secret}' found in dict(resp) output!"
            assert secret not in str_repr, f"Secret '{secret}' found in str(resp)!"
            assert secret not in repr_str, f"Secret '{secret}' found in repr(resp)!"
            assert secret not in str(resp.__dict__), f"Secret '{secret}' found in resp.__dict__!"

        # Ensure non-declared attributes cannot be accessed
        assert not hasattr(resp, "password") or getattr(resp, "password") is None
        assert not hasattr(resp, "verification_code") or getattr(resp, "verification_code") is None
        assert not hasattr(resp, "live_url") or getattr(resp, "live_url") is None

    def test_camera_response_from_db_model_never_leaks_ciphertext_or_urls(self):
        """Verify CameraInDB -> CameraResponse mapping purges encrypted blobs and RTSP URLs."""
        db_model = CameraInDB(
            id="cam_db_01",
            account_id="acc_db_01",
            name="Warehouse Cam",
            brand="generic",
            model="IPC-HFW",
            ip_address="10.0.0.50",
            port=554,
            mac_address="AA:BB:CC:DD:EE:01",
            device_serial="SN-WAREHOUSE-01",
            channel_no=1,
            encrypted_verification_code="vault:enc:verification_code",
            encrypted_username="vault:enc:admin",
            encrypted_password="vault:enc:warehouse_pass_1234",
            rtsp_path="/cam/realmonitor?channel=1&subtype=0",
            onvif_xaddr="http://10.0.0.50:80/onvif/device_service",
            onvif_profile_token="MediaProfile_Channel1",
            stream_id="stream_warehouse_01",
            stream_type="generic_rtsp",
            live_url="rtsp://admin:warehouse_pass_1234@10.0.0.50:554/cam/realmonitor",
            url_expires_at=None,
            has_ptz=False,
            is_online=True,
            created_at="2026-10-08T00:00:00Z",
            updated_at="2026-10-08T00:00:00Z",
        )

        resp = CameraResponse.model_validate(db_model)
        dumped = resp.model_dump()
        json_output = resp.model_dump_json()

        db_secrets = [
            "warehouse_pass_1234",
            "vault:enc:warehouse_pass_1234",
            "vault:enc:verification_code",
            "vault:enc:admin",
            "rtsp://admin",
            "MediaProfile_Channel1",
        ]

        for s in db_secrets:
            assert s not in json_output, f"Internal DB secret '{s}' leaked in CameraResponse JSON!"
            assert s not in str(dumped), f"Internal DB secret '{s}' leaked in CameraResponse dict!"

    def test_account_response_rejects_and_never_leaks_raw_or_encrypted_secrets(self):
        """Probe AccountResponse against raw secret and encrypted token leaks."""
        account_in_db = AccountInDB(
            id="acc_db_99",
            provider="xiaomi",
            account_name="Mi Home China Hub",
            region="cn",
            username="xiaomi_user_99",
            encrypted_secret="vault:v1:aes_secret_key_mihome_99",
            encrypted_tokens="vault:v1:aes_tokens_bundle_service_token",
            token_expire_time=1799999999,
            area_domain="cn.api.io.mi.com",
            status="active",
            last_sync_at="2026-10-08T00:00:00Z",
            created_at="2026-10-08T00:00:00Z",
            updated_at="2026-10-08T00:00:00Z",
        )

        # Build response with masked secret
        raw_secret_value = "my_super_secret_mihome_pass_2026"
        account_data = account_in_db.model_dump()
        account_data["masked_secret"] = mask_secret(raw_secret_value)
        account_data["secret"] = raw_secret_value  # Malicious attempt to inject raw secret

        resp = AccountResponse.model_validate(account_data)
        dumped = resp.model_dump()
        json_output = resp.model_dump_json()

        account_secrets = [
            raw_secret_value,
            "vault:v1:aes_secret_key_mihome_99",
            "vault:v1:aes_tokens_bundle_service_token",
            "1799999999",
        ]

        for s in account_secrets:
            assert s not in json_output, f"Account secret '{s}' leaked in AccountResponse JSON!"
            assert s not in str(dumped), f"Account secret '{s}' leaked in AccountResponse dict!"
            assert s not in str(resp.__dict__), f"Account secret '{s}' leaked in resp.__dict__!"

        assert resp.masked_secret == "my_...026"
        assert not hasattr(resp, "secret") or getattr(resp, "secret") is None
        assert not hasattr(resp, "encrypted_secret") or getattr(resp, "encrypted_secret") is None

    def test_secret_masking_boundary_stress(self):
        """Stress-test mask_secret edge cases to ensure consistent redaction."""
        # 1. Null / Empty
        assert mask_secret(None) == ""
        assert mask_secret("") == ""

        # 2. Short secrets (<= 6 chars) should be 100% asterisks
        assert mask_secret("1") == "*"
        assert mask_secret("ab") == "**"
        assert mask_secret("123456") == "******"

        # 3. 7 characters: prefix 3 and suffix 3
        m7 = mask_secret("1234567")
        assert m7 == "123...567"
        assert len(m7) == 9

        # 4. Long secrets
        long_secret = "a" * 1000
        m_long = mask_secret(long_secret)
        assert m_long == "aaa...aaa"
        assert len(m_long) == 9

        # 5. Unicode / Emojis ('🔑secret🔒' has length 8)
        assert mask_secret("🔑secret🔒") == "🔑se...et🔒"


# ==============================================================================
# Domain 2: Database Constraint Fault Injection
# ==============================================================================

class TestDatabaseConstraintIntegrityAndFaultInjection:
    """Adversarial stress-testing of relational integrity and SQLite constraints."""

    @pytest.fixture(autouse=True)
    async def setup_test_database(self, tmp_path: Path):
        """Provision a clean isolated SQLite database per test."""
        db_file = tmp_path / "adversarial_test.db"
        set_database_path(db_file)
        await init_db(db_file)
        yield
        if db_file.exists():
            try:
                db_file.unlink()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_fk_camera_invalid_account_raises_integrity_error(self):
        """Injecting camera referencing nonexistent account must fail immediately."""
        async with get_db() as db:
            with pytest.raises(aiosqlite.IntegrityError, match="FOREIGN KEY constraint failed"):
                await db.execute(
                    """
                    INSERT INTO cameras (id, account_id, name, brand, stream_id, stream_type)
                    VALUES ('cam_bad_fk', 'nonexistent_account_id', 'Bad FK Cam', 'generic', 'str_bad_fk', 'generic_rtsp');
                    """
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_fk_event_log_invalid_camera_raises_integrity_error(self):
        """Injecting event log referencing nonexistent camera must fail immediately."""
        async with get_db() as db:
            with pytest.raises(aiosqlite.IntegrityError, match="FOREIGN KEY constraint failed"):
                await db.execute(
                    """
                    INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp)
                    VALUES ('evt_bad_fk', 'nonexistent_cam_id', 'Bad Cam', 'Human', '2026-10-08T00:00:00Z');
                    """
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_fk_recording_invalid_camera_raises_integrity_error(self):
        """Injecting recording referencing nonexistent camera must fail immediately."""
        async with get_db() as db:
            with pytest.raises(aiosqlite.IntegrityError, match="FOREIGN KEY constraint failed"):
                await db.execute(
                    """
                    INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status)
                    VALUES ('rec_bad_fk', 'nonexistent_cam_id', 'Bad Cam', 'manual', '/path/a.mp4', 'a.mp4', '2026-10-08T00:00:00Z', 'completed');
                    """
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_fk_recording_invalid_event_raises_integrity_error(self):
        """Injecting recording referencing nonexistent event_id must fail immediately."""
        async with get_db() as db:
            # Create valid camera first
            await db.execute(
                """
                INSERT INTO cameras (id, name, brand, stream_id, stream_type)
                VALUES ('cam_valid', 'Valid Cam', 'generic', 'str_valid', 'generic_rtsp');
                """
            )
            await db.commit()

            with pytest.raises(aiosqlite.IntegrityError, match="FOREIGN KEY constraint failed"):
                await db.execute(
                    """
                    INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status, event_id)
                    VALUES ('rec_bad_evt', 'cam_valid', 'Valid Cam', 'event', '/path/e.mp4', 'e.mp4', '2026-10-08T00:00:00Z', 'completed', 'nonexistent_event_id');
                    """
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_cascade_delete_account_sets_camera_account_null(self):
        """Deleting an account must nullify camera.account_id without deleting camera."""
        async with get_db() as db:
            await db.execute(
                """
                INSERT INTO accounts (id, provider, account_name, encrypted_secret)
                VALUES ('acc_parent', 'ezviz', 'Parent EZVIZ', 'enc_secret');
                """
            )
            await db.execute(
                """
                INSERT INTO cameras (id, account_id, name, brand, stream_id, stream_type)
                VALUES ('cam_child', 'acc_parent', 'Child Cam', 'ezviz', 'str_child', 'ezviz_cloud');
                """
            )
            await db.commit()

            # Delete the parent account
            await db.execute("DELETE FROM accounts WHERE id = 'acc_parent';")
            await db.commit()

            # Verify camera still exists and account_id is NULL
            async with db.execute("SELECT id, account_id FROM cameras WHERE id = 'cam_child';") as cursor:
                row = await cursor.fetchone()
                assert row is not None, "Camera was deleted when account was deleted!"
                assert row["account_id"] is None, "Camera account_id was not set to NULL!"

    @pytest.mark.asyncio
    async def test_cascade_delete_camera_deletes_events_and_recordings(self):
        """Deleting a camera must CASCADE delete its events and recordings."""
        async with get_db() as db:
            await db.execute(
                """
                INSERT INTO cameras (id, name, brand, stream_id, stream_type)
                VALUES ('cam_to_delete', 'Temp Cam', 'generic', 'str_temp', 'generic_rtsp');
                """
            )
            await db.execute(
                """
                INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp)
                VALUES ('evt_casc_1', 'cam_to_delete', 'Temp Cam', 'Human', '2026-10-08T00:00:00Z');
                """
            )
            await db.execute(
                """
                INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status)
                VALUES ('rec_casc_1', 'cam_to_delete', 'Temp Cam', 'manual', '/p/1.mp4', '1.mp4', '2026-10-08T00:00:00Z', 'completed');
                """
            )
            await db.commit()

            # Delete the camera
            await db.execute("DELETE FROM cameras WHERE id = 'cam_to_delete';")
            await db.commit()

            # Verify cascade deletion
            async with db.execute("SELECT COUNT(*) FROM event_logs WHERE camera_id = 'cam_to_delete';") as cursor:
                row = await cursor.fetchone()
                assert row[0] == 0, "event_logs were not CASCADE deleted!"

            async with db.execute("SELECT COUNT(*) FROM recordings WHERE camera_id = 'cam_to_delete';") as cursor:
                row = await cursor.fetchone()
                assert row[0] == 0, "recordings were not CASCADE deleted!"

    @pytest.mark.asyncio
    async def test_cascade_delete_event_sets_recording_event_id_null(self):
        """Deleting an event must nullify recording.event_id without deleting recording."""
        async with get_db() as db:
            await db.execute(
                """
                INSERT INTO cameras (id, name, brand, stream_id, stream_type)
                VALUES ('cam_evt_test', 'Evt Cam', 'generic', 'str_evt_test', 'generic_rtsp');
                """
            )
            await db.execute(
                """
                INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp)
                VALUES ('evt_to_del', 'cam_evt_test', 'Evt Cam', 'Movement', '2026-10-08T00:00:00Z');
                """
            )
            await db.execute(
                """
                INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status, event_id)
                VALUES ('rec_linked', 'cam_evt_test', 'Evt Cam', 'event', '/p/e.mp4', 'e.mp4', '2026-10-08T00:00:00Z', 'completed', 'evt_to_del');
                """
            )
            await db.commit()

            # Delete the event
            await db.execute("DELETE FROM event_logs WHERE event_id = 'evt_to_del';")
            await db.commit()

            # Verify recording still exists with event_id = NULL
            async with db.execute("SELECT id, event_id FROM recordings WHERE id = 'rec_linked';") as cursor:
                row = await cursor.fetchone()
                assert row is not None, "Recording was prematurely deleted!"
                assert row["event_id"] is None, "Recording event_id was not set to NULL!"

    @pytest.mark.asyncio
    async def test_unique_constraint_camera_stream_id(self):
        """Injecting duplicate stream_id on different cameras must fail."""
        async with get_db() as db:
            await db.execute(
                """
                INSERT INTO cameras (id, name, brand, stream_id, stream_type)
                VALUES ('cam_1', 'Cam 1', 'generic', 'stream_duplicate', 'generic_rtsp');
                """
            )
            await db.commit()

            with pytest.raises(aiosqlite.IntegrityError, match="UNIQUE constraint failed: cameras.stream_id"):
                await db.execute(
                    """
                    INSERT INTO cameras (id, name, brand, stream_id, stream_type)
                    VALUES ('cam_2', 'Cam 2', 'generic', 'stream_duplicate', 'generic_rtsp');
                    """
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_unique_constraint_event_id(self):
        """Injecting duplicate event_id must fail."""
        async with get_db() as db:
            await db.execute(
                """
                INSERT INTO cameras (id, name, brand, stream_id, stream_type)
                VALUES ('cam_1', 'Cam 1', 'generic', 'str_uniq_evt', 'generic_rtsp');
                """
            )
            await db.execute(
                """
                INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp)
                VALUES ('evt_uniq_01', 'cam_1', 'Cam 1', 'Human', '2026-10-08T00:00:00Z');
                """
            )
            await db.commit()

            with pytest.raises(aiosqlite.IntegrityError, match="UNIQUE constraint failed: event_logs.event_id"):
                await db.execute(
                    """
                    INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp)
                    VALUES ('evt_uniq_01', 'cam_1', 'Cam 1', 'Movement', '2026-10-08T00:00:01Z');
                    """
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_check_constraints_strict_enforcement(self):
        """Verify CHECK constraints block invalid enums across all tables."""
        async with get_db() as db:
            # 1. Accounts provider invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO accounts (id, provider, account_name, encrypted_secret) VALUES ('a', 'dahua', 'Dahua', 's');"
                )
                await db.commit()

            # 2. Accounts status invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO accounts (id, provider, account_name, encrypted_secret, status) VALUES ('a', 'ezviz', 'E', 's', 'suspended');"
                )
                await db.commit()

            # 3. Cameras brand invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO cameras (id, name, brand, stream_id, stream_type) VALUES ('c', 'C', 'hikvision', 's', 'generic_rtsp');"
                )
                await db.commit()

            # 4. Cameras stream_type invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO cameras (id, name, brand, stream_id, stream_type) VALUES ('c', 'C', 'generic', 's', 'rtmp');"
                )
                await db.commit()

            # Setup valid camera for event and recording tests
            await db.execute(
                "INSERT INTO cameras (id, name, brand, stream_id, stream_type) VALUES ('c_ok', 'C', 'generic', 's_ok', 'generic_rtsp');"
            )
            await db.commit()

            # 5. Event Logs event_type invalid enum (e.g. 'Vehicle' or lowercase 'human')
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp) VALUES ('e1', 'c_ok', 'C', 'Vehicle', 'now');"
                )
                await db.commit()

            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO event_logs (event_id, camera_id, camera_name, event_type, timestamp) VALUES ('e2', 'c_ok', 'C', 'human', 'now');"
                )
                await db.commit()

            # 6. Recordings record_type invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status) VALUES ('r1', 'c_ok', 'C', 'continuous', '/p', 'f', 'now', 'completed');"
                )
                await db.commit()

            # 7. Recordings status invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status) VALUES ('r2', 'c_ok', 'C', 'manual', '/p', 'f', 'now', 'deleted');"
                )
                await db.commit()

            # 8. Recordings storage_location invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO recordings (id, camera_id, camera_name, record_type, file_path, file_name, start_time, status, storage_location) VALUES ('r3', 'c_ok', 'C', 'manual', '/p', 'f', 'now', 'completed', 's3');"
                )
                await db.commit()

            # 9. System settings category invalid enum
            with pytest.raises(aiosqlite.IntegrityError, match="CHECK constraint failed"):
                await db.execute(
                    "INSERT INTO system_settings (key, value, category) VALUES ('bad_cat', 'val', 'telemetry');"
                )
                await db.commit()

    @pytest.mark.asyncio
    async def test_save_camera_fault_injection(self):
        """Verify save_camera handles stream_id collision and FK failures gracefully."""
        # 1. First save camera successfully
        cam1 = await save_camera({
            "id": "cam_saved_1",
            "stream_id": "stream_unique_001",
            "name": "Camera 1",
            "brand": "generic",
        })
        assert cam1["id"] == "cam_saved_1"

        # 2. Attempt to save different camera with same stream_id -> raises IntegrityError
        with pytest.raises(aiosqlite.IntegrityError, match="UNIQUE constraint failed: cameras.stream_id"):
            await save_camera({
                "id": "cam_saved_2",
                "stream_id": "stream_unique_001",
                "name": "Camera 2",
                "brand": "generic",
            })

        # 3. Attempt to save camera referencing nonexistent account_id -> raises IntegrityError
        with pytest.raises(aiosqlite.IntegrityError, match="FOREIGN KEY constraint failed"):
            await save_camera({
                "id": "cam_saved_3",
                "account_id": "nonexistent_acc_123",
                "stream_id": "stream_unique_002",
                "name": "Camera 3",
                "brand": "generic",
            })


# ==============================================================================
# Domain 3: Rate Limiting Boundary Stress Testing
# ==============================================================================

class TestRateLimitBoundariesAndConcurrency:
    """Adversarial stress-testing of SlowAPI rate limiting against /api/health."""

    @pytest.fixture(autouse=True)
    def reset_rate_limiter(self):
        """Ensure clean limiter state for every test."""
        limiter.reset()
        yield
        limiter.reset()

    @pytest.mark.asyncio
    async def test_rate_limit_exact_boundary_enforcement(self):
        """Verify exact boundary at 100 req/min: 100 requests pass (200), 101st fails (429)."""
        app = create_app()
        transport = ASGITransport(app=app, client=("192.168.1.50", 12345))
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            statuses = []
            for i in range(105):
                resp = await client.get("/api/health")
                statuses.append(resp.status_code)

            # Verification of boundary
            first_100 = statuses[:100]
            remaining_5 = statuses[100:]

            assert all(code == 200 for code in first_100), f"Expected first 100 requests to be 200 OK, got: {first_100.count(200)}"
            assert all(code == 429 for code in remaining_5), f"Expected remaining 5 requests to be 429 Too Many Requests, got: {remaining_5}"

    @pytest.mark.asyncio
    async def test_rate_limit_response_payload_and_headers(self):
        """Verify 429 responses return proper JSON error message, Content-Type, and CSP headers."""
        app = create_app()
        transport = ASGITransport(app=app, client=("192.168.1.60", 12345))
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Exhaust the 100 requests quota
            for _ in range(100):
                await client.get("/api/health")

            # 101st request
            r429 = await client.get("/api/health")
            assert r429.status_code == 429
            assert "application/json" in r429.headers.get("content-type", "")

            # Verify response body
            body = r429.json()
            assert "error" in body
            assert "Rate limit exceeded: 100 per 1 minute" in body["error"]

            # Verify security headers are not dropped on 429
            assert "Content-Security-Policy" in r429.headers
            assert r429.headers["X-Frame-Options"] == "DENY"
            assert r429.headers["X-Content-Type-Options"] == "nosniff"

    @pytest.mark.asyncio
    async def test_rate_limit_concurrent_burst_stress(self):
        """Simulate high-concurrency burst attack (120 parallel async requests)."""
        app = create_app()
        transport = ASGITransport(app=app, client=("192.168.1.70", 12345))
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Fire 120 requests simultaneously
            tasks = [client.get("/api/health") for _ in range(120)]
            responses = await asyncio.gather(*tasks)

            status_codes = [r.status_code for r in responses]
            count_200 = status_codes.count(200)
            count_429 = status_codes.count(429)

            assert count_200 == 100, f"Expected exactly 100 requests to succeed under concurrent burst, got {count_200}"
            assert count_429 == 20, f"Expected exactly 20 requests to be throttled under concurrent burst, got {count_429}"

    @pytest.mark.asyncio
    async def test_rate_limit_per_client_ip_isolation(self):
        """Verify client IP isolation: exhausting quota for IP A does NOT throttle IP B."""
        app = create_app()

        trans_a = ASGITransport(app=app, client=("10.10.10.1", 5000))
        trans_b = ASGITransport(app=app, client=("10.10.10.2", 5000))

        async with AsyncClient(transport=trans_a, base_url="http://test") as client_a, \
                   AsyncClient(transport=trans_b, base_url="http://test") as client_b:
            # Client A exhausts quota
            for _ in range(100):
                resp = await client_a.get("/api/health")
                assert resp.status_code == 200

            # 101st request from Client A is throttled
            resp_a_101 = await client_a.get("/api/health")
            assert resp_a_101.status_code == 429

            # Client B is completely unaffected and succeeds
            resp_b_1 = await client_b.get("/api/health")
            assert resp_b_1.status_code == 200
