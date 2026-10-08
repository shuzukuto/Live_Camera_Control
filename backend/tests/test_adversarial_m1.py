"""
backend/tests/test_adversarial_m1.py

Adversarial Stress Testing & Fuzzing Harness for Milestone 1.
Authored by challenger_m1_1 to empirically probe:
1. Cryptographic robustness and mutation fuzzing on Vault (AES-256-GCM AEAD)
2. High-concurrency contention, lock timeouts, and deadlocks on SQLite WAL
3. go2rtc async client failure modes (timeouts, network errors, malformed payloads)
"""

import asyncio
import base64
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from typing import List

import httpx
import pytest
import pytest_asyncio

from app.database import (
    init_db,
    get_db,
    set_database_path,
    save_camera,
    get_camera_by_id,
    check_db_health,
)
from app.services.go2rtc_service import (
    Go2rtcClient,
    Go2rtcError,
    Go2rtcHttpError,
    Go2rtcStreamNotFoundError,
)
from app.vault import (
    VaultManager,
    VaultDecryptionError,
    VaultConfigurationError,
    encrypt_secret,
    decrypt_secret,
    encrypt_json,
    decrypt_json,
    mask_secret,
    init_vault,
)


# ==============================================================================
# SECTION 1: VAULT CRYPTOGRAPHIC FUZZING & MUTATION HARNESS
# ==============================================================================

class TestVaultCryptographicFuzzing:
    """Adversarial cryptographic stress testing against VaultManager."""

    @pytest.fixture(autouse=True)
    def setup_vault(self, tmp_path):
        VaultManager.reset_instance()
        salt_file = tmp_path / "fuzz_salt"
        key_file = tmp_path / "fuzz_key"
        init_vault(
            passphrase="AdversarialPassphrase_!@#$%^&*()_+~`|}{[]:;?><,./1234567890",
            salt_path=salt_file,
            master_key_file=key_file,
            iterations=10_000,  # Fast iterations for fuzzing
        )
        yield
        VaultManager.reset_instance()

    def test_fuzz_exhaustive_single_bit_flips(self):
        """
        Flip every single bit across the entire ciphertext (nonce + payload + tag).
        Every single corrupted bit MUST be rejected with VaultDecryptionError.
        No silent corruption or false positives allowed.
        """
        plaintext = "CriticalCCTVCameraSecretCredentials_P@ssw0rd!2026"
        token = encrypt_secret(plaintext)
        raw_bytes = bytearray(base64.b64decode(token))

        # Test bit flips across every byte offset in the wire format
        for byte_idx in range(len(raw_bytes)):
            for bit_offset in range(8):
                mutated = bytearray(raw_bytes)
                mutated[byte_idx] ^= 1 << bit_offset
                mutated_token = base64.b64encode(mutated).decode("utf-8")

                with pytest.raises(VaultDecryptionError):
                    decrypt_secret(mutated_token)

    def test_fuzz_sub_28_byte_truncation_boundaries(self):
        """
        Exhaustively test payloads from 1 byte up to 27 bytes (all below minimum valid size 28).
        All sub-28 byte non-empty payloads must raise VaultDecryptionError without uncaught index errors.
        """
        for length in range(1, 28):
            truncated_bytes = os.urandom(length)
            token = base64.b64encode(truncated_bytes).decode("utf-8")
            with pytest.raises(VaultDecryptionError) as exc_info:
                decrypt_secret(token)
            assert "below minimum (28 bytes)" in str(exc_info.value)

    def test_empty_string_and_none_idempotence(self):
        """
        Verify empty string and None payloads return empty string safely without error.
        """
        assert encrypt_secret("") == ""
        assert encrypt_secret(None) == ""
        assert decrypt_secret("") == ""
        assert decrypt_secret(None) == ""

    def test_fuzz_tag_stripping_and_nonce_mutation(self):
        """
        Adversarial attempt to strip 16-byte authentication tag or duplicate nonce.
        """
        plaintext = "RTSP://admin:SuperSecret@192.168.1.100:554/live/ch0"
        token = encrypt_secret(plaintext)
        raw = bytearray(base64.b64decode(token))

        # 1. Stripped tag (remove last 16 bytes)
        stripped = raw[:-16]
        stripped_token = base64.b64encode(stripped).decode("utf-8")
        with pytest.raises(VaultDecryptionError):
            decrypt_secret(stripped_token)

        # 2. Replaced tag with all zeroes
        zero_tag = raw[:-16] + b"\x00" * 16
        with pytest.raises(VaultDecryptionError):
            decrypt_secret(base64.b64encode(zero_tag).decode("utf-8"))

        # 3. Nonce replaced with all zeroes
        zero_nonce = b"\x00" * 12 + raw[12:]
        with pytest.raises(VaultDecryptionError):
            decrypt_secret(base64.b64encode(zero_nonce).decode("utf-8"))

    def test_fuzz_associated_data_tampering(self):
        """
        Test AEAD Associated Authenticated Data (AAD) binding.
        If encrypted with AAD, decryption MUST fail if AAD differs by even 1 byte.
        """
        camera_id = b"camera_uuid_998877"
        secret = "ezviz_device_verification_code_ABCD"

        token = encrypt_secret(secret, associated_data=camera_id)

        # Decrypt with correct AAD -> Success
        assert decrypt_secret(token, associated_data=camera_id) == secret

        # Decrypt with altered AAD -> VaultDecryptionError
        with pytest.raises(VaultDecryptionError):
            decrypt_secret(token, associated_data=b"camera_uuid_998878")

        # Decrypt with empty / None AAD -> VaultDecryptionError
        with pytest.raises(VaultDecryptionError):
            decrypt_secret(token, associated_data=None)

        with pytest.raises(VaultDecryptionError):
            decrypt_secret(token, associated_data=b"")

    def test_extreme_payload_sizes_and_binary_safety(self):
        """
        Test multi-megabyte payloads, null bytes, and non-ASCII character boundaries.
        """
        # 1. Multi-megabyte payload (2 MB text)
        large_text = "CameraPayloadStreamMetadata_Chunk" * 70_000  # ~2.3 MB
        token = encrypt_secret(large_text)
        decrypted = decrypt_secret(token)
        assert decrypted == large_text

        # 2. Embedded null bytes and control chars
        null_byte_text = "Camera\x00Admin\x01\x02\x03Password\x1fWith\x00Nulls"
        token = encrypt_secret(null_byte_text)
        assert decrypt_secret(token) == null_byte_text

        # 3. Extreme unicode & multi-plane emojis & Asian scripts
        intl_text = "🔒 EZVIZ 萤石 摄像头 4K Ultra-HD 📹 | \u202eRTL_OVERRIDE | 𝔉𝔯𝔞𝔨𝔱𝔲𝔯 | 🎦"
        token = encrypt_secret(intl_text)
        assert decrypt_secret(token) == intl_text

    def test_json_fuzzing_and_type_confusion(self):
        """
        Test encrypt_json and decrypt_json with deep nesting, extreme numbers,
        and malformed JSON structures.
        """
        complex_dict = {
            "token": "eyJhbGciOi...",
            "expires_in": 7200,
            "nested": {
                "tags": ["cloud", "stream", "ptz"],
                "flags": {"active": True, "quota": None, "sub": {"depth": 999}},
            },
            "unicode_key_测试": "值_val",
        }
        token = encrypt_json(complex_dict)
        restored = decrypt_json(token)
        assert restored == complex_dict

        # Tamper JSON to create invalid JSON inside valid ciphertext
        valid_b64 = encrypt_secret('{"broken_json": true, ')
        with pytest.raises(VaultDecryptionError):
            decrypt_json(valid_b64)

    def test_mask_secret_edge_cases(self):
        """
        Verify mask_secret never leaks raw secrets under any boundary lengths.
        """
        assert mask_secret("") == ""
        assert mask_secret(None) == ""
        assert mask_secret("a") == "*"
        assert mask_secret("ab") == "**"
        assert mask_secret("123456") == "******"
        assert mask_secret("1234567") == "123...567"
        assert mask_secret("short", show_prefix=10, show_suffix=10) == "*****"
        # Check that inner secret is always masked
        masked = mask_secret("SUPER_SECRET_TOKEN_XYZ123", show_prefix=4, show_suffix=4)
        assert "SECRET_TOKEN" not in masked
        assert masked == "SUPE...Z123"

    @pytest.mark.asyncio
    async def test_vault_high_concurrency_race_conditions(self):
        """
        Launch 100 concurrent async coroutines encrypting and decrypting simultaneously.
        Verify zero race conditions, zero exceptions, and zero cross-talk.
        """
        async def worker(worker_id: int):
            msg = f"worker_{worker_id}_{secrets.token_hex(16)}"
            token = encrypt_secret(msg)
            await asyncio.sleep(0.001)
            recovered = decrypt_secret(token)
            assert recovered == msg
            return token

        tasks = [worker(i) for i in range(100)]
        results = await asyncio.gather(*tasks)

        # Nonce uniqueness check across all 100 tokens
        nonces = set()
        for token in results:
            raw = base64.b64decode(token)
            nonce = raw[:12]
            assert nonce not in nonces, "CSPRNG Nonce collision detected!"
            nonces.add(nonce)


# ==============================================================================
# SECTION 2: SQLITE WAL HIGH-CONCURRENCY STRESS & INTEGRITY HARNESS
# ==============================================================================

class TestSqliteWalConcurrencyStress:
    """Adversarial stress testing against SQLite in WAL mode."""

    @pytest_asyncio.fixture(autouse=True)
    async def setup_test_db(self, tmp_path):
        db_file = tmp_path / "wal_stress.db"
        set_database_path(db_file)
        await init_db(db_file)
        yield

    @pytest.mark.asyncio
    async def test_concurrent_writer_storm_wal_resilience(self):
        """
        Simulate CCTV event ingestion storm:
        30 concurrent async tasks executing rapid INSERTs into event_logs and cameras.
        Verifies busy_timeout handling, WAL concurrency, and zero 'database is locked' errors.
        """
        base_camera = {
            "id": "cam_storm_target",
            "name": "Storm Test Camera",
            "brand": "generic",
            "stream_id": "stream_storm_01",
            "stream_type": "generic_rtsp",
        }
        await save_camera(base_camera)

        total_tasks = 25
        events_per_task = 10
        total_expected_events = total_tasks * events_per_task

        async def writer_task(task_id: int):
            for i in range(events_per_task):
                event_uuid = f"evt_{task_id}_{i}_{secrets.token_hex(6)}"
                event_type = ["Human", "Movement", "Abnormal Sound"][i % 3]
                async with get_db() as conn:
                    await conn.execute(
                        """
                        INSERT INTO event_logs (
                            event_id, camera_id, camera_name, event_type,
                            timestamp, confidence, is_read
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            event_uuid,
                            "cam_storm_target",
                            "Storm Test Camera",
                            event_type,
                            f"2026-10-08T04:{i:02d}:00Z",
                            0.95,
                            0,
                        ),
                    )
                    await conn.commit()
                await asyncio.sleep(0.002)

        tasks = [writer_task(t) for t in range(total_tasks)]
        await asyncio.gather(*tasks)

        # Verify total inserted records
        async with get_db() as conn:
            async with conn.execute("SELECT COUNT(*) FROM event_logs;") as cursor:
                row = await cursor.fetchone()
                assert row is not None
                assert row[0] == total_expected_events

        # Ensure WAL journal mode is verified active
        async with get_db() as conn:
            async with conn.execute("PRAGMA journal_mode;") as cursor:
                row = await cursor.fetchone()
                assert row is not None
                assert row[0].lower() == "wal"

        # Verify health check remains functional
        health = await check_db_health()
        assert health == "connected"

    @pytest.mark.asyncio
    async def test_mixed_concurrent_reads_and_writes_under_wal(self):
        """
        Simulate active NVR operational load:
        10 background tasks writing event logs while 10 background tasks
        continuously execute compound indexed queries and aggregations.
        """
        cam = {
            "id": "cam_mixed_01",
            "name": "Mixed Traffic Camera",
            "brand": "ezviz",
            "stream_id": "stream_mixed_01",
            "stream_type": "ezviz_cloud",
        }
        await save_camera(cam)

        stop_flag = False

        async def heavy_writer(task_id: int):
            idx = 0
            while not stop_flag and idx < 15:
                idx += 1
                async with get_db() as conn:
                    await conn.execute(
                        """
                        INSERT INTO event_logs (
                            event_id, camera_id, camera_name, event_type,
                            timestamp, confidence, is_read
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            f"evt_mix_{task_id}_{idx}_{secrets.token_hex(4)}",
                            "cam_mixed_01",
                            "Mixed Traffic Camera",
                            "Human",
                            f"2026-10-08T05:{idx:02d}:00Z",
                            0.98,
                            0,
                        ),
                    )
                    await conn.commit()
                await asyncio.sleep(0.005)

        async def heavy_reader(reader_id: int):
            read_count = 0
            while not stop_flag and read_count < 20:
                read_count += 1
                async with get_db() as conn:
                    async with conn.execute(
                        """
                        SELECT count(*), max(timestamp)
                        FROM event_logs
                        WHERE camera_id = ? AND event_type = ?;
                        """,
                        ("cam_mixed_01", "Human"),
                    ) as cursor:
                        row = await cursor.fetchone()
                        assert row is not None
                await asyncio.sleep(0.003)

        writers = [heavy_writer(i) for i in range(10)]
        readers = [heavy_reader(i) for i in range(10)]
        await asyncio.gather(*writers, *readers)

    @pytest.mark.asyncio
    async def test_foreign_key_cascade_contention(self):
        """
        Adversarial test: Delete parent camera record while child event logs
        and recordings exist. Must cascade delete child records cleanly without locking.
        """
        cam = {
            "id": "cam_parent_del",
            "name": "Target for Cascade Delete",
            "brand": "xiaomi",
            "stream_id": "stream_cascade_01",
            "stream_type": "xiaomi_p2p",
        }
        await save_camera(cam)

        async with get_db() as conn:
            for i in range(30):
                await conn.execute(
                    """
                    INSERT INTO event_logs (
                        event_id, camera_id, camera_name, event_type, timestamp
                    ) VALUES (?, ?, ?, ?, ?);
                    """,
                    (f"evt_casc_{i}", "cam_parent_del", "Cascade Cam", "Movement", f"2026-10-08T06:{i:02d}:00Z"),
                )
                await conn.execute(
                    """
                    INSERT INTO recordings (
                        id, camera_id, camera_name, record_type, file_path,
                        file_name, start_time, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (f"rec_casc_{i}", "cam_parent_del", "Cascade Cam", "manual", f"/rec/{i}.mp4", f"{i}.mp4", f"2026-10-08T06:{i:02d}:00Z", "completed"),
                )
            await conn.commit()

        # Delete parent camera
        async with get_db() as conn:
            await conn.execute("DELETE FROM cameras WHERE id = ?;", ("cam_parent_del",))
            await conn.commit()

        # Verify child records were automatically cascaded to 0
        async with get_db() as conn:
            async with conn.execute("SELECT count(*) FROM event_logs WHERE camera_id = ?;", ("cam_parent_del",)) as cursor:
                assert (await cursor.fetchone())[0] == 0
            async with conn.execute("SELECT count(*) FROM recordings WHERE camera_id = ?;", ("cam_parent_del",)) as cursor:
                assert (await cursor.fetchone())[0] == 0


# ==============================================================================
# SECTION 3: GO2RTC CLIENT ADVERSARIAL SIMULATION & EDGE CASES
# ==============================================================================

class TestGo2rtcClientAdversarial:
    """Simulates server failures, network timeouts, and malformed responses."""

    @pytest.mark.asyncio
    async def test_network_read_timeout_handling(self):
        """
        Verify Go2rtcClient catches httpx.ReadTimeout and raises Go2rtcError.
        """
        def timeout_handler(request: httpx.Request):
            raise httpx.ReadTimeout("Read timed out after 10s", request=request)

        transport = httpx.MockTransport(timeout_handler)
        client = Go2rtcClient("http://127.0.0.1:1984")
        client._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:1984",
        )

        with pytest.raises(Go2rtcError) as exc_info:
            await client.get_streams()
        assert "Failed to communicate with go2rtc" in str(exc_info.value)
        await client.close()

    @pytest.mark.asyncio
    async def test_network_connect_timeout_handling(self):
        """
        Verify Go2rtcClient catches httpx.ConnectTimeout and raises Go2rtcError.
        """
        def connect_timeout_handler(request: httpx.Request):
            raise httpx.ConnectTimeout("Connect timeout to 127.0.0.1:1984", request=request)

        transport = httpx.MockTransport(connect_timeout_handler)
        client = Go2rtcClient("http://127.0.0.1:1984")
        client._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:1984",
        )

        with pytest.raises(Go2rtcError) as exc_info:
            await client.add_stream("test_stream", "rtsp://127.0.0.1/live")
        assert "Error adding stream" in str(exc_info.value)
        await client.close()

    @pytest.mark.asyncio
    async def test_http_server_error_responses(self):
        """
        Test client handling of HTTP 500, 502, 400 status codes.
        """
        def error_handler(request: httpx.Request):
            if request.url.path == "/api/streams":
                return httpx.Response(502, text="Bad Gateway - go2rtc crashed")
            if request.url.path == "/api/webrtc":
                return httpx.Response(400, text="Invalid SDP Offer")
            return httpx.Response(500, text="Internal Server Error")

        transport = httpx.MockTransport(error_handler)
        client = Go2rtcClient("http://127.0.0.1:1984")
        client._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:1984",
        )

        with pytest.raises(Go2rtcHttpError) as exc_info:
            await client.get_streams()
        assert exc_info.value.status_code == 502
        assert "Bad Gateway" in exc_info.value.message

        with pytest.raises(Go2rtcHttpError) as exc_info:
            await client.negotiate_webrtc("cam1", "INVALID_SDP")
        assert exc_info.value.status_code == 400
        assert "Invalid SDP Offer" in exc_info.value.message

        await client.close()

    @pytest.mark.asyncio
    async def test_frame_snapshot_404_maps_to_stream_not_found(self):
        """
        Verify GET /api/frame.jpeg returning 404 cleanly maps to Go2rtcStreamNotFoundError.
        """
        def not_found_handler(request: httpx.Request):
            return httpx.Response(404, text="stream not found")

        transport = httpx.MockTransport(not_found_handler)
        client = Go2rtcClient("http://127.0.0.1:1984")
        client._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:1984",
        )

        with pytest.raises(Go2rtcStreamNotFoundError) as exc_info:
            await client.get_frame("non_existent_stream")
        assert "not found" in str(exc_info.value)
        await client.close()

    @pytest.mark.asyncio
    async def test_stream_name_with_special_characters_and_spaces(self):
        """
        Test that camera stream names with special chars, spaces, and colons
        are properly transmitted via query params.
        """
        captured_requests = []

        def echo_handler(request: httpx.Request):
            captured_requests.append(request)
            return httpx.Response(200, text="OK")

        transport = httpx.MockTransport(echo_handler)
        client = Go2rtcClient("http://127.0.0.1:1984")
        client._client = httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:1984",
        )

        complex_name = "Camera 01 / Gate & Entrance #2"
        rtsp_src = "rtsp://admin:pass@192.168.1.50:554/live?channel=1"

        await client.add_stream(complex_name, rtsp_src)
        assert len(captured_requests) == 1
        req = captured_requests[0]
        assert req.method == "PUT"
        assert req.url.path == "/api/streams"
        assert req.url.params.get("name") == complex_name
        assert req.url.params.get("src") == rtsp_src

        await client.close()
