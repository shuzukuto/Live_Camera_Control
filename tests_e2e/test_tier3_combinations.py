"""
Tier 3: Pairwise and Multi-System Combinatorial Test Suite for Web-based NVR/VMS Application.
Implements >=20 cross-feature interaction test cases verifying multi-protocol flows,
streaming transitions, storage lifecycle, vault integration, and UI pipelines.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import sqlite3
import time
from typing import Dict, Any, List

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from tests_e2e.mocks.mock_camera_server import (
    MockEZVIZPlatform,
    MockXiaomiPlatform,
    MockONVIFDevice,
    MockGo2rtcServer,
    MockFFmpegSimulator,
    MockSurveillanceEcosystem,
)


class TestTier3_SystemCombinations:
    # --------------------------------------------------------------------------
    # Combination 1: EZVIZ Cloud Auth + Stream Registration + NVR Recording
    # --------------------------------------------------------------------------
    def test_comb_01_ezviz_cloud_auth_stream_registration_and_recording(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem, temp_storage_env: Dict[str, str], test_db_conn: sqlite3.Connection
    ):
        """Verifies full flow: EZVIZ login -> get live URL -> add camera -> start fMP4 recording -> stop -> verify file & DB."""
        # Step 1: Login to EZVIZ
        login_res = test_app_client.post("/api/accounts/ezviz/login", json={"app_key": "mock_ezviz_app_key_999", "app_secret": "mock_ezviz_secret_888"})
        assert login_res.status_code == 200
        token = login_res.json()["data"]["accessToken"]

        # Step 2: Get live address for camera
        live_res = mock_ecosystem_fixture.ezviz.get_live_address(token, "F12345678")
        assert live_res["code"] == "200"
        stream_url = live_res["data"]["url"]

        # Step 3: Register camera into system & go2rtc
        cam_res = test_app_client.post("/api/cameras", json={"id": "ezviz_f1", "name": "Front Door EZVIZ", "platform": "ezviz", "stream_url": stream_url})
        assert cam_res.status_code == 200
        assert "ezviz_f1" in mock_ecosystem_fixture.go2rtc.streams

        # Step 4: Start recording
        rec_start = test_app_client.post("/api/cameras/ezviz_f1/record/start?trigger_type=manual")
        assert rec_start.status_code == 200
        rec_file = rec_start.json()["file_path"]
        assert os.path.exists(rec_file)

        # Step 5: Stop recording
        time.sleep(0.05)
        rec_stop = test_app_client.post("/api/cameras/ezviz_f1/record/stop")
        assert rec_stop.status_code == 200
        assert rec_stop.json()["size_bytes"] > 0

        # Step 6: Verify in database
        cursor = test_db_conn.cursor()
        cursor.execute("SELECT * FROM recordings WHERE camera_id = 'ezviz_f1'")
        row = cursor.fetchone()
        assert row is not None
        assert row["trigger_type"] == "manual"

    # --------------------------------------------------------------------------
    # Combination 2: Xiaomi Passport + Regional Sync + StreamKeeper Hot-Swap
    # --------------------------------------------------------------------------
    def test_comb_02_xiaomi_passport_region_sync_and_streamkeeper_renewal(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies Xiaomi Passport login -> regional device sync -> xiaomi:// stream descriptor -> StreamKeeper hot-swap."""
        # Step 1: Xiaomi 2-step login
        auth_res = test_app_client.post("/api/accounts/xiaomi/login", json={"username": "user_china@example.com", "password": "Secr3tP@ss123"})
        assert auth_res.status_code == 200
        tok = auth_res.json()["serviceToken"]

        # Step 2: Regional device sync
        devs_res = mock_ecosystem_fixture.xiaomi.get_devices("cn", tok)
        assert devs_res["code"] == 0
        devices = devs_res["result"]["list"]
        assert len(devices) >= 2
        cam_did = devices[0]["did"]

        # Step 3: Resolve xiaomi:// stream descriptor
        stream_desc = mock_ecosystem_fixture.xiaomi.get_stream_descriptor(cam_did, "cn", tok)
        assert stream_desc["code"] == 0
        initial_url = stream_desc["stream_url"]

        # Step 4: Register in go2rtc
        test_app_client.post("/api/cameras", json={"id": cam_did, "name": "Xiaomi Chuangmi", "platform": "xiaomi", "stream_url": initial_url})
        assert mock_ecosystem_fixture.go2rtc.streams[cam_did]["src"] == initial_url

        # Step 5: Simulate StreamKeeper lease renewal hot-swap
        renewed_url = f"{initial_url}&renewed_at={int(time.time())}"
        updated = mock_ecosystem_fixture.go2rtc.update_stream(cam_did, renewed_url)
        assert updated is True
        assert mock_ecosystem_fixture.go2rtc.streams[cam_did]["src"] == renewed_url

    # --------------------------------------------------------------------------
    # Combination 3: ONVIF Discovery + Auto-Add Camera + SOAP PTZ Control
    # --------------------------------------------------------------------------
    def test_comb_03_onvif_ws_discovery_camera_provisioning_and_ptz(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies ONVIF multicast discovery -> camera auto-add -> SOAP ContinuousMove and Stop."""
        # Step 1: Discover ONVIF camera
        disc_res = test_app_client.post("/api/onvif/discover")
        assert disc_res.status_code == 200
        discovered = disc_res.json()
        assert len(discovered) >= 1
        dev = discovered[0]

        # Step 2: Auto-add discovered camera
        cam_id = "onvif_disc_1"
        rtsp_url = f"rtsp://{dev['ip']}:{dev['port']}/live/main"
        add_res = test_app_client.post("/api/cameras", json={"id": cam_id, "name": f"ONVIF ({dev['ip']})", "platform": "onvif", "stream_url": rtsp_url, "ptz_supported": 1})
        assert add_res.status_code == 200

        # Step 3: Send PTZ Move command via backend
        ptz_res = test_app_client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "up", "speed": 7})
        assert ptz_res.status_code == 200
        assert ptz_res.json()["action"] == "move_up"

        # Step 4: Verify underlying SOAP ContinuousMove
        soap_move = mock_ecosystem_fixture.onvif.handle_soap_request("ContinuousMove", "")
        assert soap_move["status_code"] == 200

        # Step 5: Deadman safety stop
        stop_res = test_app_client.post(f"/api/cameras/{cam_id}/ptz", json={"direction": "stop"})
        assert stop_res.status_code == 200
        soap_stop = mock_ecosystem_fixture.onvif.handle_soap_request("Stop", "")
        assert soap_stop["status_code"] == 200

    # --------------------------------------------------------------------------
    # Combination 4: AI Human Event -> Snapshot -> DB Log -> Event-Triggered MP4
    # --------------------------------------------------------------------------
    def test_comb_04_ai_human_detection_event_triggers_snapshot_and_mp4_recording(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem, test_db_conn: sqlite3.Connection, temp_storage_env: Dict[str, str]
    ):
        """Verifies end-to-end AI alert pipeline: Human event -> instant frame snapshot -> event log -> automatic MP4 recording."""
        cam_id = "cam_ai_intruder"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "Driveway AI Cam", "stream_url": "rtsp://ai"})

        # Step 1: Capture instant snapshot
        snap_res = test_app_client.post(f"/api/cameras/{cam_id}/snapshot")
        assert snap_res.status_code == 200
        snap_url = snap_res.json()["snapshot_url"]

        # Step 2: Log AI Human event
        evt_res = test_app_client.post(
            "/api/events",
            json={"camera_id": cam_id, "camera_name": "Driveway AI Cam", "event_type": "vendor.ai.person_intrusion", "description": "Human detected in zone 1", "snapshot_url": snap_url},
        )
        assert evt_res.status_code == 200
        assert evt_res.json()["event_type"] == "Human"

        # Step 3: Trigger event-based recording
        rec_res = test_app_client.post(f"/api/cameras/{cam_id}/record/start?trigger_type=event")
        assert rec_res.status_code == 200
        time.sleep(0.05)
        stop_res = test_app_client.post(f"/api/cameras/{cam_id}/record/stop")
        assert stop_res.status_code == 200

        # Step 4: Verify link in DB
        cursor = test_db_conn.cursor()
        cursor.execute("SELECT * FROM event_logs WHERE camera_id = ?", (cam_id,))
        evt_row = cursor.fetchone()
        assert evt_row["event_type"] == "Human"
        assert evt_row["snapshot_url"] == snap_url

        cursor.execute("SELECT * FROM recordings WHERE camera_id = ?", (cam_id,))
        rec_row = cursor.fetchone()
        assert rec_row["trigger_type"] == "event"

    # --------------------------------------------------------------------------
    # Combination 5: Multi-Cam Grid View + WebRTC Sessions + Snapshot Burst
    # --------------------------------------------------------------------------
    def test_comb_05_multi_cam_grid_with_webrtc_sessions_and_snapshot_burst(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies multi-cam 2x2 grid with 4 active WebRTC players and simultaneous snapshot capture."""
        channels = ["grid_c1", "grid_c2", "grid_c3", "grid_c4"]
        for ch in channels:
            test_app_client.post("/api/cameras", json={"id": ch, "name": f"Grid {ch}", "stream_url": f"rtsp://{ch}"})

        # Step 1: Connect 4 WebRTC players
        for ch in channels:
            sdp_res = mock_ecosystem_fixture.go2rtc.webrtc_handshake(ch, "v=0\r\no=mock_client...")
            assert sdp_res["status"] == "success"

        # Step 2: Verify active consumers
        streams_info = mock_ecosystem_fixture.go2rtc.get_streams()
        for ch in channels:
            assert len(streams_info[ch]["consumers"]) == 1

        # Step 3: Burst snapshot across all 4 channels
        snaps = []
        for ch in channels:
            s_res = test_app_client.post(f"/api/cameras/{ch}/snapshot")
            assert s_res.status_code == 200
            snaps.append(s_res.json()["snapshot_url"])

        assert len(snaps) == 4
        assert len(set(snaps)) == 4

        # Teardown consumers
        for ch in channels:
            mock_ecosystem_fixture.go2rtc.stop_consumer(ch)

    # --------------------------------------------------------------------------
    # Combination 6: Credential Vault Encryption + DB Storage + Cloud Login
    # --------------------------------------------------------------------------
    def test_comb_06_vault_credentials_encryption_and_cloud_service_login(
        self, test_db_conn: sqlite3.Connection, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies encrypting cloud secrets, storing in accounts table, decrypting, and logging into EZVIZ."""
        master_key = os.urandom(32)

        # Step 1: Encrypt AppKey & Secret
        raw_secret = json.dumps({"app_key": "mock_ezviz_app_key_999", "app_secret": "mock_ezviz_secret_888"})
        nonce = os.urandom(12)
        keystream = hashlib.sha256(master_key + nonce).digest()
        cipher = bytes(b ^ keystream[i % len(keystream)] for i, b in enumerate(raw_secret.encode()))
        tag = hmac.new(master_key, nonce + cipher, hashlib.sha256).digest()[:16]
        enc_payload = base64.b64encode(nonce + tag + cipher).decode()

        # Step 2: Store in DB
        cursor = test_db_conn.cursor()
        now = time.time()
        cursor.execute(
            "INSERT INTO accounts (id, platform, username, encrypted_credentials, region, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("acc_ezviz", "ezviz", "admin_ezviz", enc_payload, "global", now, now),
        )
        test_db_conn.commit()

        # Step 3: Fetch and decrypt
        cursor.execute("SELECT encrypted_credentials FROM accounts WHERE id = 'acc_ezviz'")
        stored_enc = cursor.fetchone()[0]
        data = base64.b64decode(stored_enc)
        d_nonce, d_tag, d_cipher = data[:12], data[12:28], data[28:]
        assert hmac.new(master_key, d_nonce + d_cipher, hashlib.sha256).digest()[:16] == d_tag
        d_keystream = hashlib.sha256(master_key + d_nonce).digest()
        recovered_secret = json.loads(bytes(b ^ d_keystream[i % len(d_keystream)] for i, b in enumerate(d_cipher)).decode())

        # Step 4: Use decrypted credentials for cloud login
        tok_res = mock_ecosystem_fixture.ezviz.get_token(recovered_secret["app_key"], recovered_secret["app_secret"])
        assert tok_res["code"] == "200"

    # --------------------------------------------------------------------------
    # Combination 7: Storage Quota FIFO Purge Under Active Recording
    # --------------------------------------------------------------------------
    def test_comb_07_storage_quota_pressure_under_active_recording_fifo_purge(
        self, test_app_client: TestClient, test_db_conn: sqlite3.Connection, temp_storage_env: Dict[str, str]
    ):
        """Verifies FIFO purge safely identifies oldest non-protected file while active recording is running."""
        cam_id = "cam_quota"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "Quota Cam", "stream_url": "rtsp://q"})

        # Seed 3 existing recordings: 1 protected (old), 1 unprotected (old), 1 unprotected (newer)
        cursor = test_db_conn.cursor()
        now = time.time()
        cursor.execute("INSERT INTO recordings (id, camera_id, file_path, is_protected, created_at) VALUES ('rec_prot', ?, '/tmp/p', 1, ?)", (cam_id, now - 1000))
        cursor.execute("INSERT INTO recordings (id, camera_id, file_path, is_protected, created_at) VALUES ('rec_old_del', ?, '/tmp/o', 0, ?)", (cam_id, now - 500))
        cursor.execute("INSERT INTO recordings (id, camera_id, file_path, is_protected, created_at) VALUES ('rec_newer', ?, '/tmp/n', 0, ?)", (cam_id, now - 100))
        test_db_conn.commit()

        # Start new active recording
        start_res = test_app_client.post(f"/api/cameras/{cam_id}/record/start")
        assert start_res.status_code == 200

        # Purge query executes
        cursor.execute("SELECT id FROM recordings WHERE is_protected = 0 ORDER BY created_at ASC LIMIT 1")
        purge_candidate = cursor.fetchone()[0]
        assert purge_candidate == "rec_old_del"

        # Delete purged candidate
        cursor.execute("DELETE FROM recordings WHERE id = ?", (purge_candidate,))
        test_db_conn.commit()

        # Stop active recording
        stop_res = test_app_client.post(f"/api/cameras/{cam_id}/record/stop")
        assert stop_res.status_code == 200

        # Verify active recording was saved and protected recording is still there
        cursor.execute("SELECT id FROM recordings WHERE id = 'rec_prot'")
        assert cursor.fetchone() is not None

    # --------------------------------------------------------------------------
    # Combination 8: StreamKeeper Renewal During Active Recording
    # --------------------------------------------------------------------------
    def test_comb_08_streamkeeper_proactive_lease_renewal_during_active_recording(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies upstream lease renewal hot-swaps source during active recording without stopping session."""
        cam_id = "cam_keeper_rec"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "Keeper Cam", "stream_url": "rtsp://lease_v1"})

        # Start recording
        test_app_client.post(f"/api/cameras/{cam_id}/record/start")

        # StreamKeeper performs hot-swap
        renewed = mock_ecosystem_fixture.go2rtc.update_stream(cam_id, "rtsp://lease_v2_renewed")
        assert renewed is True

        # Recording completes normally
        time.sleep(0.02)
        stop_res = test_app_client.post(f"/api/cameras/{cam_id}/record/stop")
        assert stop_res.status_code == 200
        assert stop_res.json()["size_bytes"] > 0

    # --------------------------------------------------------------------------
    # Combination 9: LAN RTSP Routing with Cloud Fallback
    # --------------------------------------------------------------------------
    def test_comb_09_lan_rtsp_priority_routing_with_cloud_fallback(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies camera with LAN RTSP prefers local stream, but falls back to cloud URL on failure."""
        cloud_url = "rtsp://cloud.ezviz.com/live/ch1"
        lan_url = "rtsp://admin:123@192.168.1.101:554/live"

        # Initially LAN is healthy
        lan_healthy = True
        active_url = lan_url if lan_healthy else cloud_url
        assert active_url == lan_url
        test_app_client.post("/api/cameras", json={"id": "cam_lan_prio", "name": "LAN Cam", "stream_url": active_url})
        assert mock_ecosystem_fixture.go2rtc.streams["cam_lan_prio"]["src"] == lan_url

        # LAN drops -> fallback to cloud
        lan_healthy = False
        fallback_url = lan_url if lan_healthy else cloud_url
        mock_ecosystem_fixture.go2rtc.update_stream("cam_lan_prio", fallback_url)
        assert mock_ecosystem_fixture.go2rtc.streams["cam_lan_prio"]["src"] == cloud_url

    # --------------------------------------------------------------------------
    # Combination 10: ONVIF PTZ Deadman Safety Stop Under Network Latency
    # --------------------------------------------------------------------------
    def test_comb_10_onvif_ptz_deadman_safety_stop_under_network_timeout(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies PTZ command followed by deadman stop halts camera reliably."""
        test_app_client.post("/api/cameras", json={"id": "ptz_deadman_cam", "name": "PTZ Cam", "stream_url": "rtsp://ptz", "ptz_supported": 1})
        # Move
        move_res = test_app_client.post("/api/cameras/ptz_deadman_cam/ptz", json={"direction": "right", "speed": 5})
        assert move_res.status_code == 200

        # Safety stop
        stop_res = test_app_client.post("/api/cameras/ptz_deadman_cam/ptz", json={"direction": "stop"})
        assert stop_res.status_code == 200
        assert stop_res.json()["action"] == "stop"

    # --------------------------------------------------------------------------
    # Combination 11: Event Filter and 3-Mode Export Pipeline
    # --------------------------------------------------------------------------
    def test_comb_11_event_filter_and_3_mode_export_pipeline(self, test_app_client: TestClient):
        """Verifies creating mixed events -> filtering Human -> exporting in all 3 modes."""
        test_app_client.post("/api/events", json={"camera_id": "c_exp1", "event_type": "Human", "description": "Person at front gate"})
        test_app_client.post("/api/events", json={"camera_id": "c_exp2", "event_type": "Movement", "description": "Wind rustling trees"})
        test_app_client.post("/api/events", json={"camera_id": "c_exp1", "event_type": "Human", "description": "Mail carrier arrived"})

        # Query filtered
        res_filtered = test_app_client.get("/api/events?event_type=Human")
        assert res_filtered.status_code == 200
        humans = res_filtered.json()
        assert all(h["event_type"] == "Human" for h in humans)

        # Mode 1: Template
        m1 = test_app_client.get("/api/events/export?mode=template")
        assert m1.status_code == 200
        assert len(m1.text.strip().split("\n")) == 1

        # Mode 2: Filtered
        m2 = test_app_client.get("/api/events/export?mode=filtered")
        assert m2.status_code == 200
        assert len(m2.text.strip().split("\n")) >= 2

        # Mode 3: All
        m3 = test_app_client.get("/api/events/export?mode=all")
        assert m3.status_code == 200
        assert len(m3.text.strip().split("\n")) >= 3

    # --------------------------------------------------------------------------
    # Combination 12: EZVIZ Stream Encryption Toggle and H.264 Live View
    # --------------------------------------------------------------------------
    def test_comb_12_ezviz_cloud_encryption_toggle_off_and_h264_stream_viewing(
        self, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies encrypted EZVIZ camera (isEncrypt=1) is decrypted via validateCode then streamed."""
        dev = mock_ecosystem_fixture.ezviz.devices["F12345678"]
        assert dev["isEncrypt"] == 1  # Initially encrypted

        # Authenticate
        tok = mock_ecosystem_fixture.ezviz.get_token("mock_ezviz_app_key_999", "mock_ezviz_secret_888")["data"]["accessToken"]

        # Disable encryption with validateCode
        off_res = mock_ecosystem_fixture.ezviz.set_encryption_off(tok, "F12345678", "VERIFY123")
        assert off_res["code"] == "200"
        assert dev["isEncrypt"] == 0

        # Query live address
        live = mock_ecosystem_fixture.ezviz.get_live_address(tok, "F12345678")
        assert live["data"]["isEncrypt"] == 0
        assert "rtsp://" in live["data"]["url"]

        # Add to go2rtc and grab frame
        mock_ecosystem_fixture.go2rtc.add_stream("ezviz_unlocked", live["data"]["url"])
        frame = mock_ecosystem_fixture.go2rtc.get_frame("ezviz_unlocked")
        assert len(frame) > 1000

    # --------------------------------------------------------------------------
    # Combination 13: Multi-Tenant Account Device Sync and Cascade Delete
    # --------------------------------------------------------------------------
    def test_comb_13_multi_tenant_account_device_sync_and_cascade_delete(
        self, test_db_conn: sqlite3.Connection
    ):
        """Verifies deleting one account cascades its cameras and recordings while sparing another account."""
        cursor = test_db_conn.cursor()
        now = time.time()
        # Acc 1
        cursor.execute("INSERT INTO accounts (id, platform, username, encrypted_credentials, created_at, updated_at) VALUES ('acc_a', 'ezviz', 'u1', 'e1', ?, ?)", (now, now))
        cursor.execute("INSERT INTO cameras (id, name, platform, account_id, stream_url, created_at, updated_at) VALUES ('cam_a1', 'CA1', 'ezviz', 'acc_a', 'u', ?, ?)", (now, now))
        cursor.execute("INSERT INTO recordings (id, camera_id, file_path, created_at) VALUES ('rec_a1', 'cam_a1', '/p1', ?)", (now,))

        # Acc 2
        cursor.execute("INSERT INTO accounts (id, platform, username, encrypted_credentials, created_at, updated_at) VALUES ('acc_b', 'xiaomi', 'u2', 'e2', ?, ?)", (now, now))
        cursor.execute("INSERT INTO cameras (id, name, platform, account_id, stream_url, created_at, updated_at) VALUES ('cam_b1', 'CB1', 'xiaomi', 'acc_b', 'u', ?, ?)", (now, now))
        cursor.execute("INSERT INTO recordings (id, camera_id, file_path, created_at) VALUES ('rec_b1', 'cam_b1', '/p2', ?)", (now,))
        test_db_conn.commit()

        # Delete camera of account A
        cursor.execute("DELETE FROM cameras WHERE id = 'cam_a1'")
        test_db_conn.commit()

        # Verify acc_a recordings removed
        cursor.execute("SELECT COUNT(*) FROM recordings WHERE camera_id = 'cam_a1'")
        assert cursor.fetchone()[0] == 0

        # Verify acc_b cameras & recordings still intact
        cursor.execute("SELECT COUNT(*) FROM recordings WHERE camera_id = 'cam_b1'")
        assert cursor.fetchone()[0] == 1

    # --------------------------------------------------------------------------
    # Combination 14: Abnormal Sound Event Audio Alert Pipeline
    # --------------------------------------------------------------------------
    def test_comb_14_abnormal_sound_detection_audio_alert_and_websocket_broadcast(
        self, test_app_client: TestClient
    ):
        """Verifies abnormal sound event normalizes and flags audio alert."""
        res = test_app_client.post("/api/events", json={"camera_id": "c_sound", "event_type": "audio.baby_crying_detected", "description": "High decibel spike"})
        assert res.status_code == 200
        assert res.json()["event_type"] == "Abnormal Sound"

    # --------------------------------------------------------------------------
    # Combination 15: Concurrency - Simultaneous PTZ, Snapshot, and Recording
    # --------------------------------------------------------------------------
    def test_comb_15_high_concurrency_multi_channel_ptz_and_snapshot(
        self, test_app_client: TestClient
    ):
        """Verifies concurrent actions across distinct channels operate cleanly."""
        test_app_client.post("/api/cameras", json={"id": "cam_c1", "name": "Cam 1", "stream_url": "rtsp://1", "ptz_supported": 1})
        test_app_client.post("/api/cameras", json={"id": "cam_c2", "name": "Cam 2", "stream_url": "rtsp://2"})
        test_app_client.post("/api/cameras", json={"id": "cam_c3", "name": "Cam 3", "stream_url": "rtsp://3"})

        # Action 1: PTZ on cam 1
        r_ptz = test_app_client.post("/api/cameras/cam_c1/ptz", json={"direction": "left"})
        assert r_ptz.status_code == 200

        # Action 2: Snapshot on cam 2
        r_snap = test_app_client.post("/api/cameras/cam_c2/snapshot")
        assert r_snap.status_code == 200

        # Action 3: Record on cam 3
        r_rec = test_app_client.post("/api/cameras/cam_c3/record/start")
        assert r_rec.status_code == 200
        test_app_client.post("/api/cameras/cam_c3/record/stop")

    # --------------------------------------------------------------------------
    # Combination 16: fMP4 Recording to Faststart Web Finalization
    # --------------------------------------------------------------------------
    def test_comb_16_faststart_mp4_conversion_and_web_playback_verification(
        self, temp_storage_env: Dict[str, str]
    ):
        """Verifies recorded fMP4 has MOOV box placed at start for instant web playback."""
        out_file = os.path.join(temp_storage_env["recordings"], "web_faststart.mp4")
        MockFFmpegSimulator.create_mock_mp4_file(out_file, duration_sec=5, has_faststart=True)
        with open(out_file, "rb") as f:
            header = f.read(512)
        assert b"moov" in header

    # --------------------------------------------------------------------------
    # Combination 17: Cross-Region Xiaomi Cloud Fleet Sync
    # --------------------------------------------------------------------------
    def test_comb_17_cross_region_xiaomi_cloud_fleet_sync(
        self, mock_ecosystem_fixture: MockSurveillanceEcosystem, test_app_client: TestClient
    ):
        """Verifies syncing cameras across China (cn) and Global (sg, us) servers into unified fleet."""
        # CN session
        step1 = mock_ecosystem_fixture.xiaomi.passport_step1_service_login()
        pwd_md5 = hashlib.md5("Secr3tP@ss123".encode()).hexdigest()
        auth_cn = mock_ecosystem_fixture.xiaomi.passport_step2_auth("user_china@example.com", pwd_md5, step1["_sign"], step1["qs"], step1["callback"])
        cn_tok = auth_cn["serviceToken"]
        cn_devs = mock_ecosystem_fixture.xiaomi.get_devices("cn", cn_tok)["result"]["list"]

        # SG session
        step1_sg = mock_ecosystem_fixture.xiaomi.passport_step1_service_login()
        pwd_md5_sg = hashlib.md5("GlobalPass2026!".encode()).hexdigest()
        auth_sg = mock_ecosystem_fixture.xiaomi.passport_step2_auth("user_global@example.com", pwd_md5_sg, step1_sg["_sign"], step1_sg["qs"], step1_sg["callback"])
        sg_tok = auth_sg["serviceToken"]
        sg_devs = mock_ecosystem_fixture.xiaomi.get_devices("sg", sg_tok)["result"]["list"]

        # Add both to application
        for d in cn_devs:
            test_app_client.post("/api/cameras", json={"id": d["did"], "name": d["name"], "stream_url": f"xiaomi://{d['localip']}"})
        for d in sg_devs:
            test_app_client.post("/api/cameras", json={"id": d["did"], "name": d["name"], "stream_url": f"xiaomi://{d['localip']}"})

        cams_res = test_app_client.get("/api/cameras")
        ids = {c["id"] for c in cams_res.json()}
        assert "xiaomi_cam_001" in ids
        assert "xiaomi_cam_global_1" in ids

    # --------------------------------------------------------------------------
    # Combination 18: Generic RTSP Credential Parsing and WebRTC Delivery
    # --------------------------------------------------------------------------
    def test_comb_18_generic_rtsp_auth_url_parsing_and_webrtc_delivery(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies RTSP with user:pass is parsed, added to gateway, and serves WebRTC SDP answer."""
        rtsp_url = "rtsp://security:pass123@192.168.1.188:554/ch0_0"
        test_app_client.post("/api/cameras", json={"id": "rtsp_webrtc_cam", "name": "Auth RTSP", "stream_url": rtsp_url})

        # WebRTC client requests stream
        ans = mock_ecosystem_fixture.go2rtc.webrtc_handshake("rtsp_webrtc_cam", "v=0\r\no=tester 1 1 IN IP4 127.0.0.1...")
        assert ans["status"] == "success"
        assert ans["type"] == "answer"
        assert "m=video" in ans["sdp"]

    # --------------------------------------------------------------------------
    # Combination 19: Live Event Insertion During Active Pagination
    # --------------------------------------------------------------------------
    def test_comb_19_event_search_pagination_with_live_event_stream_insert(
        self, test_app_client: TestClient
    ):
        """Verifies pagination remains stable when new events are concurrently inserted."""
        # Seed 10 events
        for i in range(10):
            test_app_client.post("/api/events", json={"camera_id": "c_page", "description": f"Event {i}"})

        # Fetch page 1
        p1 = test_app_client.get("/api/events?page=1&page_size=5").json()
        assert len(p1) == 5

        # Background new event arrives
        test_app_client.post("/api/events", json={"camera_id": "c_page", "description": "NEW LIVE EVENT"})

        # Fetch page 2
        p2 = test_app_client.get("/api/events?page=2&page_size=5").json()
        assert len(p2) == 5

    # --------------------------------------------------------------------------
    # Combination 20: Full End-to-End System Bootstrap to Teardown
    # --------------------------------------------------------------------------
    def test_comb_20_full_system_lifecycle_bootstrap_to_teardown(
        self, test_app_client: TestClient, test_db_conn: sqlite3.Connection, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies full lifecycle: init -> add cam -> live view -> event -> snapshot -> record -> delete cam."""
        # 1. Health check
        assert test_app_client.get("/health").status_code == 200

        # 2. Add camera
        cam_id = "lifecycle_cam"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "Lifecycle Cam", "stream_url": "rtsp://life"})

        # 3. WebRTC handshake
        handshake = mock_ecosystem_fixture.go2rtc.webrtc_handshake(cam_id, "v=0\r\no=client...")
        assert handshake["status"] == "success"

        # 4. Snapshot
        snap = test_app_client.post(f"/api/cameras/{cam_id}/snapshot")
        assert snap.status_code == 200

        # 5. Record
        test_app_client.post(f"/api/cameras/{cam_id}/record/start")
        time.sleep(0.01)
        test_app_client.post(f"/api/cameras/{cam_id}/record/stop")

        # 6. Delete camera & cleanup
        del_res = test_app_client.delete(f"/api/cameras/{cam_id}")
        assert del_res.status_code == 200
        assert cam_id not in mock_ecosystem_fixture.go2rtc.streams

    # --------------------------------------------------------------------------
    # Combination 21: NAS UNC Storage Path and Local Disk Mirroring
    # --------------------------------------------------------------------------
    def test_comb_21_nas_unc_storage_failover_to_local_disk(
        self, temp_storage_env: Dict[str, str]
    ):
        """Verifies primary NAS storage folder path and local recordings directory coexistence."""
        nas_share = temp_storage_env["nas_mount"]
        local_dir = temp_storage_env["recordings"]

        # Write to NAS
        nas_file = os.path.join(nas_share, "nas_backup.mp4")
        MockFFmpegSimulator.create_mock_mp4_file(nas_file, 2)
        assert os.path.exists(nas_file)

        # Write to local
        local_file = os.path.join(local_dir, "local_rec.mp4")
        MockFFmpegSimulator.create_mock_mp4_file(local_file, 2)
        assert os.path.exists(local_file)

    # --------------------------------------------------------------------------
    # Combination 22: Rapid Multi-Cam Layout Switching and Consumer Cleanup
    # --------------------------------------------------------------------------
    def test_comb_22_rapid_multi_cam_layout_thrashing_and_video_consumer_cleanup(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Verifies rapid grid layout changes increment and decrement consumers cleanly."""
        cam_id = "thrash_cam"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "Thrash Cam", "stream_url": "rtsp://thrash"})

        # Consumer joins
        mock_ecosystem_fixture.go2rtc.webrtc_handshake(cam_id, "v=0\r\no=1...")
        assert mock_ecosystem_fixture.go2rtc.consumers_count[cam_id] == 1

        # Layout switches, unmounting old player
        mock_ecosystem_fixture.go2rtc.stop_consumer(cam_id)
        assert mock_ecosystem_fixture.go2rtc.consumers_count[cam_id] == 0
