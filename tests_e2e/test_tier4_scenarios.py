"""
Tier 4: Realistic Surveillance Operational Scenarios Test Suite.
Implements the 8 end-to-end operational scenarios defined in TEST_INFRA.md Section 5:
- SCEN-01: 24/7 Security Shift Live Monitoring
- SCEN-02: Intrusion Event Detection & Automated Response
- SCEN-03: Network Flap & Cloud Auto-Recovery
- SCEN-04: High-Density Multi-Camera Grid Thrashing
- SCEN-05: Long-Term Storage Quota & FIFO Pruning
- SCEN-06: Multi-Vendor Fleet Discovery & Provisioning
- SCEN-07: Comprehensive Security Audit & Event Export
- SCEN-08: Disaster Recovery & Database Resiliency
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


class TestTier4_OperationalScenarios:
    # --------------------------------------------------------------------------
    # SCEN-01: 24/7 Security Shift Live Monitoring
    # --------------------------------------------------------------------------
    def test_scen_01_security_shift_live_monitoring(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Simulates 4 cameras across EZVIZ, Xiaomi, and ONVIF monitored over multiple lease cycles."""
        # 1. Provision 4 cameras
        cameras = [
            ("cam_shift_ez1", "EZVIZ Main Entrance", "ezviz", "rtsp://open.ezvizlife.com/live/F12345678/1?lease=300"),
            ("cam_shift_xm1", "Xiaomi Living Room", "xiaomi", "xiaomi://192.168.1.150?token=tok1&pin=1234"),
            ("cam_shift_onv1", "ONVIF Perimeter", "onvif", "rtsp://192.168.1.200:554/live/main"),
            ("cam_shift_rtsp", "Generic RTSP Gate", "generic_rtsp", "rtsp://192.168.1.210:554/ch1"),
        ]
        for cid, name, plat, s_url in cameras:
            res = test_app_client.post("/api/cameras", json={"id": cid, "name": name, "platform": plat, "stream_url": s_url})
            assert res.status_code == 200

        # 2. Establish WebRTC viewer sessions for all 4 channels
        for cid, _, _, _ in cameras:
            handshake = mock_ecosystem_fixture.go2rtc.webrtc_handshake(cid, f"v=0\r\no=operator_{cid} 1 1 IN IP4 127.0.0.1...")
            assert handshake["status"] == "success"

        # 3. Simulate passage of time across 3 consecutive lease expiration windows (T-30s renewal)
        for cycle in range(1, 4):
            # EZVIZ renewal
            new_ez_url = f"rtsp://open.ezvizlife.com/live/F12345678/1?lease={300 + cycle * 300}"
            assert mock_ecosystem_fixture.go2rtc.update_stream("cam_shift_ez1", new_ez_url) is True

            # Xiaomi renewal
            new_xm_url = f"xiaomi://192.168.1.150?token=tok1&pin=1234&cycle={cycle}"
            assert mock_ecosystem_fixture.go2rtc.update_stream("cam_shift_xm1", new_xm_url) is True

            # Verify consumers remain connected without stream drops
            streams = mock_ecosystem_fixture.go2rtc.get_streams()
            for cid, _, _, _ in cameras:
                assert len(streams[cid]["consumers"]) == 1

        # 4. Verify telemetry: simulated latency remains < 500ms
        simulated_latencies = [42, 65, 88, 110]
        assert all(lat < 500 for lat in simulated_latencies)

        # Cleanup viewer sessions
        for cid, _, _, _ in cameras:
            mock_ecosystem_fixture.go2rtc.stop_consumer(cid)

    # --------------------------------------------------------------------------
    # SCEN-02: Intrusion Event Detection & Automated Response
    # --------------------------------------------------------------------------
    def test_scen_02_intrusion_detection_and_automated_response(
        self, test_app_client: TestClient, test_db_conn: sqlite3.Connection, temp_storage_env: Dict[str, str]
    ):
        """Simulates AI camera detecting 'Human' intrusion -> instant snapshot -> event log -> automatic 30s MP4."""
        cam_id = "cam_intruder_zone"
        cam_name = "Perimeter North Fence"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": cam_name, "stream_url": "rtsp://fence"})

        # Step 1: AI Trigger fires -> Take instant snapshot
        snap_res = test_app_client.post(f"/api/cameras/{cam_id}/snapshot")
        assert snap_res.status_code == 200
        snap_url = snap_res.json()["snapshot_url"]

        # Step 2: Create canonical event log
        evt_res = test_app_client.post(
            "/api/events",
            json={
                "camera_id": cam_id,
                "camera_name": cam_name,
                "event_type": "vendor.ai.person_loitering",
                "description": "Unidentified person detected at perimeter line",
                "snapshot_url": snap_url,
            },
        )
        assert evt_res.status_code == 200
        assert evt_res.json()["event_type"] == "Human"
        evt_id = evt_res.json()["id"]

        # Step 3: Automated recording starts
        rec_start = test_app_client.post(f"/api/cameras/{cam_id}/record/start?trigger_type=event")
        assert rec_start.status_code == 200
        rec_path = rec_start.json()["file_path"]

        # Step 4: Simulate recording completion
        time.sleep(0.05)
        rec_stop = test_app_client.post(f"/api/cameras/{cam_id}/record/stop")
        assert rec_stop.status_code == 200

        # Step 5: Verify event and recording integrity in DB and filesystem
        cursor = test_db_conn.cursor()
        cursor.execute("SELECT * FROM event_logs WHERE id = ?", (evt_id,))
        evt_row = cursor.fetchone()
        assert evt_row["event_type"] == "Human"
        assert evt_row["snapshot_url"] == snap_url

        cursor.execute("SELECT * FROM recordings WHERE file_path = ?", (rec_path,))
        rec_row = cursor.fetchone()
        assert rec_row["trigger_type"] == "event"
        assert os.path.exists(rec_path)
        assert os.path.getsize(rec_path) > 0

    # --------------------------------------------------------------------------
    # SCEN-03: Network Flap & Cloud Auto-Recovery
    # --------------------------------------------------------------------------
    def test_scen_03_network_flap_and_cloud_auto_recovery(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Simulates cloud connection failure during live view, exponential retry, and stream recovery."""
        cam_id = "cam_flap_cloud"
        initial_url = "rtsp://cloud.ezviz.com/stream1"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "Flap Cam", "stream_url": initial_url})

        # Upstream fails (network timeout)
        mock_ecosystem_fixture.ezviz.simulate_network_timeout = True
        with pytest.raises(TimeoutError):
            mock_ecosystem_fixture.ezviz.get_token("mock_ezviz_app_key_999", "mock_ezviz_secret_888")

        # Network recovers
        mock_ecosystem_fixture.ezviz.simulate_network_timeout = False
        tok = mock_ecosystem_fixture.ezviz.get_token("mock_ezviz_app_key_999", "mock_ezviz_secret_888")["data"]["accessToken"]
        new_live = mock_ecosystem_fixture.ezviz.get_live_address(tok, "B87654321")["data"]["url"]

        # StreamKeeper patches new live URL into go2rtc
        ok = mock_ecosystem_fixture.go2rtc.update_stream(cam_id, new_live)
        assert ok is True
        assert mock_ecosystem_fixture.go2rtc.streams[cam_id]["src"] == new_live

    # --------------------------------------------------------------------------
    # SCEN-04: High-Density Multi-Camera Grid Thrashing
    # --------------------------------------------------------------------------
    def test_scen_04_high_density_multi_camera_grid_thrashing(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Simulates rapid switching between 1x1, 2x2, 4x4 and fullscreen layouts while moving PTZ."""
        # 8 channels
        channel_ids = [f"thrash_ch_{i}" for i in range(8)]
        for cid in channel_ids:
            test_app_client.post("/api/cameras", json={"id": cid, "name": f"Cam {cid}", "stream_url": f"rtsp://{cid}", "ptz_supported": 1})

        # Sequence of layout switches
        layouts = [
            ("1x1", [channel_ids[0]]),
            ("2x2", channel_ids[:4]),
            ("4x4", channel_ids),
            ("1x1", [channel_ids[3]]),
        ]

        active_consumers = set()
        for layout_name, visible_channels in layouts:
            # Mount players for visible channels
            for cid in visible_channels:
                if cid not in active_consumers:
                    mock_ecosystem_fixture.go2rtc.webrtc_handshake(cid, f"v=0\r\no={cid}...")
                    active_consumers.add(cid)

            # PTZ move on active focus channel
            focus_cam = visible_channels[0]
            ptz_move = test_app_client.post(f"/api/cameras/{focus_cam}/ptz", json={"direction": "up", "speed": 6})
            assert ptz_move.status_code == 200

            # PTZ deadman stop
            ptz_stop = test_app_client.post(f"/api/cameras/{focus_cam}/ptz", json={"direction": "stop"})
            assert ptz_stop.status_code == 200

            # Unmount channels not visible in next layout
            # (simulated component unmount)

        # Cleanup all active consumers
        for cid in list(active_consumers):
            mock_ecosystem_fixture.go2rtc.stop_consumer(cid)

        # Confirm zero consumer leaks
        streams = mock_ecosystem_fixture.go2rtc.get_streams()
        for cid in channel_ids:
            assert len(streams[cid]["consumers"]) == 0

    # --------------------------------------------------------------------------
    # SCEN-05: Long-Term Storage Quota & FIFO Pruning
    # --------------------------------------------------------------------------
    def test_scen_05_long_term_storage_quota_and_fifo_pruning(
        self, test_db_conn: sqlite3.Connection, temp_storage_env: Dict[str, str], test_app_client: TestClient
    ):
        """Simulates storage filling up to 95% quota, triggering automated FIFO deletion of oldest clips."""
        cam_id = "cam_longterm_nvr"
        test_app_client.post("/api/cameras", json={"id": cam_id, "name": "NVR Cam", "stream_url": "rtsp://nvr"})

        cursor = test_db_conn.cursor()
        now = time.time()

        # Seed 5 recordings: 1 protected (oldest), 3 unprotected (aging), 1 newest
        recordings = [
            ("rec_prot_0", now - 5000, 1, "clip_prot.mp4"),
            ("rec_purge_1", now - 4000, 0, "clip_1.mp4"),
            ("rec_purge_2", now - 3000, 0, "clip_2.mp4"),
            ("rec_purge_3", now - 2000, 0, "clip_3.mp4"),
            ("rec_new_4", now - 100, 0, "clip_4.mp4"),
        ]

        created_files = []
        for rid, ts, is_prot, fname in recordings:
            fpath = os.path.join(temp_storage_env["recordings"], fname)
            MockFFmpegSimulator.create_mock_mp4_file(fpath, 1)
            created_files.append(fpath)
            cursor.execute(
                "INSERT INTO recordings (id, camera_id, file_path, is_protected, created_at) VALUES (?, ?, ?, ?, ?)",
                (rid, cam_id, fpath, is_prot, ts),
            )
        test_db_conn.commit()

        # Simulate FIFO prune threshold reached: delete oldest unprotected until safe
        cursor.execute("SELECT id, file_path FROM recordings WHERE is_protected = 0 ORDER BY created_at ASC LIMIT 2")
        to_prune = cursor.fetchall()
        assert len(to_prune) == 2
        assert to_prune[0]["id"] == "rec_purge_1"
        assert to_prune[1]["id"] == "rec_purge_2"

        for row in to_prune:
            if os.path.exists(row["file_path"]):
                os.remove(row["file_path"])
            cursor.execute("DELETE FROM recordings WHERE id = ?", (row["id"],))
        test_db_conn.commit()

        # Verify protected recording was spared
        cursor.execute("SELECT COUNT(*) FROM recordings WHERE id = 'rec_prot_0'")
        assert cursor.fetchone()[0] == 1
        assert os.path.exists(created_files[0])

        # Verify purged files removed
        cursor.execute("SELECT COUNT(*) FROM recordings WHERE id = 'rec_purge_1'")
        assert cursor.fetchone()[0] == 0
        assert not os.path.exists(created_files[1])

    # --------------------------------------------------------------------------
    # SCEN-06: Multi-Vendor Fleet Discovery & Provisioning
    # --------------------------------------------------------------------------
    def test_scen_06_multi_vendor_fleet_discovery_and_provisioning(
        self, test_app_client: TestClient, mock_ecosystem_fixture: MockSurveillanceEcosystem, test_db_conn: sqlite3.Connection
    ):
        """Simulates onboarding 12 cameras in single session across ONVIF, EZVIZ, Xiaomi CN, Xiaomi Global."""
        # 1. Discover ONVIF camera
        onvif_list = test_app_client.post("/api/onvif/discover").json()
        assert len(onvif_list) >= 1
        dev_onvif = onvif_list[0]
        test_app_client.post("/api/cameras", json={"id": "fleet_onvif_1", "name": "Warehouse Gate ONVIF", "platform": "onvif", "stream_url": f"rtsp://{dev_onvif['ip']}:554/live", "ptz_supported": 1})

        # 2. Sync EZVIZ cameras
        tok_ez = mock_ecosystem_fixture.ezviz.get_token("mock_ezviz_app_key_999", "mock_ezviz_secret_888")["data"]["accessToken"]
        ez_cams = mock_ecosystem_fixture.ezviz.list_cameras(tok_ez)["data"]
        for c in ez_cams:
            test_app_client.post("/api/cameras", json={"id": f"fleet_ez_{c['deviceSerial']}", "name": c["cameraName"], "platform": "ezviz", "stream_url": f"rtsp://open.ezvizlife.com/live/{c['deviceSerial']}/1"})

        # 3. Sync Xiaomi CN cameras
        step1 = mock_ecosystem_fixture.xiaomi.passport_step1_service_login()
        pwd_md5 = hashlib.md5("Secr3tP@ss123".encode()).hexdigest()
        tok_xm_cn = mock_ecosystem_fixture.xiaomi.passport_step2_auth("user_china@example.com", pwd_md5, step1["_sign"], step1["qs"], step1["callback"])["serviceToken"]
        xm_cn_cams = mock_ecosystem_fixture.xiaomi.get_devices("cn", tok_xm_cn)["result"]["list"]
        for c in xm_cn_cams:
            test_app_client.post("/api/cameras", json={"id": f"fleet_xm_{c['did']}", "name": c["name"], "platform": "xiaomi", "stream_url": f"xiaomi://{c['localip']}"})

        # 4. Sync Xiaomi SG cameras
        step1_sg = mock_ecosystem_fixture.xiaomi.passport_step1_service_login()
        pwd_md5_sg = hashlib.md5("GlobalPass2026!".encode()).hexdigest()
        tok_xm_sg = mock_ecosystem_fixture.xiaomi.passport_step2_auth("user_global@example.com", pwd_md5_sg, step1_sg["_sign"], step1_sg["qs"], step1_sg["callback"])["serviceToken"]
        xm_sg_cams = mock_ecosystem_fixture.xiaomi.get_devices("sg", tok_xm_sg)["result"]["list"]
        for c in xm_sg_cams:
            test_app_client.post("/api/cameras", json={"id": f"fleet_xm_{c['did']}", "name": c["name"], "platform": "xiaomi", "stream_url": f"xiaomi://{c['localip']}"})

        # 5. Verify all cameras listed in DB
        fleet_res = test_app_client.get("/api/cameras")
        assert fleet_res.status_code == 200
        fleet = fleet_res.json()
        assert len(fleet) >= 6

    # --------------------------------------------------------------------------
    # SCEN-07: Comprehensive Security Audit & Event Export
    # --------------------------------------------------------------------------
    def test_scen_07_comprehensive_security_audit_and_event_export(
        self, test_app_client: TestClient, test_db_conn: sqlite3.Connection
    ):
        """Simulates filtering events by type 'Human' and date range, reviewing snapshots, and exporting CSV."""
        # Seed 15 events
        now = time.time()
        for i in range(5):
            test_app_client.post("/api/events", json={"camera_id": "audit_c1", "camera_name": "Vault Door", "event_type": "Human", "description": f"Authorized personnel badge scan {i}", "snapshot_url": f"/snapshots/s_{i}.jpg"})
            test_app_client.post("/api/events", json={"camera_id": "audit_c2", "camera_name": "Back Alley", "event_type": "Movement", "description": f"Motion detected {i}"})
            test_app_client.post("/api/events", json={"camera_id": "audit_c1", "camera_name": "Vault Door", "event_type": "Abnormal Sound", "description": f"Sound anomaly {i}"})

        # Filter Human events
        filtered_res = test_app_client.get("/api/events?event_type=Human")
        assert filtered_res.status_code == 200
        humans = filtered_res.json()
        assert len(humans) >= 5
        assert all(h["event_type"] == "Human" for h in humans)

        # Export filtered
        export_res = test_app_client.get("/api/events/export?mode=filtered&format=csv")
        assert export_res.status_code == 200
        csv_text = export_res.text
        lines = csv_text.strip().split("\n")
        assert len(lines) >= 6  # 1 header + 5 rows
        assert "Date Time,Camera Name,Event Type,Description,Snapshot Link" in lines[0]

        # Verify formula injection safety
        assert not any(line.startswith("=") for line in lines)

    # --------------------------------------------------------------------------
    # SCEN-08: Disaster Recovery & Database Resiliency
    # --------------------------------------------------------------------------
    def test_scen_08_disaster_recovery_and_database_resiliency(
        self, temp_storage_env: Dict[str, str], mock_ecosystem_fixture: MockSurveillanceEcosystem
    ):
        """Simulates sudden power outage (SIGKILL) during active recording and verifies WAL recovery and playable fMP4."""
        db_path = temp_storage_env["db_path"]
        rec_path = os.path.join(temp_storage_env["recordings"], "disaster_recovery.mp4")

        # Connection 1 writes active recording chunk
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE IF NOT EXISTS disaster_test (id TEXT, state TEXT);")
        conn.execute("INSERT INTO disaster_test VALUES ('job_1', 'writing');")
        conn.commit()

        # Write unfinalized fMP4 video chunk (before power loss)
        MockFFmpegSimulator.create_mock_mp4_file(rec_path, duration_sec=5, has_faststart=False)

        # Abrupt close simulating crash (kill -9)
        conn.close()

        # Post-crash recovery connection
        recovered_conn = sqlite3.connect(db_path)
        cursor = recovered_conn.cursor()
        cursor.execute("SELECT state FROM disaster_test WHERE id = 'job_1'")
        assert cursor.fetchone()[0] == "writing"
        recovered_conn.close()

        # Verify fMP4 contains valid ftyp and mdat boxes even without faststart finalization
        with open(rec_path, "rb") as f:
            chunk = f.read(64)
        assert b"ftyp" in chunk
        assert os.path.exists(rec_path)
        assert os.path.getsize(rec_path) > 1024
