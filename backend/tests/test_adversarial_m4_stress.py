"""
stress_m4_1_verify.py

Adversarial Stress Test Harness for Milestone 4:
Features 21, 23, and 24.
"""

import asyncio
import csv
import io
import os
import sys
import tempfile
import time
from typing import Any, Dict, List

import openpyxl
from fastapi.testclient import TestClient

# Setup sys.path for backend imports
backend_dir = os.path.abspath("backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database import get_db, init_db, set_database_path, query_event_logs, save_event_log
from app.main import app
from app.models.event import CanonicalEventType
from app.services.event_service import event_service
from app.utils.export import sanitize_spreadsheet_cell, export_events_csv, export_events_xlsx, EXPORT_HEADERS


def run_tests():
    print("=" * 70)
    print("RUNNING ADVERSARIAL CHALLENGER M4.1 STRESS SUITE")
    print("=" * 70)

    # Isolated temporary database
    temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db", prefix="m4_1_stress_")
    os.close(temp_db_fd)
    set_database_path(temp_db_path)
    asyncio.run(init_db())
    print(f"[*] Initialized isolated SQLite DB: {temp_db_path}")

    passed = 0
    failed = 0

    def assert_true(cond, name, details=""):
        nonlocal passed, failed
        if cond:
            print(f"  [PASS] {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name} - {details}")
            failed += 1

    # =========================================================================
    # PART 1: NORMALIZATION FUZZING (FEATURE 21)
    # =========================================================================
    print("\n--- PART 1: NORMALIZATION FUZZING (FEATURE 21) ---")

    # 1.1 Extreme 20,000+ to 100,000 char strings
    huge_human = "A" * 20000 + "_PERSON_ALERT_" + "B" * 20000
    huge_sound = "S" * 30000 + "_BABY_CRYING_" + "T" * 30000
    huge_random = "Z" * 50000

    assert_true(event_service.normalize_event_type(huge_human) == "Human", "20k+ char string with PERSON normalizes to Human")
    assert_true(event_service.normalize_event_type(huge_sound) == "Abnormal Sound", "30k+ char string with CRY normalizes to Abnormal Sound")
    assert_true(event_service.normalize_event_type(huge_random) == "Movement", "50k+ char random string defaults to Movement")

    # 1.2 Performance & Absence of polynomial regex slowdown
    t0 = time.perf_counter()
    iterations = 500
    for _ in range(iterations):
        event_service.normalize_event_type(huge_human)
    t_elapsed = time.perf_counter() - t0
    avg_ms = (t_elapsed / iterations) * 1000.0
    print(f"      [Perf] 500 calls on 40,014-char string took {t_elapsed:.4f}s (avg {avg_ms:.4f}ms/call)")
    assert_true(avg_ms < 5.0, f"No polynomial slowdown: avg {avg_ms:.4f}ms < 5.0ms")

    # 1.3 Mixed Whitespace (\t\n\r\v\f)
    assert_true(event_service.normalize_event_type("\t\t\n\r  human  \v\f ") == "Human", "Mixed whitespace with human -> Human")
    assert_true(event_service.normalize_event_type("\r\n\t  AUDIO_ALERT \t ") == "Abnormal Sound", "Mixed whitespace with audio -> Abnormal Sound")
    assert_true(event_service.normalize_event_type("   \t\n\r   ") == "Movement", "All whitespace string -> Movement")
    assert_true(event_service.normalize_event_type("") == "Movement", "Empty string -> Movement")
    assert_true(event_service.normalize_event_type(None) == "Movement", "None value -> Movement")

    # 1.4 Compound keywords & Strict Precedence
    assert_true(event_service.normalize_event_type("human_screaming_sound") == "Human", "Precedence: human_screaming_sound -> Human")
    assert_true(event_service.normalize_event_type("sound_of_person_walking") == "Human", "Precedence: sound_of_person_walking -> Human")
    assert_true(event_service.normalize_event_type("intruder_barking_dog_alarm") == "Human", "Precedence: intruder (human) over dog bark -> Human")
    assert_true(event_service.normalize_event_type("motion_glass_break_sound") == "Abnormal Sound", "Precedence: sound over motion -> Abnormal Sound")
    assert_true(event_service.normalize_event_type("motion_line_crossing_tripwire") == "Movement", "Fallback: motion_line_crossing -> Movement")

    # 1.5 Unicode and Emojis
    assert_true(event_service.normalize_event_type("🚨 Cảnh báo Người (human) xuất hiện 👤") == "Human", "Unicode Vietnamese with keyword -> Human")
    assert_true(event_service.normalize_event_type("人脸识别 face detected") == "Human", "Unicode Chinese with keyword -> Human")
    assert_true(event_service.normalize_event_type("🔊 tiếng động lớn sound anomaly") == "Abnormal Sound", "Unicode with sound keyword -> Abnormal Sound")
    assert_true(event_service.normalize_event_type("CHUYỂN_ĐỘNG_KHÔNG_RÕ") == "Movement", "Unicode non-matching defaults to Movement")

    # 1.6 Non-string input robustness
    assert_true(event_service.normalize_event_type(12345) == "Movement", "Integer 12345 defaults to Movement")
    assert_true(event_service.normalize_event_type(["human"]) == "Human", "List ['human'] coerced to string matches Human")

    # =========================================================================
    # PART 2: SQL WILDCARD & INJECTION SAFETY (FEATURE 23)
    # =========================================================================
    print("\n--- PART 2: SQL WILDCARD & INJECTION SAFETY (FEATURE 23) ---")

    # Seed 3 distinct records
    async def seed_events():
        await save_event_log({
            "camera_id": "cam_sec_1",
            "camera_name": "Backyard North",
            "event_type": "Human",
            "description": "Legitimate package delivery courier",
            "severity": "high",
        })
        await save_event_log({
            "camera_id": "cam_sec_2",
            "camera_name": "Driveway East",
            "event_type": "Movement",
            "description": "Wind blown tree branch motion",
            "severity": "low",
        })
        await save_event_log({
            "camera_id": "cam_sec_3",
            "camera_name": "Lobby Main",
            "event_type": "Abnormal Sound",
            "description": "Night guard dropped keys noise",
            "severity": "medium",
        })

    asyncio.run(seed_events())

    with TestClient(app) as client:
        # 2.1 Wildcards: '%' and '_'
        res_percent = client.get("/api/events?query=%")
        assert_true(res_percent.status_code == 200, "Query with '%' returns 200")
        assert_true(len(res_percent.json()) == 3, f"Query with '%' matches all 3 rows safely (got {len(res_percent.json())})")

        res_underscore = client.get("/api/events?query=_")
        assert_true(res_underscore.status_code == 200, "Query with '_' returns 200")
        assert_true(isinstance(res_underscore.json(), list), "Query with '_' returns list")

        # 2.2 SQL Injection Payload: ' OR '1'='1
        # If parameterized, LIKE ? will search literally for "%' OR '1'='1%". Since no description has this, it returns 0.
        # If vulnerable to SQL injection, it would evaluate OR '1'='1 and return ALL 3 rows!
        res_sqli_or = client.get("/api/events?query=' OR '1'='1")
        assert_true(res_sqli_or.status_code == 200, "Query with \"' OR '1'='1\" returns 200 (no 500 error)")
        assert_true(len(res_sqli_or.json()) == 0, f"Query with \"' OR '1'='1\" returns 0 rows (NOT leaked via injection; got {len(res_sqli_or.json())})")

        # 2.3 SQL Injection Payload: '; DROP TABLE event_logs; --
        res_sqli_drop = client.get("/api/events?query='; DROP TABLE event_logs; --")
        assert_true(res_sqli_drop.status_code == 200, "Query with DROP TABLE returns 200")
        assert_true(len(res_sqli_drop.json()) == 0, "Query with DROP TABLE returns 0 rows")

        # Verify table still exists and data intact
        res_check = client.get("/api/events")
        assert_true(res_check.status_code == 200 and len(res_check.json()) == 3, "Table event_logs still intact after DROP attempt")

        # 2.4 SQL Injection in other parameters: camera_id, event_type, severity
        res_cam_sqli = client.get("/api/events?camera_id=' OR 1=1 --")
        assert_true(res_cam_sqli.status_code == 200 and len(res_cam_sqli.json()) == 0, "camera_id SQL injection safe (0 rows returned)")

        res_type_sqli = client.get("/api/events?event_type=' OR 1=1 --")
        assert_true(res_type_sqli.status_code == 200 and len(res_type_sqli.json()) == 0, "event_type SQL injection safe (0 rows returned)")

        res_sev_sqli = client.get("/api/events?severity=' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 --")
        assert_true(res_sev_sqli.status_code == 200 and len(res_sev_sqli.json()) == 0, "severity UNION SQL injection safe (0 rows returned)")

        # 2.5 Multi-column search verification
        res_col_cam = client.get("/api/events?query=Driveway")
        assert_true(len(res_col_cam.json()) == 1 and res_col_cam.json()[0]["camera_id"] == "cam_sec_2", "query matches camera_name column")

        res_col_desc = client.get("/api/events?query=courier")
        assert_true(len(res_col_desc.json()) == 1 and res_col_desc.json()[0]["camera_id"] == "cam_sec_1", "query matches description column")

        res_col_type = client.get("/api/events?query=Abnormal")
        assert_true(len(res_col_type.json()) == 1 and res_col_type.json()[0]["camera_id"] == "cam_sec_3", "query matches event_type column")

    # =========================================================================
    # PART 3: SPREADSHEET FORMULA INJECTION (DDE) DEFENSE (FEATURE 24)
    # =========================================================================
    print("\n--- PART 3: SPREADSHEET FORMULA INJECTION (DDE) DEFENSE (FEATURE 24) ---")

    # 3.1 Unit sanitizer verification on =, +, -, @
    dangerous_payloads = [
        "=cmd|'/C calc'!A0",
        "=1+1",
        "=SUM(A1:B10)",
        "+cmd|'/C calc'!A0",
        "+1+1",
        "+500",
        "-cmd|'/C calc'!A0",
        "-10",
        "-2+3",
        "@SUM(A1:B10)",
        "@cmd|'/C calc'!A0",
        "  =cmd|' /C notepad'!A0",  # leading spaces
        "\t+malicious_dde",         # leading tab
        "\n@formula_cell",          # leading newline
    ]

    for p in dangerous_payloads:
        san = sanitize_spreadsheet_cell(p)
        assert_true(san.startswith("'"), f"Sanitizer prepends \"'\" to {repr(p)} -> {repr(san)}")

    safe_inputs = ["Normal camera", "12345", "Human Detection", "Gate 1", ""]
    for s in safe_inputs:
        san = sanitize_spreadsheet_cell(s)
        assert_true(not san.startswith("'") or s == "", f"Sanitizer does NOT alter safe text: {repr(s)}")

    # 3.2 End-to-end CSV and XLSX DDE injection defense test
    async def seed_dde_events():
        await event_service.record_event({
            "camera_id": "cam_dde",
            "camera_name": "=cmd|' /C calc'!A0",
            "event_type": "+1+1",  # Will normalize to Movement canonical, vendor_raw_type="+1+1"
            "description": "-malicious_calc_formula",
            "snapshot_url": "@hyperlink_exfiltration",
        })

    asyncio.run(seed_dde_events())

    with TestClient(app) as client:
        # Check CSV Export
        res_csv = client.get("/api/events/export?mode=all&format=csv")
        assert_true(res_csv.status_code == 200, "CSV export returns 200")
        csv_reader = csv.reader(io.StringIO(res_csv.text))
        csv_rows = list(csv_reader)
        # Find the DDE row
        dde_row = None
        for r in csv_rows:
            if any("calc" in cell for cell in r):
                dde_row = r
                break

        assert_true(dde_row is not None, "DDE row found in CSV export")
        if dde_row:
            # Header: Date Time, Camera Name, Event Type, Description, Snapshot Link
            cam_cell = dde_row[1]
            evt_cell = dde_row[2]
            desc_cell = dde_row[3]
            snap_cell = dde_row[4]

            assert_true(cam_cell.startswith("'="), f"CSV Camera Name begins with \"'=\": {cam_cell}")
            assert_true(evt_cell.startswith("'+"), f"CSV Event Type begins with \"'+\": {evt_cell}")
            assert_true(desc_cell.startswith("'-"), f"CSV Description begins with \"'-\": {desc_cell}")
            assert_true(snap_cell.startswith("'@"), f"CSV Snapshot Link begins with \"'@\": {snap_cell}")

        # Check XLSX Export
        res_xlsx = client.get("/api/events/export?mode=all&format=xlsx")
        assert_true(res_xlsx.status_code == 200, "XLSX export returns 200")
        wb = openpyxl.load_workbook(io.BytesIO(res_xlsx.content))
        ws = wb.active
        assert_true(ws.title == "Event Logs", f"XLSX sheet title is 'Event Logs' (got {ws.title})")

        xlsx_dde_row = None
        for row in ws.iter_rows(values_only=True):
            if any("calc" in str(cell or "") for cell in row):
                xlsx_dde_row = row
                break

        assert_true(xlsx_dde_row is not None, "DDE row found in XLSX export")
        if xlsx_dde_row:
            x_cam = str(xlsx_dde_row[1])
            x_evt = str(xlsx_dde_row[2])
            x_desc = str(xlsx_dde_row[3])
            x_snap = str(xlsx_dde_row[4])
            assert_true(x_cam.startswith("'="), f"XLSX Camera Name begins with \"'=\": {x_cam}")
            assert_true(x_evt.startswith("'+"), f"XLSX Event Type begins with \"'+\": {x_evt}")
            assert_true(x_desc.startswith("'-"), f"XLSX Description begins with \"'-\": {x_desc}")
            assert_true(x_snap.startswith("'@"), f"XLSX Snapshot Link begins with \"'@\": {x_snap}")

    # =========================================================================
    # PART 4: EXPORT MODE BOUNDARIES (FEATURE 24)
    # =========================================================================
    print("\n--- PART 4: EXPORT MODE BOUNDARIES (FEATURE 24) ---")

    with TestClient(app) as client:
        # Current DB has 4 records (3 original + 1 DDE)
        # 4.1 mode=template: strictly header line only (1 line in CSV, 1 row in XLSX)
        res_tpl_csv = client.get("/api/events/export?mode=template&format=csv")
        assert_true(res_tpl_csv.status_code == 200, "mode=template CSV returns 200")
        tpl_csv_lines = [l for l in res_tpl_csv.text.strip().split("\n") if l]
        assert_true(len(tpl_csv_lines) == 1, f"mode=template CSV strictly has 1 line (got {len(tpl_csv_lines)})")
        assert_true("Date Time,Camera Name,Event Type" in tpl_csv_lines[0], "mode=template line is header")

        res_tpl_xlsx = client.get("/api/events/export?mode=template&format=xlsx")
        assert_true(res_tpl_xlsx.status_code == 200, "mode=template XLSX returns 200")
        wb_tpl = openpyxl.load_workbook(io.BytesIO(res_tpl_xlsx.content))
        ws_tpl = wb_tpl.active
        assert_true(ws_tpl.max_row == 1, f"mode=template XLSX strictly has 1 row (got {ws_tpl.max_row})")

        # 4.2 mode=unknown_999 falls back to all (1 header + 4 records = 5 lines)
        res_unk_csv = client.get("/api/events/export?mode=unknown_999&format=csv")
        assert_true(res_unk_csv.status_code == 200, "mode=unknown_999 CSV returns 200")
        unk_csv_lines = [l for l in res_unk_csv.text.strip().split("\n") if l]
        assert_true(len(unk_csv_lines) == 5, f"mode=unknown_999 fallback to all: got 5 lines (1 header + 4 rows; got {len(unk_csv_lines)})")

        res_unk_xlsx = client.get("/api/events/export?mode=unknown_999&format=xlsx")
        assert_true(res_unk_xlsx.status_code == 200, "mode=unknown_999 XLSX returns 200")
        wb_unk = openpyxl.load_workbook(io.BytesIO(res_unk_xlsx.content))
        ws_unk = wb_unk.active
        assert_true(ws_unk.max_row == 5, f"mode=unknown_999 XLSX fallback to all: got 5 rows (got {ws_unk.max_row})")

        # 4.3 0-record table boundaries
        async def clear_events():
            async with get_db() as conn:
                await conn.execute("DELETE FROM event_logs;")
                await conn.commit()

        asyncio.run(clear_events())

        # Test 0-record table for mode=all, mode=filtered, mode=template
        res_zero_all_csv = client.get("/api/events/export?mode=all&format=csv")
        zero_all_lines = [l for l in res_zero_all_csv.text.strip().split("\n") if l]
        assert_true(len(zero_all_lines) == 1, f"0-record mode=all CSV strictly header only (got {len(zero_all_lines)})")

        res_zero_flt_csv = client.get("/api/events/export?mode=filtered&format=csv")
        zero_flt_lines = [l for l in res_zero_flt_csv.text.strip().split("\n") if l]
        assert_true(len(zero_flt_lines) == 1, f"0-record mode=filtered CSV strictly header only (got {len(zero_flt_lines)})")

        res_zero_tpl_csv = client.get("/api/events/export?mode=template&format=csv")
        zero_tpl_lines = [l for l in res_zero_tpl_csv.text.strip().split("\n") if l]
        assert_true(len(zero_tpl_lines) == 1, f"0-record mode=template CSV strictly header only (got {len(zero_tpl_lines)})")

        res_zero_all_xlsx = client.get("/api/events/export?mode=all&format=xlsx")
        wb_zero_all = openpyxl.load_workbook(io.BytesIO(res_zero_all_xlsx.content))
        assert_true(wb_zero_all.active.max_row == 1, f"0-record mode=all XLSX strictly 1 row (got {wb_zero_all.active.max_row})")

        res_zero_flt_xlsx = client.get("/api/events/export?mode=filtered&format=xlsx")
        wb_zero_flt = openpyxl.load_workbook(io.BytesIO(res_zero_flt_xlsx.content))
        assert_true(wb_zero_flt.active.max_row == 1, f"0-record mode=filtered XLSX strictly 1 row (got {wb_zero_flt.active.max_row})")

        res_zero_tpl_xlsx = client.get("/api/events/export?mode=template&format=xlsx")
        wb_zero_tpl = openpyxl.load_workbook(io.BytesIO(res_zero_tpl_xlsx.content))
        assert_true(wb_zero_tpl.active.max_row == 1, f"0-record mode=template XLSX strictly 1 row (got {wb_zero_tpl.active.max_row})")

    # Clean up temp db
    try:
        os.remove(temp_db_path)
    except Exception:
        pass

    print("\n" + "=" * 70)
    print(f"ADVERSARIAL STRESS TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 70)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
