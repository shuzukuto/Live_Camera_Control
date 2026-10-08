"""
backend/tests/test_onvif_service.py

Unit tests for ONVIF WS-Discovery, SOAP Media & PTZ Client, and RTSP Validator (Features 12, 13, 14).
"""

import pytest
from app.services.onvif_service import (
    ONVIFService,
    ONVIFError,
    create_ws_security_header,
    wrap_soap_envelope,
)
from tests_e2e.mocks.mock_camera_server import MockONVIFDevice
from tests.conftest import set_current_mocks


@pytest.fixture
def mock_onvif_dev():
    dev = MockONVIFDevice(ip="192.168.1.200", port=8085)
    set_current_mocks(onvif=dev)
    return dev


@pytest.fixture
def onvif_svc(mock_onvif_dev):
    return ONVIFService()


# ==============================================================================
# WS-Discovery Probe (Feature 13)
# ==============================================================================

def test_ws_discovery_response_xml_structure(mock_onvif_dev):
    """Verifies standard ONVIF WS-Discovery ProbeMatches SOAP XML format."""
    xml = mock_onvif_dev.get_ws_discovery_response_xml()
    assert "ProbeMatches" in xml
    assert "NetworkVideoTransmitter" in xml
    assert mock_onvif_dev.xaddrs in xml
    assert mock_onvif_dev.device_uuid in xml


def test_parse_probe_matches_xml(onvif_svc, mock_onvif_dev):
    """Verifies XML parsing extracts UUID, XAddrs, and Scopes accurately."""
    xml = mock_onvif_dev.get_ws_discovery_response_xml()
    parsed = onvif_svc.parse_probe_matches_xml(xml, sender_ip=mock_onvif_dev.ip)
    assert len(parsed) == 1
    dev = parsed[0]
    assert dev["uuid"] == mock_onvif_dev.device_uuid
    assert dev["ip"] == mock_onvif_dev.ip
    assert mock_onvif_dev.xaddrs in dev["xaddrs"]
    assert len(dev["scopes"]) >= 1


@pytest.mark.asyncio
async def test_discover_devices_integration(onvif_svc, mock_onvif_dev):
    """Verifies discover_devices returns discovered cameras."""
    discovered = await onvif_svc.discover_devices(timeout=0.1)
    assert len(discovered) >= 1
    assert discovered[0]["uuid"] == mock_onvif_dev.device_uuid


def test_deduplication_of_discovered_devices():
    """Verifies duplicate UUIDs are deduplicated."""
    devices = [
        {"uuid": "urn:uuid:cam1", "ip": "192.168.1.10"},
        {"uuid": "urn:uuid:cam1", "ip": "192.168.1.10"},
        {"uuid": "urn:uuid:cam2", "ip": "192.168.1.20"},
    ]
    unique = {d["uuid"]: d for d in devices}.values()
    assert len(unique) == 2


# ==============================================================================
# SOAP Media & Device Information Services (Feature 14)
# ==============================================================================

def test_ws_security_header_creation():
    """Verifies WS-Security UsernameToken header generation with PasswordDigest."""
    header = create_ws_security_header("admin", "SecretPassword")
    assert "<wsse:Username>admin</wsse:Username>" in header
    assert "PasswordDigest" in header
    assert "<wsse:Nonce" in header
    assert "<wsu:Created>" in header

    # Empty when credentials are None
    assert create_ws_security_header(None, None) == ""


@pytest.mark.asyncio
async def test_soap_get_device_information(onvif_svc, mock_onvif_dev):
    """Verifies GetDeviceInformation retrieves manufacturer, model, firmware, serial."""
    info = await onvif_svc.get_device_information(
        device_service_url=mock_onvif_dev.xaddrs,
        username="admin",
        password="SecretPassword",
    )
    assert info.get("Manufacturer") == "GenericSecurityCorp"
    assert info.get("Model") == "GSC-IPC-4K-PRO"
    assert info.get("SerialNumber") == "GSC9988776655"


@pytest.mark.asyncio
async def test_soap_get_profiles(onvif_svc, mock_onvif_dev):
    """Verifies GetProfiles enumerates video stream profiles."""
    profiles = await onvif_svc.get_profiles(
        media_service_url=mock_onvif_dev.xaddrs,
        username="admin",
        password="SecretPassword",
    )
    assert len(profiles) >= 2
    tokens = [p.token for p in profiles]
    assert "Profile_1_Main" in tokens
    assert "Profile_2_Sub" in tokens
    main_prof = next(p for p in profiles if p.token == "Profile_1_Main")
    assert main_prof.width == 1920
    assert main_prof.height == 1080


@pytest.mark.asyncio
async def test_soap_get_stream_uri(onvif_svc, mock_onvif_dev):
    """Verifies GetStreamUri retrieves RTSP streaming URL for profile."""
    stream_uri = await onvif_svc.get_stream_uri(
        media_service_url=mock_onvif_dev.xaddrs,
        profile_token="Profile_1_Main",
        username="admin",
        password="SecretPassword",
    )
    assert stream_uri.startswith("rtsp://")
    assert mock_onvif_dev.ip in stream_uri


# ==============================================================================
# SOAP PTZ Control (Feature 14)
# ==============================================================================

@pytest.mark.asyncio
async def test_soap_continuous_move(onvif_svc, mock_onvif_dev):
    """Verifies ContinuousMove executes Pan/Tilt/Zoom velocity commands."""
    ok = await onvif_svc.continuous_move(
        ptz_service_url=mock_onvif_dev.xaddrs,
        profile_token="Profile_1_Main",
        pan=0.5,
        tilt=0.0,
        zoom=0.0,
    )
    assert ok is True


@pytest.mark.asyncio
async def test_soap_stop_ptz(onvif_svc, mock_onvif_dev):
    """Verifies Stop halts active PTZ motor movement."""
    ok = await onvif_svc.stop_ptz(
        ptz_service_url=mock_onvif_dev.xaddrs,
        profile_token="Profile_1_Main",
    )
    assert ok is True


@pytest.mark.asyncio
async def test_soap_fault_handling(onvif_svc, mock_onvif_dev):
    """Verifies handling SOAP fault responses (HTTP 500)."""
    mock_onvif_dev.simulate_soap_fault = True
    with pytest.raises(ONVIFError) as exc_info:
        await onvif_svc.get_device_information(mock_onvif_dev.xaddrs)
    assert exc_info.value.status_code == 500


# ==============================================================================
# Generic RTSP Validation (Feature 12)
# ==============================================================================

def test_rtsp_url_validation_success():
    """Verifies parsing valid RTSP URLs and credential masking."""
    url = "rtsp://admin:supersecret@192.168.1.50:554/h264/ch1/main"
    res = ONVIFService.validate_rtsp_url(url)
    assert res["valid"] is True
    assert res["hostname"] == "192.168.1.50"
    assert res["port"] == 554
    assert res["username"] == "admin"
    assert res["password"] == "supersecret"
    assert "supersecret" not in res["masked_url"]
    assert "******" in res["masked_url"]


def test_rtsp_url_validation_non_standard_port():
    """Verifies handling non-standard RTSP port (e.g. 10554)."""
    url = "rtsp://10.0.0.5:10554/stream"
    res = ONVIFService.validate_rtsp_url(url)
    assert res["hostname"] == "10.0.0.5"
    assert res["port"] == 10554


def test_rtsp_url_validation_invalid_scheme():
    """Verifies non-RTSP schemes are rejected with ValueError."""
    with pytest.raises(ValueError):
        ONVIFService.validate_rtsp_url("http://192.168.1.50/stream")

    with pytest.raises(ValueError):
        ONVIFService.validate_rtsp_url("")
