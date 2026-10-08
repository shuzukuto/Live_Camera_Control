"""
Unit Tests for go2rtc Media Gateway Supervisor and REST Client (backend/app/services/go2rtc_service.py)
"""

import os
import pytest
from pathlib import Path
import httpx

from app.services.go2rtc_service import (
    Go2rtcSupervisor,
    Go2rtcClient,
    Go2rtcError,
    Go2rtcStartupError,
    Go2rtcStreamNotFoundError,
    Go2rtcHttpError,
)


def test_go2rtc_supervisor_default_config_generation(tmp_path):
    """Supervisor synthesizes default go2rtc.yaml configuration."""
    bin_dir = tmp_path / "bin"
    config_path = tmp_path / "config" / "go2rtc.yaml"

    supervisor = Go2rtcSupervisor(
        bin_dir=bin_dir,
        config_path=config_path,
        auto_download=False,
    )

    created_path = supervisor.ensure_default_config()
    assert created_path.is_file()
    content = created_path.read_text(encoding="utf-8")

    assert "api:" in content
    assert '":1984"' in content
    assert "rtsp:" in content
    assert '":8554"' in content
    assert "webrtc:" in content
    assert '":8555"' in content
    assert "ffmpeg:" in content
    assert "stun.l.google.com" in content

    # Calling again should not overwrite existing modified config
    modified_yaml = content + "\n# custom modification\n"
    config_path.write_text(modified_yaml, encoding="utf-8")
    assert supervisor.ensure_default_config() == config_path
    assert "# custom modification" in config_path.read_text(encoding="utf-8")


def test_go2rtc_supervisor_binary_resolution_existing(tmp_path):
    """Supervisor detects existing binary in bin/."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    exe_name = "go2rtc.exe" if os.name == "nt" else "go2rtc"
    fake_bin = bin_dir / exe_name
    fake_bin.write_bytes(b"\x00" * 100)

    supervisor = Go2rtcSupervisor(
        bin_dir=bin_dir,
        config_path=tmp_path / "go2rtc.yaml",
        auto_download=False,
    )

    resolved = supervisor.resolve_binary()
    assert resolved == fake_bin


def test_go2rtc_supervisor_missing_binary_no_download(tmp_path):
    """Supervisor raises Go2rtcStartupError when binary is missing and auto_download=False."""
    supervisor = Go2rtcSupervisor(
        bin_dir=tmp_path / "empty_bin",
        config_path=tmp_path / "go2rtc.yaml",
        auto_download=False,
    )

    with pytest.raises(Go2rtcStartupError):
        supervisor.resolve_binary()


def test_go2rtc_supervisor_status_dict(tmp_path):
    """get_status returns comprehensive supervisor dictionary."""
    supervisor = Go2rtcSupervisor(
        bin_dir=tmp_path / "bin",
        config_path=tmp_path / "go2rtc.yaml",
    )
    status = supervisor.get_status()
    assert "is_running" in status
    assert "pid" in status
    assert "api_url" in status
    assert "is_ready" in status
    assert status["is_running"] is False


@pytest.mark.asyncio
async def test_go2rtc_rest_client_mock_transport():
    """Verify Go2rtcClient REST endpoints against mock HTTP transport."""
    mock_streams = {
        "cam_living_room": {
            "producers": [{"url": "rtsp://127.0.0.1:8554/cam_living_room"}],
            "consumers": [],
        }
    }

    # Custom httpx MockTransport
    def handler(request: httpx.Request) -> httpx.Response:
        url_path = request.url.path
        method = request.method

        if url_path == "/api/streams":
            if method == "GET":
                return httpx.Response(200, json=mock_streams)
            elif method == "PUT":
                name = request.url.params.get("name")
                src = request.url.params.get("src")
                mock_streams[name] = {"producers": [{"url": src}], "consumers": []}
                return httpx.Response(200, json={"status": "ok"})
            elif method == "PATCH":
                name = request.url.params.get("name")
                src = request.url.params.get("src")
                if name in mock_streams:
                    mock_streams[name]["producers"] = [{"url": src}]
                    return httpx.Response(200, json={"status": "patched"})
                return httpx.Response(404, text="Stream not found")
            elif method == "DELETE":
                src = request.url.params.get("src")
                mock_streams.pop(src, None)
                return httpx.Response(200, json={"status": "deleted"})

        elif url_path == "/api/frame.jpeg":
            src = request.url.params.get("src")
            if src in mock_streams:
                # Return dummy JPEG bytes
                return httpx.Response(200, content=b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\xFF\xD9")
            return httpx.Response(404, text="Frame not found")

        elif url_path == "/api/webrtc":
            return httpx.Response(200, text="v=0\r\no=go2rtc ... sdp answer")

        return httpx.Response(404, text="Not Found")

    transport = httpx.MockTransport(handler)
    client = Go2rtcClient(api_url="http://mock.go2rtc:1984")
    # Inject mock client
    client._client = httpx.AsyncClient(transport=transport, base_url="http://mock.go2rtc:1984")

    # 1. get_streams
    streams = await client.get_streams()
    assert "cam_living_room" in streams

    # 2. get_stream
    stream = await client.get_stream("cam_living_room")
    assert stream is not None
    assert stream["producers"][0]["url"] == "rtsp://127.0.0.1:8554/cam_living_room"

    assert await client.get_stream("unknown_cam") is None

    # 3. add_stream
    added = await client.add_stream("cam_front", "rtsp://192.168.1.100/ch0")
    assert added is True
    assert "cam_front" in (await client.get_streams())

    # 4. update_stream (hot-swap)
    updated = await client.update_stream("cam_front", "rtsp://192.168.1.100/ch1_renewed")
    assert updated is True
    stream_front = await client.get_stream("cam_front")
    assert stream_front["producers"][0]["url"] == "rtsp://192.168.1.100/ch1_renewed"

    # 5. get_frame
    jpeg_bytes = await client.get_frame("cam_front")
    assert jpeg_bytes.startswith(b"\xFF\xD8")

    with pytest.raises(Go2rtcStreamNotFoundError):
        await client.get_frame("non_existent_stream")

    # 6. negotiate_webrtc
    sdp_answer = await client.negotiate_webrtc("cam_front", "v=0\r\no=client ... sdp offer")
    assert "sdp answer" in sdp_answer

    # 7. remove_stream
    removed = await client.remove_stream("cam_front")
    assert removed is True
    assert "cam_front" not in (await client.get_streams())

    await client.close()
