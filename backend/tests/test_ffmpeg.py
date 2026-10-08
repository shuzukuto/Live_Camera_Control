"""
Unit Tests for FFmpeg Resolver Service (backend/app/services/ffmpeg_service.py)
"""

import os
import pytest
from pathlib import Path

from app.services.ffmpeg_service import (
    FFmpegService,
    ffmpeg_service,
    FFmpegNotFoundError,
    FFmpegExecutionError,
)


def test_ffmpeg_resolve_bundled_binary():
    """Verify resolver successfully locates bundled imageio_ffmpeg binary."""
    path = ffmpeg_service.get_ffmpeg_path()
    assert path is not None
    assert os.path.isfile(path)
    assert os.path.exists(path)


def test_ffmpeg_verify_executable():
    """Verify -version probe returns valid output and version information."""
    path = ffmpeg_service.get_ffmpeg_path()
    info = ffmpeg_service.verify_executable(path)
    assert info["is_valid"] is True
    assert "version" in info
    assert len(info["version"]) > 0
    # Version should start with 6 or 7 on modern setups (v7.1 on host)
    assert info["version"].startswith("7.") or info["version"].startswith("6.") or "ffmpeg" in info["header"].lower()


def test_ffmpeg_status_report():
    """Verify get_status returns 'available' status with details."""
    status = ffmpeg_service.get_status()
    assert status["status"] == "available"
    assert "version" in status
    assert "path" in status
    assert os.path.isfile(status["path"])


def test_ffmpeg_non_existent_file():
    """Probing non-existent path raises FFmpegNotFoundError."""
    service = FFmpegService()
    with pytest.raises(FFmpegNotFoundError):
        service.verify_executable("non_existent_path_to_ffmpeg_binary_xyz.exe")


def test_ffmpeg_execution_error_on_invalid_binary(tmp_path):
    """Running an invalid or corrupted file as ffmpeg raises FFmpegExecutionError."""
    dummy_bin = tmp_path / "dummy_ffmpeg.exe"
    # Create non-executable text file
    dummy_bin.write_text("corrupted_binary_content", encoding="utf-8")

    service = FFmpegService()
    with pytest.raises(FFmpegExecutionError):
        service.verify_executable(str(dummy_bin))


def test_ffmpeg_custom_bin_discovery(tmp_path, monkeypatch):
    """Verify Tier 3 discovery finds binary in custom bin/ dir when imageio is unavailable."""
    # Mock imageio_ffmpeg import failure and empty PATH
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    import sys
    monkeypatch.setitem(sys.modules, "imageio_ffmpeg", None)

    # Place a copy of real ffmpeg in custom bin dir
    real_path = ffmpeg_service.get_ffmpeg_path()
    custom_bin_dir = tmp_path / "bin"
    custom_bin_dir.mkdir(parents=True)
    exe_name = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
    target_bin = custom_bin_dir / exe_name

    import shutil
    shutil.copy2(real_path, target_bin)

    custom_service = FFmpegService(bin_dir=custom_bin_dir)
    found_path = custom_service.get_ffmpeg_path(force_refresh=True)
    assert found_path == str(target_bin.resolve())
