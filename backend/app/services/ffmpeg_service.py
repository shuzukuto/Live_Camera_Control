"""
FFmpeg Resolver Service
Locates and validates FFmpeg executable from imageio_ffmpeg, system PATH, or bin/.
"""

import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger("nvr.ffmpeg")


class FFmpegNotFoundError(RuntimeError):
    """Raised when no valid FFmpeg executable could be located."""
    pass


class FFmpegExecutionError(RuntimeError):
    """Raised when FFmpeg executable fails health check."""
    pass


class FFmpegService:
    """
    Manages discovery, caching, and health verification of the FFmpeg binary.
    """

    def __init__(self, bin_dir: Optional[Path] = None):
        self._bin_dir = bin_dir or Path("bin")
        self._cached_path: Optional[str] = None
        self._cached_version: Optional[str] = None

    def get_ffmpeg_path(self, force_refresh: bool = False) -> str:
        """
        Resolves the FFmpeg executable path.
        Priority:
        1. imageio_ffmpeg.get_ffmpeg_exe()
        2. System PATH (shutil.which('ffmpeg'))
        3. bin/ffmpeg.exe or bin/ffmpeg
        """
        if self._cached_path and not force_refresh:
            return self._cached_path

        resolved_path: Optional[str] = None
        source: str = ""

        # Tier 1: imageio_ffmpeg
        try:
            import imageio_ffmpeg
            candidate = imageio_ffmpeg.get_ffmpeg_exe()
            if candidate and os.path.isfile(candidate):
                # On Windows os.X_OK is not strictly necessary, but check if file is readable
                resolved_path = candidate
                source = "imageio_ffmpeg"
        except ImportError:
            logger.debug("imageio_ffmpeg module not installed")
        except Exception as e:
            logger.warning("Error querying imageio_ffmpeg: %s", e)

        # Tier 2: System PATH
        if not resolved_path:
            candidate = shutil.which("ffmpeg")
            if candidate:
                resolved_path = candidate
                source = "system_path"

        # Tier 3: Local project bin/ directory
        if not resolved_path:
            exe_name = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
            candidate_path = self._bin_dir / exe_name
            if candidate_path.is_file():
                resolved_path = str(candidate_path.resolve())
                source = "local_bin"

        if not resolved_path:
            raise FFmpegNotFoundError(
                "FFmpeg binary not found. Please install imageio-ffmpeg or add ffmpeg to system PATH."
            )

        # Probe and verify executable
        version_info = self.verify_executable(resolved_path)
        self._cached_path = resolved_path
        self._cached_version = version_info.get("version", "unknown")

        logger.info(
            "FFmpeg resolved successfully via %s: %s (version: %s)",
            source,
            resolved_path,
            self._cached_version,
        )
        return resolved_path

    def verify_executable(self, path: str) -> Dict[str, Any]:
        """
        Executes '{path} -version' and parses version details.
        """
        if not os.path.isfile(path):
            raise FFmpegNotFoundError(f"File does not exist: {path}")

        try:
            creationflags = 0
            if os.name == "nt":
                creationflags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                [path, "-version"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
                creationflags=creationflags,
            )
            if result.returncode != 0:
                raise FFmpegExecutionError(
                    f"FFmpeg returned exit code {result.returncode}: {result.stderr.strip()}"
                )

            lines = result.stdout.splitlines()
            header = lines[0] if lines else "unknown"
            parts = header.split()
            version = parts[2] if len(parts) >= 3 else header

            return {
                "path": path,
                "version": version,
                "header": header,
                "is_valid": True,
            }
        except subprocess.TimeoutExpired as e:
            raise FFmpegExecutionError(f"FFmpeg probe timed out after 5s: {path}") from e
        except Exception as e:
            raise FFmpegExecutionError(f"Failed to execute FFmpeg at {path}: {e}") from e

    def get_status(self) -> Dict[str, Any]:
        """Returns health status dictionary for /api/health endpoint."""
        try:
            path = self.get_ffmpeg_path()
            return {
                "status": "available",
                "version": self._cached_version or "unknown",
                "path": path,
            }
        except Exception as e:
            return {
                "status": "unavailable",
                "error": str(e),
            }


# Global singleton instance
ffmpeg_service = FFmpegService()
