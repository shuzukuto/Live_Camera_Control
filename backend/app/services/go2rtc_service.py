"""
go2rtc Process Supervisor & Async REST Client
Manages go2rtc binary download, lifecycle, config generation, and REST communication.
"""

import os
import sys
import shutil
import zipfile
import io
import platform
import subprocess
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Union

import httpx

from app.services.ffmpeg_service import ffmpeg_service

logger = logging.getLogger("nvr.go2rtc")


class Go2rtcError(Exception):
    """Base exception for go2rtc operations."""
    pass


class Go2rtcStartupError(Go2rtcError):
    """Raised when go2rtc fails to launch or become healthy."""
    pass


class Go2rtcStreamNotFoundError(Go2rtcError):
    """Raised when a requested stream is not found on go2rtc."""
    pass


class Go2rtcHttpError(Go2rtcError):
    """Raised when go2rtc REST API returns an HTTP error."""
    def __init__(self, status_code: int, message: str):
        super().__init__(f"go2rtc HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class Go2rtcSupervisor:
    """
    Supervises the local go2rtc binary lifecycle.
    """

    WINDOWS_DOWNLOAD_URL = (
        "https://github.com/AlexxIT/go2rtc/releases/download/v1.9.14/go2rtc_win64.zip"
    )
    LINUX_AMD64_URL = (
        "https://github.com/AlexxIT/go2rtc/releases/download/v1.9.14/go2rtc_linux_amd64"
    )
    LINUX_ARM64_URL = (
        "https://github.com/AlexxIT/go2rtc/releases/download/v1.9.14/go2rtc_linux_arm64"
    )

    def __init__(
        self,
        bin_dir: Path,
        config_path: Path,
        api_url: str = "http://127.0.0.1:1984",
        auto_download: bool = True,
    ):
        self.bin_dir = Path(bin_dir)
        self.config_path = Path(config_path)
        self.api_url = api_url.rstrip("/")
        self.auto_download = auto_download

        self._process: Optional[subprocess.Popen] = None
        self._is_ready: bool = False
        self._binary_path: Optional[Path] = None

    def resolve_binary(self) -> Path:
        """
        Locates the go2rtc executable in bin/ or system PATH.
        If missing and auto_download is True, downloads the binary.
        """
        if self._binary_path and self._binary_path.is_file():
            return self._binary_path

        exe_name = "go2rtc.exe" if os.name == "nt" else "go2rtc"
        candidate = self.bin_dir / exe_name

        if candidate.is_file():
            self._binary_path = candidate
            return candidate

        # Check system PATH
        path_binary = shutil.which("go2rtc")
        if path_binary:
            self._binary_path = Path(path_binary)
            return self._binary_path

        # Auto-download if enabled
        if self.auto_download:
            logger.info("go2rtc binary not found. Starting automatic download...")
            downloaded = self._download_binary()
            self._binary_path = downloaded
            return downloaded

        raise Go2rtcStartupError(
            f"go2rtc binary not found at {candidate} or in PATH, and auto_download=False."
        )

    def _download_binary(self) -> Path:
        """Downloads the appropriate binary for the host OS and architecture."""
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        is_windows = os.name == "nt"
        machine = platform.machine().lower()

        if is_windows:
            target_file = self.bin_dir / "go2rtc.exe"
            logger.info("Downloading Windows 64-bit go2rtc from %s", self.WINDOWS_DOWNLOAD_URL)
            with httpx.Client(follow_redirects=True, timeout=60.0) as client:
                res = client.get(self.WINDOWS_DOWNLOAD_URL)
                if res.status_code != 200:
                    raise Go2rtcStartupError(
                        f"Failed to download go2rtc zip: HTTP {res.status_code}"
                    )
                with zipfile.ZipFile(io.BytesIO(res.content)) as zf:
                    if "go2rtc.exe" not in zf.namelist():
                        raise Go2rtcStartupError("go2rtc.exe not found inside downloaded zip.")
                    zf.extract("go2rtc.exe", path=self.bin_dir)

            logger.info("go2rtc.exe successfully downloaded and extracted to %s", target_file)
            return target_file

        else:
            # Linux / POSIX
            target_file = self.bin_dir / "go2rtc"
            url = self.LINUX_ARM64_URL if "arm" in machine or "aarch64" in machine else self.LINUX_AMD64_URL
            logger.info("Downloading Linux go2rtc from %s", url)
            with httpx.Client(follow_redirects=True, timeout=60.0) as client:
                res = client.get(url)
                if res.status_code != 200:
                    raise Go2rtcStartupError(
                        f"Failed to download go2rtc binary: HTTP {res.status_code}"
                    )
                target_file.write_bytes(res.content)
                target_file.chmod(0o755)

            logger.info("go2rtc binary successfully downloaded to %s", target_file)
            return target_file

    def ensure_default_config(self) -> Path:
        """
        Creates a default go2rtc.yaml configuration file if one does not exist.
        Injects the resolved FFmpeg path into ffmpeg.bin.
        """
        if self.config_path.is_file():
            return self.config_path

        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        # Resolve bundled FFmpeg path
        try:
            ffmpeg_path = ffmpeg_service.get_ffmpeg_path()
        except Exception:
            ffmpeg_path = "ffmpeg"

        # Safe YAML string escaping for Windows backslashes
        safe_ffmpeg_path = ffmpeg_path.replace("\\", "/")

        default_yaml = f"""# go2rtc default configuration (Auto-generated by Web NVR)
log:
  level: info

api:
  listen: ":1984"

rtsp:
  listen: ":8554"

webrtc:
  listen: ":8555"
  candidates:
    - stun:stun.l.google.com:19302
    - stun:stun1.l.google.com:19302

ffmpeg:
  bin: "{safe_ffmpeg_path}"

streams: {{}}
"""
        self.config_path.write_text(default_yaml, encoding="utf-8")
        logger.info("Generated default go2rtc config at %s", self.config_path)
        return self.config_path

    async def start(self) -> None:
        """Starts the go2rtc process and waits until the REST API responds."""
        if self.is_running():
            logger.info("go2rtc is already running (PID: %d)", self._process.pid)
            return

        # Check if an external go2rtc instance is already listening on :1984
        if await self._check_api_alive():
            logger.info("External go2rtc instance detected on %s. Attaching to existing daemon.", self.api_url)
            self._is_ready = True
            return

        binary = self.resolve_binary()
        config = self.ensure_default_config()

        cmd = [str(binary), "-config", str(config)]
        logger.info("Launching go2rtc process: %s", " ".join(cmd))

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
        )

        # Poll API until healthy or timeout
        poll_timeout = 10.0
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < poll_timeout:
            if self._process.poll() is not None:
                # Process terminated prematurely
                stderr = self._process.stderr.read().decode(errors="ignore") if self._process.stderr else ""
                raise Go2rtcStartupError(f"go2rtc process died unexpectedly with code {self._process.returncode}: {stderr}")

            if await self._check_api_alive():
                self._is_ready = True
                logger.info("go2rtc started successfully (PID: %d)", self._process.pid)
                return

            await asyncio.sleep(0.25)

        # Timeout reached
        await self.stop()
        raise Go2rtcStartupError(f"go2rtc did not respond on {self.api_url}/api within {poll_timeout}s")

    async def stop(self) -> None:
        """Stops the go2rtc subprocess gracefully with a fallback to SIGKILL."""
        self._is_ready = False
        if not self._process:
            return

        pid = self._process.pid
        logger.info("Stopping go2rtc process (PID: %d)...", pid)

        try:
            self._process.terminate()
            for _ in range(30):
                if self._process.poll() is not None:
                    break
                await asyncio.sleep(0.1)

            if self._process.poll() is None:
                logger.warning("go2rtc did not terminate within 3s. Force killing PID %d...", pid)
                self._process.kill()
                self._process.wait(timeout=2.0)
        except Exception as e:
            logger.error("Error stopping go2rtc process: %s", e)
        finally:
            self._process = None

    def is_running(self) -> bool:
        """Returns True if the managed subprocess is alive."""
        return self._process is not None and self._process.poll() is None

    async def _check_api_alive(self) -> bool:
        """Checks if http://127.0.0.1:1984/api returns HTTP 200."""
        try:
            async with httpx.AsyncClient(timeout=1.0) as client:
                res = await client.get(f"{self.api_url}/api")
                return res.status_code == 200
        except Exception:
            return False

    def get_status(self) -> Dict[str, Any]:
        """Status report for /api/health."""
        return {
            "is_running": self.is_running() or self._is_ready,
            "pid": self._process.pid if self._process else None,
            "api_url": self.api_url,
            "is_ready": self._is_ready,
        }


class Go2rtcClient:
    """
    Async REST client interacting with go2rtc's HTTP API.
    """

    def __init__(self, api_url: str = "http://127.0.0.1:1984"):
        self.api_url = api_url.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                timeout=httpx.Timeout(10.0, connect=3.0),
            )
        return self._client

    async def close(self) -> None:
        """Closes the underlying HTTP client session."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def get_streams(self) -> Dict[str, Any]:
        """
        Retrieves all currently registered streams.
        GET /api/streams
        Returns mapping of stream name to { producers: [...], consumers: [...] }.
        """
        client = await self._get_client()
        try:
            res = await client.get("/api/streams")
            if res.status_code == 200:
                return res.json()
            raise Go2rtcHttpError(res.status_code, res.text)
        except httpx.RequestError as e:
            raise Go2rtcError(f"Failed to communicate with go2rtc: {e}") from e

    async def get_stream(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieves details of a specific stream, or None if not found."""
        streams = await self.get_streams()
        return streams.get(name)

    async def add_stream(self, name: str, src: Union[str, List[str]]) -> bool:
        """
        Adds or registers a new stream source dynamically.
        PUT /api/streams?name={name}&src={src}
        """
        client = await self._get_client()
        params = [("name", name)]
        if isinstance(src, list):
            for s in src:
                params.append(("src", s))
        else:
            params.append(("src", src))

        try:
            res = await client.put("/api/streams", params=params)
            if res.status_code in (200, 201):
                logger.info("Stream '%s' added successfully to go2rtc", name)
                return True
            raise Go2rtcHttpError(res.status_code, res.text)
        except httpx.RequestError as e:
            raise Go2rtcError(f"Error adding stream '{name}': {e}") from e

    async def update_stream(self, name: str, src: Union[str, List[str]]) -> bool:
        """
        Hot-swaps the underlying producer source of an active stream.
        PATCH /api/streams?name={name}&src={src}
        Preserves client WebRTC viewer connections without reloading!
        """
        client = await self._get_client()
        params = [("name", name)]
        if isinstance(src, list):
            for s in src:
                params.append(("src", s))
        else:
            params.append(("src", src))

        try:
            res = await client.patch("/api/streams", params=params)
            if res.status_code in (200, 204):
                logger.info("Stream '%s' hot-swapped successfully on go2rtc", name)
                return True
            raise Go2rtcHttpError(res.status_code, res.text)
        except httpx.RequestError as e:
            raise Go2rtcError(f"Error updating stream '{name}': {e}") from e

    async def remove_stream(self, name: str) -> bool:
        """
        Deletes a stream from go2rtc.
        DELETE /api/streams?src={name}
        """
        client = await self._get_client()
        try:
            res = await client.delete("/api/streams", params={"src": name})
            if res.status_code in (200, 204):
                logger.info("Stream '%s' removed successfully from go2rtc", name)
                return True
            raise Go2rtcHttpError(res.status_code, res.text)
        except httpx.RequestError as e:
            raise Go2rtcError(f"Error deleting stream '{name}': {e}") from e

    # Alias delete_stream to remove_stream for uniform contract across services
    delete_stream = remove_stream

    async def get_frame(
        self,
        name: str,
        width: Optional[int] = None,
        height: Optional[int] = None,
    ) -> bytes:
        """
        Extracts a single JPEG keyframe snapshot directly from the stream.
        GET /api/frame.jpeg?src={name}&w={width}&h={height}
        Returns raw bytes of image/jpeg.
        """
        client = await self._get_client()
        params: Dict[str, Any] = {"src": name}
        if width:
            params["w"] = width
        if height:
            params["h"] = height

        try:
            res = await client.get("/api/frame.jpeg", params=params, timeout=5.0)
            if res.status_code == 200:
                return res.content
            elif res.status_code == 404:
                raise Go2rtcStreamNotFoundError(f"Stream '{name}' not found for snapshot.")
            raise Go2rtcHttpError(res.status_code, res.text)
        except httpx.RequestError as e:
            raise Go2rtcError(f"Failed to capture frame for '{name}': {e}") from e

    async def negotiate_webrtc(self, name: str, sdp_offer: str) -> str:
        """
        WHEP WebRTC negotiation endpoint.
        POST /api/webrtc?src={name}
        Body: SDP Offer string
        Returns: SDP Answer string
        """
        client = await self._get_client()
        try:
            res = await client.post(
                "/api/webrtc",
                params={"src": name},
                content=sdp_offer,
                headers={"Content-Type": "application/sdp"},
            )
            if res.status_code == 200:
                return res.text
            raise Go2rtcHttpError(res.status_code, res.text)
        except httpx.RequestError as e:
            raise Go2rtcError(f"WebRTC negotiation failed for '{name}': {e}") from e
