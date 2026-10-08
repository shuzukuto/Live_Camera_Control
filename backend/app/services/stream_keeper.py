"""
backend/app/services/stream_keeper.py

24/7 StreamKeeper Daemon & Zero-Timeout LAN RTSP Routing Engine.
Milestone 3: Features 15 & 16.

Key responsibilities:
- Proactive lease renewal daemon for cloud streams (EZVIZ & Xiaomi) before expiry (default T-30s).
- Seamless hot-swapping in go2rtc via PATCH /api/streams?name={name}&src={src} with zero viewer disconnection.
- Zero-timeout LAN RTSP priority routing: TCP port 554 probe, auto-promotion to local RTSP, dynamic failover.
- Concurrency bounding via semaphore, in-flight deduplication, exponential retry backoff.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from app.config import settings
from app.database import get_db
from app.vault import decrypt_secret, decrypt_json, encrypt_json
from app.services.go2rtc_service import Go2rtcClient
from app.services.ezviz_service import ezviz_service, StreamLease, EZVIZError
from app.services.xiaomi_service import xiaomi_service

logger = logging.getLogger("nvr.stream_keeper")


@dataclass
class StreamKeeperStats:
    total_checks: int = 0
    total_renewals_attempted: int = 0
    total_renewals_succeeded: int = 0
    total_renewals_failed: int = 0
    total_hot_swaps: int = 0
    total_lan_promotions: int = 0
    total_lan_fallbacks: int = 0
    last_check_timestamp: Optional[float] = None


class StreamKeeper:
    """
    24/7 Daemon that proactively renews cloud stream leases before expiry,
    hot-swaps go2rtc streams seamlessly, and routes local LAN RTSP streams.
    """

    def __init__(
        self,
        go2rtc: Optional[Go2rtcClient] = None,
        renew_lead_sec: float = 30.0,
        check_interval: float = 5.0,
        max_concurrent_renewals: int = 5,
        max_retries: int = 3,
        lan_probe_interval: float = 60.0,
    ):
        self._go2rtc = go2rtc or Go2rtcClient(api_url=settings.GO2RTC_API_URL)
        self.renew_lead_sec = renew_lead_sec
        self.check_interval = check_interval
        self.max_retries = max_retries
        self.lan_probe_interval = lan_probe_interval

        self._semaphore = asyncio.Semaphore(max_concurrent_renewals)
        self._running: bool = False
        self._worker_task: Optional[asyncio.Task] = None
        self._active_renewals: Set[str] = set()
        self._retry_counts: Dict[str, int] = {}
        self._retry_backoff_until: Dict[str, float] = {}
        self._last_lan_probe: Dict[str, float] = {}
        self.stats = StreamKeeperStats()

    def get_retry_backoff(self, camera_id: str) -> float:
        """Returns remaining backoff delay in seconds for camera, or 0.0 if not backing off."""
        return max(0.0, self._retry_backoff_until.get(camera_id, 0.0) - time.time())

    def set_go2rtc_client(self, client: Go2rtcClient) -> None:
        """Injects custom/mocked Go2rtcClient for testing."""
        self._go2rtc = client

    def is_running(self) -> bool:
        """Returns True if the background renewal loop task is active."""
        return self._running and self._worker_task is not None and not self._worker_task.done()

    def start(self) -> None:
        """Starts 24/7 background worker loop (idempotent)."""
        if self.is_running():
            logger.info("StreamKeeper daemon is already running.")
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info(
            "StreamKeeper 24/7 daemon started (lead=%ss, interval=%ss, concurrency=%s).",
            self.renew_lead_sec,
            self.check_interval,
            self._semaphore._value,
        )

    async def stop(self) -> None:
        """Cancels and awaits the background worker task cleanly."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        logger.info("StreamKeeper 24/7 daemon stopped.")

    async def _worker_loop(self) -> None:
        """Periodic tick worker loop running 24/7."""
        while self._running:
            try:
                await self.check_and_renew_leases()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in StreamKeeper tick: %s", exc, exc_info=True)
            await asyncio.sleep(self.check_interval)

    async def check_and_renew_leases(self) -> List[Dict[str, Any]]:
        """
        Single inspection tick:
        1. Selects enabled cameras from SQLite.
        2. Discovers candidates needing T-30s lease renewal.
        3. Identifies candidates for LAN auto-promotion or failover.
        4. Runs tasks concurrently bounded by semaphore.
        """
        self.stats.total_checks += 1
        self.stats.last_check_timestamp = time.time()
        now = time.time()

        # Load configurable lead time from system_settings if present
        try:
            async with get_db() as conn:
                async with conn.execute(
                    "SELECT value FROM system_settings WHERE key = 'streaming.streamkeeper_renew_lead_sec';"
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        val = row["value"] if isinstance(row, dict) or hasattr(row, "keys") else row[0]
                        try:
                            self.renew_lead_sec = float(val)
                        except (ValueError, TypeError):
                            pass

                async with conn.execute(
                    "SELECT * FROM cameras WHERE enabled = 1 ORDER BY created_at ASC;"
                ) as cursor:
                    cameras = [dict(r) for r in await cursor.fetchall()]
        except Exception as e:
            logger.error("Failed to query database in StreamKeeper tick: %s", e)
            return []

        renewal_tasks = []
        for cam in cameras:
            cam_id = cam["id"]
            if cam_id in self._active_renewals:
                continue

            stream_type = cam.get("stream_type")
            expires_at = cam.get("url_expires_at")
            ip_addr = cam.get("ip_address")

            # Check 1: LAN RTSP Auto-Promotion (Feature 16)
            # If camera is currently streaming via cloud but has LAN IP
            if stream_type in ("ezviz_cloud", "xiaomi_p2p") and ip_addr:
                last_probe = self._last_lan_probe.get(cam_id, 0.0)
                if (now - last_probe) >= self.lan_probe_interval:
                    self._last_lan_probe[cam_id] = now
                    renewal_tasks.append(self._probe_and_promote_lan(cam))
                    continue

            # Check 2: LAN Failover (Feature 16)
            # If camera is marked rtsp_local but LAN connection is dead and has cloud account
            if stream_type == "rtsp_local" and ip_addr and cam.get("account_id"):
                last_probe = self._last_lan_probe.get(cam_id, 0.0)
                if (now - last_probe) >= self.lan_probe_interval:
                    self._last_lan_probe[cam_id] = now
                    renewal_tasks.append(self._verify_lan_or_failover(cam))
                    continue

            # Check 3: Proactive T-30s Lease Renewal (Feature 15)
            if expires_at is not None:
                if now < self._retry_backoff_until.get(cam_id, 0.0):
                    continue
                lead_time = self.renew_lead_sec
                if now >= (float(expires_at) - lead_time):
                    renewal_tasks.append(self.renew_camera_lease(cam))

        if not renewal_tasks:
            return []

        results = await asyncio.gather(*renewal_tasks, return_exceptions=True)
        processed = []
        for res in results:
            if isinstance(res, Exception):
                logger.error("StreamKeeper renewal error: %s", res)
            elif res:
                processed.append(res)
        return processed

    async def renew_camera_lease(self, camera: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Executes proactive cloud lease renewal and hot-swaps go2rtc stream.
        """
        cam_id = camera["id"]
        stream_id = camera.get("stream_id") or cam_id
        brand = camera.get("brand")

        if cam_id in self._active_renewals:
            return None

        self._active_renewals.add(cam_id)
        self.stats.total_renewals_attempted += 1

        try:
            async with self._semaphore:
                lease: Optional[StreamLease] = None

                if brand == "ezviz":
                    lease = await self._renew_ezviz_lease(camera)
                elif brand == "xiaomi":
                    lease = await self._renew_xiaomi_lease(camera)
                else:
                    logger.debug("Camera %s (%s) does not require cloud lease renewal.", cam_id, brand)
                    return None

                if not lease or not lease.stream_url:
                    raise ValueError(f"Provider failed to return valid stream lease for {cam_id}")

                # Hot-swap stream in go2rtc via PATCH /api/streams?name={name}&src={src}
                hot_swapped = False
                try:
                    hot_swapped = await self._go2rtc.update_stream(stream_id, lease.stream_url)
                except Exception as e:
                    logger.debug("update_stream failed, falling back to add_stream: %s", e)

                if not hot_swapped:
                    # Fallback to PUT if stream did not exist in go2rtc
                    await self._go2rtc.add_stream(stream_id, lease.stream_url)

                self.stats.total_hot_swaps += 1
                self.stats.total_renewals_succeeded += 1
                self._retry_counts[cam_id] = 0
                self._retry_backoff_until.pop(cam_id, None)

                # Determine effective expiry and stream type
                url_expires_at = None if lease.is_local_rtsp else int(lease.expires_at)
                if lease.is_local_rtsp:
                    new_stream_type = "rtsp_local"
                elif brand == "ezviz":
                    new_stream_type = "ezviz_cloud"
                elif brand == "xiaomi":
                    new_stream_type = "xiaomi_p2p"
                else:
                    new_stream_type = camera.get("stream_type") or "generic_rtsp"

                # Update SQLite database
                async with get_db() as conn:
                    await conn.execute(
                        """
                        UPDATE cameras
                        SET live_url = ?, url_expires_at = ?, is_online = 1,
                            stream_type = ?, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                        WHERE id = ?;
                        """,
                        (lease.stream_url, url_expires_at, new_stream_type, cam_id),
                    )
                    await conn.commit()

                logger.info(
                    "Stream '%s' (%s) renewed and hot-swapped successfully. Expiry: %s",
                    stream_id,
                    cam_id,
                    url_expires_at,
                )
                return {
                    "camera_id": cam_id,
                    "stream_id": stream_id,
                    "action": "renewed",
                    "expires_at": url_expires_at,
                    "is_local_rtsp": lease.is_local_rtsp,
                    "stream_url": lease.stream_url,
                }

        except Exception as exc:
            self.stats.total_renewals_failed += 1
            retries = self._retry_counts.get(cam_id, 0) + 1
            self._retry_counts[cam_id] = retries
            backoff_delay = min(300.0, 5.0 * (2 ** (retries - 1)))
            self._retry_backoff_until[cam_id] = time.time() + backoff_delay
            logger.warning(
                "Lease renewal failed for camera %s (attempt %d/%d, backoff %.1fs): %s",
                cam_id,
                retries,
                self.max_retries,
                backoff_delay,
                exc,
            )

            # If retries exceeded and past actual expiration, mark offline in DB
            cur_exp = camera.get("url_expires_at")
            if retries >= self.max_retries and cur_exp and time.time() >= float(cur_exp):
                try:
                    async with get_db() as conn:
                        await conn.execute(
                            "UPDATE cameras SET is_online = 0, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) WHERE id = ?;",
                            (cam_id,),
                        )
                        await conn.commit()
                    logger.error("Camera %s marked offline after %d failed renewals past lease expiry.", cam_id, retries)
                except Exception as dbe:
                    logger.error("Failed to update camera status: %s", dbe)

            return None
        finally:
            self._active_renewals.discard(cam_id)

    async def _renew_ezviz_lease(self, camera: Dict[str, Any]) -> StreamLease:
        """Handles EZVIZ token lifecycle, reactive re-auth, and stream lease retrieval."""
        account_id = camera.get("account_id")
        if not account_id:
            return await ezviz_service.refresh_stream_url(camera)

        async with get_db() as conn:
            async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cursor:
                account_row = await cursor.fetchone()

        if not account_row:
            raise ValueError(f"Account {account_id} not found for camera {camera['id']}")

        account = dict(account_row)
        secret = decrypt_secret(account.get("encrypted_secret"))
        app_key = account.get("username", "")
        region = account.get("region", "cn")

        tokens_bundle: Dict[str, Any] = {}
        if account.get("encrypted_tokens"):
            try:
                tokens_bundle = decrypt_json(account.get("encrypted_tokens"))
            except Exception:
                tokens_bundle = {}

        access_token = tokens_bundle.get("accessToken")
        expire_time = account.get("token_expire_time")
        now_ms = int(time.time() * 1000)

        # Proactive token refresh if token expires within 60s
        if not access_token or not expire_time or now_ms >= (expire_time - 60_000):
            token_obj = await ezviz_service.get_token(app_key=app_key, app_secret=secret, region=region)
            access_token = token_obj.access_token
            expire_time = token_obj.expire_time
            tokens_bundle["accessToken"] = access_token
            tokens_bundle["areaDomain"] = token_obj.area_domain

            async with get_db() as conn:
                await conn.execute(
                    """
                    UPDATE accounts
                    SET encrypted_tokens = ?, token_expire_time = ?, area_domain = ?,
                        status = 'active', updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    WHERE id = ?;
                    """,
                    (encrypt_json(tokens_bundle), expire_time, token_obj.area_domain, account_id),
                )
                await conn.commit()

        # Decrypt camera verification code if stored in DB
        cam_payload = dict(camera)
        if camera.get("encrypted_verification_code"):
            cam_payload["verification_code"] = decrypt_secret(camera["encrypted_verification_code"])

        try:
            return await ezviz_service.refresh_stream_url(cam_payload, access_token=access_token, region=region)
        except EZVIZError as exc:
            if exc.code == "10002":
                # Reactive re-authentication on remote token invalidation
                logger.info("EZVIZ token invalidated (10002). Forcing re-authentication...")
                token_obj = await ezviz_service.get_token(app_key=app_key, app_secret=secret, region=region, force_refresh=True)
                access_token = token_obj.access_token
                expire_time = token_obj.expire_time
                tokens_bundle["accessToken"] = access_token

                async with get_db() as conn:
                    await conn.execute(
                        "UPDATE accounts SET encrypted_tokens = ?, token_expire_time = ? WHERE id = ?;",
                        (encrypt_json(tokens_bundle), expire_time, account_id),
                    )
                    await conn.commit()
                return await ezviz_service.refresh_stream_url(cam_payload, access_token=access_token, region=region)
            raise

    async def _renew_xiaomi_lease(self, camera: Dict[str, Any]) -> StreamLease:
        """Handles Xiaomi session renewal and stream lease retrieval."""
        account_id = camera.get("account_id")
        if not account_id:
            return await xiaomi_service.refresh_stream_url(camera)

        async with get_db() as conn:
            async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cursor:
                account_row = await cursor.fetchone()

        if not account_row:
            raise ValueError(f"Account {account_id} not found for camera {camera['id']}")

        account = dict(account_row)
        secret = decrypt_secret(account.get("encrypted_secret"))
        username = account.get("username", "")
        region = account.get("region", "cn")

        tokens_bundle: Dict[str, Any] = {}
        if account.get("encrypted_tokens"):
            try:
                tokens_bundle = decrypt_json(account.get("encrypted_tokens"))
            except Exception:
                tokens_bundle = {}

        service_token = tokens_bundle.get("serviceToken")
        ssecurity = tokens_bundle.get("ssecurity")

        if not service_token or not ssecurity:
            session = await xiaomi_service.login(username=username, password=secret, region=region)
            service_token = session.service_token
            ssecurity = session.ssecurity
            tokens_bundle.update({"serviceToken": service_token, "ssecurity": ssecurity, "userId": session.user_id})

            async with get_db() as conn:
                await conn.execute(
                    "UPDATE accounts SET encrypted_tokens = ? WHERE id = ?;",
                    (encrypt_json(tokens_bundle), account_id),
                )
                await conn.commit()

        return await xiaomi_service.refresh_stream_url(
            camera,
            service_token=service_token,
            ssecurity=ssecurity,
            region=region,
        )

    async def probe_lan_reachability(self, ip: str, port: int = 554, timeout: float = 1.0) -> bool:
        """Non-blocking TCP socket connect probe for LAN RTSP port 554."""
        if not ip:
            return False
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _probe_and_promote_lan(self, camera: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Feature 16: Tests LAN reachability and promotes cloud stream to zero-timeout LAN RTSP."""
        ip = camera.get("ip_address")
        port = camera.get("port", 554)
        if not ip:
            return None

        is_reachable = await self.probe_lan_reachability(ip, port)
        if not is_reachable:
            return None

        # Build local RTSP URL
        brand = camera.get("brand")
        local_url = None
        if brand == "ezviz":
            vcode = None
            if camera.get("encrypted_verification_code"):
                vcode = decrypt_secret(camera["encrypted_verification_code"])
            if not vcode:
                return None
            local_url = ezviz_service.resolve_local_rtsp_url(
                ip=ip,
                verification_code=vcode,
                port=port,
                channel_no=camera.get("channel_no", 1),
            )
        elif brand == "xiaomi":
            local_url = f"xiaomi://{ip}?token={camera.get('device_token', '')}&pin={camera.get('pin', '0000')}"

        if not local_url:
            return None

        stream_id = camera.get("stream_id") or camera["id"]
        cam_id = camera["id"]

        logger.info("Promoting camera %s from cloud to Zero-Timeout LAN RTSP (%s)...", cam_id, ip)
        hot_swapped = False
        try:
            hot_swapped = await self._go2rtc.update_stream(stream_id, local_url)
        except Exception:
            pass
        if not hot_swapped:
            await self._go2rtc.add_stream(stream_id, local_url)

        self.stats.total_lan_promotions += 1
        self.stats.total_hot_swaps += 1

        async with get_db() as conn:
            await conn.execute(
                """
                UPDATE cameras
                SET live_url = ?, url_expires_at = NULL, stream_type = 'rtsp_local',
                    is_online = 1, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                WHERE id = ?;
                """,
                (local_url, cam_id),
            )
            await conn.commit()

        return {"camera_id": cam_id, "action": "promoted_to_lan", "stream_url": local_url}

    async def _verify_lan_or_failover(self, camera: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Feature 16: Detects LAN RTSP drop and fails over to cloud stream."""
        ip = camera.get("ip_address")
        port = camera.get("port", 554)
        if not ip:
            return None

        is_reachable = await self.probe_lan_reachability(ip, port)
        if is_reachable:
            return None  # LAN is healthy

        cam_id = camera["id"]
        if time.time() < self._retry_backoff_until.get(cam_id, 0.0):
            return None

        self.stats.total_lan_fallbacks += 1
        logger.warning("Camera %s LAN RTSP unreachable at %s:%d. Initiating failover to cloud...", cam_id, ip, port)
        return await self.renew_camera_lease(camera)


# Default global instance
stream_keeper = StreamKeeper()
