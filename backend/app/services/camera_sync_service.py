"""
backend/app/services/camera_sync_service.py

Camera Synchronization & Media Gateway Registration Orchestrator.
Orchestrates:
- Cloud account device enumeration (EZVIZ & Xiaomi)
- Decryption of account credentials and tokens
- SQLite cameras table persistence (upsert)
- Automatic stream registration into go2rtc media gateway
- Stream unregistration on camera deletion
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from app.database import get_db, save_camera, get_camera_by_id
from app.vault import decrypt_secret, decrypt_json, encrypt_secret, encrypt_json
from app.services.ezviz_service import ezviz_service, StreamLease, EZVIZError
from app.services.xiaomi_service import xiaomi_service, XiaomiSession
from app.services.onvif_service import onvif_service
from app.services.go2rtc_service import Go2rtcClient
from app.config import settings

logger = logging.getLogger("nvr.sync")


class CameraSyncService:
    """
    Coordinates device inventory synchronization and go2rtc stream registration.
    """

    def __init__(self, go2rtc: Optional[Go2rtcClient] = None):
        self._go2rtc = go2rtc or Go2rtcClient(api_url=settings.GO2RTC_API_URL)

    def set_go2rtc_client(self, client: Go2rtcClient) -> None:
        """Inject mock or custom go2rtc client."""
        self._go2rtc = client

    async def sync_account_cameras(self, account_id: str) -> List[Dict[str, Any]]:
        """
        Polls cloud provider for all cameras attached to account_id,
        persists them to SQLite, and registers streams into go2rtc.
        """
        # 1. Fetch account record
        async with get_db() as conn:
            async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cursor:
                account_row = await cursor.fetchone()

        if not account_row:
            raise ValueError(f"Account with ID {account_id} not found")

        account = dict(account_row)
        provider = account.get("provider")
        region = account.get("region", "cn")
        username = account.get("username", "")

        # Decrypt secret
        secret = decrypt_secret(account.get("encrypted_secret"))
        tokens_bundle: Dict[str, Any] = {}
        if account.get("encrypted_tokens"):
            try:
                tokens_bundle = decrypt_json(account.get("encrypted_tokens"))
            except Exception:
                tokens_bundle = {}

        synced_cameras: List[Dict[str, Any]] = []

        if provider == "ezviz":
            synced_cameras = await self._sync_ezviz_account(account, secret, tokens_bundle)
        elif provider == "xiaomi":
            synced_cameras = await self._sync_xiaomi_account(account, secret, tokens_bundle)
        else:
            raise ValueError(f"Unsupported cloud provider: {provider}")

        # Update last_sync_at timestamp
        async with get_db() as conn:
            await conn.execute(
                "UPDATE accounts SET last_sync_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) WHERE id = ?;",
                (account_id,),
            )
            await conn.commit()

        logger.info("Successfully synced %d cameras for account %s (%s)", len(synced_cameras), account_id, provider)
        return synced_cameras

    async def _sync_ezviz_account(
        self,
        account: Dict[str, Any],
        secret: str,
        tokens_bundle: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Synchronizes EZVIZ cloud cameras."""
        account_id = account["id"]
        app_key = account.get("username", "")
        region = account.get("region", "cn")
        access_token = tokens_bundle.get("accessToken")
        expire_time = account.get("token_expire_time")

        # 1. Acquire / refresh token if expired
        now_ms = int(time.time() * 1000)
        if not access_token or not expire_time or now_ms >= (expire_time - 60_000):
            token_obj = await ezviz_service.get_token(app_key=app_key, app_secret=secret, region=region)
            access_token = token_obj.access_token
            expire_time = token_obj.expire_time
            tokens_bundle["accessToken"] = access_token
            tokens_bundle["areaDomain"] = token_obj.area_domain

            # Update DB with new encrypted tokens
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

        # 2. List cameras with reactive re-authentication on 10002
        try:
            devices = await ezviz_service.list_cameras(
                access_token=access_token,
                region=region,
                area_domain=account.get("area_domain"),
            )
        except EZVIZError as exc:
            if exc.code == "10002":
                logger.info("EZVIZ token expired (10002). Performing reactive re-authentication...")
                token_obj = await ezviz_service.get_token(
                    app_key=app_key, app_secret=secret, region=region, force_refresh=True
                )
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

                devices = await ezviz_service.list_cameras(
                    access_token=access_token,
                    region=region,
                    area_domain=token_obj.area_domain,
                )
            else:
                raise

        saved_list: List[Dict[str, Any]] = []


        for dev in devices:
            serial = dev.get("deviceSerial", "")
            channel_no = dev.get("channelNo", 1)
            name = dev.get("cameraName") or dev.get("channelName") or f"EZVIZ_{serial}"
            is_online = 1 if dev.get("status") == 1 else 0
            is_encrypt = dev.get("isEncrypt", 0)
            vcode = dev.get("validateCode")

            cam_id = f"ezviz_{serial}_{channel_no}"
            stream_id = f"cam_{serial.lower()}_{channel_no}"

            # Attempt stream extraction
            stream_url = dev.get("local_rtsp")
            url_expires_at = None
            stream_type = "rtsp_local" if stream_url else "ezviz_cloud"

            if not stream_url and is_online:
                try:
                    lease = await ezviz_service.get_live_address(
                        access_token=access_token,
                        device_serial=serial,
                        channel_no=channel_no,
                        region=region,
                    )
                    stream_url = lease.stream_url
                    url_expires_at = int(lease.expires_at)
                except Exception as exc:
                    logger.warning("Could not extract live address for EZVIZ %s: %s", serial, exc)

            camera_data: Dict[str, Any] = {
                "id": cam_id,
                "account_id": account_id,
                "name": name,
                "brand": "ezviz",
                "model": dev.get("model", "EZVIZ IPC"),
                "device_serial": serial,
                "channel_no": channel_no,
                "stream_id": stream_id,
                "stream_type": stream_type,
                "live_url": stream_url,
                "url_expires_at": url_expires_at,
                "has_ptz": True,  # EZVIZ cloud supports cloud PTZ
                "is_online": is_online,
                "enabled": True,
            }

            if vcode:
                camera_data["encrypted_verification_code"] = encrypt_secret(vcode)

            saved = await save_camera(camera_data)
            saved_list.append(saved)

            # Register into go2rtc if stream_url is available
            if stream_url:
                try:
                    await self._go2rtc.add_stream(stream_id, stream_url)
                except Exception as exc:
                    logger.warning("Failed to register EZVIZ stream %s in go2rtc: %s", stream_id, exc)

        return saved_list

    async def _sync_xiaomi_account(
        self,
        account: Dict[str, Any],
        secret: str,
        tokens_bundle: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Synchronizes Xiaomi Mi Home cloud cameras."""
        account_id = account["id"]
        username = account.get("username", "")
        region = account.get("region", "cn")
        service_token = tokens_bundle.get("serviceToken")
        ssecurity = tokens_bundle.get("ssecurity")

        # 1. Login if tokens missing
        if not service_token or not ssecurity:
            session = await xiaomi_service.login(
                username=username,
                password=secret,
                region=region,
            )
            service_token = session.service_token
            ssecurity = session.ssecurity
            tokens_bundle.update({
                "userId": session.user_id,
                "serviceToken": session.service_token,
                "ssecurity": session.ssecurity,
            })
            async with get_db() as conn:
                await conn.execute(
                    """
                    UPDATE accounts
                    SET encrypted_tokens = ?, status = 'active',
                        updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    WHERE id = ?;
                    """,
                    (encrypt_json(tokens_bundle), account_id),
                )
                await conn.commit()

        # 2. Get device list
        devices = await xiaomi_service.get_devices(
            region=region,
            service_token=service_token,
            ssecurity=ssecurity,
        )

        saved_list: List[Dict[str, Any]] = []

        for dev in devices:
            did = dev.get("did", "")
            name = dev.get("name") or f"Xiaomi_{did}"
            model = dev.get("model", "")
            is_online = 1 if dev.get("isOnline") else 0
            local_ip = dev.get("localip")
            token = dev.get("token")
            pin = dev.get("pin", "0000")

            cam_id = f"xiaomi_{did}"
            stream_id = f"cam_{did.lower()}"

            # Generate stream descriptor
            try:
                descriptor_res = await xiaomi_service.get_stream_descriptor(
                    did=did,
                    region=region,
                    service_token=service_token,
                    device_ip=local_ip,
                    device_token=token,
                    pin=pin,
                )
                stream_url = descriptor_res.get("stream_url", "")
            except Exception as exc:
                logger.warning("Could not generate stream descriptor for Xiaomi %s: %s", did, exc)
                stream_url = f"xiaomi://{local_ip or '127.0.0.1'}?token={token or ''}&pin={pin}"

            camera_data: Dict[str, Any] = {
                "id": cam_id,
                "account_id": account_id,
                "name": name,
                "brand": "xiaomi",
                "model": model,
                "ip_address": local_ip,
                "device_serial": did,
                "stream_id": stream_id,
                "stream_type": "xiaomi_p2p",
                "live_url": stream_url,
                "has_ptz": True,
                "is_online": is_online,
                "enabled": True,
            }

            saved = await save_camera(camera_data)
            saved_list.append(saved)

            # Register stream into go2rtc
            if stream_url:
                try:
                    await self._go2rtc.add_stream(stream_id, stream_url)
                except Exception as exc:
                    logger.warning("Failed to register Xiaomi stream %s in go2rtc: %s", stream_id, exc)

        return saved_list

    async def register_camera_stream(self, camera: Dict[str, Any]) -> bool:
        """Registers a camera's active stream source into go2rtc."""
        stream_id = camera.get("stream_id")
        stream_url = camera.get("live_url") or camera.get("stream_url")

        if not stream_id or not stream_url:
            return False

        try:
            return await self._go2rtc.add_stream(stream_id, stream_url)
        except Exception as exc:
            logger.error("Error registering stream %s in go2rtc: %s", stream_id, exc)
            return False

    async def unregister_camera_stream(self, stream_id: str) -> bool:
        """Removes a camera stream from go2rtc."""
        try:
            return await self._go2rtc.delete_stream(stream_id)
        except Exception as exc:
            logger.error("Error removing stream %s from go2rtc: %s", stream_id, exc)
            return False


# Global default instance
camera_sync_service = CameraSyncService()
