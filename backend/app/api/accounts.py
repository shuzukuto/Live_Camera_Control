"""
backend/app/api/accounts.py

REST API Router for Cloud Account Management (EZVIZ & Xiaomi Mi Home).
Endpoints:
- GET /api/accounts - List all cloud accounts with masked secrets
- GET /api/accounts/{account_id} - Get single account details
- POST /api/accounts - Register new cloud account & authenticate
- DELETE /api/accounts/{account_id} - Delete cloud account
- POST /api/accounts/{account_id}/sync - Synchronize cameras from cloud provider
- POST /api/accounts/{account_id}/challenge - Submit 2FA OTP or captcha challenge
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.database import get_db
from app.vault import encrypt_secret, decrypt_secret, encrypt_json, decrypt_json, mask_secret
from app.services.ezviz_service import ezviz_service, EZVIZAuthError
from app.services.xiaomi_service import xiaomi_service, XiaomiAuthError
from app.services.camera_sync_service import camera_sync_service

logger = logging.getLogger("nvr.api.accounts")

router = APIRouter()


class AccountCreatePayload(BaseModel):
    provider: str = Field(..., description="'ezviz' or 'xiaomi'")
    account_name: str = Field(..., min_length=1, max_length=100)
    region: str = Field(default="cn", max_length=10)
    username: Optional[str] = Field(None, description="AppKey, Email, or Phone")
    secret: str = Field(..., min_length=1, description="AppSecret or Password")


class ChallengeSubmitPayload(BaseModel):
    otp_code: Optional[str] = None
    captcha_code: Optional[str] = None


def _format_account_response(row: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to convert raw SQLite row into safe public representation."""
    raw_secret = decrypt_secret(row.get("encrypted_secret"))
    masked = mask_secret(raw_secret)

    return {
        "id": row.get("id"),
        "provider": row.get("provider"),
        "platform": row.get("provider"),
        "account_name": row.get("account_name"),
        "region": row.get("region", "cn"),
        "username": row.get("username"),
        "masked_secret": masked,
        "status": row.get("status", "active"),
        "area_domain": row.get("area_domain"),
        "last_sync_at": row.get("last_sync_at"),
        "created_at": str(row.get("created_at")),
        "updated_at": str(row.get("updated_at")),
    }


@router.get("/accounts", summary="List cloud accounts")
async def list_accounts() -> List[Dict[str, Any]]:
    """Lists all configured cloud accounts with masked credentials."""
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM accounts ORDER BY created_at ASC;") as cursor:
            rows = await cursor.fetchall()
            return [_format_account_response(dict(r)) for r in rows]


@router.get("/accounts/{account_id}", summary="Get account details")
async def get_account(account_id: str) -> Dict[str, Any]:
    """Retrieves single cloud account metadata."""
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cursor:
            row = await cursor.fetchone()
            if not row:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Account '{account_id}' not found")
            return _format_account_response(dict(row))


@router.post("/accounts", summary="Add new cloud account")
async def add_account(payload: AccountCreatePayload) -> Dict[str, Any]:
    """
    Registers a new EZVIZ or Xiaomi cloud account, acquires initial tokens,
    and encrypts credentials at rest.
    """
    prov = payload.provider.lower()
    if prov not in ["ezviz", "xiaomi"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider '{payload.provider}'. Supported: 'ezviz', 'xiaomi'",
        )

    account_id = f"acc_{uuid.uuid4().hex[:12]}"
    enc_secret = encrypt_secret(payload.secret)
    enc_tokens = None
    token_expire_time = None
    area_domain = None
    account_status = "active"
    challenge_data = None

    # Authenticate and obtain tokens
    if prov == "ezviz":
        try:
            token_obj = await ezviz_service.get_token(
                app_key=payload.username or "",
                app_secret=payload.secret,
                region=payload.region,
            )
            tokens_bundle = {
                "accessToken": token_obj.access_token,
                "expireTime": token_obj.expire_time,
                "areaDomain": token_obj.area_domain,
            }
            enc_tokens = encrypt_json(tokens_bundle)
            token_expire_time = token_obj.expire_time
            area_domain = token_obj.area_domain
        except EZVIZAuthError as exc:
            logger.warning("EZVIZ initial authentication failed: %s", exc)
            account_status = "error"
        except Exception as exc:
            logger.warning("EZVIZ connection warning: %s", exc)
            account_status = "active"

    elif prov == "xiaomi":
        try:
            session = await xiaomi_service.login(
                username=payload.username or "",
                password=payload.secret,
                region=payload.region,
            )
            tokens_bundle = {
                "userId": session.user_id,
                "serviceToken": session.service_token,
                "ssecurity": session.ssecurity,
            }
            enc_tokens = encrypt_json(tokens_bundle)
        except XiaomiAuthError as exc:
            if exc.code == 87001:
                account_status = "challenge_required"
                challenge_data = exc.data
            else:
                account_status = "error"
        except Exception as exc:
            logger.warning("Xiaomi login warning: %s", exc)
            account_status = "active"

    async with get_db() as conn:
        await conn.execute(
            """
            INSERT INTO accounts (
                id, provider, account_name, region, username, encrypted_secret,
                encrypted_tokens, token_expire_time, area_domain, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                account_id,
                prov,
                payload.account_name,
                payload.region,
                payload.username,
                enc_secret,
                enc_tokens,
                token_expire_time,
                area_domain,
                account_status,
            ),
        )
        await conn.commit()

        async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cursor:
            row = await cursor.fetchone()

    res = _format_account_response(dict(row))
    if challenge_data:
        res["challenge"] = challenge_data
    return res


@router.delete("/accounts/{account_id}", summary="Delete cloud account")
async def delete_account(account_id: str) -> Dict[str, Any]:
    """Deletes cloud account from database."""
    async with get_db() as conn:
        async with conn.execute("SELECT id FROM accounts WHERE id = ?;", (account_id,)) as cursor:
            row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Account '{account_id}' not found")

        await conn.execute("DELETE FROM accounts WHERE id = ?;", (account_id,))
        await conn.commit()

    return {"status": "deleted", "id": account_id}


@router.post("/accounts/{account_id}/sync", summary="Synchronize cameras from account")
async def sync_account(account_id: str) -> Dict[str, Any]:
    """Polls cloud provider for account devices, persists to DB, and registers streams."""
    try:
        synced = await camera_sync_service.sync_account_cameras(account_id)
        from app.api.cameras import _format_camera_response
        sanitized_cams = [_format_camera_response(c) for c in synced]
        return {"status": "success", "count": len(sanitized_cams), "cameras": sanitized_cams}
    except Exception as exc:
        logger.error("Account %s sync failed: %s", account_id, exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Sync failed: {exc}")


@router.post("/accounts/{account_id}/challenge", summary="Submit 2FA / Captcha challenge")
async def submit_challenge(account_id: str, payload: ChallengeSubmitPayload) -> Dict[str, Any]:
    """Submits 2FA OTP code or Captcha solution to resolve account challenge."""
    async with get_db() as conn:
        async with conn.execute("SELECT * FROM accounts WHERE id = ?;", (account_id,)) as cursor:
            row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Account '{account_id}' not found")

    account = dict(row)
    if account["provider"] != "xiaomi":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Challenges only applicable to Xiaomi accounts")

    secret = decrypt_secret(account["encrypted_secret"])
    username = account.get("username", "")

    try:
        session = await xiaomi_service.login(
            username=username,
            password=secret,
            region=account.get("region", "cn"),
            otp_code=payload.otp_code,
        )
        tokens_bundle = {
            "userId": session.user_id,
            "serviceToken": session.service_token,
            "ssecurity": session.ssecurity,
        }
        async with get_db() as conn:
            await conn.execute(
                """
                UPDATE accounts
                SET encrypted_tokens = ?, status = 'active', updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                WHERE id = ?;
                """,
                (encrypt_json(tokens_bundle), account_id),
            )
            await conn.commit()

        return {"status": "success", "message": "2FA challenge resolved successfully"}
    except XiaomiAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Challenge verification failed: {exc}")
