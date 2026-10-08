from datetime import datetime, timezone
from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator


class AccountBase(BaseModel):
    provider: Literal["ezviz", "xiaomi"] = Field(
        ..., description="Cloud provider identity"
    )
    account_name: str = Field(
        ..., min_length=1, max_length=100, description="Display name for the account"
    )
    region: str = Field(
        default="cn", max_length=10, description="Regional gateway code ('cn', 'de', 'i2', 'ru', 'sg', 'us')"
    )
    username: Optional[str] = Field(
        default=None, max_length=100, description="Account username, email, phone, or AppKey"
    )


class AccountCreate(AccountBase):
    secret: str = Field(
        ..., min_length=1, description="Raw password or AppSecret (encrypted at rest before storage)"
    )


class AccountUpdate(BaseModel):
    account_name: Optional[str] = Field(None, min_length=1, max_length=100)
    region: Optional[str] = Field(None, max_length=10)
    username: Optional[str] = Field(None, max_length=100)
    secret: Optional[str] = Field(None, min_length=1, description="New secret if changing")
    status: Optional[Literal["active", "expired", "error", "challenge_required"]] = None


class AccountResponse(AccountBase):
    id: str
    masked_secret: str = Field(..., description="Masked secret (e.g. '******3a8f' or 'abc...456') for safe UI display")
    status: Literal["active", "expired", "error", "challenge_required"] = "active"
    area_domain: Optional[str] = None
    last_sync_at: Optional[str] = None
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class AccountInDB(AccountBase):
    """Internal model for database operations containing encrypted payloads."""
    id: str
    encrypted_secret: str
    encrypted_tokens: Optional[str] = None
    token_expire_time: Optional[int] = None
    area_domain: Optional[str] = None
    status: str
    last_sync_at: Optional[str] = None
    created_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)
