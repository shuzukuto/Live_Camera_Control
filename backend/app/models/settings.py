from typing import Optional, Dict, Literal
from pydantic import BaseModel, Field, ConfigDict


class SettingItem(BaseModel):
    key: str = Field(..., min_length=1, max_length=100)
    value: str
    category: Literal["general", "storage", "streaming", "security", "notification"] = "general"
    description: Optional[str] = None
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class SettingUpdate(BaseModel):
    value: str = Field(..., description="New setting value as string or JSON-serialized string")


class SettingsBatchUpdate(BaseModel):
    settings: Dict[str, str] = Field(..., description="Dictionary of key-value setting updates")


class SettingsResponse(BaseModel):
    settings: Dict[str, SettingItem]
