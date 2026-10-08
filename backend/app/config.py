"""
Core Application Configuration
Pydantic-based settings supporting environment variables and .env file.
"""

from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application runtime configuration schema.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General App Identity
    APP_NAME: str = "Web NVR/VMS Surveillance Console"
    APP_VERSION: str = "v1.0.1"
    ENV: str = Field(default="development", description="development | production | test")
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8090

    # Paths and Directories
    BASE_DIR: Path = Field(default_factory=lambda: Path(__file__).resolve().parent.parent.parent)
    DATA_DIR: Path = Field(default=Path("data"), description="SQLite database and salt path")
    RECORDINGS_DIR: Path = Field(default=Path("recordings"), description="MP4 video recordings storage")
    SNAPSHOTS_DIR: Path = Field(default=Path("snapshots"), description="JPEG snapshots storage")
    BIN_DIR: Path = Field(default=Path("bin"), description="Binaries storage (go2rtc, etc.)")
    CONFIG_DIR: Path = Field(default=Path("config"), description="YAML configuration files")

    # SQLite Database Configuration
    DATABASE_FILENAME: str = "surveillance.db"

    @property
    def DATABASE_PATH(self) -> Path:
        return self.DATA_DIR / self.DATABASE_FILENAME

    @property
    def DATABASE_URL(self) -> str:
        return f"sqlite+aiosqlite:///{self.DATABASE_PATH.as_posix()}"

    # go2rtc Media Gateway Configuration
    GO2RTC_ENABLED: bool = True
    GO2RTC_API_URL: str = "http://127.0.0.1:1984"
    GO2RTC_RTSP_URL: str = "rtsp://127.0.0.1:8554"
    GO2RTC_WEBRTC_URL: str = "http://127.0.0.1:8555"
    GO2RTC_CONFIG_FILE: Path = Path("config/go2rtc.yaml")
    GO2RTC_AUTO_DOWNLOAD: bool = True
    GO2RTC_VERSION: str = "v1.9.14"

    # Cryptographic Vault Configuration
    VAULT_MASTER_PASSPHRASE: Optional[str] = Field(
        default=None,
        description="Master secret for PBKDF2 credential vault. If None, auto-generated.",
    )
    VAULT_SALT_FILE: Path = Path("data/.vault_salt")

    # Security & CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:8090",
        "http://127.0.0.1:8090",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"

    # Storage Quotas & NVR Retention
    MAX_STORAGE_GB: float = 500.0
    MIN_FREE_SPACE_GB: float = 20.0
    RETENTION_DAYS: int = 30

    def ensure_directories(self) -> None:
        """Creates all required runtime directories if they do not exist."""
        for directory in [
            self.DATA_DIR,
            self.RECORDINGS_DIR,
            self.SNAPSHOTS_DIR,
            self.BIN_DIR,
            self.CONFIG_DIR,
        ]:
            directory.mkdir(parents=True, exist_ok=True)


# Global settings singleton
settings = Settings()
