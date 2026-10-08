"""
FastAPI Core Application Entrypoint
Integrates Lifespan context manager, go2rtc supervisor, FFmpeg resolver,
security middlewares (CSP, CORS, SlowAPI), and health checks.
"""

import logging
from pathlib import Path
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Dict, Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.services.ffmpeg_service import ffmpeg_service
from app.services.go2rtc_service import Go2rtcSupervisor, Go2rtcClient
from app.database import init_db, close_db, check_db_health
from app.vault import init_vault, is_vault_initialized
from app.api import cameras_router, onvif_router, accounts_router, nvr_router, events_router, ws_router
from app.services.stream_keeper import stream_keeper
from app.services.nvr_service import nvr_service
from app.services.storage_service import storage_retention_worker
from app.services.broadcast_service import broadcast_manager


# Configure root logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("nvr.main")

# Initialize SlowAPI rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    enabled=settings.RATE_LIMIT_ENABLED,
)

# Initialize Media Gateway Supervisor & Client
go2rtc_supervisor = Go2rtcSupervisor(
    bin_dir=settings.BIN_DIR,
    config_path=settings.GO2RTC_CONFIG_FILE,
    api_url=settings.GO2RTC_API_URL,
    auto_download=settings.GO2RTC_AUTO_DOWNLOAD,
)
go2rtc_client = Go2rtcClient(api_url=settings.GO2RTC_API_URL)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application Lifespan context manager.
    Handles startup discovery, database init, vault init, and go2rtc supervision.
    """
    logger.info("==================================================")
    logger.info("Starting %s (%s) in %s mode", settings.APP_NAME, settings.APP_VERSION, settings.ENV)
    logger.info("==================================================")

    # 1. Ensure runtime directories exist
    settings.ensure_directories()

    # 2. Probe FFmpeg binary
    try:
        ffmpeg_path = ffmpeg_service.get_ffmpeg_path()
        logger.info("FFmpeg verified at: %s", ffmpeg_path)
    except Exception as e:
        logger.error("FFmpeg initialization warning: %s", e)

    # 3. Initialize SQLite Database WAL schema
    try:
        await init_db()
        logger.info("Database WAL mode initialized successfully.")
    except Exception as e:
        logger.error("Database initialization failed: %s", e)

    # 4. Initialize Credential Vault
    try:
        init_vault(
            passphrase=settings.VAULT_MASTER_PASSPHRASE,
            salt_path=settings.DATA_DIR / ".vault_salt",
            master_key_file=settings.DATA_DIR / ".vault_master_key",
        )
        logger.info("Credential Vault initialized successfully.")
    except Exception as e:
        logger.error("Credential vault initialization failed: %s", e)

    # 5. Start go2rtc Process Supervisor
    if settings.GO2RTC_ENABLED:
        try:
            await go2rtc_supervisor.start()
            logger.info("go2rtc supervisor active on %s", settings.GO2RTC_API_URL)
        except Exception as e:
            logger.error("Failed to start go2rtc supervisor: %s", e)
    else:
        logger.info("go2rtc supervisor disabled by configuration.")

    # 6. Startup recovery for crash-interrupted recordings
    try:
        await nvr_service.recover_unfinalized_recordings()
    except Exception as e:
        logger.error("Failed to recover unfinalized recordings: %s", e)

    # 7. Start 24/7 StreamKeeper Lease Renewal Daemon
    stream_keeper.start()

    # 8. Start Automated Storage Retention Worker
    storage_retention_worker.start()

    # 9. Start Real-Time Alert Broadcast Subsystem
    await broadcast_manager.start()

    yield  # Application serves requests

    # Shutdown sequence
    logger.info("Shutting down %s...", settings.APP_NAME)
    await broadcast_manager.stop()
    await stream_keeper.stop()
    await storage_retention_worker.stop()
    if settings.GO2RTC_ENABLED:
        await go2rtc_supervisor.stop()
    await go2rtc_client.close()

    # Close DB connection pool
    try:
        await close_db()
    except Exception:
        pass

    logger.info("Shutdown complete.")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
    )

    # Attach limiter to application state
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Headers & Content Security Policy (CSP) Middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)

        # Content Security Policy configured for WebRTC, MSE, and WebSocket feeds
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "img-src 'self' data: blob:",
            "media-src 'self' blob: mediastream:",
            "connect-src 'self' ws: wss: http: https:",
            "font-src 'self' data: https://fonts.gstatic.com",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        return response

    # Global Exception Handlers
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": True,
                "status_code": exc.status_code,
                "detail": exc.detail,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": True,
                "status_code": 422,
                "detail": exc.errors(),
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled server exception: %s", exc)
        detail = str(exc) if settings.DEBUG else "Internal server error"
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": True,
                "status_code": 500,
                "detail": detail,
            },
        )

    # Health Check Endpoint
    @app.get("/api/health", tags=["System"])
    async def health_check() -> Dict[str, Any]:
        """
        Comprehensive system health check reporting status of core subsystems:
        go2rtc gateway, FFmpeg resolver, database, and vault.
        """
        ffmpeg_status = ffmpeg_service.get_status()
        go2rtc_status = go2rtc_supervisor.get_status()

        # Database health check
        db_status = "unavailable"
        try:
            db_status = await check_db_health()
        except Exception:
            db_status = "pending_or_uninitialized"

        # Vault health check
        vault_status = "unavailable"
        try:
            vault_status = "initialized" if is_vault_initialized() else "uninitialized"
        except Exception:
            vault_status = "pending_or_uninitialized"

        is_healthy = (
            ffmpeg_status.get("status") == "available"
            and go2rtc_status.get("is_running") is True
        )

        return {
            "status": "healthy" if is_healthy else "degraded",
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENV,
            "components": {
                "ffmpeg": ffmpeg_status,
                "go2rtc": go2rtc_status,
                "database": {"status": db_status},
                "vault": {"status": vault_status},
                "broadcast": broadcast_manager.get_status(),
            },
        }

    # Static directories for recordings and snapshots
    settings.RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
    settings.SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/recordings", StaticFiles(directory=str(settings.RECORDINGS_DIR)), name="recordings")
    app.mount("/snapshots", StaticFiles(directory=str(settings.SNAPSHOTS_DIR)), name="snapshots")

    # Register API Routers
    app.include_router(cameras_router, prefix="/api", tags=["Cameras"])
    app.include_router(onvif_router, tags=["ONVIF"])
    app.include_router(accounts_router, prefix="/api", tags=["Accounts"])
    app.include_router(nvr_router, prefix="/api", tags=["NVR & Storage"])
    app.include_router(events_router, prefix="/api", tags=["AI Events"])
    app.include_router(ws_router, prefix="/api", tags=["Real-time Alerts"])

    # Mount Web Surveillance Dashboard UI (must be mounted after API routers)
    static_dir = Path(__file__).resolve().parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

    return app


# Application entrypoint
app = create_app()
