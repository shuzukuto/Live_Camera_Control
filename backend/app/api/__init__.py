"""
backend/app/api/__init__.py
"""

from .cameras import router as cameras_router, onvif_router
from .accounts import router as accounts_router
from .nvr import router as nvr_router
from .events import router as events_router
from .ws import router as ws_router

__all__ = [
    "cameras_router",
    "onvif_router",
    "accounts_router",
    "nvr_router",
    "events_router",
    "ws_router",
]
