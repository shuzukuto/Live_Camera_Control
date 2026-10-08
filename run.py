#!/usr/bin/env python3
"""
Web NVR/VMS Centralized Surveillance Console - Native Runner
Starts the Uvicorn ASGI server hosting FastAPI, go2rtc media gateway, and Static Dashboard UI.
Usage:
  python run.py [--host 0.0.0.0] [--port 8090] [--no-browser]
"""

import sys
import os
import argparse
from pathlib import Path

# Ensure backend package is in python path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR / "backend"))

import uvicorn
from app.config import settings


def main():
    parser = argparse.ArgumentParser(description="Start Web NVR/VMS Surveillance System")
    parser.add_argument("--host", default=settings.HOST, help="Binding host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=settings.PORT, help="Binding port (default: 8090)")
    parser.add_argument("--reload", action="store_true", help="Enable code hot-reload")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    print("==================================================================")
    print(" [NVR/VMS] Surveillance Operations Center")
    print(f" [*] Version: {settings.APP_VERSION}")
    print(f" [*] Web Dashboard: http://localhost:{args.port}/")
    print(f" [*] go2rtc Gateway: {settings.GO2RTC_API_URL}")
    print("==================================================================")

    # Automatically open default browser on non-headless environments
    if not args.no_browser and os.environ.get("HEADLESS", "0") != "1":
        try:
            import threading
            import time
            import webbrowser

            def open_browser():
                time.sleep(1.2)
                webbrowser.open(f"http://localhost:{args.port}/")

            threading.Thread(target=open_browser, daemon=True).start()
        except Exception:
            pass

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
