#!/usr/bin/env bash
# Web NVR/VMS Centralized Surveillance Console - Linux/macOS Launcher

set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "=================================================================="
echo " Starting NVR/VMS Surveillance Console (EZVIZ, Xiaomi, RTSP/ONVIF)"
echo "=================================================================="

if [ ! -d ".venv" ]; then
    echo "[INFO] Creating virtual environment (.venv)..."
    python3 -m venv .venv
    echo "[INFO] Installing dependencies from requirements.txt..."
    .venv/bin/pip install -r requirements.txt
fi

echo "[INFO] Launching NVR Web Server at http://localhost:8090/ ..."
.venv/bin/python run.py
