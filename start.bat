@echo off
title NVR Camera Surveillance System
echo ==================================================================
echo  Khoi chay He thong Giam sat Camera Tap trung (EZVIZ, Xiaomi, RTSP)
echo ==================================================================

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Tao moi moi truong ao Python (.venv)...
    python -m venv .venv
    echo [INFO] Cai dat thu vien can thiet tu requirements.txt...
    .venv\Scripts\pip.exe install -r requirements.txt
)

echo [INFO] Khoi dong ung dung tai http://localhost:8090/ ...
.venv\Scripts\python.exe run.py
pause
