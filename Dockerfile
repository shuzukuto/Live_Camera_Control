# ==============================================================================
# Dockerfile: Centralized Web NVR/VMS Surveillance System
# Architecture: Multi-platform (linux/amd64, linux/arm64)
# Ports:
#   8090: Web Dashboard & FastAPI REST/WebSocket API
#   1984: go2rtc WebRTC WHEP & Management API
#   8554: RTSP Relay Gateway
#   8555: WebRTC UDP/TCP Streaming
# ==============================================================================

FROM python:3.12-slim-bookworm

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=8090 \
    HOST=0.0.0.0

# Install FFmpeg and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    curl \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download Linux go2rtc binary
RUN mkdir -p /app/bin && \
    ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        curl -L -s https://github.com/AlexxIT/go2rtc/releases/download/v1.9.14/go2rtc_linux_amd64 -o /app/bin/go2rtc; \
    elif [ "$ARCH" = "arm64" ]; then \
        curl -L -s https://github.com/AlexxIT/go2rtc/releases/download/v1.9.14/go2rtc_linux_arm64 -o /app/bin/go2rtc; \
    else \
        curl -L -s https://github.com/AlexxIT/go2rtc/releases/download/v1.9.14/go2rtc_linux_amd64 -o /app/bin/go2rtc; \
    fi && \
    chmod +x /app/bin/go2rtc

# Copy application source code
COPY backend ./backend
COPY config ./config
COPY run.py .

# Create volume directories
RUN mkdir -p /app/data /app/recordings /app/snapshots

# Expose required ports
EXPOSE 8090 1984 8554 8555/tcp 8555/udp

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8090/api/health || exit 1

# Start application via Python runner
CMD ["python", "run.py"]
