# Build a CPU-only container with FFmpeg and Vosk model
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# System deps: ffmpeg, curl, unzip, build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
      ffmpeg curl unzip ca-certificates gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# ---- Workdir ----
WORKDIR /api

# Copy requirements early for caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# ---- Vosk model (use higher one later)
# Example alternatives you can pass at build time:
#  - https://alphacephei.com/vosk/models/vosk-model-en-us-0.22.zip
#  - https://alphacephei.com/vosk/models/vosk-model-en-us-0.42-gigaspeech.zip
ARG MODEL_URL="https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip"

RUN mkdir -p /opt/vosk && \
    echo "Downloading Vosk model from ${MODEL_URL}..." && \
    curl -L -o /tmp/vosk.zip "$MODEL_URL" && \
    echo "Extracting model..." && \
    unzip -q /tmp/vosk.zip -d /opt/vosk && \
    rm /tmp/vosk.zip && \
    ln -s "$(find /opt/vosk -maxdepth 1 -type d -name 'vosk-model*' | head -n 1)" /opt/vosk/model && \
    echo "Vosk model installed at /opt/vosk/model"

# ---- App code ----
COPY api /api/api
COPY .env /api/.env

#------Copy static files
COPY static /api/static

# ---- Runtime env / storage outside image ----
# STORAGE_DIR=/data is where videos/audio/text are written. Mount a volume there.
ENV VOSK_MODEL_PATH=/opt/vosk/model \
    SECRET_KEY=change-me \
    FFMPEG_BIN=ffmpeg \
    HEAVY_AUDIO=0 \
    EXTRA_ENCODINGS=""

EXPOSE 8080

# healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "main:app"]

# "I have taken some reference from the web for downloading vosk model"