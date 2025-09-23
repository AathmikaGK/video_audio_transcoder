import os
from datetime import timedelta

class Settings:
    PROJECT_NAME: str = "Vid2AudioText API"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./app.db")

    STORAGE_DIR: str = os.getenv("STORAGE_DIR", "./storage")
    VIDEO_DIR: str = os.path.join(STORAGE_DIR, "videos")
    AUDIO_DIR: str = os.path.join(STORAGE_DIR, "audio")
    TEXT_DIR: str = os.path.join(STORAGE_DIR, "text")
    FFMPEG_BIN: str = os.getenv("FFMPEG_BIN", "ffmpeg")  # allow explicit path on Windows
    HEAVY_AUDIO: bool = os.getenv("HEAVY_AUDIO", "0") == "1"  # turn on HQ filters
    EXTRA_ENCODINGS: str = os.getenv("EXTRA_ENCODINGS", "")   # e.g. "flac,opus,aac"

    # Path to bundled Vosk model inside the container (see Dockerfile)
    # VOSK_MODEL_PATH: str = os.getenv("VOSK_MODEL_PATH", "/opt/vosk-model-small-en-us-0.15")
    VOSK_MODEL_PATH: str = os.getenv("VOSK_MODEL_PATH", "/opt/vosk/model")


settings = Settings()
