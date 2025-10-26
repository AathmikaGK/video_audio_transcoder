import os
from datetime import timedelta

class Settings:
    PROJECT_NAME: str = "Video Audio Transcoder"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "7f3a8b9c2d1e6f4a5b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0")
    
    # AWS Configuration
    AWS_REGION: str = os.getenv("AWS_REGION", "ap-southeast-2")
    S3_BUCKET: str = os.getenv("S3_BUCKET_NAME", "a2-group75")
    DYNAMODB_TABLE: str = os.getenv("DYNAMODB_TABLE", "a2-group75-videos")
    
    # SQS Configuration
    SQS_QUEUE_URL: str = os.getenv("SQS_QUEUE_URL", "https://sqs.ap-southeast-2.amazonaws.com/901444280953/vat-jobs")
    SQS_DLQ_URL: str = os.getenv("SQS_DLQ_URL", "https://sqs.ap-southeast-2.amazonaws.com/901444280953/vat-dlq")
    
    # Vosk Model
    VOSK_MODEL_PATH: str = os.getenv("VOSK_MODEL_PATH", "/home/ubuntu/video_audio_transcoder/venv/lib/python3.12/site-packages/vosk")
    VOSK_S3_PATH: str = "s3://n11806427-vosk-models/models/ "
    
    # FFmpeg
    FFMPEG_BIN: str = os.getenv("FFMPEG_BIN", "ffmpeg")
    HEAVY_AUDIO: bool = os.getenv("HEAVY_AUDIO", "0") == "1"
    EXTRA_ENCODINGS: str = os.getenv("EXTRA_ENCODINGS", "")
    
    # Cognito
    COGNITO_REGION = "ap-southeast-2"
    COGNITO_USERPOOL_ID = "ap-southeast-2_lOInK99x5"
    COGNITO_CLIENT_ID = "1ingln7v6suqin0roc0i53ehl1"
    COGNITO_CLIENT_SECRET = "aoel06ss40eghu8damv28ggqi7bjvohde2evn13o5ra5l18colo"
    COGNITO_DOMAIN = "myapp.auth.ap-southeast-2.amazoncognito.com"
    FLASK_SECRET_KEY = "mysupersecretkey"

    class Config:
        env_file = ".env"

settings = Settings()