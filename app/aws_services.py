# app/aws_services.py
import os
import uuid
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime

REGION = os.getenv("COGNITO_REGION", "ap-southeast-2")
BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
TABLE_NAME  = os.getenv("DYNAMODB_TABLE")

if not BUCKET_NAME:
    raise RuntimeError("Missing env var S3_BUCKET_NAME")
if not TABLE_NAME:
    raise RuntimeError("Missing env var DYNAMODB_TABLE")

s3 = boto3.client("s3", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
table = dynamodb.Table(TABLE_NAME)

def upload_to_s3(file_obj, s3_key, content_type=None):
    """
    Upload a file-like object (Werkzeug/Flask file) to S3 using upload_fileobj.
    Returns the S3 key that was stored.
    """
    extra = {}
    if content_type:
        extra["ContentType"] = content_type

    try:
        # IMPORTANT: file_obj must be at position 0
        file_obj.stream.seek(0)
        s3.upload_fileobj(
            Fileobj=file_obj.stream,
            Bucket=BUCKET_NAME,
            Key=s3_key,
            ExtraArgs=extra or None
        )
        return s3_key
    except (BotoCoreError, ClientError) as e:
        print(f"[upload_to_s3] ERROR: {e}")
        return None

def save_video_metadata(video_id, owner, filename, s3_key, status="uploaded"):
    """
    Persist a row into DynamoDB for your video.
    """
    try:
        item = {
            "video_id": video_id,        # partition key
            "owner": owner,              # who uploaded
            "filename": filename,
            "s3_key": s3_key,
            "status": status,
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        table.put_item(Item=item)
        return item
    except (BotoCoreError, ClientError) as e:
        print(f"[save_video_metadata] ERROR: {e}")
        return None
