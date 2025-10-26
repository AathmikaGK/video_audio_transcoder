import os
import json
import uuid
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

REGION = os.getenv("AWS_REGION", "ap-southeast-2")
BUCKET = os.getenv("S3_BUCKET_NAME", "a2-group75")
TABLE = os.getenv("DYNAMODB_TABLE", "a2-group75-videos")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")

s3 = boto3.client("s3", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION)
sqs = boto3.client("sqs", region_name=REGION)

# ============== S3 Functions ==============
def upload_to_s3(fileobj, filename):
    """Upload file to S3"""
    key = f"uploads/{filename}"
    try:
        s3.upload_fileobj(
            Fileobj=fileobj,
            Bucket=BUCKET,
            Key=key,
            ExtraArgs={
                "ContentType": getattr(fileobj, "mimetype", "application/octet-stream"),
                "ACL": "private"
            }
        )
        return f"s3://{BUCKET}/{key}", key, None
    except Exception as e:
        return None, None, str(e)

def get_s3_presigned_url(s3_key, expiration=3600):
    """Generate presigned URL for downloading"""
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': BUCKET, 'Key': s3_key},
            ExpiresIn=expiration
        )
        return url, None
    except Exception as e:
        return None, str(e)

# ============== DynamoDB Functions ==============
def save_video_metadata(video_id, username, s3_url, s3_key, filename):
    """Save video metadata to DynamoDB"""
    try:
        table = ddb.Table(TABLE)
        table.put_item(Item={
            "video_id": video_id,
            "username": username,
            "s3_url": s3_url,
            "s3_key": s3_key,
            "original_filename": filename,
            "status": "uploaded",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z"
        })
        return True, None
    except Exception as e:
        return False, str(e)

def get_video_metadata(video_id):
    """Get video metadata from DynamoDB"""
    try:
        table = ddb.Table(TABLE)
        response = table.get_item(Key={"video_id": video_id})
        return response.get("Item"), None
    except Exception as e:
        return None, str(e)

def update_video_status(video_id, status, **kwargs):
    """Update video status in DynamoDB"""
    try:
        table = ddb.Table(TABLE)
        update_expr = "SET #status = :status, updated_at = :updated_at"
        expr_attr_names = {"#status": "status"}
        expr_attr_values = {
            ":status": status,
            ":updated_at": datetime.utcnow().isoformat() + "Z"
        }
        
        # Add optional fields
        if "audio_s3_key" in kwargs:
            update_expr += ", audio_s3_key = :audio"
            expr_attr_values[":audio"] = kwargs["audio_s3_key"]
        if "transcript_s3_key" in kwargs:
            update_expr += ", transcript_s3_key = :transcript"
            expr_attr_values[":transcript"] = kwargs["transcript_s3_key"]
        if "error_message" in kwargs:
            update_expr += ", error_message = :error"
            expr_attr_values[":error"] = kwargs["error_message"]
        if "job_id" in kwargs:
            update_expr += ", job_id = :job_id"
            expr_attr_values[":job_id"] = kwargs["job_id"]
        
        table.update_item(
            Key={"video_id": video_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values
        )
        return True, None
    except Exception as e:
        return False, str(e)

def list_user_videos(username):
    """List all videos for a user"""
    try:
        table = ddb.Table(TABLE)
        response = table.scan(
            FilterExpression="username = :username",
            ExpressionAttributeValues={":username": username}
        )
        return response.get("Items", []), None
    except Exception as e:
        return [], str(e)

# ============== SQS Functions ==============
def send_job_to_queue(video_id, s3_key, username):
    """Send transcoding job to SQS"""
    try:
        message_body = json.dumps({
            "video_id": video_id,
            "s3_key": s3_key,
            "username": username,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
        
        response = sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=message_body,
            MessageAttributes={
                'video_id': {
                    'StringValue': video_id,
                    'DataType': 'String'
                },
                'username': {
                    'StringValue': username,
                    'DataType': 'String'
                }
            }
        )
        
        return response['MessageId'], None
    except Exception as e:
        return None, str(e)