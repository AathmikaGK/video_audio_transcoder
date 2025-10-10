import os
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

# Load env when running via gunicorn too
load_dotenv()

REGION = os.getenv("COGNITO_REGION", "ap-southeast-2")
BUCKET = os.getenv("S3_BUCKET_NAME")
TABLE  = os.getenv("DYNAMODB_TABLE")

s3  = boto3.client("s3", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION)

def upload_to_s3(fileobj, filename):
    """
    Uploads the incoming Werkzeug file to S3 under uploads/<filename>.
    Returns (s3_url, None) on success; (None, 'error message') on failure.
    """
    key = f"uploads/{filename}"
    try:
        s3.upload_fileobj(
            Fileobj=fileobj,
            Bucket=BUCKET,
            Key=key,
            ExtraArgs={"ContentType": getattr(fileobj, "mimetype", "application/octet-stream"),
                       "ACL": "private"}
        )
        return f"s3://{BUCKET}/{key}", None
    except (BotoCoreError, ClientError) as e:
        msg = f"S3 upload failed: {getattr(e, 'response', {}).get('Error', {}).get('Message', str(e))}"
        print(msg)
        return None, msg
    except Exception as e:
        msg = f"S3 upload failed: {repr(e)}"
        print(msg)
        return None, msg

def save_video_metadata(video_id: str, username: str, s3_url: str):
    """
    Writes a simple item to DynamoDB.
    Returns (True, None) on success; (False, 'error message') on failure.
    """
    try:
        table = ddb.Table(TABLE)
        table.put_item(Item={
            "video_id": video_id,
            "owner": username,
            "s3_url": s3_url,
        })
        return True, None
    except (BotoCoreError, ClientError) as e:
        msg = f"DDB put failed: {getattr(e, 'response', {}).get('Error', {}).get('Message', str(e))}"
        print(msg)
        return False, msg
    except Exception as e:
        msg = f"DDB put failed: {repr(e)}"
        print(msg)
        return False, msg
