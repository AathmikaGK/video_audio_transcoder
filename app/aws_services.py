import boto3

# Initialize S3 and DynamoDB clients
s3_client = boto3.client("s3", region_name="ap-southeast-2")
dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-2")

# Your bucket and table names
BUCKET_NAME = "a2-group75"
TABLE_NAME = "a2-group75-videos"

# Get a reference to the DynamoDB table
video_table = dynamodb.Table(TABLE_NAME)

def upload_to_s3(file_path, s3_key):
    """Upload a file to S3."""
    s3_client.upload_file(file_path, BUCKET_NAME, s3_key)
    return f"https://{BUCKET_NAME}.s3.ap-southeast-2.amazonaws.com/{s3_key}"

def save_video_metadata(video_id, filename, status, s3_url):
    """Save video metadata to DynamoDB."""
    item = {
        "video_id": video_id,
        "filename": filename,
        "status": status,
        "s3_url": s3_url,
    }
    video_table.put_item(Item=item)
    return item


