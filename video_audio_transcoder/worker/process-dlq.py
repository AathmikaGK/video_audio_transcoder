import boto3
import json
from datetime import datetime

# Configuration
AWS_REGION = "ap-southeast-2"
DLQ_URL = "https://sqs.ap-southeast-2.amazonaws.com/901444280953/vat-dlq"
DYNAMODB_TABLE = "a2-group75-videos"

sqs = boto3.client("sqs", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE)

def process_dlq():
    print("🔍 Checking DLQ for failed messages...")
    
    # Receive messages from DLQ
    response = sqs.receive_message(
        QueueUrl=DLQ_URL,
        MaxNumberOfMessages=10,
        WaitTimeSeconds=5
    )
    
    messages = response.get('Messages', [])
    
    if not messages:
        print("✅ No messages in DLQ")
        return
    
    print(f"📥 Found {len(messages)} failed message(s)")
    
    for message in messages:
        body = json.loads(message['Body'])
        video_id = body.get('video_id')
        
        print(f"\n{'='*60}")
        print(f"💀 FAILED JOB: {video_id}")
        print(f"   S3 Key: {body.get('s3_key')}")
        print(f"   User: {body.get('username')}")
        print(f"{'='*60}")
        
        # Update DynamoDB
        try:
            table.update_item(
                Key={'video_id': video_id},
                UpdateExpression='SET #status = :status, updated_at = :updated, error_message = :error',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'failed_permanent',
                    ':updated': datetime.utcnow().isoformat() + 'Z',
                    ':error': 'Failed after 3 attempts (moved to DLQ)'
                }
            )
            print(f"✅ Updated DynamoDB: {video_id} → failed_permanent")
        except Exception as e:
            print(f"❌ DynamoDB update failed: {e}")
        
        # Delete from DLQ
        sqs.delete_message(
            QueueUrl=DLQ_URL,
            ReceiptHandle=message['ReceiptHandle']
        )
        print(f"🗑️  Deleted from DLQ")
    
    print(f"\n✅ Processed {len(messages)} DLQ message(s)")

if __name__ == "__main__":
    process_dlq()