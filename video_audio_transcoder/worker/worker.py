#!/usr/bin/env python3
"""
Worker Microservice - Polls SQS and processes transcoding jobs
"""
import os
import json
import time
import boto3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Import processing logic
from tasks import process_job

# Configuration
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
DYNAMODB_TABLE = os.getenv("DYNAMODB_TABLE", "a2-group75-videos")
POLL_WAIT_TIME = 20  # Long polling (saves costs)
MAX_MESSAGES = 1  # Process one job at a time (single-threaded)

# AWS clients
sqs = boto3.client("sqs", region_name=AWS_REGION)
ddb = boto3.resource("dynamodb", region_name=AWS_REGION).Table(DYNAMODB_TABLE)

def update_job_status(video_id, status, **kwargs):
    """Update job status in DynamoDB"""
    try:
        update_expr = "SET #status = :status, updated_at = :updated_at"
        expr_attr_names = {"#status": "status"}
        expr_attr_values = {
            ":status": status,
            ":updated_at": datetime.utcnow().isoformat() + "Z"
        }
        
        if "audio_s3_key" in kwargs:
            update_expr += ", audio_s3_key = :audio"
            expr_attr_values[":audio"] = kwargs["audio_s3_key"]
        if "transcript_s3_key" in kwargs:
            update_expr += ", transcript_s3_key = :transcript"
            expr_attr_values[":transcript"] = kwargs["transcript_s3_key"]
        if "error_message" in kwargs:
            update_expr += ", error_message = :error"
            expr_attr_values[":error"] = kwargs["error_message"]
        
        ddb.update_item(
            Key={"video_id": video_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values
        )
        print(f"✅ Updated DynamoDB: {video_id} → {status}")
        return True
    except Exception as e:
        print(f"❌ Failed to update DynamoDB: {e}")
        return False

def process_message(message):
    """Process a single SQS message"""
    try:
        # Parse message
        body = json.loads(message['Body'])
        video_id = body.get('video_id')
        s3_key = body.get('s3_key')
        username = body.get('username')
        
        print(f"\n{'='*60}")
        print(f"📥 Received job: {video_id}")
        print(f"   S3 Key: {s3_key}")
        print(f"   User: {username}")
        print(f"{'='*60}\n")
        
        # Update status to processing
        update_job_status(video_id, "processing")
        
        # Process the job
        success, audio_key, transcript_key, error = process_job(video_id, s3_key)
        
        if success:
            # Update status to done
            update_job_status(
                video_id, 
                "done",
                audio_s3_key=audio_key,
                transcript_s3_key=transcript_key
            )
            print(f"✅ Job completed successfully: {video_id}\n")
            return True
        else:
            # Update status to failed
            update_job_status(video_id, "failed", error_message=error)
            print(f"❌ Job failed: {video_id} - {error}\n")
            return False
            
    except Exception as e:
        print(f"❌ Error processing message: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main worker loop"""
    print("="*60)
    print("🚀 WORKER MICROSERVICE STARTED")
    print("="*60)
    print(f"Region: {AWS_REGION}")
    print(f"Queue: {SQS_QUEUE_URL}")
    print(f"DynamoDB: {DYNAMODB_TABLE}")
    print(f"Polling every {POLL_WAIT_TIME} seconds...")
    print("="*60 + "\n")
    
    while True:
        try:
            print(f"⏳ Polling SQS queue... (waiting up to {POLL_WAIT_TIME}s)")
            
            response = sqs.receive_message(
                QueueUrl=SQS_QUEUE_URL,
                MaxNumberOfMessages=MAX_MESSAGES,
                WaitTimeSeconds=POLL_WAIT_TIME,
                
                MessageAttributeNames=['All'],
                AttributeNames=['All']  # IMPORTANT: Get receive count
            )
            
            messages = response.get('Messages', [])
            
            if not messages:
                print("   No messages in queue")
                consecutive_errors = 0
                continue
            
            print(f"   Found {len(messages)} message(s)\n")
            
            for message in messages:
                receipt_handle = message['ReceiptHandle']
                message_id = message['MessageId']
                
                # Get receive count
                attributes = message.get('Attributes', {})
                receive_count = int(attributes.get('ApproximateReceiveCount', 0))
                
                print(f"📨 Processing message ID: {message_id}")
                print(f"   Receive count: {receive_count}")
                
                # Process the job
                success = process_message(message)
                
                if success:
                    # ONLY delete on success
                    try:
                        sqs.delete_message(
                            QueueUrl=SQS_QUEUE_URL,
                            ReceiptHandle=receipt_handle
                        )
                        print(f"🗑️  Deleted message {message_id} from queue\n")
                    except Exception as e:
                        print(f"⚠️  Failed to delete message: {e}\n")
                else:
                    # DON'T delete - let SQS handle retry/DLQ
                    print(f"⚠️  Message {message_id} NOT deleted (will retry)")
                    print(f"   Receive count: {receive_count}/3")
                    
                    if receive_count >= 2:
                        print(f"   ⚠️  Next failure will move to DLQ\n")
                     
            
            consecutive_errors = 0
            
        except KeyboardInterrupt:
            print("\n🛑 Worker stopped by user")
            break
        except Exception as e:
            print(f"❌ Error in main loop: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(5)  # Wait before retrying

if __name__ == "__main__":
    main()