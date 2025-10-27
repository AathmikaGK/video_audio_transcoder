"""
Dead Letter Queue (DLQ) Handler Lambda Function

This function is triggered when messages end up in the DLQ after 3 failed processing attempts.
It logs the failure, updates DynamoDB, and can send notifications.

Trigger: SQS DLQ
Runtime: Python 3.12
Timeout: 60 seconds
Memory: 256 MB
"""

import json
import boto3
import os
from datetime import datetime

# AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Environment variables
DYNAMODB_TABLE = os.environ.get('DYNAMODB_TABLE', 'a2-group75-videos')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')  # Optional: for alerts

def lambda_handler(event, context):
    """
    Lambda handler function
    
    Args:
        event: SQS DLQ event containing failed messages
        context: Lambda context object
    
    Returns:
        dict: Response with processed message count
    """
    print(f"DLQ Handler triggered with {len(event['Records'])} message(s)")
    
    processed_count = 0
    failed_count = 0
    
    for record in event['Records']:
        try:
            # Process each failed message
            process_dlq_message(record)
            processed_count += 1
            
        except Exception as e:
            print(f"Error processing DLQ message: {e}")
            failed_count += 1
    
    print(f"✅ Processed: {processed_count}, ❌ Failed: {failed_count}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed': processed_count,
            'failed': failed_count
        })
    }

def process_dlq_message(record):
    """
    Process a single DLQ message
    
    Args:
        record: SQS record containing the failed message
    """
    # Extract message details
    message_id = record['messageId']
    body = json.loads(record['body'])
    
    video_id = body.get('video_id', 'UNKNOWN')
    s3_key = body.get('s3_key', 'UNKNOWN')
    username = body.get('username', 'UNKNOWN')
    
    # Get failure metadata
    attributes = record.get('attributes', {})
    receive_count = int(attributes.get('ApproximateReceiveCount', 0))
    first_receive_timestamp = attributes.get('ApproximateFirstReceiveTimestamp', '')
    
    print(f"\n{'='*60}")
    print(f"💀 FAILED JOB DETECTED")
    print(f"{'='*60}")
    print(f"Video ID: {video_id}")
    print(f"S3 Key: {s3_key}")
    print(f"Username: {username}")
    print(f"Receive Count: {receive_count}")
    print(f"Message ID: {message_id}")
    print(f"{'='*60}\n")
    
    # Update DynamoDB with permanent failure status
    update_dynamodb_failed_job(video_id, receive_count, message_id)
    
    # Log to CloudWatch
    log_failure_details(video_id, s3_key, username, receive_count, message_id)
    
    # Send notification (if SNS topic configured)
    if SNS_TOPIC_ARN:
        send_failure_notification(video_id, username, s3_key)
    
    print(f"✅ DLQ message processed for video_id: {video_id}")

def update_dynamodb_failed_job(video_id, receive_count, message_id):
    """
    Update DynamoDB to mark job as permanently failed
    
    Args:
        video_id: The video ID
        receive_count: Number of times message was received
        message_id: SQS message ID
    """
    try:
        table = dynamodb.Table(DYNAMODB_TABLE)
        
        table.update_item(
            Key={'video_id': video_id},
            UpdateExpression='SET #status = :status, updated_at = :updated_at, error_message = :error, dlq_message_id = :msg_id, receive_count = :count',
            ExpressionAttributeNames={
                '#status': 'status'
            },
            ExpressionAttributeValues={
                ':status': 'failed_permanent',
                ':updated_at': datetime.utcnow().isoformat() + 'Z',
                ':error': f'Job failed after {receive_count} attempts. Moved to DLQ.',
                ':msg_id': message_id,
                ':count': receive_count
            }
        )
        
        print(f"✅ Updated DynamoDB: {video_id} → failed_permanent")
        
    except Exception as e:
        print(f"❌ Failed to update DynamoDB: {e}")
        raise

def log_failure_details(video_id, s3_key, username, receive_count, message_id):
    """
    Log comprehensive failure details to CloudWatch
    
    Args:
        video_id: The video ID
        s3_key: S3 key of the video
        username: User who submitted the job
        receive_count: Number of processing attempts
        message_id: SQS message ID
    """
    failure_log = {
        'event_type': 'JOB_PERMANENT_FAILURE',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'video_id': video_id,
        's3_key': s3_key,
        'username': username,
        'receive_count': receive_count,
        'message_id': message_id,
        'action_taken': 'Marked as failed_permanent in DynamoDB'
    }
    
    print(f"📊 FAILURE LOG: {json.dumps(failure_log, indent=2)}")

def send_failure_notification(video_id, username, s3_key):
    """
    Send SNS notification about permanent job failure
    
    Args:
        video_id: The video ID
        username: User who submitted the job
        s3_key: S3 key of the video
    """
    try:
        message = f"""
🚨 PERMANENT JOB FAILURE ALERT 🚨

A transcoding job has permanently failed after 3 attempts.

Details:
- Video ID: {video_id}
- User: {username}
- S3 Key: {s3_key}
- Status: Moved to Dead Letter Queue

Action Required:
- Review CloudWatch logs for error details
- Check if video file is corrupted
- Consider manual retry or user notification

Timestamp: {datetime.utcnow().isoformat()}Z
        """
        
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject='🚨 Video Transcoding Job Failed Permanently',
            Message=message
        )
        
        print(f"📧 SNS notification sent")
        
    except Exception as e:
        print(f"⚠️ Failed to send SNS notification: {e}")
        # Don't raise - notification failure shouldn't fail the whole function