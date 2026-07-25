import json
import os
import logging
import boto3
from botocore.exceptions import ClientError

# Set up structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_boto_client(service_name):
    """Helper to allow easier mocking during unit tests."""
    return boto3.client(service_name)

def lambda_handler(event, context):
    """
    AWS Lambda entry point triggered by EventBridge when an S3 bucket is modified.
    """
    sns_topic_arn = os.getenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:mock-topic")
    
    s3_client = get_boto_client('s3')
    sns_client = get_boto_client('sns')

    try:
        # Extract details from the CloudTrail / EventBridge payload
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        bucket_name = request_params.get('bucketName')
        user_arn = detail.get('userIdentity', {}).get('arn', 'Unknown User')

        if not bucket_name:
            logger.warning("No bucket name found in the event payload.")
            return {"statusCode": 400, "body": "Invalid event: Missing bucket name"}

        logger.info(f"🔍 Analyzing bucket: {bucket_name} modified by: {user_arn}")

        # 1. ACTION: Enforce S3 Public Access Block (Auto-Remediation)
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        logger.info(f"✅ Successfully secured bucket: {bucket_name}")

        # 2. ACTION: Publish Alert to SNS
        alert_message = (
            f"🚨 AUTOMATED SECURITY REMEDIATION TRIGGERED 🚨\n\n"
            f"Resource: S3 Bucket ({bucket_name})\n"
            f"Action Taken: Enforced Public Access Block\n"
            f"Triggered By: {user_arn}\n"
            f"Status: Resolved automatically in < 5 seconds."
        )

        sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject="[SECURITY ALERT] Public S3 Bucket Remediated",
            Message=alert_message
        )
        logger.info("📩 Notification published to SNS.")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Remediation successful",
                "bucket": bucket_name
            })
        }

    except ClientError as e:
        logger.error(f"❌ AWS ClientError: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"❌ Unexpected Error: {str(e)}")
        raise e