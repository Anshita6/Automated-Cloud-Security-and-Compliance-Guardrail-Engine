import os
import boto3
from moto import mock_aws
import pytest
from src.lambda_function import lambda_handler

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:security-alerts"

@mock_aws
def test_lambda_handler_secures_s3_bucket(aws_credentials):
    # 1. Setup Mock AWS Resources
    s3 = boto3.client("s3", region_name="us-east-1")
    sns = boto3.client("sns", region_name="us-east-1")
    
    bucket_name = "unsecure-test-bucket"
    s3.create_bucket(Bucket=bucket_name)
    
    # Create mock SNS topic
    sns.create_topic(Name="security-alerts")

    # 2. Simulated CloudTrail / EventBridge payload for public bucket creation
    event = {
        "detail": {
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/johndoe"},
            "requestParameters": {"bucketName": bucket_name}
        }
    }

    # 3. Execute Lambda Handler
    response = lambda_handler(event, None)

    # 4. Assertions / Verifications
    assert response["statusCode"] == 200

    # Verify S3 Public Access Block was applied
    public_block = s3.get_public_access_block(Bucket=bucket_name)
    config = public_block["PublicAccessBlockConfiguration"]
    
    assert config["BlockPublicAcls"] is True
    assert config["IgnorePublicAcls"] is True
    assert config["BlockPublicPolicy"] is True
    assert config["RestrictPublicBuckets"] is True