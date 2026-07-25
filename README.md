# Automated Cloud Security and Compliance Guardrail Engine

An event-driven cloud security tool built using Python, AWS (Lambda, EventBridge, CloudWatch, SNS), and Terraform.

## Problem Statement
Manual cloud auditing leads to delayed security responses. Publicly exposed resources and over-permissive IAM rights create major security vulnerabilities and compliance risks for enterprise infrastructure.

## Solution Architecture
1. EventBridge captures CloudTrail security events (such as an S3 bucket configuration being set to public).
2. A serverless AWS Lambda function executed via Python and Boto3 automatically enforces public access blocks in under five seconds.
3. Amazon SNS publishes real-time security alerts to designated security operations contacts.
4. Terraform declaratively manages all infrastructure resources.

## Tech Stack
* Programming Language: Python 3.11 (Boto3 SDK, Pytest, Moto)
* Cloud Platform: Amazon Web Services (Lambda, EventBridge, CloudWatch, SNS, IAM, S3)
* Infrastructure as Code: Terraform
* CI/CD & Automation: GitHub Actions, Docker, Bash

## Repository Structure
```text
.
├── .github/
│   └── workflows/
│       └── deploy.yml          # GitHub Actions CI/CD Pipeline
├── src/
│   ├── __init__.py
│   └── lambda_function.py      # Core Boto3 auto-remediation logic
├── tests/
│   └── test_remediation.py     # Unit tests with Moto AWS mocks
├── terraform/
│   └── main.tf                 # Declarative infrastructure definitions
├── Dockerfile                  # Containerized testing environment
├── requirements.txt            # Python dependencies
└── README.md