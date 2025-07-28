#!/usr/bin/env python3
"""
AWS Config Anomaly Detection CDK App
Simple deployment for non-technical users
"""

import aws_cdk as cdk
from anomaly_detection_stack import AnomalyDetectionStack

app = cdk.App()

# Get configuration from context or use defaults
config = {
    'panther_api_url': app.node.try_get_context('panther_api_url') or 'https://your-panther-instance.runpanther.net/api/graphql',
    'panther_api_token': app.node.try_get_context('panther_api_token') or 'your-api-token-here',
    'training_schedule': app.node.try_get_context('training_schedule') or 'cron(0 6 * * ? *)',  # 6 AM daily
    'environment': app.node.try_get_context('environment') or 'dev'
}

AnomalyDetectionStack(
    app, 
    "AWSConfigAnomalyDetection",
    config=config,
    env=cdk.Environment(
        account=app.node.try_get_context('account'),
        region=app.node.try_get_context('region') or 'us-west-2'
    )
)

app.synth() 