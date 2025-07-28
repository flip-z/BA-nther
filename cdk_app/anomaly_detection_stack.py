from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as _lambda,
    aws_s3 as s3,
    aws_apigateway as apigateway,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_logs as logs,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct

class AnomalyDetectionStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, config: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Create S3 bucket for model storage
        model_bucket = s3.Bucket(
            self, "AnomalyModelBucket",
            bucket_name=f"aws-config-anomaly-models-{self.account}-{self.region}",
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,  # Keep models even if stack is deleted
            auto_delete_objects=False
        )
        
        # Create IAM role for Lambda functions
        lambda_role = iam.Role(
            self, "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies={
                "S3ModelAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:PutObject",
                                "s3:DeleteObject",
                                "s3:ListBucket"
                            ],
                            resources=[
                                model_bucket.bucket_arn,
                                f"{model_bucket.bucket_arn}/*"
                            ]
                        )
                    ]
                )
            }
        )
        
        # Create training function with Docker container
        training_function = _lambda.DockerImageFunction(
            self, "TrainingFunction",
            code=_lambda.DockerImageCode.from_image_asset(
                directory="lambda_functions",
                file="Dockerfile.training"
            ),
            role=lambda_role,
            timeout=Duration.minutes(15),  # Maximum allowed for Lambda
            memory_size=3008,  # Maximum memory for better performance
            environment={
                "S3_BUCKET": model_bucket.bucket_name,
                "PANTHER_API_URL": config["panther_api_url"],
                "PANTHER_API_TOKEN": config["panther_api_token"]
            },
            log_group=logs.LogGroup(
                self, "TrainingFunctionLogGroup",
                log_group_name=f"/aws/lambda/{construct_id}-TrainingFunction",
                retention=logs.RetentionDays.ONE_WEEK,
                removal_policy=RemovalPolicy.DESTROY
            )
        )
        
        # Create detection function with Docker container
        detection_function = _lambda.DockerImageFunction(
            self, "DetectionFunction",
            code=_lambda.DockerImageCode.from_image_asset(
                directory="lambda_functions",
                file="Dockerfile.detection"
            ),
            role=lambda_role,
            timeout=Duration.seconds(30),
            memory_size=1024,
            environment={
                "S3_BUCKET": model_bucket.bucket_name
            },
            log_group=logs.LogGroup(
                self, "DetectionFunctionLogGroup", 
                log_group_name=f"/aws/lambda/{construct_id}-DetectionFunction",
                retention=logs.RetentionDays.ONE_WEEK,
                removal_policy=RemovalPolicy.DESTROY
            )
        )
        
        # Create API Gateway for detection endpoint
        api = apigateway.RestApi(
            self, "AnomalyDetectionAPI",
            rest_api_name="AWS Config Anomaly Detection",
            description="Real-time anomaly detection for AWS Config events",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["Content-Type", "Authorization"]
            )
        )
        
        # Create health check endpoint
        health_integration = apigateway.LambdaIntegration(
            detection_function,
            proxy=True,  # Use Lambda proxy integration
            integration_responses=[{
                'statusCode': '200',
                'responseParameters': {
                    'method.response.header.Access-Control-Allow-Origin': "'*'"
                }
            }]
        )
        
        health_resource = api.root.add_resource("health")
        health_resource.add_method(
            "GET", 
            health_integration,
            method_responses=[{
                'statusCode': '200',
                'responseParameters': {
                    'method.response.header.Access-Control-Allow-Origin': True
                }
            }]
        )
        
        # Create detection endpoint
        detect_integration = apigateway.LambdaIntegration(detection_function)
        
        detect_resource = api.root.add_resource("detect")
        detect_resource.add_method("POST", detect_integration)
        
        # Create scheduled training with EventBridge
        training_rule = events.Rule(
            self, "TrainingScheduleRule",
            description="Trigger model training on schedule",
            schedule=events.Schedule.expression(config.get("training_schedule", "cron(0 6 * * ? *)"))
        )
        
        training_rule.add_target(targets.LambdaFunction(training_function))
        
        # Output the API endpoints
        CfnOutput(
            self, "DetectionEndpoint",
            description="REST API endpoint for anomaly detection",
            value=f"{api.url}detect"
        )
        
        CfnOutput(
            self, "HealthCheckEndpoint", 
            description="Health check endpoint",
            value=f"{api.url}health"
        )
        
        CfnOutput(
            self, "AnomalyModelBucketName",
            description="S3 bucket for model storage",
            value=model_bucket.bucket_name
        )
        
        CfnOutput(
            self, "TrainingFunctionName",
            description="Training function name for manual invocation",
            value=training_function.function_name
        ) 