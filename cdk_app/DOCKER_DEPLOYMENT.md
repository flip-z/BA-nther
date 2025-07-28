# Docker-Based Lambda Deployment Guide

This deployment uses Docker containers for both Lambda functions to handle the scikit-learn size limitations that were preventing standard Lambda deployments.

## 🐳 What Changed

### Previous Issues
- Standard Lambda packages hit the 250MB limit with scikit-learn and dependencies
- Deployment failures due to package size constraints

### Docker Solution
- Both functions now use custom Docker containers
- Based on AWS Lambda Python runtime images
- Full scikit-learn support without size limitations
- Better dependency management and reproducibility

## 🚀 Deployment Steps

### 1. Prerequisites

Make sure you have Docker installed and running:
```bash
docker --version
```

Install/update CDK and dependencies:
```bash
npm install -g aws-cdk@latest
pip install -r requirements.txt
```

### 2. Docker Setup

The CDK will automatically handle Docker image building and pushing to ECR. You don't need to build images manually.

### 3. Deploy

Use the existing deployment process:
```bash
# If first time deploying
cdk bootstrap

# Deploy with your config
python deploy.py
```

Or deploy directly:
```bash
cdk deploy \
  --context panther_api_url="https://your-company.runpanther.net/api/graphql" \
  --context panther_api_token="your-api-token"
```

## 📦 What Gets Created

### Docker Images
- **Detection Function**: Lightweight image (~200MB) with scikit-learn for real-time inference
- **Training Function**: Full ML image (~300MB) with pandas, scikit-learn, and training dependencies

### AWS Resources
- **ECR Repositories**: Automatically created for each function's Docker images
- **Lambda Functions**: Running as container images instead of zip packages
- **S3 Bucket**: Model storage (unchanged)
- **API Gateway**: REST API endpoints (unchanged)
- **EventBridge**: Scheduled training (unchanged)

## 🔍 Verification

After deployment, test both functions:

### Health Check
```bash
curl https://your-api-endpoint/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "AWS Config Anomaly Detection",
  "timestamp": "2024-06-27T10:30:00Z",
  "sklearn_available": true
}
```

### Manual Training
```bash
aws lambda invoke \
  --function-name AWSConfigAnomalyDetection-TrainingFunction-XXXXX \
  /tmp/training-response.json
```

### Detection Test
```bash
curl -X POST https://your-api-endpoint/detect \
  -H "Content-Type: application/json" \
  -d '{
    "eventName": "DeleteConfigRule",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.168.1.100",
    "userAgent": "curl/7.68.0",
    "recipientAccountId": 999999999999,
    "p_event_time": "2024-06-27 03:15:22"
  }'
```

## 🛠️ Troubleshooting

### Common Issues

**"Docker not found during CDK deploy"**
- Ensure Docker is installed and running
- CDK needs Docker to build the container images

**"ECR repository access denied"**
- Check your AWS credentials have ECR permissions
- CDK bootstrap may need to be run again

**"Container image too large"**
- Check the Dockerfile isn't copying unnecessary files
- The .dockerignore file should exclude cache and build files

**"Function timeout during training"**
- Training function has 15-minute timeout (Lambda maximum)
- For larger datasets, consider using ECS Fargate instead

### Monitoring

Check CloudWatch logs:
```bash
# Training function logs
aws logs tail /aws/lambda/AWSConfigAnomalyDetection-TrainingFunction-XXXXX --follow

# Detection function logs  
aws logs tail /aws/lambda/AWSConfigAnomalyDetection-DetectionFunction-XXXXX --follow
```

### Performance

**Cold Start Impact:**
- Container images have slightly longer cold starts (~2-3 seconds vs ~1 second)
- Use provisioned concurrency for production if needed

**Memory Usage:**
- Training function: 3008MB (maximum) for large dataset processing
- Detection function: 1024MB for fast inference

## 🧹 Cleanup

To remove everything:
```bash
cdk destroy
```

This will:
- Delete Lambda functions and their container images
- Remove ECR repositories
- Delete API Gateway
- Remove EventBridge rules
- Keep S3 bucket with models (manual deletion required)

## 📈 Scaling Considerations

### For Larger Workloads

If you exceed Lambda limits:

**Training (>15 minutes or >3GB memory):**
- Consider ECS Fargate with the same Docker images
- Use AWS Batch for even larger ML workloads

**Detection (>1000 requests/second):**
- Enable API Gateway caching
- Use Lambda provisioned concurrency
- Consider Amazon SageMaker endpoints for production ML serving

## 🔒 Security Notes

- Docker images are private in your ECR repositories
- Images inherit all existing IAM policies
- No additional security configuration needed

## 📊 Cost Impact

**Container vs Zip:**
- ECR storage: ~$0.10/month per GB for images
- Slightly higher Lambda invocation cost due to longer cold starts
- Overall cost increase: typically <$5/month for normal usage 