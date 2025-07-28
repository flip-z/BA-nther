# AWS Config Anomaly Detection - CDK Deployment

This is a **complete, production-ready** anomaly detection system for AWS Config events. It automatically trains daily and provides a fast API for real-time anomaly detection.

## 🚀 Quick Setup (5 minutes)

### Prerequisites
- AWS CLI configured with appropriate permissions
- Python 3.8+ installed
- Node.js 16+ installed (for CDK)

### Step 1: Configure Your Settings

Edit `config.json` with your details:

```json
{
  "panther_api_url": "https://your-company.runpanther.net/api/graphql",
  "panther_api_token": "your-actual-api-token-from-panther",
  "training_schedule": "cron(0 6 * * ? *)",
  "aws_region": "us-west-2",
  "environment": "prod"
}
```

**How to get your Panther API token:**
1. Go to your Panther console
2. Navigate to Settings → API Tokens
3. Create a new token with "Data Lake Query" permissions
4. Copy the token into `config.json`

### Step 2: Install Dependencies

```bash
# Install CDK globally (one-time setup)
npm install -g aws-cdk

# Install Python dependencies
pip install -r requirements.txt
```

### Step 3: Deploy to AWS

```bash
# Bootstrap CDK (first time only)
cdk bootstrap

# Deploy the stack
cdk deploy --parameters panther_api_url="https://your-company.runpanther.net/api/graphql" \
           --parameters panther_api_token="your-actual-token"
```

**That's it!** ✨

## 📋 What Gets Created

After deployment, you'll have:

- **📊 Daily Training**: Automatically gathers last 30 days of Config data and trains a new model at 6 AM
- **🚀 REST API**: Fast endpoint for real-time anomaly detection  
- **☁️ S3 Storage**: Secure model storage with versioning
- **📝 CloudWatch Logs**: Complete monitoring and debugging

## 🔗 Using Your API

After deployment, CDK will show you the API endpoint:

```
✅ AWSConfigAnomalyDetection

Outputs:
AWSConfigAnomalyDetection.DetectionEndpoint = https://abc123.execute-api.us-west-2.amazonaws.com/prod/detect
AWSConfigAnomalyDetection.HealthCheckEndpoint = https://abc123.execute-api.us-west-2.amazonaws.com/prod/health
```

### Test the Health Check
```bash
curl https://your-endpoint/health
```

### Detect Anomalies
```bash
curl -X POST https://your-endpoint/detect \
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

### Response Example
```json
{
  "is_anomaly": true,
  "anomaly_score": -0.0847,
  "confidence": 0.0847,
  "rarity_analysis": [
    {
      "feature": "eventName",
      "value": "DeleteConfigRule",
      "category": "UNSEEN",
      "description": "never seen in training"
    }
  ],
  "suspicious_features": [
    {
      "feature": "eventName", 
      "description": "never seen in training"
    }
  ]
}
```

## ⚙️ Configuration Options

### Training Schedule
Change when models retrain by editing `training_schedule` in `config.json`:

- `"cron(0 6 * * ? *)"` - Daily at 6 AM
- `"cron(0 18 * * ? *)"` - Daily at 6 PM  
- `"cron(0 12 * * 1 *)"` - Weekly on Monday at noon

### Manual Training
Force a training run anytime:

```bash
aws lambda invoke --function-name AWSConfigAnomalyDetection-TrainingFunction-xxx response.json
```

### View Logs
```bash
aws logs tail /aws/lambda/AWSConfigAnomalyDetection-TrainingFunction-xxx --follow
aws logs tail /aws/lambda/AWSConfigAnomalyDetection-DetectionFunction-xxx --follow
```

## 🛠️ Troubleshooting

### Common Issues

**"No CloudTrail table found"**
- Check your Panther API URL and token
- Make sure your Panther instance has CloudTrail data

**"Failed to gather training data"**  
- Check CloudWatch logs for the training function
- Verify your API token has "Data Lake Query" permissions

**"Model not found"**
- Run training manually first: `aws lambda invoke --function-name ...TrainingFunction...`
- Check S3 bucket for model files

### Getting Help

1. Check CloudWatch logs for detailed error messages
2. Verify your Panther API credentials
3. Ensure your AWS account has the necessary permissions

## 🧹 Cleanup

To remove everything:

```bash
cdk destroy
```

This will delete all AWS resources **except** the S3 bucket (which contains your models). Delete the bucket manually if you want to remove everything completely.

## 🔒 Security Notes

- API has CORS enabled for web applications
- S3 bucket has versioning enabled to prevent accidental model deletion
- Lambda functions run with minimal required permissions
- CloudWatch logs retain for 1 week (configurable)

## 📈 Scaling

This setup handles:
- **Training**: Up to 100k events (15-minute Lambda limit)
- **Detection**: 1000+ requests/second (API Gateway + Lambda)

For larger datasets, consider:
- Using ECS Fargate for training (removes 15-minute limit)
- Adding API Gateway caching
- Using Lambda provisioned concurrency for consistent response times 