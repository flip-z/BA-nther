# Panther Anomaly Detection API Reference

Complete reference guide for the Panther Security Log Anomaly Detection API deployed on AWS Lambda + API Gateway.

## Base URL

```
https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect
```

Replace `YOUR-API-ID` with your actual API Gateway ID from deployment.

## Authentication

No authentication required. The API is designed for internal security infrastructure use.

## Endpoint

### POST Request

Analyze a security event for anomalies using pre-trained machine learning models.

#### Request Format

```json
{
  "event_data": {
    // Required: The security event to analyze
    "eventName": "CreateUser",
    "sourceIPAddress": "10.0.0.1"
    // ... additional event fields
  },
  "log_type": "AWS IAM",          // Optional: Force specific model
  "anomaly_threshold": -0.3       // Optional: Custom sensitivity threshold
}
```

#### Response Format

```json
{
  "log_type": "AWS IAM",
  "is_anomaly": false,
  "anomaly_score": -0.213,
  "anomaly_threshold": -0.3,
  "explanation": "Event appears normal with typical feature patterns.",
  "feature_deviations": {
    "sourceIPAddress": {
      "type": "categorical",
      "value": "trustedadvisor.amazonaws.com",
      "rarity_score": 0.15,
      "deviation_level": "normal"
    }
  },
  "model_info": {
    "training_samples": 240438,
    "features_used_count": 7,
    "features_found_in_event": 6
  }
}
```

## Supported Models

### AWS IAM
- **Auto-detection**: Events with `"eventsource": "iam.amazonaws.com"`
- **Explicit selection**: `"log_type": "AWS IAM"`
- **Key features**: sourceIPAddress, eventName, userIdentity fields, temporal patterns
- **Training data**: 240,438 CloudTrail IAM events

### AWS Config  
- **Auto-detection**: Events with `"eventsource": "config.amazonaws.com"`
- **Explicit selection**: `"log_type": "AWS Config"`
- **Key features**: sourceIPAddress, eventName, userAgent, sessionContext
- **Training data**: 9,990 CloudTrail Config events

### AWS VPC Flow
- **Auto-detection**: Events with `"eventsource": "vpc-flow-logs.amazonaws.com"`
- **Explicit selection**: `"log_type": "AWS VPC Flow"`  
- **Key features**: interfaceId, account, protocol, bytes, packets
- **Training data**: 855,395 VPC Flow log events

## Request Examples

### Auto-Detection via eventSource

```bash
curl -X POST https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "eventName": "CreateUser",
      "eventsource": "iam.amazonaws.com",
      "sourceIPAddress": "10.0.0.1",
      "userIdentity": {
        "type": "AssumedRole",
        "accountId": "123456789012"
      },
      "p_event_time": "2024-08-14T15:30:00Z"
    }
  }'
```

### Explicit Model Selection

```bash
curl -X POST https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "eventName": "CreateUser", 
      "sourceIPAddress": "192.168.1.100"
    },
    "log_type": "AWS IAM"
  }'
```

### Custom Sensitivity Threshold

```bash
curl -X POST https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect \
  -H "Content-Type: application/json" \
  -d '{
    "event_data": {
      "eventName": "SuspiciousActivity",
      "sourceIPAddress": "unknown-ip.com"
    },
    "log_type": "AWS IAM",
    "anomaly_threshold": -0.1
  }'
```

## Response Fields

### Core Fields
- **`log_type`**: Model used for detection (AWS IAM, AWS Config, AWS VPC Flow)
- **`is_anomaly`**: Boolean indicating if event is anomalous
- **`anomaly_score`**: Float score from Isolation Forest (lower = more anomalous)  
- **`anomaly_threshold`**: Threshold used for classification (default: -0.3)
- **`explanation`**: Human-readable explanation of the result

### Feature Analysis
- **`feature_deviations`**: Detailed analysis of each feature:
  - **`type`**: "categorical" or "numerical"
  - **`value`**: Actual feature value from event
  - **`rarity_score`**: For categorical (0-1, higher = rarer)
  - **`z_score`**: For numerical (standard deviations from mean)
  - **`deviation_level`**: "normal", "moderate", "high", "rare"

### Model Information
- **`model_info`**: Metadata about the model used:
  - **`training_samples`**: Number of events used to train model
  - **`features_used_count`**: Total features in the model
  - **`features_found_in_event`**: Features extracted from this event

## Error Responses

### 400 Bad Request
```json
{
  "error": "Missing required field: event_data",
  "log_type": null,
  "is_anomaly": false,
  "anomaly_score": null
}
```

### 500 Internal Server Error
```json
{
  "error": "Model 'InvalidModel' not found",
  "log_type": null,
  "is_anomaly": false,  
  "anomaly_score": null
}
```

## Feature Engineering

### Temporal Features
All models automatically extract time-based features from `p_event_time`:
- **`hour`**: Hour of day (0-23)
- **`day_of_week`**: Day of week (0-6, Monday=0)

### CloudTrail Field Mapping
Field names are normalized between event format and model format:
- `eventsource` → `eventSource`  
- `sourceipaddress` → `sourceIPAddress`
- `recipientaccountid` → `recipientAccountId`

### Data Science Approach
- **Coverage Threshold**: Features must be present in 70% of training data
- **Entropy Analysis**: Prioritizes features with high information content
- **Cardinality Limits**: Categorical features limited to 2-1000 unique values
- **Variance Filtering**: Numerical features must have variance > 0.01

## Anomaly Scoring

### Isolation Forest Algorithm
- **Contamination Rate**: 10% (expects 10% of events to be anomalous)
- **Score Range**: Typically -0.6 to +0.4
- **Interpretation**: Lower scores indicate higher anomaly likelihood

### Threshold Guidelines
- **-0.5**: Very sensitive (catches subtle anomalies, more false positives)
- **-0.3**: Default balanced (recommended for most use cases)  
- **-0.1**: Conservative (only flags clear anomalies, fewer false positives)

### Score Interpretation
- **< -0.5**: Highly anomalous
- **-0.5 to -0.3**: Moderately anomalous  
- **-0.3 to 0**: Slight deviation from normal
- **> 0**: Very normal behavior

## Performance Characteristics

### Response Times
- **Average**: 120ms per request
- **95th percentile**: < 200ms
- **Cold start**: < 2 seconds (first request after idle period)

### Throughput
- **Concurrent requests**: 1000+ (AWS Lambda auto-scaling)
- **Rate limits**: None imposed by API
- **Timeout**: 300 seconds maximum

### Model Sizes
- **AWS IAM**: 7 features, 240K training samples
- **AWS Config**: 7 features, 10K training samples  
- **AWS VPC Flow**: 7 features, 855K training samples

## Integration Patterns

### Real-time Processing
```python
import requests

def check_security_event(event):
    response = requests.post(
        "https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect",
        json={"event_data": event},
        timeout=10
    )
    
    if response.status_code == 200:
        result = response.json()
        if result["is_anomaly"]:
            alert_security_team(event, result)
        
    return result
```

### Batch Processing
```python
import asyncio
import aiohttp

async def process_events_batch(events):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for event in events:
            task = analyze_event_async(session, event)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return results

async def analyze_event_async(session, event):
    async with session.post(
        "https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect",
        json={"event_data": event}
    ) as response:
        return await response.json()
```

### Stream Processing
```python
# Kinesis/Kafka integration example
def process_stream_record(record):
    event = json.loads(record.value)
    
    result = requests.post(api_url, json={
        "event_data": event,
        "anomaly_threshold": -0.2  # Sensitive for stream processing
    })
    
    if result.json()["is_anomaly"]:
        send_to_siem(event, result.json())
```

## Best Practices

### Request Optimization
1. **Include p_event_time**: Enables temporal feature extraction
2. **Use eventSource for auto-detection**: More efficient than explicit model selection
3. **Batch requests when possible**: Better throughput for bulk analysis
4. **Set appropriate timeouts**: 10-30 seconds recommended

### Threshold Selection
1. **Start with default (-0.3)**: Good balance for most security use cases
2. **Lower for sensitive systems (-0.5)**: Financial, critical infrastructure
3. **Higher for noisy environments (-0.1)**: Development, testing systems
4. **Adjust based on false positive rates**: Monitor and tune over time

### Error Handling
1. **Handle timeout gracefully**: API may take longer during cold starts
2. **Check status codes**: Don't assume 200 means successful detection
3. **Log API errors**: Important for debugging integration issues
4. **Implement retry logic**: With exponential backoff for reliability

### Security Considerations
1. **Network security**: Deploy within VPC if handling sensitive data
2. **Access control**: Use IAM policies to restrict Lambda invoke permissions
3. **Data privacy**: API doesn't log request data, but implement own controls
4. **Rate limiting**: Consider implementing client-side rate limiting

## Troubleshooting

### Common Issues

**404 Not Found**
- Check endpoint URL includes `/detect` path
- Verify API Gateway deployment is active

**Model not found errors**  
- Verify `log_type` spelling matches exactly: "AWS IAM", "AWS Config", "AWS VPC Flow"
- Use auto-detection with `eventsource` field instead

**Low feature coverage**
- Include more relevant fields from your log schema
- Check field name casing (sourceIPAddress not sourceipaddress)

**Unexpected anomaly scores**
- Verify event timestamp format: ISO 8601 with Z suffix
- Check for typos in categorical field values
- Consider that rare but legitimate values may score as anomalous

### Debugging Steps

1. **Test with known good event**: Use examples from this documentation
2. **Check response fields**: Look at `features_found_in_event` count
3. **Examine feature deviations**: Understand which features drive the score
4. **Try different thresholds**: Rule out threshold sensitivity issues
5. **Use explicit model selection**: Eliminate auto-detection as variable

### Performance Issues

1. **Cold start delays**: First request after idle may take 1-2 seconds
2. **Concurrent limit**: AWS Lambda has account-level concurrent execution limits  
3. **Memory constraints**: Large events may hit Lambda memory limits
4. **Timeout errors**: Increase client timeout, especially for first requests

## Monitoring

### Key Metrics
- **Request latency**: Monitor P95/P99 response times
- **Error rates**: Track 4xx/5xx responses
- **Anomaly detection rates**: Baseline normal vs anomaly ratios
- **Feature extraction success**: Monitor `features_found_in_event`

### CloudWatch Metrics
- `AWS/Lambda/Duration`: Response time metrics
- `AWS/Lambda/Errors`: Error count tracking  
- `AWS/Lambda/Invocations`: Request volume
- `AWS/ApiGateway/4XXError`: Client error monitoring
- `AWS/ApiGateway/5XXError`: Server error monitoring

### Logging
- Lambda function logs available in CloudWatch Logs
- API Gateway access logs can be enabled for request tracking
- Custom application metrics can be sent to CloudWatch

This completes the comprehensive API documentation with examples, best practices, and troubleshooting guidance.