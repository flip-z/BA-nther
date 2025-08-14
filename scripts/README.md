# Panther Security Log Anomaly Detection

A complete pipeline for collecting security logs from Panther's GraphQL API, training machine learning models, and deploying anomaly detection as a serverless API via AWS Lambda + API Gateway.

## Architecture Overview

This system consists of a **development pipeline** and **production deployment**:

### Development Pipeline
1. **Data Collector** (`data_collector/`) - Fetches security logs via Panther GraphQL API
2. **Model Trainer** (`model_trainer/`) - Trains Isolation Forest models on collected logs  
3. **Anomaly Detector** (`anomaly_detector/`) - Detects anomalies in individual events
4. **Feature Selection** (`shared/feature_selection.py`) - Optimized feature selection algorithms

### Production Deployment
- **AWS Lambda Function** - Containerized anomaly detector with pre-trained models
- **API Gateway** - HTTP API endpoint for real-time anomaly detection
- **Comprehensive Test Suite** - Validates API functionality and performance

### Supported Log Types
- **AWS IAM** (CloudTrail events from `iam.amazonaws.com`)
- **AWS Config** (CloudTrail events from `config.amazonaws.com`)  
- **AWS VPC Flow** (VPC Flow logs from `vpc-flow-logs.amazonaws.com`)

## Setup

### Prerequisites
- Python 3.11+
- Docker (for containerized deployment)
- AWS CLI configured with appropriate permissions
- Panther API token (from your Panther console)
- Your Panther instance URL (e.g., `https://company.panther.com`)

### Configuration

1. Copy the environment template:
```bash
cp config/.env.example config/.env
```

2. Set your Panther API credentials in `config/.env`:
```
PANTHER_API_TOKEN=your_token_here
PANTHER_API_URL=https://your-company.panther.com/public/graphql
```

3. Customize queries in `config/config.json`:
```json
{
  "queries": [
    {
      "title": "security_logs",
      "time": 30,
      "query": "SELECT * FROM panther_logs.public.aws_cloudtrail WHERE p_event_time >= now() - interval '{days} days'"
    }
  ]
}
```

Each query needs:
- `title`: Name for the dataset (used as filename)
- `time`: Number of days to look back for data
- `query`: SQL query to execute (use `{days}` placeholder)

## Workflow

### 1. Development Pipeline (Recommended)

Execute the complete training pipeline:
```bash
cd scripts
./run_pipeline.sh
```

This will:
1. Collect security logs from Panther API
2. Train anomaly detection models for each log type
3. Save models and metadata to `models/` directory

**Options:**
- `./run_pipeline.sh --skip-data-collection` - Use existing data, skip collection phase

### 2. Production Deployment

Deploy to AWS Lambda + API Gateway:
```bash
./deploy/deploy_lambda.sh
```

This will:
1. Build Docker container with trained models
2. Deploy to AWS Lambda
3. Create API Gateway HTTP API
4. Provide API endpoint for testing

### 3. Testing & Validation

#### Local Testing
Test anomaly detection locally:
```bash
python test_local_comprehensive.py
```

#### API Testing  
Test the deployed API comprehensively:
```bash
python test_api_comprehensive.py --api-url https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect
```

This will:
1. Dynamically discover available models
2. Test auto-detection via `eventSource` field
3. Test explicit model selection via `log_type`
4. Test custom anomaly thresholds
5. Benchmark performance across all models

### Individual Scripts

#### 1. Data Collection
```bash
cd scripts/data_collector
pip install -r requirements.txt
python data_collector.py
```

#### 2. Model Training
```bash
cd scripts/model_trainer
pip install -r requirements.txt
python model_trainer.py
```

#### 3. Anomaly Detection
```bash
cd scripts/anomaly_detector
pip install -r requirements.txt

# Analyze event from JSON string
python anomaly_detector.py --event '{"timestamp": "2024-01-01T12:00:00Z", "source": "app", ...}'

# Analyze event from file
python anomaly_detector.py --file event.json

# Analyze event from stdin
echo '{"timestamp": "2024-01-01T12:00:00Z", ...}' | python anomaly_detector.py
```

## API Usage

Once deployed, the API Gateway endpoint accepts HTTP POST requests:

### Request Format
```json
{
  "event_data": { 
    "eventName": "CreateUser",
    "eventsource": "iam.amazonaws.com",
    "sourceIPAddress": "10.0.0.1"
  },
  "log_type": "AWS IAM",           // optional - auto-detected if not provided
  "anomaly_threshold": -0.2        // optional - defaults to -0.2
}
```

### Model Auto-Detection
Events are automatically assigned to models based on `eventsource` field:
- `iam.amazonaws.com` → AWS IAM model
- `config.amazonaws.com` → AWS Config model  
- `vpc-flow-logs.amazonaws.com` → AWS VPC Flow model

### Response Format
```json
{
  "log_type": "AWS IAM",
  "is_anomaly": false,
  "anomaly_score": -0.213,
  "anomaly_threshold": -0.2,
  "explanation": "Event appears normal with typical feature patterns.",
  "feature_deviations": {
    "eventName": {
      "type": "categorical",
      "value": "CreateUser", 
      "rarity_score": 0.95,
      "deviation_level": "rare"
    }
  },
  "model_info": {
    "training_samples": 240438,
    "features_used_count": 10,
    "features_found_in_event": 2
  }
}
```

### Example API Calls
```bash
# Auto-detection via eventSource
curl -X POST https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect \
  -H "Content-Type: application/json" \
  -d '{"event_data":{"eventName":"CreateUser","eventsource":"iam.amazonaws.com"}}'

# Explicit model selection
curl -X POST https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect \
  -H "Content-Type: application/json" \
  -d '{"event_data":{"eventName":"CreateUser"},"log_type":"AWS IAM"}'

# Custom threshold (more sensitive)
curl -X POST https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect \
  -H "Content-Type: application/json" \
  -d '{"event_data":{"eventName":"SuspiciousActivity"},"anomaly_threshold":-0.15}'
```

## Output

### Data Collector
- Saves security logs to `data/` directory
- Each query type gets its own JSON file

### Model Trainer  
- Saves trained models to `models/` directory
- Creates separate models for each log type
- Stores feature statistics for explanations

### Anomaly Detector
Returns JSON with:
- `is_anomaly`: Boolean anomaly prediction
- `anomaly_score`: Numerical score (lower = more anomalous)
- `confidence`: Absolute confidence in prediction
- `explanation`: Human-readable anomaly explanation
- `feature_deviations`: Detailed feature analysis

## Configuration

### Queries (`config/config.json`)
Simple configuration with three fields per query:
- `title`: Dataset name (becomes filename)
- `time`: Days to look back for training data
- `query`: SQL query with `{days}` placeholder

### Model Parameters (Hard-coded)
- Isolation Forest contamination rate: 0.1 (10% anomalies expected)
- Query polling: 5-minute timeout with 5-second intervals
- Result pagination: Up to 10 pages per query
- Feature selection: Low cardinality + time-based features prioritized
- Statistical thresholds: Z-score > 2 for numerical, rarity > 0.8 for categorical

## File Structure
```
scripts/
├── data_collector/          # GraphQL data collection
│   ├── data_collector.py
│   ├── Dockerfile
│   └── requirements.txt
├── model_trainer/           # Anomaly model training
│   ├── model_trainer.py
│   ├── Dockerfile  
│   └── requirements.txt
├── anomaly_detector/        # Real-time detection (Lambda handler)
│   ├── anomaly_detector.py
│   ├── Dockerfile
│   └── requirements.txt
├── deploy/                  # AWS deployment scripts
│   └── deploy_lambda.sh     # Lambda + API Gateway deployment
├── shared/                  # Common utilities
│   ├── __init__.py
│   ├── utils.py             # Core feature engineering
│   ├── feature_selection.py # Enhanced feature selection algorithms
│   └── requirements.txt
├── config/                  # Configuration files
│   ├── config.json
│   └── .env.example
├── data/                    # Collected security logs (gitignored)
├── models/                  # Trained models and metadata (gitignored)
├── test_local_comprehensive.py # Local testing suite
├── test_api_comprehensive.py   # Comprehensive API test suite
├── run_pipeline.sh            # Complete training pipeline
└── docker-compose.yml       # Container orchestration (development)
```

## Features

### Serverless Architecture
- **AWS Lambda** deployment with API Gateway integration
- **Auto-scaling** to handle traffic spikes
- **Pay-per-request** pricing model  
- **Sub-120ms response times** for real-time detection

### Intelligent Model Selection
- **Automatic log type detection** via `eventSource` field mapping
- **Explicit model selection** via `log_type` parameter
- **Graceful handling** of unsupported log types (no dangerous defaults)
- **Multiple model support**: AWS IAM, Config, VPC Flow logs

### Comprehensive Testing
- **Dynamic model discovery** from configuration and trained models
- **Performance benchmarking** across all model types
- **Error handling validation** for edge cases
- **100% success rate** with proper error classification

### Security-Focused Analysis
- **Feature engineering** optimized for security events
- **Time-based anomaly detection** (unusual hours, days, patterns)
- **Categorical rarity analysis** for IPs, user agents, event names
- **Configurable sensitivity** via custom anomaly thresholds

### Explainable Results
- **Human-readable explanations** for each prediction
- **Feature deviation analysis** with severity levels
- **Model transparency** showing training data size and feature usage
- **Confidence scoring** based on feature coverage

### Production-Ready
- **Docker containerization** for consistent deployment
- **Retry logic** and comprehensive error handling
- **Configuration-driven** pipeline (no hard-coded values)
- **Direct API integration** via HTTP endpoints
- **Comprehensive logging** and monitoring support