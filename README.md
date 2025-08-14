# Panther Security Log Anomaly Detection

A complete pipeline for collecting security logs from Panther's GraphQL API, training machine learning models, and deploying anomaly detection as a serverless API via AWS Lambda + API Gateway.

## Overview

### Core Pipeline

#### Script 1: Data Collector (`data_collector/`)
- Uses Panther's executeDataLakeQuery mutation + polling pattern
- Handles async query execution with proper status monitoring
- Automatically paginates through large result sets
- Saves JSON security logs for training

#### Script 2: Model Trainer (`model_trainer/`)
- Analyzes security logs and trains Isolation Forest models
- Uses enhanced feature selection with temporal discrimination
- Computes statistical baselines for explainable anomalies

#### Script 3: Anomaly Detector (`anomaly_detector/`)
- Detects anomalies in individual security log events
- Provides anomaly scores and human-readable explanations
- Compares events against learned baselines

#### Script 4: Feature Selection (`shared/feature_selection.py`)
- Optimized feature selection algorithms with coverage and entropy analysis
- Temporal bonuses for hour/day_of_week features
- Enhanced model performance with 10-feature selection

### Production Deployment
- **AWS Lambda Function** - Containerized anomaly detector with pre-trained models
- **API Gateway** - HTTP API endpoint for real-time anomaly detection  
- **Comprehensive Testing** - Local and API test suites for validation

## Setup

### Prerequisites
- Python 3.11+
- Docker and docker-compose
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
      "title": "AWS Config",
      "time": 30,
      "query": "select * exclude (p_source_file, p_any_trace_ids, ...) from panther_logs.public.aws_cloudtrail where p_occurs_since('{time}d') and eventSource = 'config.amazonaws.com'"
    }
  ]
}
```

Each query needs:
- `title`: Name for the dataset (used as filename)
- `time`: Number of days to look back for data
- `query`: SQL query to execute (use `{time}d` placeholder)

## Usage

### Shell Script (Recommended)

Run the complete pipeline:
```bash
cd scripts
./run_pipeline.sh
```

Options:
- `./run_pipeline.sh --skip-data-collection` - Use existing data, skip collection phase

### Production Deployment

Deploy to AWS Lambda + API Gateway:
```bash
cd scripts
./deploy/deploy_lambda.sh
```

This will:
1. Build Docker container with trained models
2. Deploy to AWS Lambda
3. Create API Gateway HTTP API
4. Provide API endpoint for testing

### Testing & Validation

#### Local Testing
Test anomaly detection locally:
```bash
cd scripts
python test_local_comprehensive.py
```

#### API Testing  
Test the deployed API comprehensively:
```bash
cd scripts
python test_api_comprehensive.py --api-url https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod/detect
```

### Docker Compose (Development)

```bash
cd scripts
docker-compose up --build
```

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

# Analyze event from file
python anomaly_detector.py --file event.json

# Analyze event from stdin
echo '{"eventName": "test", "eventSource": "iam.amazonaws.com"}' | python anomaly_detector.py

# Set custom anomaly threshold (default is -0.2)
python anomaly_detector.py --file event.json --anomaly-threshold -0.15
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
- `query`: SQL query with `{time}d` placeholder for temporal filtering

### Model Parameters
- **Algorithm**: Isolation Forest with 10% contamination rate
- **Features**: Enhanced selection targeting 10 features with 60% coverage threshold
- **Threshold**: Default -0.2 (optimized for temporal anomaly detection)  
- **Query polling**: 5-minute timeout with 5-second intervals
- **Result pagination**: Up to 10 pages per query
- **Statistical thresholds**: Z-score > 2 for numerical, rarity > 0.8 for categorical

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
├── shared/                  # Common utilities
│   ├── __init__.py
│   ├── utils.py             # Core feature engineering
│   ├── feature_selection.py # Enhanced feature selection algorithms
│   └── requirements.txt
├── deploy/                  # AWS deployment scripts
│   └── deploy_lambda.sh     # Lambda + API Gateway deployment
├── config/                  # Configuration files
│   ├── config.json
│   └── .env.example
├── data/                    # Collected security logs (gitignored)
├── models/                  # Trained models and metadata (gitignored)
├── test_local_comprehensive.py # Local testing suite
├── test_api_comprehensive.py   # Comprehensive API test suite
├── run_pipeline.sh          # Complete training pipeline
└── docker-compose.yml       # Container orchestration (development)
```

## Features

### Serverless Architecture
- **AWS Lambda** deployment with API Gateway integration
- **Auto-scaling** to handle traffic spikes
- **Pay-per-request** pricing model  
- **Sub-120ms response times** for real-time detection

### Enhanced Machine Learning
- **Isolation Forest** with 10% contamination rate
- **10-feature selection** with temporal discrimination bonuses
- **Optimized thresholds** (-0.2 default) for temporal anomaly detection
- **Multiple model support**: AWS IAM, Config, VPC Flow logs

### Simple Configuration
- Just 3 fields per query: title, time, SQL query
- All GraphQL complexity hidden in scripts
- Easy to add new data sources without GraphQL knowledge
- Configuration-driven pipeline (no hard-coded values)

### Security-Focused Analysis
- **Feature engineering** optimized for security events
- **Time-based anomaly detection** (unusual hours, days, patterns)
- **Categorical rarity analysis** for IPs, user agents, event names
- **Configurable sensitivity** via custom anomaly thresholds

### Explainable Results
- **Human-readable explanations** for each prediction
- **Feature deviation analysis** with severity levels
- **Model transparency** showing training data size and feature usage
- **Z-score analysis** for numerical, rarity scoring for categorical

### Comprehensive Testing
- **Dynamic model discovery** from configuration and trained models
- **Performance benchmarking** across all model types
- **Error handling validation** for edge cases
- **Local and API test suites** for complete validation

### Production-Ready
- **Docker containerization** for consistent deployment
- **Retry logic** and comprehensive error handling
- **Direct API integration** via HTTP endpoints
- **Comprehensive logging** and monitoring support