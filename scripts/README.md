# Panther Security Log Anomaly Detection

A three-script system for collecting security logs from Panther's GraphQL API, training anomaly detection models, and detecting anomalies in real-time events.

## Overview

### Script 1: Data Collector (`data_collector/`)
- Uses Panther's executeDataLakeQuery mutation + polling pattern
- Handles async query execution with proper status monitoring
- Automatically paginates through large result sets
- Saves JSON security logs for training

### Script 2: Model Trainer (`model_trainer/`)
- Analyzes security logs and trains Isolation Forest models
- Focuses on low cardinality and time-based features
- Computes statistical baselines for explainable anomalies

### Script 3: Anomaly Detector (`anomaly_detector/`)
- Detects anomalies in individual security log events
- Provides anomaly scores and human-readable explanations
- Compares events against learned baselines

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

## Usage

### Docker Compose (Recommended)

Run the complete pipeline:
```bash
cd scripts
docker-compose up --build
```

This will:
1. Collect security logs from Panther API
2. Train anomaly detection models
3. Start the anomaly detector service

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
├── anomaly_detector/        # Real-time detection
│   ├── anomaly_detector.py
│   ├── Dockerfile
│   └── requirements.txt
├── shared/                  # Common utilities
│   ├── __init__.py
│   ├── utils.py
│   └── requirements.txt
├── config/                  # Configuration files
│   ├── config.json
│   └── .env.example
├── data/                    # Collected security logs
├── models/                  # Trained models and metadata
└── docker-compose.yml       # Container orchestration
```

## Features

### Simple Configuration
- Just 3 fields per query: title, time, SQL query
- All GraphQL complexity hidden in scripts
- Easy to add new data sources without GraphQL knowledge
- Hard-coded optimal settings for security log analysis

### Security-Focused Analysis
- Prioritizes security-relevant features (IPs, user agents, protocols)
- Time-based anomaly detection (unusual hours, days)
- Low-cardinality categorical analysis

### Explainable Results
- Z-score analysis for numerical features
- Rarity scoring for categorical features  
- Human-readable anomaly explanations
- Feature deviation classifications

### Production-Ready
- Docker containerization for consistent deployment
- Retry logic and error handling
- Comprehensive logging
- Modular architecture ready for AWS Lambda conversion