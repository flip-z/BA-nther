# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## System Overview

This is the **Panther Security Log Anomaly Detection** system - a three-stage pipeline for collecting security logs from Panther's GraphQL API, training Isolation Forest models, and detecting anomalies in real-time events.

### Architecture Pipeline

1. **Data Collector** (`data_collector/`) - Fetches security logs via Panther GraphQL API
2. **Model Trainer** (`model_trainer/`) - Trains Isolation Forest models on collected logs  
3. **Anomaly Detector** (`anomaly_detector/`) - Detects anomalies in individual events
4. **Feature Selection** (`shared/feature_selection.py`) - Optimized feature selection with temporal discrimination

The system processes CloudTrail (AWS Config, AWS IAM) and VPC Flow logs, extracting temporal and categorical features for anomaly detection.

## Common Commands

### Pipeline Execution
```bash
# Complete pipeline (recommended)
./run_pipeline.sh

# Skip data collection (use existing data)
./run_pipeline.sh --skip-data-collection

# Docker compose deployment
docker-compose up --build
```

### Individual Components
```bash
# Data collection
cd data_collector && python data_collector.py

# Model training  
cd model_trainer && python model_trainer.py

# Anomaly detection
cd anomaly_detector && python anomaly_detector.py --file event.json
echo '{"eventName": "test"}' | python anomaly_detector.py
```

### Testing
```bash
# Test with sample event
python anomaly_detector/anomaly_detector.py --file event.json

# Test optimization
python test_optimization.py
```

## Configuration

### Environment Setup
- Copy `config/.env.example` to `config/.env`
- Set `PANTHER_API_TOKEN` and `PANTHER_API_URL`
- API URL format: `https://company.panther.com/public/graphql`

### Query Configuration (`config/config.json`)
Each query requires:
- `title`: Dataset name (becomes filename and log type)
- `time`: Days of historical data to collect
- `query`: SQL query with `{time}d` placeholder for temporal filtering

## Key Architecture Components

### Feature Engineering (`shared/utils.py` + `shared/feature_selection.py`)
- **Time Features**: Extracts hour, day_of_week, day_of_month, month from `p_event_time`
- **Field Normalization**: Maps lowercase CloudTrail fields to camelCase model format
- **Feature Selection**: Enhanced algorithm with coverage (60%+), cardinality (2-1000), entropy, and temporal bonuses

### Model Training Strategy
- **Algorithm**: Isolation Forest with 10% contamination rate
- **Feature Optimization**: Enhanced selection targeting 10 features with coverage (60%+), temporal bonuses
- **Preprocessing**: Label encoding for categoricals, StandardScaler for numericals
- **Persistence**: Models, encoders, scalers, and metadata saved to `models/` directory

### Anomaly Detection Logic
- **Threshold**: Default -0.2 (optimized for temporal anomaly detection)
- **Binary Classification**: `is_anomaly = score < threshold`
- **Explanations**: Score-based natural language aligned with classification
- **Feature Analysis**: Z-score for numerical (>2 = high deviation), rarity score for categorical (>0.8 = rare)

### Log Type Determination
Auto-detects log type based on:
1. `eventsource` field mapping (iam.amazonaws.com → AWS IAM, config.amazonaws.com → AWS Config)
2. Fallback heuristics for alert/audit log patterns
3. Default to first available model

### Data Processing Pipeline
1. **Collection**: GraphQL executeDataLakeQuery with polling pattern, handles pagination
2. **Training**: Flattens nested JSON, extracts time features, selects optimal features
3. **Detection**: Normalizes field names, applies same feature extraction, compares against baselines

## File Organization

```
scripts/
├── shared/
│   ├── utils.py             # Core feature engineering & utilities
│   └── feature_selection.py # Enhanced feature selection algorithms
├── data_collector/          # Panther API integration
├── model_trainer/           # ML training pipeline  
├── anomaly_detector/        # Real-time detection
├── config/                  # Configuration & credentials
├── data/                    # Collected JSON logs
├── models/                  # Trained models & metadata
├── run_pipeline.sh          # Orchestration script
├── test_local_comprehensive.py   # Local testing suite
└── test_api_comprehensive.py     # API testing suite
```

## Development Notes

### Model Constraints
- Pre-trained models expect all original features (hybrid approach: full features for model, optimal subset for analysis)
- Field name normalization required between event format (lowercase) and training format (camelCase)
- `is_business_hours` feature completely removed as redundant with temporal features

### Performance Optimizations
- Feature coverage threshold (60%) eliminates sparse features while retaining useful patterns
- Enhanced feature selection targets 10 features with temporal discrimination bonuses
- Cardinality limits prevent high-dimensional categorical explosion  
- Deduplication removes redundant temporal features (hour vs hour_of_day)
- Skip data collection flag (`--skip-data-collection`) for development iteration

### Error Handling
- NonRetryableError class for auth/limit failures
- Tenacity retry logic with exponential backoff
- Comprehensive logging with structured messages
- Validation for API credentials and URL format