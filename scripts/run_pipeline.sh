#!/bin/bash

# Panther Security Log Anomaly Detection Pipeline
# Runs the complete data collection -> training -> detection pipeline

set -e

# Parse command line arguments
SKIP_DATA_COLLECTION=false
SHOW_HELP=false

for arg in "$@"; do
    case $arg in
        --skip-data-collection)
            SKIP_DATA_COLLECTION=true
            shift
            ;;
        --help|-h)
            SHOW_HELP=true
            shift
            ;;
        *)
            echo "Unknown argument: $arg"
            SHOW_HELP=true
            ;;
    esac
done

# Show help if requested
if [ "$SHOW_HELP" = true ]; then
    echo "Panther Security Log Anomaly Detection Pipeline"
    echo "=============================================="
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  --skip-data-collection    Skip data collection step and use existing data"
    echo "  --help, -h               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       Run full pipeline (collect data + train models)"
    echo "  $0 --skip-data-collection  Skip data collection, only retrain models"
    exit 0
fi

echo "Starting Panther Security Log Anomaly Detection Pipeline"
echo "========================================================"

# Check if .env file exists
if [ ! -f "config/.env" ]; then
    echo "Error: config/.env file not found"
    echo "Please copy config/.env.example to config/.env and set your PANTHER_API_TOKEN"
    exit 1
fi

# Source environment variables
export $(cat config/.env | xargs)

if [ -z "$PANTHER_API_TOKEN" ] && [ "$SKIP_DATA_COLLECTION" = false ]; then
    echo "Error: PANTHER_API_TOKEN not set in config/.env"
    exit 1
fi

# Step 1: Data Collection (conditional)
if [ "$SKIP_DATA_COLLECTION" = false ]; then
    echo "Step 1: Collecting security logs from Panther API..."
    cd data_collector
    python data_collector.py
    cd ..
else
    echo "Step 1: Skipping data collection (using existing data)..."
    
    # Validate that data directory exists and has content
    if [ ! -d "data" ] || [ -z "$(ls -A data 2>/dev/null)" ]; then
        echo "Error: No existing data found in 'data/' directory"
        echo "Please run without --skip-data-collection first, or ensure data files exist"
        exit 1
    fi
    
    # Show what data files are available
    echo "Found existing data files:"
    ls -la data/ | grep -v "^total" | grep -v "^d" | head -5
    if [ $(ls data/ | wc -l) -gt 5 ]; then
        echo "... and $(($(ls data/ | wc -l) - 5)) more files"
    fi
fi

echo ""
echo "Step 2: Training anomaly detection models..."
cd model_trainer  
python model_trainer.py
cd ..

echo ""
echo "Step 3: Anomaly detector is ready for use"
echo "Examples:"
echo "  echo '{\"timestamp\": \"2024-01-01T12:00:00Z\", \"source\": \"app\"}' | python anomaly_detector/anomaly_detector.py"
echo "  python anomaly_detector/anomaly_detector.py --file event.json"
echo ""
echo "Pipeline completed successfully!"
echo "Models saved to: $(pwd)/models/"
echo "Data saved to: $(pwd)/data/"