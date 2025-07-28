"""
AWS Lambda handler for anomaly detection API
Fast, lightweight endpoint for real-time anomaly detection
"""

import json
import os
import boto3
import pandas as pd
import pickle
from datetime import datetime
from typing import Dict, Any, Optional
import logging

# Import scikit-learn if available
try:
    from sklearn.ensemble import IsolationForest  
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lambda environment
s3_client = boto3.client('s3')
S3_BUCKET = os.environ['S3_BUCKET']

# Global cache for model components (persists across Lambda invocations)
model_cache = {}

def detect(event, context):
    """Main Lambda handler for anomaly detection API"""
    try:
        # Log the incoming event for debugging
        logger.info(f"Received event: {json.dumps(event)}")
        
        # Handle health check requests
        if event.get('requestContext', {}).get('http', {}).get('path', '').endswith('/health'):
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    "status": "healthy",
                    "service": "AWS Config Anomaly Detection",
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "sklearn_available": SKLEARN_AVAILABLE
                })
            }
        
        # Parse request for detection
        if 'body' not in event:
            return create_response(400, {"error": "No request body provided"})
        
        # Handle both string and dict body formats
        if isinstance(event['body'], str):
            try:
                event_data = json.loads(event['body'])
            except json.JSONDecodeError:
                return create_response(400, {"error": "Invalid JSON in request body"})
        else:
            event_data = event['body']
        
        # Validate required fields
        if not isinstance(event_data, dict):
            return create_response(400, {"error": "Request body must be a JSON object"})
        
        logger.info(f"Processing anomaly detection request for event: {event_data.get('eventName', 'unknown')}")
        
        # Load model (cached)
        model_components = load_model_from_s3()
        if not model_components:
            return create_response(500, {"error": "Failed to load model"})
        
        # Detect anomaly
        result = detect_anomaly(event_data, model_components)
        
        logger.info(f"Detection complete. Result: {'ANOMALY' if result['is_anomaly'] else 'NORMAL'}")
        
        return create_response(200, result)
        
    except Exception as e:
        logger.error(f"Detection failed: {str(e)}")
        return create_response(500, {"error": f"Detection failed: {str(e)}"})

def create_response(status_code: int, body: Dict[str, Any]):
    """Create standardized API response with CORS headers"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, X-Amz-Date, Authorization, X-Api-Key'
        },
        'body': json.dumps(body)
    }

def load_model_from_s3():
    """Load model components from S3 with caching"""
    global model_cache
    
    model_name = 'aws_config_isolation_forest_latest'
    
    # Check if model is already cached
    if model_name in model_cache:
        logger.info("Using cached model")
        return model_cache[model_name]
    
    try:
        logger.info("Loading model from S3...")
        
        # Download model files to /tmp
        model_files = {
            'model': f"/tmp/{model_name}_model.pkl",
            'scaler': f"/tmp/{model_name}_scaler.pkl", 
            'encoders': f"/tmp/{model_name}_encoders.pkl",
            'metadata': f"/tmp/{model_name}_metadata.json"
        }
        
        # Check if files exist in S3 and download
        for file_type, local_path in model_files.items():
            s3_key = f"models/{model_name}_{file_type}.{'pkl' if file_type != 'metadata' else 'json'}"
            
            try:
                s3_client.download_file(S3_BUCKET, s3_key, local_path)
            except Exception as e:
                logger.error(f"Failed to download {s3_key}: {e}")
                return None
        
        # Load components
        with open(model_files['model'], 'rb') as f:
            model = pickle.load(f)
            
        with open(model_files['scaler'], 'rb') as f:
            scaler = pickle.load(f)
            
        with open(model_files['encoders'], 'rb') as f:
            encoders = pickle.load(f)
            
        with open(model_files['metadata'], 'r') as f:
            metadata = json.load(f)
        
        # Cache the loaded model
        model_components = {
            'model': model,
            'scaler': scaler,
            'encoders': encoders,
            'metadata': metadata
        }
        
        model_cache[model_name] = model_components
        
        logger.info(f"Model loaded successfully. Features: {len(metadata['features'])}")
        return model_components
        
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return None

def prepare_event_features(event_data: Dict[str, Any], model_components: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare a single event's features for anomaly detection"""
    
    metadata = model_components['metadata']
    encoders = model_components['encoders']
    features = metadata['features']
    feature_info = metadata['feature_info']
    
    feature_vector = {}
    
    for feat in features:
        if feat in ['hour_of_day', 'day_of_week']:
            # Time-based features
            if feat == 'hour_of_day':
                try:
                    if 'p_event_time' in event_data:
                        event_time = pd.to_datetime(event_data['p_event_time'])
                        feature_vector[feat] = event_time.hour
                    else:
                        feature_vector[feat] = 12  # Default to noon
                except:
                    feature_vector[feat] = 12
                    
            elif feat == 'day_of_week':
                try:
                    if 'p_event_time' in event_data:
                        event_time = pd.to_datetime(event_data['p_event_time'])
                        feature_vector[feat] = event_time.dayofweek
                    else:
                        feature_vector[feat] = 1  # Default to Tuesday
                except:
                    feature_vector[feat] = 1
        else:
            # Categorical features
            if feat in event_data:
                raw_value = str(event_data[feat])
                
                if feat in encoders:
                    encoder = encoders[feat]
                    try:
                        if raw_value in encoder.classes_:
                            encoded_value = encoder.transform([raw_value])[0]
                            feature_vector[feat] = encoded_value
                        else:
                            # Unknown value - use most common class
                            most_common_class = encoder.classes_[0]
                            encoded_value = encoder.transform([most_common_class])[0]
                            feature_vector[feat] = encoded_value
                    except:
                        feature_vector[feat] = 0
                else:
                    feature_vector[feat] = 0
            else:
                # Missing feature
                feature_vector[feat] = 0
    
    return feature_vector

def analyze_feature_rarity(feature_vector: Dict[str, Any], model_components: Dict[str, Any]) -> list:
    """Analyze how common/rare each feature value is based on training data"""
    
    metadata = model_components['metadata']
    feature_frequencies = metadata.get('feature_frequencies', {})
    total_samples = metadata['training_stats']['total_samples']
    
    rarity_analysis = []
    
    for feat, value in feature_vector.items():
        if feat not in feature_frequencies:
            continue
            
        freq_dict = feature_frequencies[feat]
        
        if feat in ['hour_of_day', 'day_of_week']:
            # Time features - lookup by numeric value
            frequency = freq_dict.get(value, 0)
            raw_value = str(value)
        else:
            # Categorical features - need to get original value
            if feat in model_components['encoders']:
                encoder = model_components['encoders'][feat]
                try:
                    raw_value = encoder.inverse_transform([value])[0]
                    frequency = freq_dict.get(str(raw_value), 0)
                except:
                    raw_value = str(value)
                    frequency = 0
            else:
                raw_value = str(value)
                frequency = 0
        
        # Calculate rarity percentage
        rarity_pct = (frequency / total_samples) * 100 if total_samples > 0 else 0
        
        # Categorize based on frequency
        if frequency == 0:
            category = "UNSEEN"
            description = f"never seen in training"
        elif rarity_pct < 0.1:
            category = "VERY_RARE"
            description = f"very rare: {rarity_pct:.2f}%"
        elif rarity_pct < 1.0:
            category = "RARE"
            description = f"rare: {rarity_pct:.1f}%"
        elif rarity_pct < 10.0:
            category = "UNCOMMON"
            description = f"uncommon: {rarity_pct:.1f}%"
        else:
            category = "COMMON"
            description = f"common: {rarity_pct:.1f}%"
        
        rarity_analysis.append({
            'feature': feat,
            'value': raw_value,
            'frequency': frequency,
            'rarity_pct': rarity_pct,
            'category': category,
            'description': description
        })
    
    return rarity_analysis

def detect_anomaly(event_data: Dict[str, Any], model_components: Dict[str, Any]) -> Dict[str, Any]:
    """Detect if an event is anomalous"""
    
    # Prepare features
    feature_vector = prepare_event_features(event_data, model_components)
    
    # Convert to DataFrame for consistency
    df_features = pd.DataFrame([feature_vector])
    
    # Handle different model types
    if model_components['model'] == 'STATISTICAL_MODEL':
        logger.info("Using statistical anomaly detection")
        # Simple statistical anomaly detection
        anomaly_score = 0.0
        feature_stats = model_components.get('feature_stats', {})
        
        # Calculate anomaly score based on feature rarity
        for feat, value in feature_vector.items():
            if feat in feature_stats:
                stat = feature_stats[feat]
                if stat['type'] == 'categorical':
                    freq = stat['frequencies'].get(str(value), 0)
                    total = stat['total']
                    rarity = 1.0 - (freq / total) if total > 0 else 1.0
                    anomaly_score += rarity
                elif stat['type'] == 'numeric':
                    # Simple z-score based anomaly
                    z_score = abs(value - stat['mean']) / stat['std'] if stat['std'] > 0 else 0
                    anomaly_score += min(z_score / 3.0, 1.0)  # Normalize to 0-1
        
        anomaly_score /= len(feature_vector)  # Average
        is_anomaly = anomaly_score > 0.3  # Threshold for statistical model
        prediction = -1 if is_anomaly else 1
        confidence = anomaly_score
        
    elif SKLEARN_AVAILABLE:
        # Use real isolation forest
        scaler = model_components['scaler']
        scaled_features = scaler.transform(df_features)
        
        model = model_components['model']
        prediction = model.predict(scaled_features)[0]
        anomaly_score = model.decision_function(scaled_features)[0]
        
        is_anomaly = prediction == -1
        confidence = abs(anomaly_score)
    else:
        # Fallback
        logger.warning("No model available")
        anomaly_score = 0.0
        is_anomaly = False
        prediction = 1
        confidence = 0.0
    
    # Get score context from training data
    metadata = model_components['metadata']
    score_range = metadata['training_stats']['anomaly_score_range']
    
    # Feature rarity analysis - fast lookups for analyst context
    rarity_analysis = analyze_feature_rarity(feature_vector, model_components)
    
    # Sort by rarity (most suspicious first)
    rarity_analysis.sort(key=lambda x: x['rarity_pct'])
    
    # Summary of suspicious features
    suspicious_features = [item for item in rarity_analysis if item['rarity_pct'] < 1.0]
    
    return {
        'is_anomaly': is_anomaly,
        'anomaly_score': float(anomaly_score),
        'confidence': float(confidence),
        'prediction': int(prediction),
        'score_range': score_range,
        'model_info': {
            'features_used': metadata['features'],
            'training_samples': metadata['training_stats']['total_samples'],
            'expected_anomaly_rate': metadata['training_stats']['anomaly_rate']
        },
        'rarity_analysis': rarity_analysis,
        'suspicious_features': suspicious_features,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    } 