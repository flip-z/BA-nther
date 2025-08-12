#!/usr/bin/env python3
"""
Real-time Security Anomaly Detector
Detects anomalies in individual security log events using pre-trained models
"""

import json
import os
import sys
from typing import Dict, List, Any, Tuple, Optional
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from pathlib import Path
from dotenv import load_dotenv
import argparse

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent / "shared"))
from utils import (
    setup_logging, load_config, load_json, 
    flatten_json, extract_time_features
)

class SecurityAnomalyDetector:
    def __init__(self, models_dir: str, anomaly_threshold: float = -0.3):
        self.logger = setup_logging("SecurityAnomalyDetector", "INFO")
        self.models_dir = Path(models_dir)
        self.anomaly_threshold = anomaly_threshold
        
        self.models = {}
        self.metadata = {}
        self.label_encoders = {}
        self.scalers = {}
        
        self.load_all_models()
        
        self.logger.info(f"Initialized detector with {len(self.models)} models")

    def load_all_models(self):
        """Load all trained models and their metadata"""
        if not self.models_dir.exists():
            raise FileNotFoundError(f"Models directory not found: {self.models_dir}")
        
        # Find all model files
        model_files = list(self.models_dir.glob("*_isolation_forest.joblib"))
        
        for model_file in model_files:
            log_type = model_file.stem.replace("_isolation_forest", "")
            
            try:
                # Load model
                model = joblib.load(model_file)
                self.models[log_type] = model
                
                # Load metadata
                metadata_file = self.models_dir / f"{log_type}_metadata.json"
                if metadata_file.exists():
                    self.metadata[log_type] = load_json(str(metadata_file))
                
                # Load encoders
                encoders_file = self.models_dir / f"{log_type}_encoders.joblib"
                if encoders_file.exists():
                    encoders = joblib.load(encoders_file)
                    self.label_encoders.update(encoders)
                
                # Load scaler
                scaler_file = self.models_dir / f"{log_type}_scaler.joblib"
                if scaler_file.exists():
                    self.scalers[log_type] = joblib.load(scaler_file)
                
                self.logger.info(f"Loaded model for {log_type}")
                
            except Exception as e:
                self.logger.error(f"Failed to load model for {log_type}: {e}")

    def determine_log_type(self, event: Dict[str, Any]) -> Optional[str]:
        """Determine the log type of an event based on available models"""
        event_flat = flatten_json(event)
        
        # Get all available model types
        available_types = list(self.models.keys())
        
        if not available_types:
            return None
        
        # CloudTrail service-based mapping
        if 'eventsource' in event_flat:
            eventsource = event_flat['eventsource'].lower()
            
            # Map AWS service sources to model names
            service_to_model = {
                'iam.amazonaws.com': 'AWS IAM',
                'config.amazonaws.com': 'AWS Config', 
                'ec2.amazonaws.com': 'AWS VPC Flow',
                'vpc-flow-logs.amazonaws.com': 'AWS VPC Flow'
            }
            
            for service, model_name in service_to_model.items():
                if eventsource == service and model_name in available_types:
                    return model_name
        
        # Legacy heuristic fallbacks for non-CloudTrail events
        # Check for alert-specific fields
        if any(field in event_flat for field in ['alertId', 'severity', 'title', 'runbook']):
            if 'alert_logs' in available_types:
                return 'alert_logs'
        
        # Check for audit-specific fields
        if any(field in event_flat for field in ['actor', 'action', 'resource']):
            if 'audit_logs' in available_types:
                return 'audit_logs'
        
        # Default to first available model
        return available_types[0]

    def preprocess_event(self, event: Dict[str, Any], log_type: str) -> pd.DataFrame:
        """Preprocess a single event for anomaly detection"""
        if log_type not in self.metadata:
            raise ValueError(f"No model available for log type: {log_type}")
        
        metadata = self.metadata[log_type]
        
        # For now, we still need to provide ALL features to the pre-trained model
        # The models were trained expecting all 23 features
        categorical_features = metadata['categorical_features']
        numerical_features = metadata['numerical_features']
        
        # TODO: In the future, retrain models with optimal features only
        optimal_features = self.analyze_feature_quality(log_type, target_features=10)
        self.logger.debug(f"Model still requires all {len(categorical_features + numerical_features)} features, but {len(optimal_features)} are optimal")
        
        # Flatten and extract time features
        flattened = flatten_json(event)
        
        # Normalize field names to match training data format
        flattened = self.normalize_field_names(flattened)
        
        # Extract time features from standard p_event_time field
        if 'p_event_time' in flattened:
            time_features = extract_time_features(flattened['p_event_time'])
            flattened.update(time_features)
        elif 'timestamp' in flattened or 'createdAt' in flattened:
            # Fallback for non-standard timestamp fields
            timestamp_field = 'timestamp' if 'timestamp' in flattened else 'createdAt'
            time_features = extract_time_features(flattened[timestamp_field])
            flattened.update(time_features)
        
        # Create DataFrame
        df = pd.DataFrame([flattened])
        
        # Handle categorical features
        for feature in categorical_features:
            if feature in df.columns:
                df[feature] = df[feature].fillna('unknown').astype(str)
                
                encoder_key = f"{log_type}_{feature}"
                if encoder_key in self.label_encoders:
                    le = self.label_encoders[encoder_key]
                    # Handle unseen categories
                    value = df[feature].iloc[0]
                    if value not in le.classes_:
                        # Map to 'unknown' if encoder has it, otherwise use first class
                        if 'unknown' in le.classes_:
                            df[feature] = 'unknown'
                        else:
                            df[feature] = le.classes_[0]
                    
                    df[feature] = le.transform(df[feature])
                else:
                    # If no encoder, use 0 as default
                    df[feature] = 0
            else:
                # Feature not present, use 0 as default
                df[feature] = 0
        
        # Handle numerical features
        for feature in numerical_features:
            if feature in df.columns:
                df[feature] = pd.to_numeric(df[feature], errors='coerce')
                df[feature] = df[feature].fillna(0)
            else:
                # Feature not present, use 0 as default
                df[feature] = 0
        
        # Select all features that the pre-trained model expects
        all_expected_features = categorical_features + numerical_features
        df = df.reindex(columns=all_expected_features, fill_value=0)
        
        # Scale numerical features
        if log_type in self.scalers:
            scaler = self.scalers[log_type]
            df[numerical_features] = scaler.transform(df[numerical_features])
        
        return df

    def normalize_field_names(self, flattened: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize field names to match training data format (camelCase)"""
        normalized = {}
        
        # Field name mappings from event format to model format
        field_mappings = {
            # CloudTrail field mappings
            'recipientaccountid': 'recipientAccountId',
            'useragent': 'userAgent',
            'useridentity.accountId': 'userIdentity.accountId',
            'useridentity.type': 'userIdentity.type',
            'useridentity.invokedBy': 'userIdentity.invokedBy',
            'useridentity.sessionContext.sessionIssuer.accountId': 'userIdentity.sessionContext.sessionIssuer.accountId',
            'useridentity.sessionContext.sessionIssuer.userName': 'userIdentity.sessionContext.sessionIssuer.userName',
            'eventname': 'eventName',
            'eventsource': 'eventSource',
            'eventtype': 'eventType',
            'eventversion': 'eventVersion',
            'eventcategory': 'eventCategory',
            'eventtime': 'eventTime',
            'awsregion': 'awsRegion',
            'sourceipaddress': 'sourceIPAddress',
            'requestid': 'requestId',
            'eventid': 'eventId',
        }
        
        for original_key, value in flattened.items():
            # Use mapping if available, otherwise keep original
            normalized_key = field_mappings.get(original_key, original_key)
            normalized[normalized_key] = value
        
        return normalized

    def analyze_feature_quality(self, log_type: str, target_features: int = 10) -> List[str]:
        """Analyze and select optimal features based on coverage, cardinality, and information content"""
        if log_type not in self.metadata:
            return []
        
        metadata = self.metadata[log_type]
        feature_stats = metadata.get('feature_stats', {})
        training_samples = metadata.get('training_samples', 1)
        
        feature_scores = []
        
        for feature, stats in feature_stats.items():
            # Skip is_business_hours entirely - we don't want to use it
            if feature == 'is_business_hours':
                continue
                
            # Calculate coverage (how often this feature appears)
            if stats['type'] == 'categorical':
                total_feature_samples = sum(stats['value_counts'].values()) if 'value_counts' in stats else 0
            else:
                # For numerical features, assume they're always present if in stats
                total_feature_samples = training_samples
            
            coverage = total_feature_samples / training_samples if training_samples > 0 else 0
            
            # Skip very sparse features
            if coverage < 0.7:
                continue
                
            # Calculate cardinality
            if stats['type'] == 'categorical':
                cardinality = stats.get('unique_count', len(stats.get('value_counts', {})))
            else:
                # For numerical features, use a reasonable estimate
                cardinality = min(1000, training_samples // 10)
            
            # Skip constant features or extremely high cardinality
            if cardinality < 2 or cardinality > 1000:
                continue
            
            # Calculate information content (entropy-like measure)
            if stats['type'] == 'categorical':
                value_counts = stats.get('value_counts', {})
                total = sum(value_counts.values())
                if total > 0:
                    # Calculate normalized entropy (0 = all same value, 1 = uniform distribution)
                    entropy = -sum((count/total) * np.log2(count/total) for count in value_counts.values() if count > 0)
                    max_entropy = np.log2(len(value_counts)) if len(value_counts) > 1 else 1
                    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0
                else:
                    normalized_entropy = 0
            else:
                # For numerical features, assume reasonable entropy
                normalized_entropy = 0.7
            
            # Score feature (higher is better)
            # Prefer good coverage, moderate cardinality, high information content
            cardinality_score = min(1.0, cardinality / 100)  # Sweet spot around 10-100 unique values
            if cardinality > 100:
                cardinality_score = max(0.1, 1.0 - (cardinality - 100) / 900)  # Penalize very high cardinality
            
            score = (coverage * 0.4) + (cardinality_score * 0.3) + (normalized_entropy * 0.3)
            
            feature_scores.append((feature, score, coverage, cardinality, normalized_entropy))
        
        # Sort by score 
        feature_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Remove redundant features
        deduped_features = []
        for feature, score, coverage, cardinality, entropy in feature_scores:
            # Skip redundant temporal features
            if feature == 'hour_of_day' and any(f[0] == 'hour' for f in deduped_features):
                continue  # hour_of_day is identical to hour
            if feature == 'is_business_hours':
                # Skip is_business_hours if we already have hour OR day_of_week (it's derivable)
                has_hour = any(f[0] == 'hour' for f in deduped_features)
                has_day_of_week = any(f[0] == 'day_of_week' for f in deduped_features)
                if has_hour or has_day_of_week:
                    continue
            
            deduped_features.append((feature, score, coverage, cardinality, entropy))
            
            if len(deduped_features) >= target_features:
                break
        
        selected_features = [f[0] for f in deduped_features]
        
        self.logger.debug(f"Feature selection for {log_type}:")
        for feature, score, coverage, cardinality, entropy in deduped_features:
            self.logger.debug(f"  {feature}: score={score:.3f} coverage={coverage:.2f} cardinality={cardinality} entropy={entropy:.3f}")
        
        return selected_features

    def calculate_feature_deviations(self, event: Dict[str, Any], log_type: str) -> Dict[str, Dict[str, Any]]:
        """Calculate how much each feature deviates from normal patterns - only for optimal features"""
        if log_type not in self.metadata:
            self.logger.debug(f"No metadata found for log_type: {log_type}")
            return {}
        
        metadata = self.metadata[log_type]
        feature_stats = metadata.get('feature_stats', {})
        
        # Only calculate deviations for optimal features
        optimal_features = self.analyze_feature_quality(log_type, target_features=10)
        self.logger.debug(f"Calculating deviations for {len(optimal_features)} optimal features only")
        
        self.logger.debug(f"Feature stats available: {list(feature_stats.keys())}")
        
        # Flatten event
        flattened = flatten_json(event)
        
        self.logger.debug(f"Flattened event fields (before normalization): {list(flattened.keys())}")
        
        # Normalize field names to match training data format
        flattened = self.normalize_field_names(flattened)
        
        self.logger.debug(f"Flattened event fields (after normalization): {list(flattened.keys())}")
        
        # Extract time features from standard p_event_time field
        if 'p_event_time' in flattened:
            time_features = extract_time_features(flattened['p_event_time'])
            flattened.update(time_features)
        elif 'timestamp' in flattened or 'createdAt' in flattened:
            # Fallback for non-standard timestamp fields
            timestamp_field = 'timestamp' if 'timestamp' in flattened else 'createdAt'
            time_features = extract_time_features(flattened[timestamp_field])
            flattened.update(time_features)
        
        deviations = {}
        
        # Debug: Check for field name mismatches
        event_fields = set(flattened.keys())
        model_features = set(feature_stats.keys())
        common_fields = event_fields.intersection(model_features)
        missing_in_event = model_features - event_fields
        missing_in_model = event_fields - model_features
        
        self.logger.debug(f"Common fields (after normalization): {common_fields}")
        self.logger.debug(f"Fields in model but not in event: {missing_in_event}")
        self.logger.debug(f"Fields in event but not in model: {missing_in_model}")
        
        for feature, stats in feature_stats.items():
            # Only process optimal features
            if feature not in optimal_features:
                continue
            if feature not in flattened:
                continue
            
            value = flattened[feature]
            
            if stats['type'] == 'numerical':
                try:
                    numeric_value = float(value)
                    mean = stats['mean']
                    std = stats['std']
                    
                    # Calculate z-score
                    z_score = (numeric_value - mean) / std if std > 0 else 0
                    
                    deviations[feature] = {
                        'type': 'numerical',
                        'value': numeric_value,
                        'mean': mean,
                        'std': std,
                        'z_score': z_score,
                        'deviation_level': self.classify_deviation(abs(z_score))
                    }
                except (ValueError, TypeError):
                    pass
                    
            elif stats['type'] == 'categorical':
                str_value = str(value)
                value_counts = stats['value_counts']
                total_count = sum(value_counts.values())
                
                frequency = value_counts.get(str_value, 0)
                rarity_score = 1 - (frequency / total_count) if total_count > 0 else 1
                
                deviations[feature] = {
                    'type': 'categorical',
                    'value': str_value,
                    'frequency': frequency,
                    'total_samples': total_count,
                    'rarity_score': rarity_score,
                    'deviation_level': self.classify_rarity(rarity_score)
                }
        
        return deviations

    def classify_deviation(self, z_score: float) -> str:
        """Classify numerical deviation level"""
        if z_score > 3:
            return "extreme"
        elif z_score > 2:
            return "high"
        elif z_score > 1:
            return "moderate"
        else:
            return "normal"

    def classify_rarity(self, rarity_score: float) -> str:
        """Classify categorical rarity level"""
        if rarity_score > 0.95:
            return "extremely_rare"
        elif rarity_score > 0.8:
            return "rare"
        elif rarity_score > 0.5:
            return "uncommon"
        else:
            return "common"

    def generate_explanation(self, deviations: Dict[str, Dict[str, Any]], anomaly_score: float, is_anomaly: bool) -> str:
        """Generate human-readable explanation that aligns with the anomaly classification"""
        if not deviations:
            return "No feature deviations calculated for analysis."
        
        # Find notable deviations for explanation
        notable_features = []
        
        for feature, deviation in deviations.items():
            if deviation['type'] == 'numerical' and deviation['deviation_level'] in ['high', 'extreme']:
                notable_features.append(f"{feature} (z-score: {deviation['z_score']:.1f})")
            elif deviation['type'] == 'categorical' and deviation['deviation_level'] in ['rare', 'extremely_rare']:
                notable_features.append(f"{feature} (rarity: {deviation['rarity_score']:.2f})")
        
        # Create explanation based on classification
        if is_anomaly:
            if notable_features:
                feature_list = ", ".join(notable_features[:3])  # Top 3 features
                return f"This event appears anomalous (score: {anomaly_score:.3f}) due to unusual patterns in {feature_list}."
            else:
                return f"This event appears anomalous (score: {anomaly_score:.3f}) due to unusual feature combinations."
        else:
            if notable_features:
                feature_list = ", ".join(notable_features[:2])  # Top 2 features  
                return f"This event appears normal (score: {anomaly_score:.3f}) despite some variations in {feature_list}."
            else:
                return f"This event appears normal (score: {anomaly_score:.3f}) with typical feature patterns."

    def detect_anomaly(self, event: Dict[str, Any], log_type: Optional[str] = None) -> Dict[str, Any]:
        """Detect anomaly in a single event"""
        # Determine log type if not provided
        if log_type is None:
            log_type = self.determine_log_type(event)
        
        if log_type not in self.models:
            return {
                "error": f"No model available for log type: {log_type}",
                "log_type": log_type
            }
        
        try:
            # Preprocess event
            processed_event = self.preprocess_event(event, log_type)
            
            # Get model prediction
            model = self.models[log_type]
            anomaly_prediction = model.predict(processed_event)[0]
            anomaly_score = model.decision_function(processed_event)[0]
            
            # Calculate feature deviations
            deviations = self.calculate_feature_deviations(event, log_type)
            
            # Apply anomaly threshold for binary classification
            is_anomaly = float(anomaly_score) < self.anomaly_threshold
            
            # Generate explanation
            explanation = self.generate_explanation(deviations, anomaly_score, is_anomaly)
            
            # Analyze optimal features for this log type (this is what we actually use)
            optimal_features = self.analyze_feature_quality(log_type, target_features=10)
            all_available_features = self.metadata[log_type].get('categorical_features', []) + self.metadata[log_type].get('numerical_features', [])
            
            # Normalize event and extract time features to check which features are present
            flattened_event = self.normalize_field_names(flatten_json(event))
            if 'p_event_time' in flattened_event:
                time_features = extract_time_features(flattened_event['p_event_time'])
                flattened_event.update(time_features)
            elif 'timestamp' in flattened_event or 'createdAt' in flattened_event:
                timestamp_field = 'timestamp' if 'timestamp' in flattened_event else 'createdAt'
                time_features = extract_time_features(flattened_event[timestamp_field])
                flattened_event.update(time_features)
            
            # Calculate feature presence for optimal features (what we actually use)
            optimal_features_in_event = len([f for f in optimal_features if f in flattened_event])
            optimal_features_missing = len(optimal_features) - optimal_features_in_event
            
            # Prepare result
            result = {
                "log_type": log_type,
                "is_anomaly": is_anomaly,
                "anomaly_score": float(anomaly_score),
                "anomaly_threshold": self.anomaly_threshold,
                "explanation": explanation,
                "feature_deviations": deviations,
                "model_info": {
                    "training_samples": self.metadata[log_type].get('training_samples', 0),
                    "total_features_available": len(all_available_features),
                    "features_actually_used": optimal_features,
                    "features_used_count": len(optimal_features),
                    "features_found_in_event": optimal_features_in_event,
                    "features_missing_from_event": optimal_features_missing
                }
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return {
                "error": str(e),
                "log_type": log_type
            }

def main():
    parser = argparse.ArgumentParser(description="Security Log Anomaly Detector")
    parser.add_argument("--event", type=str, help="JSON string of event to analyze")
    parser.add_argument("--file", type=str, help="Path to JSON file containing event")
    parser.add_argument("--log-type", type=str, help="Specify log type (optional)")
    parser.add_argument("--models-dir", type=str, help="Path to models directory")
    parser.add_argument("--anomaly-threshold", type=float, default=-0.3, help="Anomaly score threshold for classification (default: -0.3)")
    
    args = parser.parse_args()
    
    # Load environment variables
    load_dotenv()
    
    # Determine models directory
    if args.models_dir:
        models_dir = Path(args.models_dir)
    else:
        models_dir = Path(__file__).parent.parent / "models"
    
    try:
        # Initialize detector
        detector = SecurityAnomalyDetector(str(models_dir), anomaly_threshold=args.anomaly_threshold)
        
        # Get event data
        event = None
        if args.event:
            event = json.loads(args.event)
        elif args.file:
            with open(args.file, 'r') as f:
                event = json.load(f)
        else:
            # Read from stdin
            event_str = sys.stdin.read().strip()
            if event_str:
                event = json.loads(event_str)
        
        if not event:
            print("Error: No event data provided")
            sys.exit(1)
        
        # Detect anomaly
        result = detector.detect_anomaly(event, args.log_type)
        
        # Output result
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print(f"Detection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()