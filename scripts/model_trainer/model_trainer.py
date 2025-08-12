#!/usr/bin/env python3
"""
Security Log Model Trainer
Trains Isolation Forest models for anomaly detection on security logs
"""

import json
import os
import sys
from typing import Dict, List, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib
from pathlib import Path
from dotenv import load_dotenv

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent / "shared"))
from utils import (
    setup_logging, load_config, save_json, load_json, 
    flatten_json, extract_time_features, get_categorical_features, 
    get_numerical_features, calculate_feature_stats, ensure_directory
)

class SecurityLogModelTrainer:
    def __init__(self, config_path: str):
        self.logger = setup_logging("SecurityLogModelTrainer")
        self.config = load_config(config_path)
        self.queries = self.config["queries"]
        
        # Hard-coded data settings
        self.data_settings = {
            "output_directory": "../data"
        }
        
        # Set up directories
        self.data_dir = Path(__file__).parent / self.data_settings["output_directory"]
        self.models_dir = Path(__file__).parent.parent / "models"
        ensure_directory(str(self.models_dir))
        
        self.label_encoders = {}
        self.scalers = {}
        
        self.logger.info("Initialized model trainer")

    def load_security_logs(self, filename: str) -> pd.DataFrame:
        """Load and preprocess security logs"""
        filepath = self.data_dir / filename
        
        if not filepath.exists():
            raise FileNotFoundError(f"Data file not found: {filepath}")
        
        self.logger.info(f"Loading logs from {filepath}")
        logs = load_json(str(filepath))
        
        if not logs:
            raise ValueError(f"No data found in {filename}")
        
        # Convert to DataFrame
        processed_logs = []
        for log in logs:
            # Flatten nested structure
            flattened = flatten_json(log)
            
            # Extract time features - prioritize p_event_time
            timestamp_field = None
            if 'p_event_time' in flattened:
                timestamp_field = 'p_event_time'
            elif 'timestamp' in flattened:
                timestamp_field = 'timestamp'
            elif 'createdAt' in flattened:
                timestamp_field = 'createdAt'
            
            if timestamp_field:
                time_features = extract_time_features(flattened[timestamp_field])
                flattened.update(time_features)
            
            processed_logs.append(flattened)
        
        df = pd.DataFrame(processed_logs)
        self.logger.info(f"Loaded {len(df)} logs with {len(df.columns)} features")
        
        return df

    def select_features(self, df: pd.DataFrame, log_type: str) -> Tuple[List[str], List[str], pd.DataFrame]:
        """Select optimal features for anomaly detection"""
        self.logger.info(f"Selecting features for {log_type}")
        
        # Filter out Panther-specific fields except p_event_time before feature selection
        filtered_columns = [col for col in df.columns if not col.startswith('p_') or col == 'p_event_time']
        df_filtered = df[filtered_columns]
        
        self.logger.info(f"Filtered out {len(df.columns) - len(filtered_columns)} Panther p_ fields (kept p_event_time)")
        
        # Get categorical and numerical features from filtered data
        categorical_features = get_categorical_features(df_filtered, max_cardinality=50)
        numerical_features = get_numerical_features(df_filtered)
        
        # Security-specific feature selection
        security_categorical = []
        security_numerical = []
        
        # Prioritize CloudTrail-specific categorical features
        priority_categorical = [
            'eventname', 'eventsource', 'eventtype', 'eventcategory', 'awsregion',
            'sourceipaddress', 'useragent', 'useridentity.type', 'useridentity.arn',
            'useridentity.accountid', 'useridentity.principalid', 'useridentity.username',
            'recipientaccountid', 'requestid', 'errorcode', 'errormessage'
        ]
        
        for feature in categorical_features:
            feature_lower = feature.lower()
            if any(priority in feature_lower for priority in priority_categorical):
                security_categorical.append(feature)
            elif df_filtered[feature].nunique() <= 20:  # Low cardinality
                security_categorical.append(feature)
        
        # Prioritize CloudTrail-relevant numerical features
        priority_numerical = [
            'hour', 'hour_of_day', 'day_of_week', 'day_of_month', 'month',
            'responsecode', 'requestparameters', 'responseelements', 'resources'
        ]
        
        for feature in numerical_features:
            feature_lower = feature.lower()
            if any(priority in feature_lower for priority in priority_numerical):
                security_numerical.append(feature)
            elif feature in ['hour', 'hour_of_day', 'day_of_week', 'day_of_month', 'month']:
                security_numerical.append(feature)  # Time features are always valuable
        
        # Limit total features to prevent overfitting
        security_categorical = security_categorical[:15]
        security_numerical = security_numerical[:15]
        
        self.logger.info(f"Selected {len(security_categorical)} categorical and {len(security_numerical)} numerical features")
        
        return security_categorical, security_numerical, df_filtered

    def preprocess_features(self, df: pd.DataFrame, categorical_features: List[str], 
                           numerical_features: List[str], log_type: str, is_training: bool = True) -> pd.DataFrame:
        """Preprocess features for model training"""
        processed_df = df.copy()
        
        # Handle categorical features
        for feature in categorical_features:
            if feature in processed_df.columns:
                # Fill missing values
                processed_df[feature] = processed_df[feature].fillna('unknown')
                processed_df[feature] = processed_df[feature].astype(str)
                
                if is_training:
                    # Create and fit label encoder
                    le = LabelEncoder()
                    processed_df[feature] = le.fit_transform(processed_df[feature])
                    self.label_encoders[f"{log_type}_{feature}"] = le
                else:
                    # Use existing label encoder
                    le = self.label_encoders[f"{log_type}_{feature}"]
                    # Handle unseen categories
                    unique_vals = set(processed_df[feature].unique())
                    known_vals = set(le.classes_)
                    
                    for val in unique_vals - known_vals:
                        processed_df.loc[processed_df[feature] == val, feature] = 'unknown'
                    
                    processed_df[feature] = le.transform(processed_df[feature])
        
        # Handle numerical features
        for feature in numerical_features:
            if feature in processed_df.columns:
                # Fill missing values with median
                processed_df[feature] = pd.to_numeric(processed_df[feature], errors='coerce')
                processed_df[feature] = processed_df[feature].fillna(processed_df[feature].median())
        
        # Select only the features we want
        selected_features = [f for f in categorical_features + numerical_features if f in processed_df.columns]
        processed_df = processed_df[selected_features]
        
        # Scale numerical features
        if is_training:
            scaler = StandardScaler()
            processed_df[numerical_features] = scaler.fit_transform(processed_df[numerical_features])
            self.scalers[log_type] = scaler
        else:
            scaler = self.scalers[log_type]
            processed_df[numerical_features] = scaler.transform(processed_df[numerical_features])
        
        return processed_df

    def train_isolation_forest(self, df: pd.DataFrame, log_type: str) -> IsolationForest:
        """Train Isolation Forest model"""
        self.logger.info(f"Training Isolation Forest for {log_type}")
        
        # Isolation Forest parameters optimized for security logs
        model = IsolationForest(
            contamination=0.1,  # Assume 10% anomalies
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1
        )
        
        model.fit(df)
        
        # Calculate anomaly scores for validation
        scores = model.decision_function(df)
        anomalies = model.predict(df)
        
        anomaly_rate = (anomalies == -1).sum() / len(anomalies)
        self.logger.info(f"Model trained. Anomaly rate: {anomaly_rate:.3f}")
        
        return model

    def train_models_for_log_type(self, log_type: str, filename: str) -> Dict[str, Any]:
        """Train complete model pipeline for a log type"""
        self.logger.info(f"Training models for {log_type}")
        
        # Load data
        df = self.load_security_logs(filename)
        
        if len(df) < 100:
            self.logger.warning(f"Insufficient data for {log_type}: {len(df)} logs")
            return None
        
        # Select features
        categorical_features, numerical_features, df_filtered = self.select_features(df, log_type)
        
        if not categorical_features and not numerical_features:
            self.logger.warning(f"No suitable features found for {log_type}")
            return None
        
        # Preprocess features
        processed_df = self.preprocess_features(
            df, categorical_features, numerical_features, log_type, is_training=True
        )
        
        # Train model
        model = self.train_isolation_forest(processed_df, log_type)
        
        # Calculate feature statistics on filtered data
        feature_stats = calculate_feature_stats(df_filtered, categorical_features + numerical_features)
        
        # Prepare model metadata
        model_metadata = {
            'log_type': log_type,
            'categorical_features': categorical_features,
            'numerical_features': numerical_features,
            'feature_stats': feature_stats,
            'training_samples': len(df),
            'model_params': model.get_params()
        }
        
        # Save model and metadata
        model_path = self.models_dir / f"{log_type}_isolation_forest.joblib"
        metadata_path = self.models_dir / f"{log_type}_metadata.json"
        encoders_path = self.models_dir / f"{log_type}_encoders.joblib"
        scaler_path = self.models_dir / f"{log_type}_scaler.joblib"
        
        joblib.dump(model, model_path)
        save_json(model_metadata, str(metadata_path))
        
        # Save encoders for this log type
        log_encoders = {k: v for k, v in self.label_encoders.items() if k.startswith(f"{log_type}_")}
        if log_encoders:
            joblib.dump(log_encoders, encoders_path)
        
        # Save scaler
        if log_type in self.scalers:
            joblib.dump(self.scalers[log_type], scaler_path)
        
        self.logger.info(f"Model saved for {log_type}")
        
        return model_metadata

    def train_all_models(self) -> Dict[str, Any]:
        """Train models for all configured log types"""
        results = {}
        
        for query_config in self.queries:
            title = query_config["title"]
            filename = f"{title}.json"
            
            try:
                model_metadata = self.train_models_for_log_type(title, filename)
                if model_metadata:
                    results[title] = model_metadata
                else:
                    results[title] = {"error": "Training failed"}
                    
            except Exception as e:
                self.logger.error(f"Failed to train model for {title}: {e}")
                results[title] = {"error": str(e)}
        
        return results

def main():
    # Load environment variables
    load_dotenv()
    
    # Set up paths
    config_path = Path(__file__).parent.parent / "config" / "config.json"
    
    if not config_path.exists():
        print(f"Error: Configuration file not found at {config_path}")
        sys.exit(1)
    
    # Initialize trainer
    try:
        trainer = SecurityLogModelTrainer(str(config_path))
        
        print("Starting security log model training...")
        results = trainer.train_all_models()
        
        print("\nTraining Summary:")
        print("-" * 60)
        
        for log_type, result in results.items():
            if "error" in result:
                print(f"{log_type}: FAILED - {result['error']}")
            else:
                print(f"{log_type}: SUCCESS")
                print(f"  - Training samples: {result['training_samples']:,}")
                print(f"  - Categorical features: {len(result['categorical_features'])}")
                print(f"  - Numerical features: {len(result['numerical_features'])}")
        
        print(f"\nModels saved to: {trainer.models_dir}")
        
    except Exception as e:
        print(f"Training failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()