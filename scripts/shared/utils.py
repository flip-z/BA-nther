import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import pandas as pd
from pathlib import Path

def setup_logging(name: str, level: str = "INFO") -> logging.Logger:
    """Set up logging configuration"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Replace environment variables in config
        config_str = json.dumps(config)
        for key, value in os.environ.items():
            config_str = config_str.replace(f"${{{key}}}", value)
        
        return json.loads(config_str)
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in configuration file: {config_path}")

def save_json(data: Any, filepath: str) -> None:
    """Save data to JSON file"""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)

def load_json(filepath: str) -> Any:
    """Load data from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)

def flatten_json(nested_json: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
    """Flatten nested JSON structure for feature extraction"""
    flattened = {}
    
    for key, value in nested_json.items():
        new_key = f"{prefix}.{key}" if prefix else key
        
        if isinstance(value, dict):
            flattened.update(flatten_json(value, new_key))
        elif isinstance(value, list):
            if value and isinstance(value[0], dict):
                # For lists of objects, create separate features
                for i, item in enumerate(value[:5]):  # Limit to first 5 items
                    flattened.update(flatten_json(item, f"{new_key}[{i}]"))
            else:
                # For lists of primitives
                flattened[f"{new_key}_count"] = len(value)
                if value:
                    flattened[f"{new_key}_first"] = str(value[0])
        else:
            flattened[new_key] = value
    
    return flattened

def is_port_field(column_name: str) -> bool:
    """Check if a column represents a port field that should be treated as categorical"""
    if not isinstance(column_name, str):
        return False
    
    column_lower = column_name.lower()
    port_patterns = [
        'port', 'srcport', 'dstport', 'source_port', 'dest_port', 
        'src_port', 'dst_port', 'sourceport', 'destport',
        'remote_port', 'local_port', 'server_port', 'client_port'
    ]
    
    return any(pattern in column_lower for pattern in port_patterns)

def extract_time_features(timestamp_str: str) -> Dict[str, Any]:
    """Extract time-based features from timestamp"""
    try:
        dt = pd.to_datetime(timestamp_str)
        return {
            'hour': dt.hour,
            'hour_of_day': dt.hour,  # Explicit hour_of_day feature  
            'day_of_week': dt.dayofweek,
            'day_of_month': dt.day,
            'month': dt.month
        }
    except:
        return {
            'hour': -1,
            'hour_of_day': -1,  # Explicit hour_of_day feature
            'day_of_week': -1,
            'day_of_month': -1,
            'month': -1
        }

def get_categorical_features(df: pd.DataFrame, max_cardinality: int = 50) -> List[str]:
    """Identify low-cardinality categorical features suitable for anomaly detection"""
    categorical_features = []
    
    for col in df.columns:
        # Check if this is a port field that should be treated as categorical
        if is_port_field(col):
            unique_count = df[col].nunique()
            if 2 <= unique_count <= max_cardinality:
                categorical_features.append(col)
        elif df[col].dtype == 'object' or df[col].dtype == 'category':
            unique_count = df[col].nunique()
            if 2 <= unique_count <= max_cardinality:
                categorical_features.append(col)
    
    return categorical_features

def get_numerical_features(df: pd.DataFrame) -> List[str]:
    """Identify numerical features suitable for anomaly detection"""
    numerical_features = []
    
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            # Exclude port fields - they should be treated as categorical
            if is_port_field(col):
                continue
            # Exclude features with too little variance
            if df[col].var() > 0.01:
                numerical_features.append(col)
    
    return numerical_features

def calculate_feature_stats(df: pd.DataFrame, features: List[str]) -> Dict[str, Dict[str, Any]]:
    """Calculate statistical baselines for features"""
    stats = {}
    
    for feature in features:
        if feature in df.columns:
            if pd.api.types.is_numeric_dtype(df[feature]):
                # Handle boolean fields differently 
                if df[feature].dtype == 'bool':
                    value_counts = df[feature].value_counts()
                    stats[feature] = {
                        'value_counts': value_counts.to_dict(),
                        'unique_count': int(df[feature].nunique()),
                        'most_common': str(value_counts.index[0]) if len(value_counts) > 0 else None,
                        'most_common_freq': int(value_counts.iloc[0]) if len(value_counts) > 0 else 0,
                        'type': 'categorical'
                    }
                else:
                    stats[feature] = {
                        'mean': float(df[feature].mean()),
                        'std': float(df[feature].std()),
                        'min': float(df[feature].min()),
                        'max': float(df[feature].max()),
                        'median': float(df[feature].median()),
                        'q25': float(df[feature].quantile(0.25)),
                        'q75': float(df[feature].quantile(0.75)),
                        'type': 'numerical'
                    }
            else:
                value_counts = df[feature].value_counts()
                stats[feature] = {
                    'value_counts': value_counts.to_dict(),
                    'unique_count': int(df[feature].nunique()),
                    'most_common': str(value_counts.index[0]) if len(value_counts) > 0 else None,
                    'most_common_freq': int(value_counts.iloc[0]) if len(value_counts) > 0 else 0,
                    'type': 'categorical'
                }
    
    return stats

def ensure_directory(path: str) -> None:
    """Ensure directory exists"""
    Path(path).mkdir(parents=True, exist_ok=True)