"""
AWS Lambda handler for training the anomaly detection model
Combines data gathering and model training in a single function
"""

import json
import os
import boto3
import pandas as pd
import numpy as np
import pickle
from datetime import datetime, timedelta
import requests
from typing import Dict, List, Any, Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Lambda environment
s3_client = boto3.client('s3')
S3_BUCKET = os.environ['S3_BUCKET']
PANTHER_API_URL = os.environ['PANTHER_API_URL']
PANTHER_API_TOKEN = os.environ['PANTHER_API_TOKEN']

def main(event, context):
    """Main Lambda handler for training"""
    try:
        print("🚀 Starting AWS Config anomaly detection training...")
        
        # Step 1: Gather data from Panther
        print("📊 Gathering CloudTrail data from Panther...")
        df = gather_cloudtrail_data()
        
        if df is None or len(df) == 0:
            return create_response(500, "Failed to gather training data")
        
        print(f"✅ Collected {len(df):,} CloudTrail events")
        
        # Step 2: Analyze and prepare features
        print("🔧 Preparing features for modeling...")
        model_features, feature_info, df_processed = prepare_features_for_modeling(df)
        
        if len(model_features) == 0:
            return create_response(500, "No suitable features found for modeling")
        
        # Step 3: Train isolation forest model
        print("🤖 Training isolation forest model...")
        model_metadata = build_isolation_forest_model(df_processed, model_features, feature_info)
        
        # Step 4: Save model to S3
        print("💾 Saving model to S3...")
        save_model_to_s3(model_metadata)
        
        print("🎉 Training completed successfully!")
        
        return create_response(200, {
            "message": "Training completed successfully",
            "model_stats": model_metadata['training_stats'],
            "features_used": len(model_features),
            "training_samples": len(df)
        })
        
    except Exception as e:
        print(f"❌ Training failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return create_response(500, f"Training failed: {str(e)}")

def create_response(status_code: int, body):
    """Create standardized Lambda response"""
    return {
        'statusCode': status_code,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps(body) if isinstance(body, dict) else body
    }

def gather_cloudtrail_data():
    """Gather CloudTrail data from Panther API"""
    try:
        # Get table information
        client = PantherGraphQLClient(PANTHER_API_URL, PANTHER_API_TOKEN)
        
        # Find CloudTrail table
        tables = client.get_database_tables()
        cloudtrail_table = client.find_cloudtrail_table(tables)
        
        if not cloudtrail_table:
            raise Exception("Could not find CloudTrail table")
        
        # Query last 30 days of Config events
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        df = client.query_cloudtrail_data(
            cloudtrail_table['full_name'],
            start_date,
            end_date,
            'p_event_time',
            'config.amazonaws.com',  # Filter for Config events
            strategy='standard'
        )
        
        return df
        
    except Exception as e:
        print(f"❌ Failed to gather data: {e}")
        return None

class PantherGraphQLClient:
    def __init__(self, api_url, api_token):
        self.api_url = api_url
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
    
    def get_database_tables(self):
        """Get all database tables from Panther"""
        query = '''
        query {
            dataCatalog {
                databases {
                    name
                    tables {
                        name
                        databaseName
                    }
                }
            }
        }
        '''
        
        response = requests.post(
            self.api_url,
            json={'query': query},
            headers=self.headers,
            timeout=30
        )
        
        if response.status_code != 200:
            raise Exception(f"GraphQL request failed: {response.status_code}")
        
        data = response.json()
        if 'errors' in data:
            raise Exception(f"GraphQL errors: {data['errors']}")
        
        return data['data']['dataCatalog']['databases']
    
    def find_cloudtrail_table(self, databases):
        """Find the CloudTrail table"""
        for db in databases:
            for table in db['tables']:
                table_name = table['name'].lower()
                if 'cloudtrail' in table_name or 'aws_cloudtrail' in table_name:
                    return {
                        'name': table['name'],
                        'database': db['name'],
                        'full_name': f"{db['name']}.{table['name']}"
                    }
        return None
    
    def query_cloudtrail_data(self, table_name, start_date, end_date, time_column, service_filter, strategy='sample'):
        """Query CloudTrail data with Config service filter"""
        
        # Build the query
        if strategy == 'sample':
            # Sample approach - get a representative sample
            query = f'''
            SELECT 
                eventName,
                eventSource,
                awsRegion,
                sourceIPAddress,
                userAgent,
                recipientAccountId,
                {time_column}
            FROM {table_name}
            WHERE {time_column} >= '{start_date.strftime("%Y-%m-%d")}'
                AND {time_column} < '{end_date.strftime("%Y-%m-%d")}'
                AND eventSource = '{service_filter}'
            ORDER BY RANDOM()
            LIMIT 10000
            '''
        else:
            # Standard approach - get all data (be careful with large datasets)
            query = f'''
            SELECT 
                eventName,
                eventSource,
                awsRegion,
                sourceIPAddress,
                userAgent,
                recipientAccountId,
                {time_column}
            FROM {table_name}
            WHERE {time_column} >= '{start_date.strftime("%Y-%m-%d")}'
                AND {time_column} < '{end_date.strftime("%Y-%m-%d")}'
                AND eventSource = '{service_filter}'
            ORDER BY {time_column} DESC
            '''
        
        # Execute query via GraphQL
        graphql_query = '''
        query($sql: String!) {
            queryData(query: $sql) {
                results
                error
            }
        }
        '''
        
        response = requests.post(
            self.api_url,
            json={
                'query': graphql_query,
                'variables': {'sql': query}
            },
            headers=self.headers,
            timeout=120
        )
        
        if response.status_code != 200:
            raise Exception(f"Query request failed: {response.status_code}")
        
        data = response.json()
        if 'errors' in data:
            raise Exception(f"Query errors: {data['errors']}")
        
        query_result = data['data']['queryData']
        if query_result['error']:
            raise Exception(f"SQL query error: {query_result['error']}")
        
        # Convert results to DataFrame
        results = query_result['results']
        if not results:
            print("⚠️ No results returned from query")
            return pd.DataFrame()
        
        df = pd.DataFrame(results)
        print(f"✅ Retrieved {len(df):,} rows from Panther")
        
        return df

def prepare_features_for_modeling(df):
    """Prepare features for isolation forest modeling"""
    
    print(f"📊 Input data shape: {df.shape}")
    
    # Core features that are most relevant for anomaly detection
    model_features = []
    feature_info = {}
    
    # Categorical features to encode
    categorical_features = ['eventName', 'awsRegion', 'sourceIPAddress', 'userAgent']
    
    # Create a copy for processing
    df_processed = df.copy()
    
    # Process each categorical feature
    for feature in categorical_features:
        if feature in df_processed.columns:
            print(f"🔧 Processing {feature}...")
            
            # Get value counts
            value_counts = df_processed[feature].value_counts()
            
            # Store information about this feature
            feature_info[feature] = {
                'type': 'categorical',
                'unique_values': len(value_counts),
                'top_values': value_counts.head(10).to_dict(),
                'total_samples': len(df_processed)
            }
            
            # Add to model features
            model_features.append(feature)
    
    # Numerical features
    numerical_features = []
    if 'recipientAccountId' in df_processed.columns:
        numerical_features.append('recipientAccountId')
        model_features.append('recipientAccountId')
        feature_info['recipientAccountId'] = {
            'type': 'numerical',
            'unique_values': df_processed['recipientAccountId'].nunique()
        }
    
    # Time-based features
    if 'p_event_time' in df_processed.columns:
        print("🕐 Creating time-based features...")
        df_processed['p_event_time'] = pd.to_datetime(df_processed['p_event_time'])
        
        # Hour of day
        df_processed['hour_of_day'] = df_processed['p_event_time'].dt.hour
        model_features.append('hour_of_day')
        feature_info['hour_of_day'] = {
            'type': 'time',
            'description': 'Hour of day (0-23)'
        }
        
        # Day of week
        df_processed['day_of_week'] = df_processed['p_event_time'].dt.dayofweek
        model_features.append('day_of_week')
        feature_info['day_of_week'] = {
            'type': 'time',
            'description': 'Day of week (0=Monday, 6=Sunday)'
        }
    
    print(f"✅ Prepared {len(model_features)} features for modeling")
    for feature in model_features:
        print(f"   - {feature}: {feature_info.get(feature, {}).get('type', 'unknown')}")
    
    return model_features, feature_info, df_processed

def build_isolation_forest_model(df_processed, model_features, feature_info):
    """Build and train isolation forest model"""
    
    print(f"🤖 Training on {len(df_processed):,} samples with {len(model_features)} features")
    
    # Prepare feature matrix
    feature_encoders = {}
    df_model = df_processed[model_features].copy()
    
    # Encode categorical features
    for feature in model_features:
        if feature_info[feature]['type'] == 'categorical':
            print(f"🔤 Encoding {feature}...")
            encoder = LabelEncoder()
            df_model[feature] = encoder.fit_transform(df_model[feature].astype(str))
            feature_encoders[feature] = encoder
    
    # Scale features
    print("📏 Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_model)
    
    # Train isolation forest
    print("🌲 Training isolation forest...")
    isolation_forest = IsolationForest(
        contamination=0.1,  # Expect 10% anomalies
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        max_features=1.0,
        bootstrap=False,
        n_jobs=-1
    )
    
    isolation_forest.fit(X_scaled)
    
    # Evaluate on training data for reference
    predictions = isolation_forest.predict(X_scaled)
    anomaly_scores = isolation_forest.decision_function(X_scaled)
    
    anomaly_rate = (predictions == -1).mean() * 100
    
    print(f"✅ Model trained successfully!")
    print(f"   - Training samples: {len(X_scaled):,}")
    print(f"   - Features: {len(model_features)}")
    print(f"   - Detected anomaly rate: {anomaly_rate:.1f}%")
    print(f"   - Score range: {anomaly_scores.min():.3f} to {anomaly_scores.max():.3f}")
    
    # Package everything
    model_metadata = {
        'model': isolation_forest,
        'scaler': scaler,
        'encoders': feature_encoders,
        'features': model_features,
        'feature_info': feature_info,
        'training_stats': {
            'total_samples': len(X_scaled),
            'anomaly_rate': anomaly_rate,
            'anomaly_score_range': {
                'min': float(anomaly_scores.min()),
                'max': float(anomaly_scores.max()),
                'mean': float(anomaly_scores.mean()),
                'std': float(anomaly_scores.std())
            }
        },
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    return model_metadata

def save_model_to_s3(model_metadata):
    """Save model components to S3"""
    
    model_name = 'aws_config_isolation_forest_latest'
    
    print(f"💾 Saving model: {model_name}")
    
    # Save each component
    components = ['model', 'scaler', 'encoders']
    
    for component in components:
        key = f"models/{model_name}_{component}.pkl"
        
        # Serialize to bytes
        data = pickle.dumps(model_metadata[component])
        
        # Upload to S3
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=data,
            ContentType='application/octet-stream'
        )
        
        print(f"   ✅ Saved {component}: s3://{S3_BUCKET}/{key}")
    
    # Save metadata as JSON
    metadata_json = {
        'features': model_metadata['features'],
        'feature_info': model_metadata['feature_info'],
        'training_stats': model_metadata['training_stats'],
        'timestamp': model_metadata['timestamp']
    }
    
    metadata_key = f"models/{model_name}_metadata.json"
    s3_client.put_object(
        Bucket=S3_BUCKET,
        Key=metadata_key,
        Body=json.dumps(metadata_json, indent=2),
        ContentType='application/json'
    )
    
    print(f"   ✅ Saved metadata: s3://{S3_BUCKET}/{metadata_key}")
    print("🎉 All model components saved successfully!") 