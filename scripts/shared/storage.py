"""
Storage abstraction layer for state management
Supports local JSON files now, DynamoDB later
"""

import json
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

class StateStorage(ABC):
    """Abstract base class for state storage backends"""
    
    @abstractmethod
    def get_state(self, query_title: str) -> Optional[Dict[str, Any]]:
        """Get state for a specific query"""
        pass
    
    @abstractmethod
    def save_state(self, query_title: str, state: Dict[str, Any]) -> None:
        """Save state for a specific query"""
        pass
    
    @abstractmethod
    def list_queries(self) -> List[str]:
        """List all queries that have state"""
        pass
    
    @abstractmethod
    def delete_state(self, query_title: str) -> None:
        """Delete state for a specific query"""
        pass

class LocalStateStorage(StateStorage):
    """Local file-based state storage using JSON files"""
    
    def __init__(self, state_dir: str = "data/.state"):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("LocalStateStorage")
    
    def _get_state_file(self, query_title: str) -> Path:
        """Get path to state file for a query"""
        return self.state_dir / f"{query_title}.json"
    
    def get_state(self, query_title: str) -> Optional[Dict[str, Any]]:
        """Get state for a specific query"""
        state_file = self._get_state_file(query_title)
        
        if not state_file.exists():
            return None
        
        try:
            with open(state_file, 'r') as f:
                state = json.load(f)
            
            self.logger.info(f"Loaded existing state for {query_title}: {state.get('record_count', 0)} records, last run: {state.get('last_run', 'never')}")
            return state
            
        except (json.JSONDecodeError, IOError) as e:
            self.logger.error(f"Failed to load state for {query_title}: {e}")
            return None
    
    def save_state(self, query_title: str, state: Dict[str, Any]) -> None:
        """Save state for a specific query"""
        state_file = self._get_state_file(query_title)
        
        # Add metadata
        now = datetime.utcnow().isoformat() + "Z"
        state_with_meta = {
            **state,
            "title": query_title,
            "updated_at": now
        }
        
        # Add created_at if not exists
        if "created_at" not in state_with_meta:
            state_with_meta["created_at"] = now
        
        try:
            with open(state_file, 'w') as f:
                json.dump(state_with_meta, f, indent=2, default=str)
            
            self.logger.info(f"Saved state for {query_title}: {state.get('record_count', 0)} records, last_data: {state.get('last_data_timestamp', 'none')}")
            
        except IOError as e:
            self.logger.error(f"Failed to save state for {query_title}: {e}")
            raise
    
    def list_queries(self) -> List[str]:
        """List all queries that have state"""
        if not self.state_dir.exists():
            return []
        
        queries = []
        for file_path in self.state_dir.glob("*.json"):
            query_title = file_path.stem
            queries.append(query_title)
        
        return sorted(queries)
    
    def delete_state(self, query_title: str) -> None:
        """Delete state for a specific query"""
        state_file = self._get_state_file(query_title)
        
        if state_file.exists():
            try:
                state_file.unlink()
                self.logger.debug(f"Deleted state for {query_title}")
            except OSError as e:
                self.logger.error(f"Failed to delete state for {query_title}: {e}")
                raise

class DynamoDBStateStorage(StateStorage):
    """DynamoDB-based state storage (future implementation)"""
    
    def __init__(self, table_name: str, region: str = "us-east-1"):
        self.table_name = table_name
        self.region = region
        self.logger = logging.getLogger("DynamoDBStateStorage")
        # TODO: Initialize boto3 client
        raise NotImplementedError("DynamoDB storage not yet implemented")
    
    def get_state(self, query_title: str) -> Optional[Dict[str, Any]]:
        # TODO: Implement DynamoDB get_item
        raise NotImplementedError("DynamoDB storage not yet implemented")
    
    def save_state(self, query_title: str, state: Dict[str, Any]) -> None:
        # TODO: Implement DynamoDB put_item
        raise NotImplementedError("DynamoDB storage not yet implemented")
    
    def list_queries(self) -> List[str]:
        # TODO: Implement DynamoDB scan
        raise NotImplementedError("DynamoDB storage not yet implemented")
    
    def delete_state(self, query_title: str) -> None:
        # TODO: Implement DynamoDB delete_item
        raise NotImplementedError("DynamoDB storage not yet implemented")

def create_storage(storage_type: str, state_dir: str = "data/.state") -> StateStorage:
    """Factory function to create storage backend based on config"""
    if storage_type == "local":
        # Use provided state directory path
        return LocalStateStorage(state_dir)
    
    elif storage_type == "prod":
        # Use DynamoDB for production (future implementation)
        # TODO: Add environment variables for DynamoDB table name and region
        table_name = os.getenv("ANOMALY_DETECTION_TABLE", "anomaly-detection-state")
        region = os.getenv("AWS_REGION", "us-east-1")
        return DynamoDBStateStorage(table_name, region)
    
    else:
        raise ValueError(f"Unknown storage type: {storage_type}. Use 'local' or 'prod'")

# State data model helpers
def create_initial_state(query_title: str, window_days: int) -> Dict[str, Any]:
    """Create initial state for a new query"""
    now = datetime.utcnow().isoformat() + "Z"
    
    return {
        "title": query_title,
        "window_days": window_days,
        "last_run": None,
        "last_data_timestamp": None,
        "record_count": 0,
        "created_at": now,
        "updated_at": now
    }

def update_state_after_run(state: Dict[str, Any], 
                          last_data_timestamp: str, 
                          record_count: int) -> Dict[str, Any]:
    """Update state after successful data collection"""
    now = datetime.utcnow().isoformat() + "Z"
    
    return {
        **state,
        "last_run": now,
        "last_data_timestamp": last_data_timestamp,
        "record_count": record_count,
        "updated_at": now
    }