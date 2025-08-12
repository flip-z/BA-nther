#!/usr/bin/env python3
"""Test script to validate the optimized time window calculation"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from data_collector.data_collector import PantherDataCollector
from shared.utils import load_json

def test_optimization():
    # Load existing state files
    state_files = [
        "data/.state/AWS Config.json",
        "data/.state/AWS IAM.json", 
        "data/.state/AWS VPC Flow.json"
    ]
    
    # Mock collector (we can't fully initialize due to missing API creds)
    class MockCollector:
        def __init__(self):
            self.logger = self._setup_logger()
        
        def _setup_logger(self):
            import logging
            logger = logging.getLogger("TestCollector")
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            return logger
        
        def calculate_optimized_time_window(self, state, configured_window_days):
            """Copy the optimization method for testing"""
            from datetime import datetime, timedelta
            import pandas as pd
            
            # First run or no state: use full configured window
            if not state or not state.get('last_data_timestamp'):
                self.logger.info(f"First run or no state: using full window of {configured_window_days} days")
                return configured_window_days
            
            try:
                # Parse the last data timestamp
                last_timestamp_str = state['last_data_timestamp']
                last_timestamp = pd.to_datetime(last_timestamp_str).to_pydatetime()
                current_time = datetime.utcnow()
                
                # Calculate days since last collection
                time_diff = current_time - last_timestamp
                days_since_last = time_diff.total_seconds() / (24 * 3600)
                
                # Add 1 day buffer for safety (timezone issues, processing delays, etc.)
                optimized_days = max(1, int(days_since_last) + 1)
                
                # Cap at configured window for edge cases (very old state, etc.)
                optimized_days = min(optimized_days, configured_window_days)
                
                self.logger.info(f"Last data timestamp: {last_timestamp_str}")
                self.logger.info(f"Days since last collection: {days_since_last:.2f}")
                self.logger.info(f"Optimized time window: {optimized_days} days (configured: {configured_window_days})")
                
                return optimized_days
                
            except Exception as e:
                self.logger.warning(f"Failed to calculate optimized window: {e}. Using full window.")
                return configured_window_days
    
    collector = MockCollector()
    
    # Test configurations (from config.json)
    configs = [
        {"title": "AWS Config", "time": 30},
        {"title": "AWS IAM", "time": 30}, 
        {"title": "AWS VPC Flow", "time": 14}
    ]
    
    print("Testing Optimized Time Window Calculations")
    print("=" * 50)
    
    for config in configs:
        title = config["title"]
        configured_days = config["time"]
        
        print(f"\n📊 {title}")
        print("-" * 20)
        
        try:
            state_file = f"data/.state/{title}.json"
            if os.path.exists(state_file):
                state = load_json(state_file)
                optimized_days = collector.calculate_optimized_time_window(state, configured_days)
                
                efficiency = (configured_days - optimized_days) / configured_days * 100
                print(f"⚡ Efficiency gain: {efficiency:.1f}% reduction ({configured_days}d → {optimized_days}d)")
                
            else:
                print(f"❌ No state file found: {state_file}")
                
        except Exception as e:
            print(f"❌ Error testing {title}: {e}")

if __name__ == "__main__":
    test_optimization()