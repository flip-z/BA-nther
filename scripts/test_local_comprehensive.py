#!/usr/bin/env python3
"""
Comprehensive Local Testing Suite for Panther Anomaly Detection
Tests all models, edge cases, and performance before deployment
"""

import json
import sys
import os
import time
import traceback
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import statistics

# Add paths for imports
sys.path.append(str(Path(__file__).parent / "anomaly_detector"))
sys.path.append(str(Path(__file__).parent / "shared"))

# Import directly from the files
from anomaly_detector import SecurityAnomalyDetector
from utils import load_json

class ComprehensiveLocalTester:
    def __init__(self, models_dir: str = "models"):
        self.models_dir = Path(models_dir)
        self.detector = None
        self.test_results = {
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'errors': [],
            'performance_metrics': {},
            'model_validations': {}
        }
        
        self.initialize_detector()
    
    def initialize_detector(self):
        """Initialize the anomaly detector"""
        try:
            self.detector = SecurityAnomalyDetector(str(self.models_dir))
            print(f"✅ Initialized detector with {len(self.detector.models)} models")
        except Exception as e:
            print(f"❌ Failed to initialize detector: {e}")
            sys.exit(1)
    
    def log_test(self, test_name: str, passed: bool, details: str = "", error: str = ""):
        """Log test results"""
        self.test_results['total_tests'] += 1
        if passed:
            self.test_results['passed'] += 1
            status = "✅ PASS"
        else:
            self.test_results['failed'] += 1
            self.test_results['errors'].append(f"{test_name}: {error}")
            status = "❌ FAIL"
        
        print(f"   {status}: {test_name}")
        if details:
            print(f"      {details}")
        if error:
            print(f"      Error: {error}")
    
    def test_model_loading(self):
        """Test that all models load correctly"""
        print("\n🔧 Model Loading Tests")
        print("-" * 40)
        
        expected_models = ["AWS IAM", "AWS Config", "AWS VPC Flow"]
        
        for model_name in expected_models:
            try:
                model_exists = model_name in self.detector.models
                metadata_exists = model_name in self.detector.metadata
                
                self.log_test(
                    f"Model {model_name} loaded",
                    model_exists and metadata_exists,
                    f"Model: {model_exists}, Metadata: {metadata_exists}"
                )
                
                if model_exists and metadata_exists:
                    # Validate feature counts
                    metadata = self.detector.metadata[model_name]
                    cat_features = len(metadata.get('categorical_features', []))
                    num_features = len(metadata.get('numerical_features', []))
                    total_features = cat_features + num_features
                    
                    feature_count_valid = 4 <= total_features <= 7
                    self.log_test(
                        f"{model_name} feature count in range",
                        feature_count_valid,
                        f"{total_features} features ({cat_features} categorical + {num_features} numerical)"
                    )
                    
                    self.test_results['model_validations'][model_name] = {
                        'total_features': total_features,
                        'categorical_features': cat_features,
                        'numerical_features': num_features,
                        'training_samples': metadata.get('training_samples', 0)
                    }
                    
            except Exception as e:
                self.log_test(f"Model {model_name} validation", False, error=str(e))
    
    def generate_synthetic_event(self, model_name: str, anomalous: bool = False) -> Dict[str, Any]:
        """Generate synthetic test events based on model metadata"""
        if model_name not in self.detector.metadata:
            raise ValueError(f"No metadata for model {model_name}")
        
        metadata = self.detector.metadata[model_name]
        feature_stats = metadata.get('feature_stats', {})
        
        event = {
            "p_event_time": datetime.utcnow().isoformat() + "Z"
        }
        
        # Generate categorical features
        for feature in metadata.get('categorical_features', []):
            if feature in feature_stats and feature_stats[feature]['type'] == 'categorical':
                value_counts = feature_stats[feature].get('value_counts', {})
                if value_counts:
                    if anomalous and random.random() < 0.7:  # 70% chance of rare value for anomalies
                        # Pick a rare value
                        sorted_values = sorted(value_counts.items(), key=lambda x: x[1])
                        rare_values = [v for v, c in sorted_values[:max(1, len(sorted_values)//10)]]
                        event[feature] = random.choice(rare_values) if rare_values else list(value_counts.keys())[0]
                    else:
                        # Pick common value weighted by frequency
                        values = list(value_counts.keys())
                        weights = list(value_counts.values())
                        event[feature] = random.choices(values, weights=weights)[0]
        
        # Generate numerical features  
        for feature in metadata.get('numerical_features', []):
            if feature in feature_stats and feature_stats[feature]['type'] == 'numerical':
                mean = feature_stats[feature].get('mean', 0)
                std = feature_stats[feature].get('std', 1)
                
                if anomalous and random.random() < 0.7:  # 70% chance of extreme value
                    # Generate value 3+ standard deviations away
                    multiplier = random.choice([-1, 1]) * (3 + random.random() * 2)  # -5 to -3 or +3 to +5
                    value = mean + (std * multiplier)
                else:
                    # Normal value within 1-2 standard deviations
                    multiplier = random.uniform(-2, 2)
                    value = mean + (std * multiplier)
                
                # Handle special cases for specific fields
                if feature in ['hour']:
                    value = max(0, min(23, int(value)))
                elif feature in ['day_of_week']:
                    value = max(0, min(6, int(value)))
                elif feature.endswith('Count') or 'packets' in feature.lower() or 'bytes' in feature.lower():
                    value = max(0, int(value))
                
                event[feature] = value
        
        return event
    
    def test_synthetic_events(self):
        """Test detection with synthetic events"""
        print("\n🎯 Synthetic Event Tests")
        print("-" * 40)
        
        for model_name in self.detector.models.keys():
            try:
                # Test normal events
                normal_event = self.generate_synthetic_event(model_name, anomalous=False)
                result = self.detector.detect_anomaly(normal_event, model_name)
                
                normal_test_passed = (
                    'error' not in result and 
                    result.get('anomaly_score', 0) > -0.5  # Reasonable threshold for "normal-ish"
                )
                self.log_test(
                    f"{model_name} normal synthetic event",
                    normal_test_passed,
                    f"Score: {result.get('anomaly_score', 'N/A'):.3f}, Anomaly: {result.get('is_anomaly', 'N/A')}"
                )
                
                # Test anomalous events
                anomalous_event = self.generate_synthetic_event(model_name, anomalous=True)
                result = self.detector.detect_anomaly(anomalous_event, model_name)
                
                # We expect some anomalous events to be detected, but not all (depends on randomness)
                anomalous_test_passed = 'error' not in result
                details = f"Score: {result.get('anomaly_score', 'N/A'):.3f}, Anomaly: {result.get('is_anomaly', 'N/A')}"
                self.log_test(
                    f"{model_name} anomalous synthetic event",
                    anomalous_test_passed,
                    details
                )
                
            except Exception as e:
                self.log_test(f"{model_name} synthetic event generation", False, error=str(e))
    
    def test_edge_cases(self):
        """Test edge cases and error handling"""
        print("\n⚠️  Edge Case Tests")
        print("-" * 40)
        
        # Test empty event
        try:
            result = self.detector.detect_anomaly({}, "AWS IAM")
            empty_event_handled = 'error' not in result
            self.log_test(
                "Empty event handling",
                empty_event_handled,
                f"Score: {result.get('anomaly_score', 'N/A')}"
            )
        except Exception as e:
            self.log_test("Empty event handling", False, error=str(e))
        
        # Test invalid model name
        try:
            result = self.detector.detect_anomaly({"test": "event"}, "Invalid Model")
            invalid_model_handled = 'error' in result
            self.log_test(
                "Invalid model name handling",
                invalid_model_handled,
                f"Error message present: {bool(result.get('error'))}"
            )
        except Exception as e:
            self.log_test("Invalid model name handling", False, error=str(e))
        
        # Test missing required fields
        minimal_event = {"p_event_time": "2024-01-01T12:00:00Z"}
        try:
            result = self.detector.detect_anomaly(minimal_event, "AWS IAM")
            minimal_event_handled = 'error' not in result
            self.log_test(
                "Missing fields handling",
                minimal_event_handled,
                f"Features found: {result.get('model_info', {}).get('features_found_in_event', 'N/A')}"
            )
        except Exception as e:
            self.log_test("Missing fields handling", False, error=str(e))
        
        # Test malformed timestamp
        bad_time_event = {"p_event_time": "invalid-timestamp", "eventName": "test"}
        try:
            result = self.detector.detect_anomaly(bad_time_event, "AWS IAM")
            bad_time_handled = 'error' not in result  # Should handle gracefully
            self.log_test(
                "Malformed timestamp handling",
                bad_time_handled,
                "Graceful degradation expected"
            )
        except Exception as e:
            self.log_test("Malformed timestamp handling", False, error=str(e))
    
    def test_known_events(self):
        """Test with known good/bad events from test files"""
        print("\n📋 Known Event Tests") 
        print("-" * 40)
        
        # Test with the existing test event file
        test_event_file = Path(__file__).parent / "test_event.json"
        if test_event_file.exists():
            try:
                test_event = load_json(str(test_event_file))
                result = self.detector.detect_anomaly(test_event, "AWS IAM")
                
                known_event_processed = 'error' not in result
                self.log_test(
                    "test_event.json processing",
                    known_event_processed,
                    f"Score: {result.get('anomaly_score', 'N/A'):.3f}, Features used: {result.get('model_info', {}).get('features_used_count', 'N/A')}"
                )
                
            except Exception as e:
                self.log_test("test_event.json processing", False, error=str(e))
        else:
            self.log_test("test_event.json exists", False, error="File not found")
    
    def test_performance(self, num_events: int = 10):
        """Test detection performance"""
        print(f"\n⚡ Performance Tests ({num_events} events per model)")
        print("-" * 40)
        
        for model_name in self.detector.models.keys():
            try:
                events = [
                    self.generate_synthetic_event(model_name, anomalous=random.choice([True, False]))
                    for _ in range(num_events)
                ]
                
                start_time = time.time()
                for event in events:
                    self.detector.detect_anomaly(event, model_name)
                end_time = time.time()
                
                total_time = end_time - start_time
                avg_time = total_time / num_events
                
                # Performance is acceptable if < 1 second per event
                performance_acceptable = avg_time < 1.0
                
                self.log_test(
                    f"{model_name} performance",
                    performance_acceptable,
                    f"{avg_time:.3f}s avg per event, {total_time:.3f}s total"
                )
                
                self.test_results['performance_metrics'][model_name] = {
                    'avg_time_per_event': avg_time,
                    'total_time': total_time,
                    'events_tested': num_events
                }
                
            except Exception as e:
                self.log_test(f"{model_name} performance", False, error=str(e))
    
    def test_threshold_sensitivity(self):
        """Test sensitivity to different anomaly thresholds"""
        print("\n🎚️  Threshold Sensitivity Tests")
        print("-" * 40)
        
        thresholds = [-0.1, -0.3, -0.5]
        model_name = "AWS IAM"  # Test with one model
        
        for threshold in thresholds:
            try:
                # Generate a mix of events
                events = [
                    self.generate_synthetic_event(model_name, anomalous=False),
                    self.generate_synthetic_event(model_name, anomalous=True),
                ]
                
                anomaly_counts = []
                for event in events:
                    self.detector.anomaly_threshold = threshold
                    result = self.detector.detect_anomaly(event, model_name)
                    if 'error' not in result and result.get('is_anomaly', False):
                        anomaly_counts.append(1)
                    else:
                        anomaly_counts.append(0)
                
                threshold_working = True  # Basic test that it doesn't crash
                anomaly_rate = sum(anomaly_counts) / len(anomaly_counts) * 100
                
                self.log_test(
                    f"Threshold {threshold} sensitivity",
                    threshold_working,
                    f"Anomaly rate: {anomaly_rate:.1f}%"
                )
                
            except Exception as e:
                self.log_test(f"Threshold {threshold} sensitivity", False, error=str(e))
        
        # Reset to default
        self.detector.anomaly_threshold = -0.3
    
    def test_feature_analysis(self):
        """Test feature analysis and explanation generation"""
        print("\n🔬 Feature Analysis Tests")
        print("-" * 40)
        
        for model_name in self.detector.models.keys():
            try:
                # Generate event with some extreme values
                event = self.generate_synthetic_event(model_name, anomalous=True)
                result = self.detector.detect_anomaly(event, model_name)
                
                has_feature_deviations = bool(result.get('feature_deviations'))
                has_explanation = bool(result.get('explanation'))
                has_model_info = bool(result.get('model_info'))
                
                feature_analysis_complete = all([
                    has_feature_deviations,
                    has_explanation,
                    has_model_info,
                    'error' not in result
                ])
                
                details = f"Deviations: {len(result.get('feature_deviations', {}))}, Explanation: {bool(result.get('explanation'))}"
                
                self.log_test(
                    f"{model_name} feature analysis",
                    feature_analysis_complete,
                    details
                )
                
            except Exception as e:
                self.log_test(f"{model_name} feature analysis", False, error=str(e))
    
    def run_all_tests(self):
        """Run the complete test suite"""
        print("🧪 Panther Anomaly Detection - Comprehensive Local Testing")
        print("=" * 60)
        
        start_time = time.time()
        
        # Run all test categories
        self.test_model_loading()
        self.test_synthetic_events()
        self.test_edge_cases()
        self.test_known_events()
        self.test_performance()
        self.test_threshold_sensitivity()
        self.test_feature_analysis()
        
        end_time = time.time()
        
        # Print final summary
        self.print_summary(end_time - start_time)
        
        return self.test_results['failed'] == 0
    
    def print_summary(self, total_time: float):
        """Print test summary"""
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)
        
        print(f"Total Tests: {self.test_results['total_tests']}")
        print(f"✅ Passed: {self.test_results['passed']}")
        print(f"❌ Failed: {self.test_results['failed']}")
        print(f"⏱️  Total Time: {total_time:.2f}s")
        
        if self.test_results['failed'] > 0:
            print(f"\n❌ FAILED TESTS ({self.test_results['failed']}):")
            for error in self.test_results['errors']:
                print(f"   • {error}")
        
        print(f"\n🏷️  MODEL SUMMARY:")
        for model_name, validation in self.test_results['model_validations'].items():
            print(f"   • {model_name}: {validation['total_features']} features, {validation['training_samples']:,} samples")
        
        if self.test_results['performance_metrics']:
            print(f"\n⚡ PERFORMANCE SUMMARY:")
            for model_name, perf in self.test_results['performance_metrics'].items():
                print(f"   • {model_name}: {perf['avg_time_per_event']:.3f}s avg per event")
        
        success_rate = (self.test_results['passed'] / self.test_results['total_tests']) * 100
        print(f"\n🎯 Success Rate: {success_rate:.1f}%")
        
        if self.test_results['failed'] == 0:
            print("\n🎉 ALL TESTS PASSED! System ready for deployment.")
        else:
            print(f"\n⚠️  {self.test_results['failed']} tests failed. Review issues before deployment.")

def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Local Testing for Panther Anomaly Detection")
    parser.add_argument("--models-dir", default="models", help="Path to models directory")
    parser.add_argument("--performance-events", type=int, default=10, help="Number of events for performance testing")
    
    args = parser.parse_args()
    
    # Check if models directory exists
    models_path = Path(args.models_dir)
    if not models_path.exists():
        print(f"❌ Models directory not found: {models_path}")
        print("   Please run model training first: cd model_trainer && python model_trainer.py")
        sys.exit(1)
    
    try:
        tester = ComprehensiveLocalTester(args.models_dir)
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Testing framework error: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()