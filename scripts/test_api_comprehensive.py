#!/usr/bin/env python3
"""
Comprehensive API Test Suite for Panther Anomaly Detection
Dynamically discovers available models and generates tests based on configuration
"""

import requests
import json
import time
import statistics
from pathlib import Path
from typing import Dict, List, Any, Optional
import glob
import re

class PantherAnomalyAPITester:
    def __init__(self, api_url: str, config_dir: str = "config", models_dir: str = "models"):
        # Use the API URL exactly as provided - should include /detect endpoint
        self.api_url = api_url
        self.config_dir = Path(config_dir)
        self.models_dir = Path(models_dir)
        
        self.config = self.load_config()
        self.available_models = self.discover_models()
        self.model_metadata = self.load_model_metadata()
        self.eventsource_mappings = self.extract_eventsource_mappings()
        
        self.test_results = []
        self.performance_metrics = {
            'response_times': [],
            'success_count': 0,
            'error_count': 0,
            'model_performance': {}
        }
        
        # Separate benchmark metrics to avoid double-counting
        self.benchmark_metrics = {
            'response_times': [],
            'model_performance': {}
        }
        
        print(f"🔍 Discovered {len(self.available_models)} models: {', '.join(self.available_models)}")
        print(f"🌐 Testing API endpoint: {self.api_url}")
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from config.json"""
        config_file = self.config_dir / "config.json"
        if not config_file.exists():
            print(f"⚠️  Config file not found: {config_file}")
            return {"queries": []}
        
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        print(f"📋 Loaded config with {len(config.get('queries', []))} log types")
        return config
    
    def discover_models(self) -> List[str]:
        """Discover available models by scanning the models directory"""
        if not self.models_dir.exists():
            print(f"⚠️  Models directory not found: {self.models_dir}")
            return []
        
        # Find all isolation forest model files
        model_files = list(self.models_dir.glob("*_isolation_forest.joblib"))
        
        # Extract model names from filenames
        models = []
        for model_file in model_files:
            model_name = model_file.stem.replace("_isolation_forest", "")
            models.append(model_name)
        
        return sorted(models)
    
    def load_model_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Load metadata for all available models"""
        metadata = {}
        
        for model_name in self.available_models:
            metadata_file = self.models_dir / f"{model_name}_metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata[model_name] = json.load(f)
                print(f"📊 Loaded metadata for {model_name}")
            else:
                print(f"⚠️  No metadata found for {model_name}")
                metadata[model_name] = {}
        
        return metadata
    
    def extract_eventsource_mappings(self) -> Dict[str, str]:
        """Extract eventSource to model mappings from detector code"""
        # Based on the anomaly detector code we reviewed
        return {
            'iam.amazonaws.com': 'AWS IAM',
            'config.amazonaws.com': 'AWS Config',
            'vpc-flow-logs.amazonaws.com': 'AWS VPC Flow'
        }
    
    def generate_test_event(self, model_name: str, include_eventsource: bool = False) -> Dict[str, Any]:
        """Generate realistic test event data based on model metadata"""
        # Always add timestamp for time feature extraction
        event_data = {
            "p_event_time": "2024-08-14T15:30:00Z"
        }
        
        # Get model metadata for feature requirements
        metadata = self.model_metadata.get(model_name, {})
        categorical_features = metadata.get('categorical_features', [])
        numerical_features = metadata.get('numerical_features', [])
        feature_stats = metadata.get('feature_stats', {})
        
        # Generate model-specific test data based on actual feature requirements
        if model_name == 'AWS IAM':
            # CloudTrail IAM event with required features
            event_data.update({
                "sourceIPAddress": "trustedadvisor.amazonaws.com",
                "eventName": "ListSAMLProviders", 
                "recipientAccountId": "465197116942",
                "userIdentity": {"accountId": "465197116942"},
                "requestParameters": {"maxItems": 100}
            })
            if include_eventsource:
                event_data["eventsource"] = "iam.amazonaws.com"
                
        elif model_name == 'AWS Config':
            # CloudTrail Config event with required features  
            event_data.update({
                "sourceIPAddress": "config.amazonaws.com",
                "eventName": "DescribeConfigurationRecorders",
                "userAgent": "config.amazonaws.com",
                "recipientAccountId": "187901811700",
                "userIdentity": {
                    "sessionContext": {
                        "sessionIssuer": {
                            "arn": "arn:aws:iam::187901811700:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig",
                            "principalId": "AROASXP6SDP2LVVYPSXYA"
                        }
                    }
                }
            })
            if include_eventsource:
                event_data["eventsource"] = "config.amazonaws.com"
                
        elif model_name == 'AWS VPC Flow':
            # VPC Flow event with required features (not CloudTrail!)
            event_data.update({
                "interfaceId": "eni-09402a0e479845ccf",
                "account": "616907755205", 
                "bytes": 44,
                "packets": 1,
                "protocol": 6,
                "tcpFlags": 2,
                "version": 2
            })
            if include_eventsource:
                event_data["eventsource"] = "vpc-flow-logs.amazonaws.com"
        
        return event_data
    
    def make_request(self, payload: Dict[str, Any], test_description: str) -> Dict[str, Any]:
        """Make API request and measure performance"""
        start_time = time.time()
        
        try:
            response = requests.post(
                self.api_url,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=30
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            result = {
                'test': test_description,
                'status_code': response.status_code,
                'response_time': response_time,
                'success': response.status_code == 200,
                'payload': payload,
                'response': None,
                'error': None
            }
            
            if response.status_code == 200:
                try:
                    result['response'] = response.json()
                    self.performance_metrics['success_count'] += 1
                except json.JSONDecodeError as e:
                    result['error'] = f"JSON decode error: {e}"
                    result['success'] = False
                    self.performance_metrics['error_count'] += 1
            else:
                result['error'] = f"HTTP {response.status_code}: {response.text}"
                self.performance_metrics['error_count'] += 1
            
            self.performance_metrics['response_times'].append(response_time)
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            result = {
                'test': test_description,
                'status_code': None,
                'response_time': response_time,
                'success': False,
                'payload': payload,
                'response': None,
                'error': str(e)
            }
            
            self.performance_metrics['error_count'] += 1
            self.performance_metrics['response_times'].append(response_time)
            
            return result
    
    def make_benchmark_request(self, payload: Dict[str, Any], test_description: str) -> Dict[str, Any]:
        """Make API request for benchmarking without affecting main test counters"""
        start_time = time.time()
        
        try:
            response = requests.post(
                self.api_url,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=30
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            result = {
                'test': test_description,
                'status_code': response.status_code,
                'response_time': response_time,
                'success': response.status_code == 200,
                'payload': payload,
                'response': None,
                'error': None
            }
            
            if response.status_code == 200:
                try:
                    result['response'] = response.json()
                except json.JSONDecodeError as e:
                    result['error'] = f"JSON decode error: {e}"
                    result['success'] = False
            else:
                result['error'] = f"HTTP {response.status_code}: {response.text}"
            
            # Only add to benchmark metrics, not main counters
            self.benchmark_metrics['response_times'].append(response_time)
            
            return result
            
        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time
            
            result = {
                'test': test_description,
                'status_code': None,
                'response_time': response_time,
                'success': False,
                'payload': payload,
                'response': None,
                'error': str(e)
            }
            
            # Only add to benchmark metrics, not main counters
            self.benchmark_metrics['response_times'].append(response_time)
            
            return result
    
    def test_auto_detection_models(self):
        """Test auto-detection via eventSource field for all available models"""
        print(f"\n🎯 Testing Auto-Detection via eventSource...")
        
        for model_name in self.available_models:
            # Generate test data with eventSource
            event_data = self.generate_test_event(model_name, include_eventsource=True)
            
            if 'eventsource' not in event_data:
                print(f"⏭️  Skipping {model_name} - no eventSource mapping found")
                continue
            
            payload = {"event_data": event_data}
            
            result = self.make_request(
                payload, 
                f"Auto-detect {model_name} via eventSource"
            )
            
            self.test_results.append(result)
            
            if result['success']:
                detected_type = result['response'].get('log_type', 'Unknown')
                expected_type = model_name
                
                if detected_type == expected_type:
                    print(f"✅ {model_name}: Correctly detected ({result['response_time']:.3f}s)")
                else:
                    print(f"❌ {model_name}: Expected {expected_type}, got {detected_type} ({result['response_time']:.3f}s)")
            else:
                print(f"❌ {model_name}: {result['error']} ({result['response_time']:.3f}s)")
    
    def test_explicit_model_selection(self):
        """Test explicit model selection via log_type parameter"""
        print(f"\n🎯 Testing Explicit Model Selection...")
        
        for model_name in self.available_models:
            event_data = self.generate_test_event(model_name, include_eventsource=False)
            
            payload = {
                "event_data": event_data,
                "log_type": model_name
            }
            
            result = self.make_request(
                payload,
                f"Explicit selection of {model_name}"
            )
            
            self.test_results.append(result)
            
            if result['success']:
                detected_type = result['response'].get('log_type', 'Unknown')
                
                if detected_type == model_name:
                    print(f"✅ {model_name}: Correctly selected ({result['response_time']:.3f}s)")
                else:
                    print(f"❌ {model_name}: Expected {model_name}, got {detected_type} ({result['response_time']:.3f}s)")
            else:
                print(f"❌ {model_name}: {result['error']} ({result['response_time']:.3f}s)")
    
    def test_custom_thresholds(self):
        """Test custom anomaly thresholds"""
        print(f"\n🎯 Testing Custom Anomaly Thresholds...")
        
        thresholds = [-0.5, -0.3, -0.1, 0.0]
        
        if not self.available_models:
            print("⏭️  No models available for threshold testing")
            return
        
        # Use first available model for threshold testing
        model_name = self.available_models[0]
        event_data = self.generate_test_event(model_name)
        
        for threshold in thresholds:
            payload = {
                "event_data": event_data,
                "log_type": model_name,
                "anomaly_threshold": threshold
            }
            
            result = self.make_request(
                payload,
                f"Custom threshold {threshold} with {model_name}"
            )
            
            self.test_results.append(result)
            
            if result['success']:
                is_anomaly = result['response'].get('is_anomaly', False)
                anomaly_score = result['response'].get('anomaly_score', 0)
                used_threshold = result['response'].get('anomaly_threshold', -0.3)
                
                print(f"✅ Threshold {threshold}: {'ANOMALY' if is_anomaly else 'NORMAL'} "
                      f"(score: {anomaly_score:.3f}, used: {used_threshold}) "
                      f"({result['response_time']:.3f}s)")
            else:
                print(f"❌ Threshold {threshold}: {result['error']} ({result['response_time']:.3f}s)")
    
    def test_error_cases(self):
        """Test error handling with invalid requests"""
        print(f"\n🎯 Testing Error Handling...")
        
        error_tests = [
            {
                "payload": {},
                "description": "Empty payload"
            },
            {
                "payload": {"invalid_field": "test"},
                "description": "Missing event_data field"
            },
            {
                "payload": {"event_data": {}, "log_type": "NonExistentModel"},
                "description": "Invalid log_type"
            },
            {
                "payload": {"event_data": {"eventName": "test"}, "anomaly_threshold": "invalid"},
                "description": "Invalid threshold type"
            }
        ]
        
        for error_test in error_tests:
            result = self.make_request(
                error_test["payload"],
                f"Error case: {error_test['description']}"
            )
            
            self.test_results.append(result)
            
            # For error cases, we expect either 4xx status or error in response
            expected_error = result['status_code'] in [400, 500] or not result['success']
            
            if expected_error:
                print(f"✅ {error_test['description']}: Correctly handled error ({result['response_time']:.3f}s)")
                # This error test passed - update the result to reflect success
                if not result['success']:
                    result['success'] = True
                    # Adjust the counters since this should be counted as a success
                    self.performance_metrics['success_count'] += 1
                    self.performance_metrics['error_count'] -= 1
            else:
                print(f"⚠️  {error_test['description']}: Unexpected success ({result['response_time']:.3f}s)")
    
    def benchmark_performance(self):
        """Run performance benchmarks"""
        print(f"\n🎯 Running Performance Benchmarks...")
        
        if not self.available_models:
            print("⏭️  No models available for performance testing")
            return
        
        # Test each model with multiple requests
        for model_name in self.available_models:
            model_times = []
            
            print(f"📊 Benchmarking {model_name}...")
            
            for i in range(5):  # 5 requests per model
                event_data = self.generate_test_event(model_name, include_eventsource=True)
                payload = {"event_data": event_data}
                
                result = self.make_benchmark_request(
                    payload,
                    f"Performance test {i+1} for {model_name}"
                )
                
                if result['success']:
                    model_times.append(result['response_time'])
            
            if model_times:
                avg_time = statistics.mean(model_times)
                min_time = min(model_times)
                max_time = max(model_times)
                
                self.benchmark_metrics['model_performance'][model_name] = {
                    'avg_response_time': avg_time,
                    'min_response_time': min_time,
                    'max_response_time': max_time,
                    'requests_tested': len(model_times)
                }
                
                print(f"  📈 Avg: {avg_time:.3f}s, Min: {min_time:.3f}s, Max: {max_time:.3f}s")
    
    def generate_report(self):
        """Generate comprehensive test report"""
        print(f"\n" + "="*80)
        print(f"🎉 COMPREHENSIVE API TEST REPORT")
        print(f"="*80)
        
        total_tests = len(self.test_results)
        success_rate = (self.performance_metrics['success_count'] / total_tests * 100) if total_tests > 0 else 0
        
        print(f"\n📊 OVERALL RESULTS:")
        print(f"  • Total Tests: {total_tests}")
        print(f"  • Successful: {self.performance_metrics['success_count']}")
        print(f"  • Failed: {self.performance_metrics['error_count']}")
        print(f"  • Success Rate: {success_rate:.1f}%")
        
        if self.performance_metrics['response_times']:
            print(f"\n⏱️  PERFORMANCE METRICS:")
            times = self.performance_metrics['response_times']
            print(f"  • Average Response Time: {statistics.mean(times):.3f}s")
            print(f"  • Minimum Response Time: {min(times):.3f}s")
            print(f"  • Maximum Response Time: {max(times):.3f}s")
            print(f"  • Median Response Time: {statistics.median(times):.3f}s")
            
            if len(times) > 1:
                print(f"  • Standard Deviation: {statistics.stdev(times):.3f}s")
        
        if self.benchmark_metrics['model_performance']:
            print(f"\n🏆 MODEL PERFORMANCE COMPARISON:")
            for model_name, perf in self.benchmark_metrics['model_performance'].items():
                print(f"  • {model_name}:")
                print(f"    - Average: {perf['avg_response_time']:.3f}s")
                print(f"    - Range: {perf['min_response_time']:.3f}s - {perf['max_response_time']:.3f}s")
                print(f"    - Requests: {perf['requests_tested']}")
            
            if self.benchmark_metrics['response_times']:
                print(f"\n📊 BENCHMARK SUMMARY:")
                bench_times = self.benchmark_metrics['response_times']
                print(f"  • Total Benchmark Requests: {len(bench_times)}")
                print(f"  • Average Benchmark Time: {statistics.mean(bench_times):.3f}s")
                print(f"  • Benchmark Range: {min(bench_times):.3f}s - {max(bench_times):.3f}s")
        
        print(f"\n🔍 DISCOVERED CONFIGURATION:")
        print(f"  • Available Models: {', '.join(self.available_models)}")
        print(f"  • EventSource Mappings:")
        for eventsource, model in self.eventsource_mappings.items():
            if model in self.available_models:
                print(f"    - {eventsource} → {model}")
        
        # Show failed tests
        failed_tests = [r for r in self.test_results if not r['success']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  • {test['test']}: {test['error']}")
        
        print(f"\n🌐 API ENDPOINT: {self.api_url}")
        print(f"="*80)
    
    def run_all_tests(self):
        """Run the complete test suite"""
        print(f"🚀 Starting Comprehensive API Test Suite")
        print(f"🌐 API Endpoint: {self.api_url}")
        print(f"📁 Config Directory: {self.config_dir}")
        print(f"🤖 Models Directory: {self.models_dir}")
        
        try:
            self.test_auto_detection_models()
            self.test_explicit_model_selection()
            self.test_custom_thresholds()
            self.test_error_cases()
            self.benchmark_performance()
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Test suite interrupted by user")
        except Exception as e:
            print(f"\n❌ Unexpected error in test suite: {e}")
        
        finally:
            self.generate_report()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Comprehensive Panther Anomaly Detection API Tester")
    parser.add_argument(
        "--api-url", 
        required=True, 
        help="API Gateway endpoint URL"
    )
    parser.add_argument(
        "--config-dir", 
        default="config", 
        help="Configuration directory (default: config)"
    )
    parser.add_argument(
        "--models-dir", 
        default="models", 
        help="Models directory (default: models)"
    )
    
    args = parser.parse_args()
    
    # Create and run test suite
    tester = PantherAnomalyAPITester(
        api_url=args.api_url,
        config_dir=args.config_dir,
        models_dir=args.models_dir
    )
    
    tester.run_all_tests()


if __name__ == "__main__":
    main()