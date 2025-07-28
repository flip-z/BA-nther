#!/usr/bin/env python3
"""
Simple deployment script for AWS Config Anomaly Detection
Reads config.json and deploys with proper parameters
"""

import json
import subprocess
import sys
import os

def load_config():
    """Load configuration from config.json"""
    if not os.path.exists('config.json'):
        print("❌ config.json not found. Please create it first!")
        print("Copy config.json.template and edit it with your settings.")
        sys.exit(1)
    
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    # Validate required fields
    required_fields = ['panther_api_url', 'panther_api_token']
    for field in required_fields:
        if not config.get(field) or config[field] == f"your-{field.replace('_', '-')}-here":
            print(f"❌ Please set {field} in config.json")
            sys.exit(1)
    
    return config

def run_command(command):
    """Run shell command and handle errors"""
    print(f"🔨 Running: {command}")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"❌ Command failed: {command}")
        sys.exit(1)

def main():
    print("🚀 AWS Config Anomaly Detection - Easy Deploy")
    print("=" * 50)
    print()
    
    # Load configuration
    config = load_config()
    print(f"✅ Configuration loaded")
    print(f"   API URL: {config['panther_api_url']}")
    print(f"   Region: {config.get('aws_region', 'us-west-2')}")
    print(f"   Environment: {config.get('environment', 'dev')}")
    print()
    
    # Check prerequisites
    print("🔍 Checking prerequisites...")
    
    try:
        subprocess.run(['cdk', '--version'], capture_output=True, check=True)
        print("✅ CDK is installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ CDK not found. Please install with: npm install -g aws-cdk")
        sys.exit(1)
    
    try:
        subprocess.run(['aws', 'sts', 'get-caller-identity'], capture_output=True, check=True)
        print("✅ AWS CLI is configured")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ AWS CLI not configured. Please run: aws configure")
        sys.exit(1)
    
    print()
    
    # Install dependencies
    print("📦 Installing Python dependencies...")
    run_command("pip install -r requirements.txt")
    print()
    
    # Deploy with parameters from config
    print("🚀 Deploying to AWS...")
    deploy_cmd = f"""cdk deploy \\
        --context panther_api_url="{config['panther_api_url']}" \\
        --context panther_api_token="{config['panther_api_token']}" \\
        --context region="{config.get('aws_region', 'us-west-2')}" \\
        --context environment="{config.get('environment', 'dev')}" \\
        --require-approval never"""
    
    run_command(deploy_cmd)
    
    print()
    print("🎉 Deployment complete!")
    print()
    print("📋 Next steps:")
    print("1. Check the outputs above for your API endpoint")
    print("2. Test with: curl https://your-endpoint/health")
    print("3. Manual training: aws lambda invoke --function-name ...TrainingFunction... /tmp/response.json")
    print()
    print("📖 For more details, see README.md")

if __name__ == "__main__":
    main() 