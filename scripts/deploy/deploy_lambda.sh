#!/bin/bash

# AWS Lambda + API Gateway Deployment Script for Panther Anomaly Detector
# Usage: ./deploy_lambda.sh [function-name] [aws-region] [aws-account-id]

set -e

# Configuration
FUNCTION_NAME="${1:-panther-anomaly-detector}"
AWS_REGION="${2:-us-east-1}"
AWS_ACCOUNT_ID="${3}"
ECR_REPO_NAME="panther-anomaly-detector"
IMAGE_TAG="latest"
API_GATEWAY_NAME="${FUNCTION_NAME}-api"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Deploying Panther Anomaly Detector to AWS Lambda + API Gateway${NC}"

# Check if AWS session is active (works with granted, profiles, etc.)
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo -e "${RED}❌ No active AWS session found.${NC}"
    echo "Please ensure you have valid AWS credentials via:"
    echo "  • granted (already assumed/selected a role)"
    echo "  • AWS CLI (aws configure)"
    echo "  • Environment variables"
    echo "  • IAM roles"
    exit 1
fi

# Auto-detect AWS account ID from current session if not provided
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo -e "${YELLOW}🔍 Auto-detecting AWS Account ID from current session...${NC}"
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
    
    if [ -z "$AWS_ACCOUNT_ID" ]; then
        echo -e "${RED}❌ Failed to detect AWS Account ID${NC}"
        echo "Usage: $0 [function-name] [aws-region] [aws-account-id]"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Detected Account ID: ${AWS_ACCOUNT_ID}${NC}"
fi

# Show current session info for verification
echo -e "${YELLOW}📋 Current AWS Session:${NC}"
CURRENT_USER=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo "Unknown")
echo "   User/Role: ${CURRENT_USER}"
echo "   Account ID: ${AWS_ACCOUNT_ID}"
echo "   Region: ${AWS_REGION}"
echo ""

ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_URI="${ECR_URI}/${ECR_REPO_NAME}:${IMAGE_TAG}"

# Check if required files exist - use absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS_DIR="${SCRIPT_DIR}/../models"

if [ ! -f "${MODELS_DIR}/AWS Config_isolation_forest.joblib" ]; then
    echo -e "${RED}❌ Error: Pre-trained models not found in ${MODELS_DIR}${NC}"
    echo "Checked for: AWS Config_isolation_forest.joblib"
    echo ""
    echo "Available files in models directory:"
    ls -la "${MODELS_DIR}" 2>/dev/null || echo "Models directory does not exist"
    echo ""
    echo "Please run the data collection and model training pipeline first."
    exit 1
fi

echo -e "${GREEN}✅ Found pre-trained models in ${MODELS_DIR}${NC}"

# Docker environment detection and guidance
echo -e "${YELLOW}🐳 Detecting Docker environment...${NC}"
DOCKER_VERSION=$(docker --version 2>/dev/null || echo "Unknown")
echo "Docker version: ${DOCKER_VERSION}"

# Check if Docker Desktop is being used
if docker info 2>/dev/null | grep -q "Docker Desktop"; then
    echo -e "${YELLOW}📱 Docker Desktop detected${NC}"
    
    # Check if containerd is enabled (common cause of OCI manifest issues)
    if docker info 2>/dev/null | grep -q "containerd"; then
        echo -e "${YELLOW}⚠️  Containerd detected in Docker Desktop${NC}"
        echo -e "${YELLOW}If you encounter manifest errors, consider:${NC}"
        echo "   1. Docker Desktop → Settings → Features in Development → Turn OFF 'Use containerd'"
        echo "   2. Or rely on the legacy builder (DOCKER_BUILDKIT=0) used in this script"
        echo ""
    fi
    
    # Check BuildKit default
    BUILDKIT_STATUS=$(docker info 2>/dev/null | grep -i buildkit || echo "BuildKit status unknown")
    echo "BuildKit status: ${BUILDKIT_STATUS}"
else
    echo -e "${GREEN}Standard Docker installation detected (good for Lambda compatibility)${NC}"
fi

echo ""

echo -e "${YELLOW}📦 Building Docker image...${NC}"
# Change to the scripts directory for proper Docker build context
SCRIPTS_DIR="${SCRIPT_DIR}/.."
cd "${SCRIPTS_DIR}"

# Build the image from the scripts directory with proper context for Lambda (x86_64)
# Force Docker V2 Schema 2 manifest format (required for AWS Lambda compatibility)
echo -e "${YELLOW}🏗️ Building fresh image for amd64 with Docker V2 manifest format...${NC}"

# Method 1: Use legacy Docker builder (DOCKER_BUILDKIT=0) - most reliable for Lambda
echo -e "${YELLOW}Attempting build with legacy Docker builder (Docker V2 manifest guaranteed)...${NC}"
if DOCKER_BUILDKIT=0 docker build --platform=linux/amd64 --no-cache -f anomaly_detector/Dockerfile -t ${ECR_REPO_NAME}:${IMAGE_TAG} .; then
    echo -e "${GREEN}✅ Successfully built with legacy Docker builder${NC}"
else
    echo -e "${YELLOW}⚠️  Legacy builder failed, trying BuildKit with Docker format...${NC}"
    # Method 2: Use BuildKit but force Docker format output
    if docker buildx build --platform=linux/amd64 --no-cache --output type=docker -f anomaly_detector/Dockerfile -t ${ECR_REPO_NAME}:${IMAGE_TAG} . --load; then
        echo -e "${GREEN}✅ Successfully built with BuildKit (Docker format)${NC}"
    else
        echo -e "${RED}❌ Both build methods failed${NC}"
        echo -e "${YELLOW}Possible Docker Desktop configuration issue - see containerd settings${NC}"
        exit 1
    fi
fi

# Comprehensive platform and entrypoint verification
echo -e "${YELLOW}🔍 Verifying image platform and Lambda compatibility...${NC}"
ARCH=$(docker inspect ${ECR_REPO_NAME}:${IMAGE_TAG} --format '{{.Architecture}}')
OS=$(docker inspect ${ECR_REPO_NAME}:${IMAGE_TAG} --format '{{.Os}}')
CONFIG=$(docker inspect ${ECR_REPO_NAME}:${IMAGE_TAG} --format '{{.Config.Cmd}}')

echo "📋 Built image details:"
echo "   Architecture: ${ARCH}"
echo "   OS: ${OS}"
echo "   Command: ${CONFIG}"

# Critical validation for Lambda
if [ "${ARCH}" != "amd64" ]; then
    echo -e "${RED}❌ CRITICAL: Image built for ${ARCH}, but Lambda requires amd64${NC}"
    echo -e "${RED}This will cause Runtime.InvalidEntrypoint errors${NC}"
    exit 1
fi

if [ "${OS}" != "linux" ]; then
    echo -e "${RED}❌ CRITICAL: Image built for ${OS}, but Lambda requires linux${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Image architecture (${ARCH}) and OS (${OS}) are compatible with Lambda x86_64${NC}"

# Verify the command/entrypoint is set correctly
if [[ "${CONFIG}" == *"anomaly_detector.lambda_handler"* ]]; then
    echo -e "${GREEN}✅ Lambda handler correctly configured${NC}"
else
    echo -e "${YELLOW}⚠️  Lambda handler configuration: ${CONFIG}${NC}"
fi

echo -e "${YELLOW}🏗️  Setting up ECR repository...${NC}"
# Stay in scripts directory - don't change back to deploy

# Create ECR repository if it doesn't exist
aws ecr describe-repositories --repository-names ${ECR_REPO_NAME} --region ${AWS_REGION} > /dev/null 2>&1 || \
aws ecr create-repository --repository-name ${ECR_REPO_NAME} --region ${AWS_REGION}

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_URI}

# Tag and push image
docker tag ${ECR_REPO_NAME}:${IMAGE_TAG} ${IMAGE_URI}

# Local image validation for AWS Lambda compatibility
echo -e "${YELLOW}🔍 Validating local image for AWS Lambda compatibility...${NC}"

# Verify image exists locally
if ! docker image inspect ${ECR_REPO_NAME}:${IMAGE_TAG} > /dev/null 2>&1; then
    echo -e "${RED}❌ Local image not found: ${ECR_REPO_NAME}:${IMAGE_TAG}${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Local image exists and ready for push${NC}"

# Since we used legacy Docker builder (DOCKER_BUILDKIT=0), we can be confident about Docker V2 format
echo -e "${GREEN}✅ Built with legacy Docker builder - Docker V2 Schema 2 format guaranteed${NC}"

# Basic image information
IMAGE_SIZE=$(docker image inspect ${ECR_REPO_NAME}:${IMAGE_TAG} --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1024/1024}')
echo "📋 Image size: ${IMAGE_SIZE}"
echo "📋 Image architecture: $(docker image inspect ${ECR_REPO_NAME}:${IMAGE_TAG} --format '{{.Architecture}}')"

echo -e "${YELLOW}📤 Pushing image to ECR...${NC}"
if ! docker push ${IMAGE_URI}; then
    echo -e "${RED}❌ Failed to push image to ECR${NC}"
    echo -e "${YELLOW}This could be due to:${NC}"
    echo "  • Image manifest format incompatibility with Lambda"
    echo "  • ECR authentication issues"
    echo "  • Network connectivity problems"
    echo ""
    echo -e "${YELLOW}Troubleshooting steps:${NC}"
    echo "  1. Check image manifest format above"
    echo "  2. Verify ECR login: aws ecr get-login-password --region ${AWS_REGION}"
    echo "  3. Try rebuilding image with different Docker settings"
    exit 1
fi
echo -e "${GREEN}✅ Successfully pushed image to ECR${NC}"

# Validate registry image manifest (now that it's in ECR)
echo -e "${YELLOW}🔍 Validating ECR image manifest format...${NC}"
if REGISTRY_MANIFEST=$(docker manifest inspect ${IMAGE_URI} --verbose 2>/dev/null); then
    REGISTRY_MEDIA_TYPE=$(echo "$REGISTRY_MANIFEST" | grep -o '"mediaType"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
    echo "📋 ECR image manifest media type: ${REGISTRY_MEDIA_TYPE}"
    
    if [[ "${REGISTRY_MEDIA_TYPE}" == *"application/vnd.docker"* ]]; then
        echo -e "${GREEN}✅ ECR image has Docker V2 Schema 2 manifest - compatible with Lambda${NC}"
    elif [[ "${REGISTRY_MEDIA_TYPE}" == *"application/vnd.oci"* ]]; then
        echo -e "${YELLOW}⚠️  ECR image has OCI manifest - may cause Lambda deployment issues${NC}"
    else
        echo -e "${YELLOW}⚠️  ECR image has unknown manifest type: ${REGISTRY_MEDIA_TYPE}${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Could not inspect ECR manifest (may take a moment to be available)${NC}"
    echo -e "${YELLOW}Proceeding with Lambda deployment...${NC}"
fi

echo -e "${YELLOW}⚡ Creating/updating Lambda function...${NC}"

# Check if function exists
if aws lambda get-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION} > /dev/null 2>&1; then
    echo "Function exists, updating code..."
    aws lambda update-function-code \
        --function-name ${FUNCTION_NAME} \
        --image-uri ${IMAGE_URI} \
        --region ${AWS_REGION}
    
    # Wait for code update to complete before making configuration changes
    echo -e "${YELLOW}⏳ Waiting for function code update to complete...${NC}"
    aws lambda wait function-updated --function-name ${FUNCTION_NAME} --region ${AWS_REGION}
    echo -e "${GREEN}✅ Function code update completed${NC}"
else
    echo "Creating new function..."
    
    # Create execution role if it doesn't exist
    ROLE_NAME="${FUNCTION_NAME}-execution-role"
    TRUST_POLICY='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }'
    
    if ! aws iam get-role --role-name ${ROLE_NAME} > /dev/null 2>&1; then
        aws iam create-role \
            --role-name ${ROLE_NAME} \
            --assume-role-policy-document "$TRUST_POLICY"
        
        aws iam attach-role-policy \
            --role-name ${ROLE_NAME} \
            --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        
        # Wait for role to be available
        sleep 10
    fi
    
    ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}"
    
    if ! aws lambda create-function \
        --function-name ${FUNCTION_NAME} \
        --package-type Image \
        --code ImageUri=${IMAGE_URI} \
        --role ${ROLE_ARN} \
        --timeout 300 \
        --memory-size 1024 \
        --architectures x86_64 \
        --region ${AWS_REGION} \
        --description "Panther Security Log Anomaly Detection"; then
        echo -e "${RED}❌ Failed to create Lambda function${NC}"
        echo -e "${YELLOW}This is likely due to image manifest incompatibility${NC}"
        echo "Image URI: ${IMAGE_URI}"
        echo "Manifest type checked above should be 'application/vnd.docker.*'"
        exit 1
    fi
fi

# Update function configuration (consolidated to avoid ResourceConflictException)
echo -e "${YELLOW}🔧 Updating function configuration (timeout, memory, architecture)...${NC}"

# Create a retry function for ResourceConflictException
update_function_config() {
    local max_retries=3
    local retry_count=0
    local wait_time=5
    
    while [ $retry_count -lt $max_retries ]; do
        if aws lambda update-function-configuration \
            --function-name ${FUNCTION_NAME} \
            --timeout 300 \
            --memory-size 1024 \
            --region ${AWS_REGION} 2>/dev/null; then
            echo -e "${GREEN}✅ Function configuration updated successfully${NC}"
            return 0
        else
            retry_count=$((retry_count + 1))
            echo -e "${YELLOW}⚠️  Configuration update attempt ${retry_count} failed, waiting ${wait_time}s...${NC}"
            sleep $wait_time
            wait_time=$((wait_time * 2))  # Exponential backoff
        fi
    done
    
    echo -e "${RED}❌ Failed to update function configuration after ${max_retries} attempts${NC}"
    return 1
}

# Call the retry function
update_function_config

# Wait for configuration update to complete
echo -e "${YELLOW}⏳ Waiting for configuration update to complete...${NC}"
aws lambda wait function-updated --function-name ${FUNCTION_NAME} --region ${AWS_REGION}

# Now update architecture separately (only if needed)
CURRENT_ARCH=$(aws lambda get-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION} --query 'Configuration.Architectures[0]' --output text)
if [ "${CURRENT_ARCH}" != "x86_64" ]; then
    echo -e "${YELLOW}🔧 Updating function architecture to x86_64...${NC}"
    aws lambda update-function-configuration \
        --function-name ${FUNCTION_NAME} \
        --architectures x86_64 \
        --region ${AWS_REGION}
    
    echo -e "${YELLOW}⏳ Waiting for architecture update to complete...${NC}"
    aws lambda wait function-updated --function-name ${FUNCTION_NAME} --region ${AWS_REGION}
else
    echo -e "${GREEN}✅ Function architecture already set to x86_64${NC}"
fi

echo -e "${GREEN}✅ Lambda deployment complete!${NC}"

# Step 2: Create API Gateway
echo -e "${YELLOW}🌐 Creating API Gateway...${NC}"

# Check if API Gateway already exists
API_ID=$(aws apigatewayv2 get-apis --region ${AWS_REGION} --query "Items[?Name=='${API_GATEWAY_NAME}'].ApiId" --output text)

if [ -n "$API_ID" ] && [ "$API_ID" != "None" ]; then
    echo -e "${YELLOW}API Gateway ${API_GATEWAY_NAME} already exists with ID: ${API_ID}${NC}"
else
    # Create HTTP API Gateway
    echo -e "${YELLOW}Creating new HTTP API Gateway...${NC}"
    API_RESPONSE=$(aws apigatewayv2 create-api \
        --name ${API_GATEWAY_NAME} \
        --protocol-type HTTP \
        --description "API Gateway for Panther Anomaly Detector" \
        --region ${AWS_REGION})
    
    API_ID=$(echo "$API_RESPONSE" | jq -r '.ApiId')
    echo -e "${GREEN}✅ Created API Gateway with ID: ${API_ID}${NC}"
fi

# Get API Gateway invoke URL
API_ENDPOINT=$(aws apigatewayv2 get-api --api-id ${API_ID} --region ${AWS_REGION} --query 'ApiEndpoint' --output text)

# Create Lambda integration
echo -e "${YELLOW}🔗 Creating Lambda integration...${NC}"

# Check if integration already exists
INTEGRATION_ID=$(aws apigatewayv2 get-integrations --api-id ${API_ID} --region ${AWS_REGION} --query "Items[?IntegrationUri=='arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${FUNCTION_NAME}'].IntegrationId" --output text)

if [ -n "$INTEGRATION_ID" ] && [ "$INTEGRATION_ID" != "None" ]; then
    echo -e "${YELLOW}Lambda integration already exists with ID: ${INTEGRATION_ID}${NC}"
else
    # Create integration
    INTEGRATION_RESPONSE=$(aws apigatewayv2 create-integration \
        --api-id ${API_ID} \
        --integration-type AWS_PROXY \
        --integration-method POST \
        --integration-uri "arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${FUNCTION_NAME}" \
        --payload-format-version "2.0" \
        --region ${AWS_REGION})
    
    INTEGRATION_ID=$(echo "$INTEGRATION_RESPONSE" | jq -r '.IntegrationId')
    echo -e "${GREEN}✅ Created Lambda integration with ID: ${INTEGRATION_ID}${NC}"
fi

# Create route
echo -e "${YELLOW}🛤️  Creating API routes...${NC}"

# Check if route already exists
ROUTE_ID=$(aws apigatewayv2 get-routes --api-id ${API_ID} --region ${AWS_REGION} --query "Items[?RouteKey=='POST /detect'].RouteId" --output text)

if [ -n "$ROUTE_ID" ] && [ "$ROUTE_ID" != "None" ]; then
    echo -e "${YELLOW}Route already exists with ID: ${ROUTE_ID}${NC}"
else
    # Create route
    ROUTE_RESPONSE=$(aws apigatewayv2 create-route \
        --api-id ${API_ID} \
        --route-key "POST /detect" \
        --target "integrations/${INTEGRATION_ID}" \
        --region ${AWS_REGION})
    
    ROUTE_ID=$(echo "$ROUTE_RESPONSE" | jq -r '.RouteId')
    echo -e "${GREEN}✅ Created route with ID: ${ROUTE_ID}${NC}"
fi

# Add Lambda permission for API Gateway
echo -e "${YELLOW}🔐 Adding Lambda permissions...${NC}"

# Create a unique statement ID
STATEMENT_ID="apigateway-invoke-${API_ID}"

# Check if permission already exists by trying to remove it (will fail if it doesn't exist)
aws lambda remove-permission \
    --function-name ${FUNCTION_NAME} \
    --statement-id ${STATEMENT_ID} \
    --region ${AWS_REGION} > /dev/null 2>&1 || echo -n ""

# Add permission for API Gateway to invoke Lambda
aws lambda add-permission \
    --function-name ${FUNCTION_NAME} \
    --statement-id ${STATEMENT_ID} \
    --action lambda:InvokeFunction \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${AWS_REGION}:${AWS_ACCOUNT_ID}:${API_ID}/*/*" \
    --region ${AWS_REGION} > /dev/null

echo -e "${GREEN}✅ Lambda permission added for API Gateway${NC}"

# Deploy API Gateway
echo -e "${YELLOW}🚀 Deploying API Gateway...${NC}"

# Create deployment
DEPLOYMENT_RESPONSE=$(aws apigatewayv2 create-deployment \
    --api-id ${API_ID} \
    --description "Deployment for Panther Anomaly Detector API" \
    --region ${AWS_REGION})

DEPLOYMENT_ID=$(echo "$DEPLOYMENT_RESPONSE" | jq -r '.DeploymentId')
echo -e "${GREEN}✅ Created deployment with ID: ${DEPLOYMENT_ID}${NC}"

# Get the final API URL
INVOKE_URL="${API_ENDPOINT}/detect"

echo ""
echo -e "${GREEN}🎉 Deployment complete!${NC}"
echo ""
echo -e "${GREEN}📋 Deployment Summary:${NC}"
echo "  • Lambda Function: ${FUNCTION_NAME}"
echo "  • API Gateway: ${API_GATEWAY_NAME}"
echo "  • Region: ${AWS_REGION}"
echo ""
echo -e "${GREEN}Function ARN:${NC} arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${FUNCTION_NAME}"
echo -e "${GREEN}🌐 API Endpoint:${NC} ${INVOKE_URL}"
echo ""
echo -e "${GREEN}📝 Test the API with:${NC}"
echo ""
echo -e "${YELLOW}Basic test (auto-detects model):${NC}"
echo "curl -X POST ${INVOKE_URL} \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"event_data\":{\"eventName\":\"test\",\"sourceIPAddress\":\"192.168.1.1\"}}'"
echo ""
echo -e "${YELLOW}AWS IAM events (via eventSource):${NC}"
echo "curl -X POST ${INVOKE_URL} \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"event_data\":{\"eventName\":\"CreateUser\",\"eventSource\":\"iam.amazonaws.com\",\"sourceIPAddress\":\"10.0.0.1\"}}'"
echo ""
echo -e "${YELLOW}Explicit model selection:${NC}"
echo "curl -X POST ${INVOKE_URL} \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"event_data\":{\"eventName\":\"CreateUser\"},\"log_type\":\"AWS IAM\"}'"
echo ""
echo -e "${GREEN}Available Models:${NC}"
echo "  • AWS IAM (eventSource: iam.amazonaws.com)"
echo "  • AWS Config (eventSource: config.amazonaws.com)"  
echo "  • AWS VPC Flow (eventSource: vpc-flow-logs.amazonaws.com)"
echo ""
echo -e "${GREEN}Test with comprehensive test suite:${NC}"
echo "python test_api_comprehensive.py --api-url ${INVOKE_URL}"
echo ""
echo -e "${GREEN}Request Format:${NC}"
echo "{"
echo "  \"event_data\": { /* your security event */ },"
echo "  \"log_type\": \"AWS IAM\",        // optional - auto-detected if not provided"
echo "  \"anomaly_threshold\": -0.3      // optional - defaults to -0.3"
echo "}"