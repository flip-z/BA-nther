#!/bin/bash

# AWS Lambda + API Gateway Deprovision Script for Panther Anomaly Detector
# Usage: ./deprovision_lambda.sh [function-name] [aws-region] [aws-account-id]

set -e

# Configuration
FUNCTION_NAME="${1:-panther-anomaly-detector}"
AWS_REGION="${2:-us-east-1}"
AWS_ACCOUNT_ID="${3}"
ECR_REPO_NAME="panther-anomaly-detector"
API_GATEWAY_NAME="${FUNCTION_NAME}-api"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${RED}🗑️  Deprovisioning Panther Anomaly Detector AWS Resources${NC}"

# Check if AWS session is active
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

echo -e "${YELLOW}🕵️  Discovering resources to deprovision...${NC}"

# Step 1: Find and remove API Gateway
echo -e "${YELLOW}🌐 Looking for API Gateway...${NC}"

API_ID=$(aws apigatewayv2 get-apis --region ${AWS_REGION} --query "Items[?Name=='${API_GATEWAY_NAME}'].ApiId" --output text 2>/dev/null)

if [ -n "$API_ID" ] && [ "$API_ID" != "None" ]; then
    echo -e "${YELLOW}Found API Gateway ${API_GATEWAY_NAME} with ID: ${API_ID}${NC}"
    
    # Get API endpoint for logging
    API_ENDPOINT=$(aws apigatewayv2 get-api --api-id ${API_ID} --region ${AWS_REGION} --query 'ApiEndpoint' --output text 2>/dev/null || echo "Unknown")
    echo "   Endpoint: ${API_ENDPOINT}"
    
    # Delete API Gateway
    echo -e "${YELLOW}🗑️  Deleting API Gateway...${NC}"
    if aws apigatewayv2 delete-api --api-id ${API_ID} --region ${AWS_REGION}; then
        echo -e "${GREEN}✅ Successfully deleted API Gateway${NC}"
    else
        echo -e "${RED}❌ Failed to delete API Gateway${NC}"
    fi
else
    echo -e "${GREEN}✅ No API Gateway found with name ${API_GATEWAY_NAME}${NC}"
fi

# Step 2: Remove Lambda function
echo -e "${YELLOW}⚡ Looking for Lambda function...${NC}"

if aws lambda get-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION} > /dev/null 2>&1; then
    echo -e "${YELLOW}Found Lambda function: ${FUNCTION_NAME}${NC}"
    
    # Get function details for logging
    FUNCTION_ARN=$(aws lambda get-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION} --query 'Configuration.FunctionArn' --output text 2>/dev/null || echo "Unknown")
    RUNTIME=$(aws lambda get-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION} --query 'Configuration.PackageType' --output text 2>/dev/null || echo "Unknown")
    echo "   ARN: ${FUNCTION_ARN}"
    echo "   Package Type: ${RUNTIME}"
    
    # Delete Lambda function
    echo -e "${YELLOW}🗑️  Deleting Lambda function...${NC}"
    if aws lambda delete-function --function-name ${FUNCTION_NAME} --region ${AWS_REGION}; then
        echo -e "${GREEN}✅ Successfully deleted Lambda function${NC}"
    else
        echo -e "${RED}❌ Failed to delete Lambda function${NC}"
    fi
else
    echo -e "${GREEN}✅ No Lambda function found with name ${FUNCTION_NAME}${NC}"
fi

# Step 3: Remove IAM execution role
echo -e "${YELLOW}🔐 Looking for IAM execution role...${NC}"

ROLE_NAME="${FUNCTION_NAME}-execution-role"
if aws iam get-role --role-name ${ROLE_NAME} > /dev/null 2>&1; then
    echo -e "${YELLOW}Found IAM role: ${ROLE_NAME}${NC}"
    
    # Detach policies before deleting role
    echo -e "${YELLOW}🔗 Detaching policies from role...${NC}"
    
    # List and detach managed policies
    ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name ${ROLE_NAME} --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    if [ -n "$ATTACHED_POLICIES" ]; then
        echo "$ATTACHED_POLICIES" | tr '\t' '\n' | while read -r policy_arn; do
            if [ -n "$policy_arn" ]; then
                echo -e "${YELLOW}   Detaching policy: ${policy_arn}${NC}"
                aws iam detach-role-policy --role-name ${ROLE_NAME} --policy-arn "${policy_arn}"
            fi
        done
    fi
    
    # List and delete inline policies
    INLINE_POLICIES=$(aws iam list-role-policies --role-name ${ROLE_NAME} --query 'PolicyNames[]' --output text 2>/dev/null)
    if [ -n "$INLINE_POLICIES" ]; then
        echo "$INLINE_POLICIES" | tr '\t' '\n' | while read -r policy_name; do
            if [ -n "$policy_name" ]; then
                echo -e "${YELLOW}   Deleting inline policy: ${policy_name}${NC}"
                aws iam delete-role-policy --role-name ${ROLE_NAME} --policy-name "${policy_name}"
            fi
        done
    fi
    
    # Delete the role
    echo -e "${YELLOW}🗑️  Deleting IAM role...${NC}"
    if aws iam delete-role --role-name ${ROLE_NAME}; then
        echo -e "${GREEN}✅ Successfully deleted IAM role${NC}"
    else
        echo -e "${RED}❌ Failed to delete IAM role${NC}"
    fi
else
    echo -e "${GREEN}✅ No IAM role found with name ${ROLE_NAME}${NC}"
fi

# Step 4: Handle ECR repository (optional - ask user)
echo -e "${YELLOW}📦 Checking ECR repository...${NC}"

if aws ecr describe-repositories --repository-names ${ECR_REPO_NAME} --region ${AWS_REGION} > /dev/null 2>&1; then
    echo -e "${YELLOW}Found ECR repository: ${ECR_REPO_NAME}${NC}"
    
    # Get repository details
    REPO_URI=$(aws ecr describe-repositories --repository-names ${ECR_REPO_NAME} --region ${AWS_REGION} --query 'repositories[0].repositoryUri' --output text 2>/dev/null || echo "Unknown")
    IMAGE_COUNT=$(aws ecr describe-images --repository-name ${ECR_REPO_NAME} --region ${AWS_REGION} --query 'length(imageDetails)' --output text 2>/dev/null || echo "0")
    echo "   URI: ${REPO_URI}"
    echo "   Images: ${IMAGE_COUNT}"
    
    echo -e "${YELLOW}⚠️  ECR repository contains Docker images${NC}"
    echo -e "${YELLOW}Do you want to delete the ECR repository and all images? (y/N):${NC}"
    read -r DELETE_ECR
    
    if [[ "$DELETE_ECR" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}🗑️  Deleting ECR repository and all images...${NC}"
        
        # Force delete repository (removes all images)
        if aws ecr delete-repository --repository-name ${ECR_REPO_NAME} --region ${AWS_REGION} --force; then
            echo -e "${GREEN}✅ Successfully deleted ECR repository and images${NC}"
        else
            echo -e "${RED}❌ Failed to delete ECR repository${NC}"
        fi
    else
        echo -e "${YELLOW}⏭️  Skipping ECR repository deletion${NC}"
        echo -e "${YELLOW}   Repository will remain: ${REPO_URI}${NC}"
        echo -e "${YELLOW}   To delete manually later: aws ecr delete-repository --repository-name ${ECR_REPO_NAME} --region ${AWS_REGION} --force${NC}"
    fi
else
    echo -e "${GREEN}✅ No ECR repository found with name ${ECR_REPO_NAME}${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Deprovision complete!${NC}"
echo ""
echo -e "${GREEN}📋 Resources Removed:${NC}"
echo "  • API Gateway: ${API_GATEWAY_NAME} (${API_ID:-Not found})"
echo "  • Lambda Function: ${FUNCTION_NAME}"
echo "  • IAM Role: ${ROLE_NAME}"
if [[ "$DELETE_ECR" =~ ^[Yy]$ ]]; then
    echo "  • ECR Repository: ${ECR_REPO_NAME}"
else
    echo "  • ECR Repository: ${ECR_REPO_NAME} (preserved)"
fi
echo "  • Region: ${AWS_REGION}"
echo ""
echo -e "${GREEN}✅ All specified resources have been deprovisioned${NC}"
echo -e "${YELLOW}💡 Note: This script does not remove CloudWatch Logs groups or other indirect resources${NC}"
echo -e "${YELLOW}   To clean up logs: aws logs delete-log-group --log-group-name /aws/lambda/${FUNCTION_NAME}${NC}"