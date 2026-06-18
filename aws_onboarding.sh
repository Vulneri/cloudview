#!/usr/bin/env bash
# ==============================================================================
# Vulneri Security - AWS Onboarding & Integration Automation Script
# ==============================================================================
# This script creates an IAM user with appropriate read-only permissions for
# CSPM (Security Posture) and CloudView (Asset Inventory & FinOps/Billing),
# attaches the necessary AWS-managed policies, generates access keys, and
# outputs the credentials in a clean JSON format to paste into the platform.
# ==============================================================================

set -eo pipefail

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
AMBER='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# --- Configuration ---
USER_NAME="vulneri-integration-user"
POLICIES=(
  "arn:aws:iam::aws:policy/SecurityAudit"
  "arn:aws:iam::aws:policy/ReadOnlyAccess"
  "arn:aws:iam::aws:policy/AWSBillingReadOnlyAccess"
)

print_header() {
  echo -e "${CYAN}======================================================================"
  echo -e "          Vulneri Security - AWS Integration Setup"
  echo -e "======================================================================${NC}"
  echo -e "This script will configure the permissions required for:"
  echo -e "  - ${BOLD}CSPM (Security)${NC}: Continuous security audits & compliance"
  echo -e "  - ${BOLD}CloudView (Inventory & FinOps)${NC}: Cost & asset visibility"
  echo -e "======================================================================"
}

log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
  echo -e "${AMBER}[WARNING]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# --- Prerequisites check ---
check_prerequisites() {
  echo
  log_info "Checking environment prerequisites..."
  
  if ! command -v aws &> /dev/null; then
    log_error "AWS CLI not found. Please run this inside AWS CloudShell or make sure the AWS CLI is installed."
    exit 1
  fi
  
  log_success "AWS CLI detected."

  # Check active session / identity
  if ! IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null); then
    log_error "Could not authenticate to AWS. Run 'aws configure' or use the AWS CloudShell."
    exit 1
  fi
  
  ACCOUNT_ID=$(echo "$IDENTITY" | grep -o '"Account": "[^"]*' | cut -d'"' -f4)
  ARN=$(echo "$IDENTITY" | grep -o '"Arn": "[^"]*' | cut -d'"' -f4)
  
  log_success "Successfully authenticated to AWS Account: ${BOLD}${ACCOUNT_ID}${NC}"
  log_info "Active identity: $ARN"
}

# --- Cleanup existing user if any ---
cleanup_existing_user() {
  if aws iam get-user --user-name "$USER_NAME" &>/dev/null; then
    echo
    log_warn "User '${USER_NAME}' already exists in this account."
    log_info "Cleaning up previous access keys and policies to ensure a fresh configuration..."
    
    # List and delete access keys
    KEYS=$(aws iam list-access-keys --user-name "$USER_NAME" --query "AccessKeyMetadata[].AccessKeyId" --output text)
    for key in $KEYS; do
      log_info "Removing old access key: $key"
      aws iam delete-access-key --user-name "$USER_NAME" --access-key-id "$key"
    done
    
    # Detach attached policies
    ATTACHED_POLICIES=$(aws iam list-attached-user-policies --user-name "$USER_NAME" --query "AttachedPolicies[].PolicyArn" --output text)
    for policy_arn in $ATTACHED_POLICIES; do
      log_info "Detaching old policy: $(basename "$policy_arn")"
      aws iam detach-user-policy --user-name "$USER_NAME" --policy-arn "$policy_arn"
    done
    
    # Delete inline policies
    INLINE_POLICIES=$(aws iam list-user-policies --user-name "$USER_NAME" --query "PolicyNames[]" --output text)
    for policy_name in $INLINE_POLICIES; do
      log_info "Removing old inline policy: $policy_name"
      aws iam delete-user-policy --user-name "$USER_NAME" --policy-name "$policy_name"
    done

    # Finally, delete user to start fresh
    log_info "Deleting old user for recreation..."
    aws iam delete-user --user-name "$USER_NAME"
    log_success "Cleanup completed."
  fi
}

# --- Create IAM User ---
create_user() {
  echo
  log_info "Creating new IAM User: ${BOLD}${USER_NAME}${NC}..."
  aws iam create-user --user-name "$USER_NAME" > /dev/null
  log_success "IAM User '${USER_NAME}' created successfully."
}

# --- Attach Policies ---
attach_policies() {
  echo
  log_info "Attaching recommended audit and read policies..."
  for policy in "${POLICIES[@]}"; do
    log_info "Attaching: ${BOLD}$(basename "$policy")${NC}"
    aws iam attach-user-policy --user-name "$USER_NAME" --policy-arn "$policy"
  done
  log_success "All policies attached successfully."
}

# --- Create Access Keys ---
create_access_key() {
  echo
  log_info "Generating new access keys for integration..."
  
  # Add small buffer delay to ensure IAM consistency (eventual consistency)
  sleep 3

  KEY_DATA=$(aws iam create-access-key --user-name "$USER_NAME" --output json)
  
  ACCESS_KEY_ID=$(echo "$KEY_DATA" | grep -o '"AccessKeyId": "[^"]*' | cut -d'"' -f4)
  SECRET_ACCESS_KEY=$(echo "$KEY_DATA" | grep -o '"SecretAccessKey": "[^"]*' | cut -d'"' -f4)
  
  log_success "Access keys generated successfully."
}

# --- Output result ---
print_output() {
  echo
  echo -e "${GREEN}======================================================================"
  echo -e "                        SETUP COMPLETED"
  echo -e "======================================================================${NC}"
  echo -e "Copy the following JSON block entirely and paste it in the Vulneri dashboard:"
  echo
  
  # Print the JSON wrapper format cleanly
  echo -e "${BOLD}{"
  echo -e "  \"accessKeyId\": \"$ACCESS_KEY_ID\","
  echo -e "  \"secretAccessKey\": \"$SECRET_ACCESS_KEY\""
  echo -e "}${NC}"
  
  echo
  echo -e "${GREEN}======================================================================"
  echo -e "Store these keys securely. This message will not be displayed again."
  echo -e "======================================================================${NC}"
}

main() {
  print_header
  check_prerequisites
  cleanup_existing_user
  create_user
  attach_policies
  create_access_key
  print_output
}

main
