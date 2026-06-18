#!/usr/bin/env bash
# ==============================================================================
# Vulneri Security - Azure Onboarding Setup Script for CloudView
# ==============================================================================
# This script runs in Azure Cloud Shell (Bash) and configures the identity
# and read-only permissions required for Vulneri CloudView:
#   - Resource inventory, governance, Defender for Cloud, Azure Policy,
#     monitoring, basic security posture, and complementary cost context.
# ==============================================================================

set -euo pipefail

# --- Color Definitions ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
AMBER='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# --- Defaults ---
DISPLAY_NAME="Vulneri-CloudView-Integration"
MINIMAL="false"
ENABLE_ENTRA="false"
ENABLE_KEYVAULT="false"
SUBSCRIPTION_ID=""
NON_INTERACTIVE="false"
JSON_ONLY="false"

# --- Globals for Audit Logging ---
WARNINGS_LIST=()
READER_STATUS="skipped"
SECURITY_STATUS="skipped"
COST_STATUS="skipped"
MONITOR_STATUS="skipped"
KEYVAULT_STATUS="skipped"
GRAPH_CONSENT_STATUS="not_requested"
CLIENT_ID=""
CLIENT_SECRET=""
SP_OBJECT_ID=""
TENANT_ID=""
SUB_NAME=""
SIGNED_IN_ACCOUNT=""
ROLE_ASSIGNMENT_STATUS="skipped"

# --- Graph Application Permissions to configure under --enable-entra ---
GRAPH_PERMS=(
  "Directory.Read.All"
  "Application.Read.All"
  "RoleManagement.Read.Directory"
  "Policy.Read.All"
  "UserAuthenticationMethod.Read.All"
  "GroupSettings.Read.All"
  "IdentityRiskEvent.Read.All"
  "IdentityRiskyUser.Read.All"
  "IdentityRiskyServicePrincipal.Read.All"
)

# --- Usage Message ---
usage() {
  cat <<USAGE
Vulneri CloudView Azure Onboarding Script

Usage:
  ./azure_onboarding.sh [options]

Options:
  --minimal                   Minimal mode: only assigns the mandatory "Reader" role.
                              Reduces coverage for Defender, Costs, Monitor, and parts of CSPM/Inventory.
  --enable-entra              Configure Microsoft Graph Application Permissions for Entra ID, MFA,
                              Conditional Access, Identity Protection, and directory role assessment.
                              Requires Directory Administrator privileges to grant admin consent.
  --enable-keyvault-metadata  Assign "Key Vault Reader" role at subscription level to allow reading
                              Key Vault configurations and metadata (no secret values are read).
  --subscription-id <id>      Target Azure Subscription ID to configure (defaults to currently active subscription).
  --display-name <name>       Custom Display Name for App Registration (default: "Vulneri-CloudView-Integration").
  --non-interactive           Skip confirmation prompts.
  --json-only                 Only output the final JSON configuration block (silences logs).
  -h, --help                  Show this help message.

USAGE
}

# --- Required Functions ---

# Print banner outlining read-only visibility focus and safety bounds
print_header() {
  if [ "$JSON_ONLY" = "false" ]; then
    echo -e "${CYAN}== Vulneri CloudView Azure Setup ==${NC}"
    echo
    echo -e "This script prepares an Azure read-only integration for Vulneri CloudView v1.0."
    echo
    echo -e "CloudView uses this identity to provide:"
    echo -e "- resource inventory;"
    echo -e "- governance and configuration analysis;"
    echo -e "- Defender for Cloud integrations;"
    echo -e "- Azure Policy compliance scanning;"
    echo -e "- active metrics monitoring;"
    echo -e "- costs as a complementary context;"
    echo -e "- basic security posture insights."
    echo
    echo -e "This onboarding step only prepares the integration identity."
    echo -e "It does not collect inventory now, and does not alter production resources."
    echo -e "======================================================================"
  fi
}

log_info() {
  if [ "$JSON_ONLY" = "false" ]; then
    echo -e "${BLUE}[INFO]${NC} $1" >&2
  fi
}

log_success() {
  if [ "$JSON_ONLY" = "false" ]; then
    echo -e "${GREEN}[OK]${NC} $1" >&2
  fi
}

log_warn() {
  if [ "$JSON_ONLY" = "false" ]; then
    echo -e "${AMBER}[WARNING]${NC} $1" >&2
  fi
  # Collect warnings into a global array for final JSON report
  WARNINGS_LIST+=("$1")
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

read_input() {
  local var_name="$1"
  local val=""
  if [ -t 0 ]; then
    read -r val
  elif [ -c /dev/tty ]; then
    read -r val </dev/tty
  else
    val=""
  fi
  eval "$var_name=\"\$val\""
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --minimal)
        MINIMAL="true"
        shift
        ;;
      --enable-entra)
        ENABLE_ENTRA="true"
        shift
        ;;
      --enable-keyvault-metadata)
        ENABLE_KEYVAULT="true"
        shift
        ;;
      --enable-cost)
        log_warn "Option --enable-cost is deprecated. Cost permissions are now configured by default."
        shift
        ;;
      --enable-security-reader)
        log_warn "Option --enable-security-reader is deprecated. Security permissions are now configured by default."
        shift
        ;;
      --subscription-id)
        if [ -z "${2:-}" ] || [[ "$2" =~ ^-- ]]; then
          log_error "Option --subscription-id requires a value."
          exit 5
        fi
        SUBSCRIPTION_ID="$2"
        shift 2
        ;;
      --display-name)
        if [ -z "${2:-}" ] || [[ "$2" =~ ^-- ]]; then
          log_error "Option --display-name requires a value."
          exit 5
        fi
        DISPLAY_NAME="$2"
        shift 2
        ;;
      --non-interactive)
        NON_INTERACTIVE="true"
        shift
        ;;
      --json-only)
        JSON_ONLY="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

check_dependencies() {
  log_info "Checking script dependencies..."
  if ! command -v az &>/dev/null; then
    log_error "Azure CLI ('az') is not installed or not in PATH."
    exit 1
  fi
  if ! command -v jq &>/dev/null; then
    log_error "Command 'jq' is not installed or not in PATH. Please install 'jq' to run this script."
    exit 1
  fi
  log_success "All dependencies verified."
}

# Resolve active Tenant ID, Subscription details, and Signed-in Account User Name
load_azure_context() {
  log_info "Verifying Azure Active Session context..."
  
  TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null || echo "")
  if [ -z "$TENANT_ID" ]; then
    log_error "No authenticated Azure context found. Please run 'az login' or execute within Azure Cloud Shell."
    exit 1
  fi

  if [ -z "$SUBSCRIPTION_ID" ]; then
    SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null || echo "")
    if [ -z "$SUBSCRIPTION_ID" ]; then
      log_error "Could not auto-detect active Subscription ID."
      exit 1
    fi
  fi

  log_info "Validating accessibility of Subscription ID: $SUBSCRIPTION_ID..."
  if ! az account set --subscription "$SUBSCRIPTION_ID" &>/dev/null; then
    log_error "Subscription ID '$SUBSCRIPTION_ID' is invalid, inactive, or not accessible with current credentials."
    exit 1
  fi

  SUB_NAME=$(az account show --subscription "$SUBSCRIPTION_ID" --query name -o tsv 2>/dev/null || echo "Unknown Subscription")
  SIGNED_IN_ACCOUNT=$(az account show --subscription "$SUBSCRIPTION_ID" --query user.name -o tsv 2>/dev/null || echo "Unknown account")

  if [ "$JSON_ONLY" = "false" ]; then
    echo >&2
    echo -e "${BOLD}Current Azure Context:${NC}" >&2
    echo -e "- Tenant ID: ${TENANT_ID}" >&2
    echo -e "- Subscription: ${SUB_NAME} (${SUBSCRIPTION_ID})" >&2
    echo -e "- Signed-in account: ${SIGNED_IN_ACCOUNT}" >&2
  fi
}

# Show detailed permissions checklist, safety boundaries, and prompt confirmation
confirm_execution() {
  if [ "$NON_INTERACTIVE" = "true" ]; then
    return 0
  fi

  # Determine target file descriptor for prints (stderr when json-only is set)
  local fd=1
  if [ "$JSON_ONLY" = "true" ]; then
    fd=2
  fi

  {
    echo
    echo -e "${BOLD}Permissions to be configured:${NC}"
    
    if [ "$MINIMAL" = "true" ]; then
      echo -e "- Reader: required"
      echo -e "- Security Reader: skipped (minimal mode)"
      echo -e "- Cost Management Reader: skipped (minimal mode)"
      echo -e "- Monitoring Reader: skipped (minimal mode)"
      echo -e "- Key Vault Reader: skipped (minimal mode)"
      echo -e "- Microsoft Graph permissions: skipped (minimal mode)"
      echo
      echo -e "${AMBER}${BOLD}WARNING:${NC} Minimal mode reduces coverage for Defender for Cloud, Cost/FinOps, Azure Monitor, and parts of CSPM/Inventory."
    else
      echo -e "- Reader: required"
      echo -e "- Security Reader: standard"
      echo -e "- Cost Management Reader: standard"
      echo -e "- Monitoring Reader: standard"
      
      if [ "$ENABLE_KEYVAULT" = "true" ]; then
        echo -e "- Key Vault Reader: enabled"
      else
        echo -e "- Key Vault Reader: skipped (run with --enable-keyvault-metadata to enable)"
      fi
      
      if [ "$ENABLE_ENTRA" = "true" ]; then
        echo -e "- Microsoft Graph permissions: enabled"
        echo -e "  (Requires directory administrator consent to read Entra ID, MFA, CA, and Identity Protection)"
      else
        echo -e "- Microsoft Graph permissions: skipped (run with --enable-entra to enable)"
      fi
    fi

    echo
    echo -e "${BOLD}Safety notes:${NC}"
    echo -e "- No virtual machines will be created."
    echo -e "- No networks will be changed."
    echo -e "- No databases will be accessed."
    echo -e "- No storage file contents will be read."
    echo -e "- No resources will be deleted."
    echo -e "- No storage account keys will be listed or accessed."
    echo -e "- No data will be sent to Vulneri during this onboarding step."
    echo -e "- A client secret will be generated and shown once at the end."
    echo
  } >&${fd}

  echo -n "Do you want to continue and create/update the CloudView integration identity? [y/N]: " >&${fd}
  local confirm
  read_input confirm
  
  if [[ ! "$confirm" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    log_error "Setup cancelled by user."
    exit 3
  fi
}

# Check if application exists under displayName and safely reuse or create a unique timestamp-suffixed fallback
find_or_create_app_registration() {
  log_info "Searching for existing App Registrations with display name '${DISPLAY_NAME}'..."
  
  local apps_json
  apps_json=$(az ad app list --display-name "$DISPLAY_NAME" -o json 2>/dev/null || echo "[]")
  local count
  count=$(echo "$apps_json" | jq 'length')
  
  local reused_app="false"
  
  if [ "$count" -eq 1 ]; then
    CLIENT_ID=$(echo "$apps_json" | jq -r '.[0].appId')
    reused_app="true"
    log_success "Found exactly one matching App Registration (Client ID: ${CLIENT_ID}). Reusing it."
  elif [ "$count" -gt 1 ]; then
    log_warn "Multiple App Registrations with display name '${DISPLAY_NAME}' were found."
    
    local action="create"
    if [ "$NON_INTERACTIVE" = "false" ]; then
      local fd=1
      if [ "$JSON_ONLY" = "true" ]; then
        fd=2
      fi
      echo >&${fd}
      echo -e "${AMBER}How would you like to proceed?${NC}" >&${fd}
      echo -e "  [1] Create a new App Registration with a unique timestamp suffix." >&${fd}
      echo -e "  [2] Abort setup." >&${fd}
      echo -n "Select an option [1-2]: " >&${fd}
      
      local choice
      read_input choice
      if [ "$choice" = "1" ]; then
        action="create"
      else
        log_error "Multiple App Registrations found and user chose to abort."
        exit 1
      fi
    else
      # Non-interactive mode: create a new one with timestamp suffix
      action="create"
    fi
    
    if [ "$action" = "create" ]; then
      local timestamp
      timestamp=$(date +%s)
      DISPLAY_NAME="${DISPLAY_NAME}-${timestamp}"
      log_warn "Creating a new App Registration with suffix: ${DISPLAY_NAME}"
      reused_app="false"
    fi
  fi
  
  if [ "$reused_app" = "false" ]; then
    log_info "Creating new App Registration: '${DISPLAY_NAME}'..."
    local app_json
    app_json=$(az ad app create --display-name "$DISPLAY_NAME" -o json 2>/dev/null || echo "")
    
    if [ -z "$app_json" ]; then
      log_error "Failed to create App Registration."
      log_error "Ensure that your Microsoft Entra ID tenant configurations allow users to register applications."
      exit 1
    fi
    CLIENT_ID=$(echo "$app_json" | jq -r .appId)
    log_success "App Registration created (Client ID: ${CLIENT_ID})."
  fi
}

# Ensure the corresponding Service Principal exists, using a retry loop with progressive backoff for replication lag
ensure_service_principal() {
  log_info "Ensuring corresponding Service Principal exists for Client ID: ${CLIENT_ID}..."
  
  local attempts=5
  local sleep_time=2
  
  for ((i=1; i<=attempts; i++)); do
    log_info "Verifying Service Principal existence (Attempt $i/$attempts)..."
    SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || echo "")
    
    if [ -n "$SP_OBJECT_ID" ]; then
      log_success "Service Principal verified (Object ID: ${SP_OBJECT_ID})."
      return 0
    fi
    
    if [ "$i" -lt "$attempts" ]; then
      log_warn "Service Principal replication lagging. Retrying in ${sleep_time}s..."
      sleep $sleep_time
      sleep_time=$((sleep_time + 2))
    fi
  done
  
  log_info "Creating missing Service Principal..."
  local sp_json
  sp_json=$(az ad sp create --id "$CLIENT_ID" -o json 2>/dev/null || echo "")
  SP_OBJECT_ID=$(echo "$sp_json" | jq -r '.id' 2>/dev/null || echo "")
  
  if [ -z "$SP_OBJECT_ID" ] || [ "$SP_OBJECT_ID" = "null" ]; then
    SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || echo "")
  fi

  if [ -z "$SP_OBJECT_ID" ]; then
    log_error "Failed to verify or create Service Principal for App Registration ${CLIENT_ID}."
    exit 1
  fi
  
  log_success "Service Principal successfully verified/created (Object ID: ${SP_OBJECT_ID})."
}

# Generate new secret credential on the App Registration without deleting existing secrets (--append)
create_client_secret() {
  log_info "Generating client secret credential..."
  
  local secret_json
  secret_json=$(az ad app credential reset --id "$CLIENT_ID" --append -o json 2>/dev/null || echo "")
  CLIENT_SECRET=$(echo "$secret_json" | jq -r .password 2>/dev/null || echo "")
  
  if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
    log_error "Failed to generate client secret."
    log_error "Verify that your account has ownership or Application Administrator privileges on this App Registration."
    exit 1
  fi
  
  log_success "Client secret generated."
}

# Dynamic Microsoft Graph application permissions resolution, merge, and setup
configure_graph_permissions() {
  if [ "$ENABLE_ENTRA" != "true" ] || [ "$MINIMAL" = "true" ]; then
    GRAPH_CONSENT_STATUS="not_requested"
    return 0
  fi
  
  log_info "Querying Microsoft Graph service principal definitions..."
  # Graph API appId is always 00000003-0000-0000-c000-000000000000
  local graph_sp_json
  graph_sp_json=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" -o json 2>/dev/null || echo "")
  if [ -z "$graph_sp_json" ]; then
    log_warn "Failed to query Microsoft Graph Service Principal. Skipping Graph permissions setup."
    GRAPH_CONSENT_STATUS="failed"
    return 0
  fi
  
  local resource_access="[]"
  for perm in "${GRAPH_PERMS[@]}"; do
    local role_id
    role_id=$(echo "$graph_sp_json" | jq -r --arg val "$perm" '.appRoles[] | select(.value==$val) | .id' 2>/dev/null || echo "")
    if [ -n "$role_id" ] && [ "$role_id" != "null" ]; then
      resource_access=$(echo "$resource_access" | jq --arg id "$role_id" '. += [{"id": $id, "type": "Role"}]')
    else
      log_warn "Graph role ID not found for: ${perm}"
    fi
  done
  
  log_info "Retrieving existing requiredResourceAccess for the App Registration..."
  local existing_rra
  existing_rra=$(az ad app show --id "$CLIENT_ID" --query "requiredResourceAccess" -o json 2>/dev/null || echo "[]")
  
  # Merge new Graph permissions with existing ones without overwriting other resources
  log_info "Merging new Graph permissions with existing ones..."
  local merged_rra
  merged_rra=$(echo "$existing_rra" | jq \
    --arg target_resource_id "00000003-0000-0000-c000-000000000000" \
    --argjson graph_access "$resource_access" \
    '
    (map(.resourceAppId == $target_resource_id) | index(true)) as $idx
    | if $idx == null then
        . + [{"resourceAppId": $target_resource_id, "resourceAccess": $graph_access}]
      else
        .[$idx].resourceAccess = (.[$idx].resourceAccess + $graph_access | unique_by(.id))
      fi
    ')
  
  log_info "Updating App Registration required resource access with Microsoft Graph permissions..."
  if az ad app update --id "$CLIENT_ID" --required-resource-accesses "$merged_rra" &>/dev/null; then
    log_success "Microsoft Graph permissions successfully updated and merged."
  else
    log_warn "Failed to configure required resource access for Microsoft Graph. Skipping Graph setup."
    GRAPH_CONSENT_STATUS="failed"
    return 0
  fi
  
  # Attempt to automatically grant admin consent
  log_info "Attempting to automatically grant admin consent..."
  sleep 3
  if az ad app permission admin-consent --id "$CLIENT_ID" &>/dev/null; then
    log_success "Administrator consent successfully granted for Microsoft Graph permissions."
    GRAPH_CONSENT_STATUS="granted"
  else
    log_warn "Automatic administrator consent failed."
    log_warn "To consent manually, navigate in Azure Portal to:"
    log_warn "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$CLIENT_ID"
    GRAPH_CONSENT_STATUS="pending_admin_consent"
  fi
}

# Verify role existence at scope and execute assignment if missing
assign_role_if_needed() {
  local role_name="$1"
  local scope="$2"
  local is_required="$3"
  
  ROLE_ASSIGNMENT_STATUS="failed"
  
  log_info "Checking if '${role_name}' role is already assigned..."
  
  local existing_assignment
  existing_assignment=$(az role assignment list --scope "$scope" --query "[?principalId=='$SP_OBJECT_ID' && roleDefinitionName=='$role_name'].id" -o tsv 2>/dev/null || echo "")
  
  if [ -n "$existing_assignment" ]; then
    log_success "Role '${role_name}' is already assigned at scope ${scope}."
    ROLE_ASSIGNMENT_STATUS="already_exists"
    return 0
  fi
  
  log_info "Assigning role '${role_name}' to Service Principal..."
  if az role assignment create --assignee-object-id "$SP_OBJECT_ID" --assignee-principal-type "ServicePrincipal" --role "$role_name" --scope "$scope" --output none 2>/dev/null; then
    log_success "Role '${role_name}' successfully assigned."
    ROLE_ASSIGNMENT_STATUS="created"
    return 0
  else
    log_warn "Failed to assign role '${role_name}' at scope ${scope}."
    if [ "$is_required" = "true" ]; then
      log_error "Core role assignment '${role_name}' is required for onboarding. Aborting setup."
      log_error "Probable causes: Your account lacks 'Owner' or 'User Access Administrator' permissions on the subscription."
      exit 1
    else
      log_warn "Optional role assignment '${role_name}' failed. Skipping."
      ROLE_ASSIGNMENT_STATUS="failed"
      return 0
    fi
  fi
}

assign_required_roles() {
  echo >&2
  log_info "Initiating subscription role assignments..."
  
  # Reader (Required)
  assign_role_if_needed "Reader" "/subscriptions/$SUBSCRIPTION_ID" "true"
  READER_STATUS="$ROLE_ASSIGNMENT_STATUS"
  
  if [ "$MINIMAL" = "true" ]; then
    log_info "Minimal profile active. Optional roles setup skipped."
    return 0
  fi

  # Security Reader (Standard)
  assign_role_if_needed "Security Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
  SECURITY_STATUS="$ROLE_ASSIGNMENT_STATUS"
  
  # Cost Management Reader (Standard)
  assign_role_if_needed "Cost Management Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
  COST_STATUS="$ROLE_ASSIGNMENT_STATUS"

  # Monitoring Reader (Standard)
  assign_role_if_needed "Monitoring Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
  MONITOR_STATUS="$ROLE_ASSIGNMENT_STATUS"

  # Key Vault Reader (Optional metadata scope)
  if [ "$ENABLE_KEYVAULT" = "true" ]; then
    assign_role_if_needed "Key Vault Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
    KEYVAULT_STATUS="$ROLE_ASSIGNMENT_STATUS"
  fi
}

# Print the final credential JSON block and a hidden secret audit JSON block
print_final_json() {
  # Build warnings array
  local warnings_json="[]"
  if [ ${#WARNINGS_LIST[@]} -gt 0 ]; then
    warnings_json=$(printf '%s\n' "${WARNINGS_LIST[@]}" | jq -R . | jq -s .)
  fi

  # Build roles array
  local roles_json
  roles_json=$(jq -n \
    --arg reader_status "$READER_STATUS" \
    --arg security_status "$SECURITY_STATUS" \
    --arg cost_status "$COST_STATUS" \
    --arg monitor_status "$MONITOR_STATUS" \
    --arg keyvault_status "$KEYVAULT_STATUS" \
    --arg scope "/subscriptions/$SUBSCRIPTION_ID" \
    '[
      {name: "Reader", scope: $scope, status: $reader_status},
      {name: "Security Reader", scope: $scope, status: $security_status},
      {name: "Cost Management Reader", scope: $scope, status: $cost_status},
      {name: "Monitoring Reader", scope: $scope, status: $monitor_status},
      {name: "Key Vault Reader", scope: $scope, status: $keyvault_status}
    ]')

  # Fetch Graph Definitions for checking role existence
  local graph_sp_json
  graph_sp_json=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" -o json 2>/dev/null || echo "")

  # Resolve Graph API permissions statuses
  local graph_status_list="[]"
  for perm in "${GRAPH_PERMS[@]}"; do
    local status="skipped"
    if [ "$ENABLE_ENTRA" = "true" ] && [ "$MINIMAL" = "false" ]; then
      local role_id=""
      if [ -n "$graph_sp_json" ]; then
        role_id=$(echo "$graph_sp_json" | jq -r --arg val "$perm" '.appRoles[] | select(.value==$val) | .id' 2>/dev/null || echo "")
      fi
      
      if [ -z "$role_id" ] || [ "$role_id" = "null" ]; then
        status="role_not_found"
      elif [ "$GRAPH_CONSENT_STATUS" = "granted" ]; then
        status="granted"
      elif [ "$GRAPH_CONSENT_STATUS" = "pending_admin_consent" ]; then
        status="pending_admin_consent"
      elif [ "$GRAPH_CONSENT_STATUS" = "failed" ]; then
        status="failed"
      else
        status="configured"
      fi
    fi
    graph_status_list=$(echo "$graph_status_list" | jq --arg name "$perm" --arg stat "$status" '. += [{"name": $name, "status": $stat}]')
  done

  # Determine coverage mapping
  local inv_cov="full"
  local cspm_cov="full"
  local entra_cov="not_enabled"
  
  if [ "$MINIMAL" = "true" ]; then
    inv_cov="partial"
    cspm_cov="partial"
  fi
  if [ "$COST_STATUS" = "failed" ] || [ "$SECURITY_STATUS" = "failed" ] || [ "$MONITOR_STATUS" = "failed" ]; then
    inv_cov="partial"
  fi
  if [ "$SECURITY_STATUS" = "failed" ] || [ "$MONITOR_STATUS" = "failed" ]; then
    cspm_cov="partial"
  fi
  if [ "$ENABLE_ENTRA" = "true" ] && [ "$MINIMAL" = "false" ]; then
    if [ "$GRAPH_CONSENT_STATUS" = "granted" ]; then
      entra_cov="enabled"
    elif [ "$GRAPH_CONSENT_STATUS" = "pending_admin_consent" ]; then
      entra_cov="pending_admin_consent"
    elif [ "$GRAPH_CONSENT_STATUS" = "failed" ]; then
      entra_cov="failed"
    fi
  fi

  local coverage_json
  coverage_json=$(jq -n \
    --arg inv "$inv_cov" \
    --arg cspm "$cspm_cov" \
    --arg entra "$entra_cov" \
    '{azureInventory: $inv, cspmAzure: $cspm, entraIdentity: $entra}')

  local mode_val="default"
  if [ "$MINIMAL" = "true" ]; then
    mode_val="minimal"
  fi

  # Construct final full configuration JSON block
  local final_json
  final_json=$(jq -n \
    --arg tenantId "$TENANT_ID" \
    --arg subscriptionId "$SUBSCRIPTION_ID" \
    --arg subscriptionName "$SUB_NAME" \
    --arg clientId "$CLIENT_ID" \
    --arg clientSecret "$CLIENT_SECRET" \
    --arg displayName "$DISPLAY_NAME" \
    --arg mode "$mode_val" \
    --argjson azureRoles "$roles_json" \
    --argjson graphPermissions "$graph_status_list" \
    --arg consent "$GRAPH_CONSENT_STATUS" \
    --argjson coverage "$coverage_json" \
    --argjson warnings "$warnings_json" \
    '{tenantId: $tenantId, subscriptionId: $subscriptionId, subscriptionName: $subscriptionName, clientId: $clientId, clientSecret: $clientSecret, displayName: $displayName, integrationType: "cloudview", cloudProvider: "azure", mode: $mode, azureRoles: $azureRoles, graphPermissions: $graphPermissions, graphConsentStatus: $consent, coverage: $coverage, warnings: $warnings}')

  # Build rolesAssigned list for redacted JSON
  local roles_assigned="[\"Reader\""
  if [ "$MINIMAL" = "false" ]; then
    if [ "$SECURITY_STATUS" != "failed" ] && [ "$SECURITY_STATUS" != "skipped" ]; then
      roles_assigned="${roles_assigned}, \"Security Reader\""
    fi
    if [ "$COST_STATUS" != "failed" ] && [ "$COST_STATUS" != "skipped" ]; then
      roles_assigned="${roles_assigned}, \"Cost Management Reader\""
    fi
    if [ "$MONITOR_STATUS" != "failed" ] && [ "$MONITOR_STATUS" != "skipped" ]; then
      roles_assigned="${roles_assigned}, \"Monitoring Reader\""
    fi
    if [ "$ENABLE_KEYVAULT" = "true" ] && [ "$KEYVAULT_STATUS" != "failed" ]; then
      roles_assigned="${roles_assigned}, \"Key Vault Reader\""
    fi
  fi
  roles_assigned="${roles_assigned}]"

  # Construct redacted configuration JSON block
  local redacted_json
  redacted_json=$(jq -n \
    --arg tenantId "$TENANT_ID" \
    --arg subscriptionId "$SUBSCRIPTION_ID" \
    --arg subscriptionName "$SUB_NAME" \
    --arg clientId "$CLIENT_ID" \
    --arg displayName "$DISPLAY_NAME" \
    --argjson rolesAssigned "$roles_assigned" \
    '{tenantId: $tenantId, subscriptionId: $subscriptionId, subscriptionName: $subscriptionName, clientId: $clientId, clientSecret: "***hidden***", displayName: $displayName, rolesAssigned: $rolesAssigned}')

  if [ "$JSON_ONLY" = "false" ]; then
    echo >&2
    echo -e "${GREEN}======================================================================" >&2
    echo -e "Setup completed." >&2
    echo >&2
    echo -e "Copy the JSON block below and paste it into the Vulneri CloudView dashboard." >&2
    echo >&2
    echo -e "Important:" >&2
    echo -e "- Store this credential securely." >&2
    echo -e "- The client secret will not be shown again." >&2
    echo -e "- You can revoke this integration anytime by removing the App Registration or its role assignments in Azure." >&2
    echo -e "======================================================================${NC}" >&2
    
    # Standard JSON Block on stdout
    echo "$final_json"
    
    echo >&2
    echo -e "${GREEN}======================================================================" >&2
    echo -e "Audit Summary (Redacted):" >&2
    echo -e "======================================================================${NC}" >&2
    
    # Redacted JSON Block on stdout
    echo "$redacted_json"
  else
    # Output only raw JSON on stdout
    echo "$final_json"
  fi
}

main() {
  parse_args "$@"
  print_header
  check_dependencies
  load_azure_context
  confirm_execution
  find_or_create_app_registration
  ensure_service_principal
  assign_required_roles
  configure_graph_permissions
  create_client_secret
  print_final_json
}

main "$@"
