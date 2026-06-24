#!/usr/bin/env bash
# ==============================================================================
# Vulneri Security - Azure Onboarding Setup Script for CloudView
# ==============================================================================
set -euo pipefail

# Helper function to print messages to stderr
log() {
  echo "$@" >&2
}

# 1. Validate dependencies: az and jq.
log "Validating dependencies..."
if ! command -v az &>/dev/null; then
  log "Error: Azure CLI ('az') is not installed or not in PATH."
  exit 1
fi
if ! command -v jq &>/dev/null; then
  log "Error: 'jq' is not installed or not in PATH."
  exit 1
fi

# 2. Get active context: tenantId and subscriptionId.
log "Obtaining active subscription and tenant..."
TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null || true)
SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null || true)

if [ -z "$TENANT_ID" ] || [ -z "$SUBSCRIPTION_ID" ]; then
  log "Error: Could not retrieve active Azure account details. Please login with 'az login'."
  exit 1
fi

# 3. Create or reuse App Registration.
APP_NAME="Vulneri-CloudView-Integration"
log "Checking App Registration..."
APP_JSON=$(az ad app list --display-name "$APP_NAME" -o json 2>/dev/null || echo "[]")
APP_COUNT=$(echo "$APP_JSON" | jq 'length')

if [ "$APP_COUNT" -gt 0 ]; then
  CLIENT_ID=$(echo "$APP_JSON" | jq -r '.[0].appId')
  if [ "$APP_COUNT" -gt 1 ]; then
    log "Warning: Multiple App Registrations found with display name '$APP_NAME'. Reusing the first one (Client ID: $CLIENT_ID)."
  else
    log "Reusing existing App Registration: $APP_NAME ($CLIENT_ID)"
  fi
else
  log "Creating new App Registration: $APP_NAME"
  NEW_APP=$(az ad app create --display-name "$APP_NAME" -o json 2>/dev/null || true)
  if [ -z "$NEW_APP" ]; then
    log "Error: Failed to create App Registration."
    exit 1
  fi
  CLIENT_ID=$(echo "$NEW_APP" | jq -r '.appId')
fi

# 4. Guarantee Service Principal exists.
log "Verifying Service Principal..."
SP_OBJECT_ID=""
for i in {1..5}; do
  SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)
  if [ -n "$SP_OBJECT_ID" ]; then
    break
  fi
  sleep 2
done

if [ -z "$SP_OBJECT_ID" ]; then
  log "Creating Service Principal..."
  NEW_SP=$(az ad sp create --id "$CLIENT_ID" -o json 2>/dev/null || true)
  SP_OBJECT_ID=$(echo "$NEW_SP" | jq -r '.id' 2>/dev/null || true)
  if [ -z "$SP_OBJECT_ID" ] || [ "$SP_OBJECT_ID" = "null" ]; then
    SP_OBJECT_ID=$(az ad sp show --id "$CLIENT_ID" --query id -o tsv 2>/dev/null || true)
  fi
fi

if [ -z "$SP_OBJECT_ID" ]; then
  log "Error: Failed to verify or create Service Principal for App Registration $CLIENT_ID."
  exit 1
fi

# 5. Generate client secret using --append.
log "Generating new client secret..."
SECRET_JSON=$(az ad app credential reset --id "$CLIENT_ID" --append -o json 2>/dev/null || true)
CLIENT_SECRET=$(echo "$SECRET_JSON" | jq -r '.password' 2>/dev/null || true)

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" = "null" ]; then
  log "Error: Failed to generate client secret."
  exit 1
fi

# Helper function to assign roles with retry
assign_role() {
  local role="$1"
  local scope="$2"
  local required="$3"
  
  log "Checking role assignment '$role' at scope $scope..."
  EXISTING=$(az role assignment list --scope "$scope" --query "[?principalId=='$SP_OBJECT_ID' && roleDefinitionName=='$role'].id" -o tsv 2>/dev/null || true)
  
  if [ -n "$EXISTING" ]; then
    log "Role '$role' already assigned."
    return 0
  fi
  
  log "Assigning role '$role'..."
  local attempts=5
  local sleep_time=3
  for ((i=1; i<=attempts; i++)); do
    if az role assignment create --assignee-object-id "$SP_OBJECT_ID" --assignee-principal-type "ServicePrincipal" --role "$role" --scope "$scope" --output none 2>/dev/null; then
      log "Role '$role' assigned successfully."
      return 0
    fi
    log "Warning: Role assignment attempt $i/$attempts failed. Retrying in ${sleep_time}s..."
    sleep $sleep_time
    sleep_time=$((sleep_time + 3))
  done
  
  if [ "$required" = "true" ]; then
    log "Error: Required role '$role' assignment failed. Aborting."
    exit 1
  fi
  
  log "Warning: Optional role '$role' assignment failed at scope $scope. Continuing."
}

# 6. Assign Subscription roles
log "Assigning Subscription roles..."
assign_role "Reader" "/subscriptions/$SUBSCRIPTION_ID" "true"
assign_role "Security Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
assign_role "Cost Management Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
assign_role "Monitoring Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"
assign_role "Key Vault Reader" "/subscriptions/$SUBSCRIPTION_ID" "false"

# 7. Configure Microsoft Graph Application Permissions
GRAPH_PERMS=(
  "Directory.Read.All"
  "User.Read.All"
  "Group.Read.All"
  "GroupMember.Read.All"
  "Application.Read.All"
  "RoleManagement.Read.Directory"
  "Policy.Read.All"
  "UserAuthenticationMethod.Read.All"
  "GroupSettings.Read.All"
  "IdentityRiskEvent.Read.All"
  "IdentityRiskyUser.Read.All"
  "IdentityRiskyServicePrincipal.Read.All"
)

log "Resolving Microsoft Graph permissions..."
GRAPH_SP=$(az ad sp show --id "00000003-0000-0000-c000-000000000000" -o json 2>/dev/null || echo "")
if [ -z "$GRAPH_SP" ]; then
  log "Warning: Failed to fetch Microsoft Graph Service Principal. Skipping Graph permissions."
else
  RESOURCE_ACCESS="[]"
  for perm in "${GRAPH_PERMS[@]}"; do
    ROLE_ID=$(echo "$GRAPH_SP" | jq -r --arg val "$perm" '.appRoles[] | select(.value==$val) | .id' 2>/dev/null || true)
    if [ -n "$ROLE_ID" ] && [ "$ROLE_ID" != "null" ]; then
      RESOURCE_ACCESS=$(echo "$RESOURCE_ACCESS" | jq --arg id "$ROLE_ID" '. += [{"id": $id, "type": "Role"}]')
    else
      log "Warning: Graph role ID not found for: $perm"
    fi
  done
  
  if [ "$RESOURCE_ACCESS" != "[]" ]; then
    EXISTING_RRA=$(az ad app show --id "$CLIENT_ID" --query "requiredResourceAccess" -o json 2>/dev/null || echo "[]")
    MERGED_RRA=$(echo "$EXISTING_RRA" | jq \
      --arg target_resource_id "00000003-0000-0000-c000-000000000000" \
      --argjson graph_access "$RESOURCE_ACCESS" \
      '
      (map(.resourceAppId == $target_resource_id) | index(true)) as $idx
      | if $idx == null then
          . + [{"resourceAppId": $target_resource_id, "resourceAccess": $graph_access}]
        else
          .[$idx].resourceAccess = (.[$idx].resourceAccess + $graph_access | unique_by(.id))
        end
      ')
    
    log "Updating required resource access for Microsoft Graph..."
    if az ad app update --id "$CLIENT_ID" --required-resource-accesses "$MERGED_RRA" &>/dev/null; then
      log "Graph permissions updated successfully."
    else
      log "Warning: Failed to update required resource access for Microsoft Graph."
    fi
  fi
fi

# 8. Try to grant admin consent automatically.
log "Attempting to grant administrator consent automatically..."
sleep 3
if az ad app permission admin-consent --id "$CLIENT_ID" &>/dev/null; then
  log "Administrator consent granted successfully."
else
  log "Warning: Automatic administrator consent failed."
  log "Note: Azure resources inventory and security analysis will still work normally."
  log "However, Entra ID (Active Directory) datasets, MFA, and Conditional Access checks"
  log "may return 403 (Unauthorized) until manual consent is granted."
  log "To grant consent manually, please navigate to the following link in the Azure Portal"
  log "using a Directory Admin account and click 'Grant admin consent for <Directory>':"
  log "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/CallAnAPI/appId/$CLIENT_ID"
fi

# 9. Try to assign Reader role at Root Management Group scope.
log "Attempting to assign Reader role at Root Management Group..."
assign_role "Reader" "/providers/Microsoft.Management/managementGroups/$TENANT_ID" "false"

# 10. Print final JSON only to stdout.
cat <<JSON
{
  "tenantId": "$TENANT_ID",
  "subscriptionId": "$SUBSCRIPTION_ID",
  "clientId": "$CLIENT_ID",
  "clientSecret": "$CLIENT_SECRET"
}
JSON
