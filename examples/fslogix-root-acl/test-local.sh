#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEV_PROVIDER_DIR="${DEV_PROVIDER_DIR:-/tmp/azurefilesacl-dev}"
GO_BIN="${GO_BIN:-go}"

if ! command -v "${GO_BIN}" >/dev/null 2>&1; then
  if [[ -x /tmp/go/bin/go ]]; then
    GO_BIN="/tmp/go/bin/go"
  else
    echo "Unable to find Go. Set GO_BIN to a Go binary path." >&2
    exit 1
  fi
fi

mkdir -p "${DEV_PROVIDER_DIR}"
GOTOOLCHAIN=auto "${GO_BIN}" -C "${PROVIDER_ROOT}" build -o "${DEV_PROVIDER_DIR}/terraform-provider-azurefilesacl" .

export TF_CLI_CONFIG_FILE="${SCRIPT_DIR}/dev.tfrc"

get_storage_account_key() {
  local storage_account_id
  local storage_account_name
  local storage_account_resource_group_name

  storage_account_id="$(
    terraform -chdir="${SCRIPT_DIR}" console <<'EOF' | tr -d '"'
var.storage_account_resource_id
EOF
  )"
  read -r storage_account_name storage_account_resource_group_name <<<"$(
    az resource show \
      --ids "${storage_account_id}" \
      --query '[name, resourceGroup]' \
      -o tsv
  )"

  az storage account keys list \
    --resource-group "${storage_account_resource_group_name}" \
    --account-name "${storage_account_name}" \
    --query '[0].value' \
    -o tsv
}

apply_with_account_key() {
  local account_key

  account_key="$(get_storage_account_key)"

  terraform -chdir="${SCRIPT_DIR}" apply \
    -var='auth_method=account_key' \
    -var="account_key=${account_key}" \
    "$@"
}

destroy_with_account_key() {
  local account_key

  account_key="$(get_storage_account_key)"

  terraform -chdir="${SCRIPT_DIR}" destroy \
    -var='auth_method=account_key' \
    -var="account_key=${account_key}" \
    "$@"
}

command="${1:-validate}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "${command}" in
  validate)
    terraform -chdir="${SCRIPT_DIR}" validate "$@"
    ;;
  plan)
    account_key="$(get_storage_account_key)"
    terraform -chdir="${SCRIPT_DIR}" plan \
      -input=false \
      -lock=false \
      -var='auth_method=account_key' \
      -var="account_key=${account_key}" \
      "$@"
    ;;
  apply)
    apply_with_account_key "$@"
    ;;
  apply-account-key)
    apply_with_account_key "$@"
    ;;
  destroy)
    destroy_with_account_key "$@"
    ;;
  *)
    echo "Usage: $0 [validate|plan|apply|apply-account-key|destroy]" >&2
    exit 1
    ;;
esac
