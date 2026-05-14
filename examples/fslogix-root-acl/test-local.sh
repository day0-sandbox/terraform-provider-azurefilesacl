#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVIDER_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEV_PROVIDER_DIR="${DEV_PROVIDER_DIR:-/tmp/azacl-dev}"
GO_BIN="${GO_BIN:-go}"
STORAGE_ACCOUNT_RESOURCE_GROUP_NAME="${STORAGE_ACCOUNT_RESOURCE_GROUP_NAME:-rg-avd-fslogix-hybrid}"

if ! command -v "${GO_BIN}" >/dev/null 2>&1; then
  if [[ -x /tmp/go/bin/go ]]; then
    GO_BIN="/tmp/go/bin/go"
  else
    echo "Unable to find Go. Set GO_BIN to a Go binary path." >&2
    exit 1
  fi
fi

mkdir -p "${DEV_PROVIDER_DIR}"
GOTOOLCHAIN=auto "${GO_BIN}" -C "${PROVIDER_ROOT}" build -o "${DEV_PROVIDER_DIR}/terraform-provider-azacl" .

export TF_CLI_CONFIG_FILE="${SCRIPT_DIR}/dev.tfrc"

get_storage_account_key() {
  local storage_account_name

  storage_account_name="$(
    terraform -chdir="${SCRIPT_DIR}" console <<'EOF' | tr -d '"'
var.storage_account_name
EOF
  )"

  az storage account keys list \
    --resource-group "${STORAGE_ACCOUNT_RESOURCE_GROUP_NAME}" \
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
