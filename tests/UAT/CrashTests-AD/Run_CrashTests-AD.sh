#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ARTIFACTS="${SCRIPT_DIR}/artifacts"

main() {
  mkdir -p "${ARTIFACTS}"
  if [[ "${EARE_AD_UAT_EXPORT:-0}" == "1" ]]; then
    command -v pwsh >/dev/null 2>&1 || {
      printf 'pwsh is required when EARE_AD_UAT_EXPORT=1
' >&2
      exit 1
    }
    export_args=(
      -NoProfile
      -File "${SCRIPT_DIR}/powershell/Export-CrashTestsAD.ps1"
      -ProviderName "${EARE_AD_UAT_PROVIDER:-crashtests-ad}"
      -Output "${ARTIFACTS}/ad-export.zip"
    )
    if [[ -n "${EARE_AD_UAT_HOST:-}" ]]; then
      export_args+=(-Server "${EARE_AD_UAT_HOST}")
    fi
    if [[ -n "${EARE_AD_UAT_ALLOW_PARTIAL:-}" ]]; then
      export_args+=(-AllowPartial)
    fi
    pwsh "${export_args[@]}"
  fi
  (
    cd "${REPO_ROOT}"
    python3 -m pytest tests/UAT/CrashTests-AD/crashtests -v --junitxml="${ARTIFACTS}/pytest.xml"
  ) >"${ARTIFACTS}/eare.stdout.log" 2>"${ARTIFACTS}/eare.stderr.log"
}

main "$@"
