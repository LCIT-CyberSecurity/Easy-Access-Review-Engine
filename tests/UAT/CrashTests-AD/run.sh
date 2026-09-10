#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ARTIFACTS="${SCRIPT_DIR}/artifacts"

main() {
  mkdir -p "${ARTIFACTS}"
  (
    cd "${REPO_ROOT}"
    python3 -m pytest tests/UAT/CrashTests-AD/crashtests -v --junitxml="${ARTIFACTS}/pytest.xml"
  ) >"${ARTIFACTS}/eare.stdout.log" 2>"${ARTIFACTS}/eare.stderr.log"
}

main "$@"
