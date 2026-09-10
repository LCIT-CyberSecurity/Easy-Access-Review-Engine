#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ARTIFACTS="${SCRIPT_DIR}/artifacts"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"

fail() {
  printf 'CrashTests-OpenLDAP failed: %s\n' "$*" >&2
  exit 1
}

capture() {
  mkdir -p "${ARTIFACTS}"
  docker compose -f "${COMPOSE_FILE}" logs --no-color >"${ARTIFACTS}/docker.log" 2>&1 || true
  docker exec eare-crashtests-openldap slapd -VV >"${ARTIFACTS}/slapd-version.txt" 2>&1 || true
  docker exec eare-crashtests-openldap ldapsearch -Y EXTERNAL -H ldapi:/// -b "" -s base '+' '*' >"${ARTIFACTS}/ldapsearch-rootdse.ldif" 2>&1 || true
}

main() {
  trap 'capture' ERR INT
  command -v docker >/dev/null 2>&1 || fail "docker is not installed"
  docker version >/dev/null 2>&1 || fail "Docker Engine is not reachable"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not available"
  docker compose -f "${COMPOSE_FILE}" up -d --build --force-recreate
  capture
  (
    cd "${REPO_ROOT}"
    python3 -m pytest tests/UAT/CrashTests-OpenLDAP/crashtests -v --junitxml="${ARTIFACTS}/pytest.xml"
  ) >"${ARTIFACTS}/eare.stdout.log" 2>"${ARTIFACTS}/eare.stderr.log"
}

main "$@"
