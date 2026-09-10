#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ARTIFACTS="${SCRIPT_DIR}/artifacts"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"

fail() {
  printf 'CrashTests-CRM run failed: %s\n' "$*" >&2
  exit 1
}

capture_diagnostics() {
  mkdir -p "${ARTIFACTS}"
  docker compose -f "${COMPOSE_FILE}" logs --no-color >"${ARTIFACTS}/docker.log" 2>&1 || true
  docker inspect eare-crashtests-crm >"${ARTIFACTS}/container-inspect.json" 2>/dev/null || true
  docker exec eare-crashtests-crm getfacl -R /srv/crm >"${ARTIFACTS}/filesystem-acl.txt" 2>&1 || true
  docker exec eare-crashtests-crm getent passwd >"${ARTIFACTS}/users.txt" 2>&1 || true
  docker exec eare-crashtests-crm getent group >"${ARTIFACTS}/groups.txt" 2>&1 || true
  docker exec eare-crashtests-crm sh -c 'for g in crm-compta crm-sales crm-logistics crm-support crm-admin; do printf "%s:" "$g"; getent group "$g" | cut -d: -f4; done' >"${ARTIFACTS}/role-memberships.txt" 2>&1 || true
}

main() {
  trap 'capture_diagnostics' ERR INT
  command -v docker >/dev/null 2>&1 || fail "docker is not installed"
  docker version >/dev/null 2>&1 || fail "Docker Engine is not reachable"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not available"
  mkdir -p "${ARTIFACTS}"
  docker compose -f "${COMPOSE_FILE}" up -d --build --force-recreate
  state="$(docker inspect -f '{{.State.Status}}' eare-crashtests-crm 2>/dev/null || true)"
  [[ "${state}" == "running" ]] || fail "container is not running; current state: ${state:-unknown}"
  for attempt in $(seq 1 60); do
    if docker exec eare-crashtests-crm test -f /srv/crm/.ready >/dev/null 2>&1; then
      break
    fi
    if [[ "${attempt}" == "60" ]]; then
      capture_diagnostics
      fail "lab did not become ready after ACL/data generation"
    fi
    sleep 1
  done
  capture_diagnostics
  (
    cd "${REPO_ROOT}"
    python3 -m pytest tests/UAT/CrashTests-CRM/crashtests -v --junitxml="${ARTIFACTS}/pytest.xml"
  ) >"${ARTIFACTS}/eare.stdout.log" 2>"${ARTIFACTS}/eare.stderr.log" || {
    printf 'CT-CRM suite failed. Relevant artifacts are in %s\n' "${ARTIFACTS}" >&2
    tail -n 80 "${ARTIFACTS}/eare.stdout.log" >&2 || true
    tail -n 80 "${ARTIFACTS}/eare.stderr.log" >&2 || true
    exit 1
  }
  printf '{"suite":"CrashTests-CRM","status":"passed","artifacts":"tests/UAT/CrashTests-CRM/artifacts"}\n' >"${ARTIFACTS}/summary.json"
  printf 'CrashTests-CRM passed. Artifacts: %s\n' "${ARTIFACTS}"
}

main "$@"
