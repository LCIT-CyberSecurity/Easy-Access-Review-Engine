#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
ARTIFACTS="${SCRIPT_DIR}/artifacts"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"

fail() {
  capture
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
  trap 'capture' EXIT INT TERM
  command -v docker >/dev/null 2>&1 || fail "docker is not installed"
  docker version >/dev/null 2>&1 || fail "Docker Engine is not reachable"
  docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not available"
  docker compose -f "${COMPOSE_FILE}" up -d --build --force-recreate
  for _ in 1 2 3 4 5; do
    if [[ "$(docker inspect -f '{{.State.Running}}' eare-crashtests-openldap 2>/dev/null || true)" == "true" ]]; then
      break
    fi
    sleep 1
  done
  [[ "$(docker inspect -f '{{.State.Running}}' eare-crashtests-openldap 2>/dev/null || true)" == "true" ]] || {
    docker logs eare-crashtests-openldap >&2 || true
    fail "OpenLDAP container exited during startup"
  }
  capture
  (
    cd "${REPO_ROOT}"
    pytest tests/UAT/CrashTests-OpenLDAP/crashtests -v --junitxml="${ARTIFACTS}/pytest.xml"
  ) >"${ARTIFACTS}/eare.stdout.log" 2>"${ARTIFACTS}/eare.stderr.log"
}

main "$@"
