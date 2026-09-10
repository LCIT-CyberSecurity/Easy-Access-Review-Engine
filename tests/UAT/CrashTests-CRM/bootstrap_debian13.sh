#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"

fail() {
  printf 'CrashTests-CRM bootstrap failed: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

detect_os() {
  [[ -r /etc/os-release ]] || fail "/etc/os-release is not readable"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "debian" ]] || fail "expected Debian, got ${ID:-unknown}"
  [[ "${VERSION_ID:-}" == "13" ]] || fail "expected Debian 13, got ${VERSION_ID:-unknown}"
}

install_docker_if_missing() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    printf 'Docker and Docker Compose plugin already installed.\n'
    return
  fi
  command -v sudo >/dev/null 2>&1 || fail "sudo is required to install Docker"
  printf 'Installing Docker Engine and Docker Compose plugin for Debian 13.\n'
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo tee /etc/apt/keyrings/docker.asc >/dev/null
    sudo chmod a+r /etc/apt/keyrings/docker.asc
  fi
  if [[ ! -f /etc/apt/sources.list.d/docker.list ]]; then
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable\n' "$(dpkg --print-architecture)" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  fi
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

check_docker() {
  command -v docker >/dev/null 2>&1 || fail "docker is not installed"
  docker version >/dev/null 2>&1 || fail "Docker Engine is not reachable. Start Docker or check user permissions."
  docker compose version >/dev/null 2>&1 || fail "Docker Compose plugin is not available"
}

main() {
  trap 'printf "Bootstrap interrupted or failed near line %s.\n" "$LINENO" >&2' ERR
  detect_os
  need_cmd awk
  need_cmd sed
  need_cmd grep
  install_docker_if_missing
  check_docker
  [[ -f "${COMPOSE_FILE}" ]] || fail "missing compose file: ${COMPOSE_FILE}"
  docker compose -f "${COMPOSE_FILE}" build
  docker compose -f "${COMPOSE_FILE}" up -d --force-recreate
  state="$(docker inspect -f '{{.State.Status}}' eare-crashtests-crm 2>/dev/null || true)"
  [[ "${state}" == "running" ]] || {
    docker compose -f "${COMPOSE_FILE}" logs --no-color crashtests-crm >&2 || true
    fail "container is not running; current state: ${state:-unknown}"
  }
  printf '\nCrashTests-CRM lab is ready.\n'
  printf 'Run the UAT suite with:\n'
  printf '  tests/UAT/CrashTests-CRM/run.sh\n'
  printf 'Or run pytest directly with:\n'
  printf '  python3 -m pytest tests/UAT/CrashTests-CRM/crashtests -v\n'
}

main "$@"
