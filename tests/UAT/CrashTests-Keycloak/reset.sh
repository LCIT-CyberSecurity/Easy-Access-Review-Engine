#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
project=eare-keycloak-crashtest
compose=(docker compose -p "$project" -f compose.yaml)

"${compose[@]}" down --remove-orphans --volumes
docker volume rm eare-keycloak-crashtest-keycloak-db eare-keycloak-crashtest-eare-data 2>/dev/null || true
