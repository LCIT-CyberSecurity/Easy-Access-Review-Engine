#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
project=eare-keycloak-crashtest
compose=(docker compose -p "$project" -f compose.yaml)

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
if docker ps --format '{{.Ports}}' | grep -q '127.0.0.1:4173->'; then
  echo "4173 detected; it will not be modified" >&2
fi

"${compose[@]}" up -d --build
echo "Infrastructure is running on http://127.0.0.1:4175."
echo "Seed the realm and LDAP federation with the documented read-only setup, then run the EARE API workflow."
echo "The live scenario is intentionally fail-closed until seed/expected fixtures are installed."
