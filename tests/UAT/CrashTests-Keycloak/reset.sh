#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
project=eare-keycloak-crashtest
created_runtime_env=false
if [[ ! -f .env.runtime ]]; then
  umask 077
  cat > .env.runtime <<'EOF'
KEYCLOAK_DB_PASSWORD=reset-only
KEYCLOAK_ADMIN_PASSWORD=reset-only
EARE_SESSION_SECRET=reset-only
EARE_ADMIN_PASSWORD=reset-only
EARE_KEYCLOAK_CLIENT_SECRET=reset-only
EOF
  created_runtime_env=true
fi
compose=(docker compose --env-file "$PWD/.env.runtime" -p "$project" -f compose.yaml)

"${compose[@]}" down --remove-orphans --volumes
docker volume rm eare-keycloak-crashtest-keycloak-db eare-keycloak-crashtest-eare-data 2>/dev/null || true
if [[ "$created_runtime_env" == true ]]; then
  rm -f .env.runtime
fi
