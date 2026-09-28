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
EARE_LDAP_PASSWORD=reset-only
EOF
  created_runtime_env=true
fi
compose=(docker compose --env-file "$PWD/.env.runtime" -p "$project" -f compose.yaml)

aurora_webui=$(docker ps -aq --filter name='^eare-aurora-webui$')
if [[ -n "$aurora_webui" ]]; then
  docker compose -f ../../../docker/compose.aurora.yaml down --remove-orphans
  if docker volume inspect eare-aurora-data >/dev/null 2>&1; then
    docker volume rm eare-aurora-data
  fi
fi
docker rm -f eare-keycloak-crashtest-eare-webui-1 2>/dev/null || true
"${compose[@]}" down --remove-orphans --volumes
docker volume rm eare-keycloak-crashtest-keycloak-db eare-keycloak-crashtest-eare-data 2>/dev/null || true
if [[ "$created_runtime_env" == true ]]; then
  rm -f .env.runtime
fi
