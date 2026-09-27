#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
project=eare-keycloak-crashtest
compose=(docker compose -p "$project" -f compose.yaml)
api_url=${EARE_URL:-http://127.0.0.1:4175}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker network inspect web_default >/dev/null 2>&1 || { echo "existing OpenLDAP network web_default is required" >&2; exit 1; }
docker inspect eare-crashtests-ldap >/dev/null 2>&1 || { echo "existing OpenLDAP container is required" >&2; exit 1; }

before_4173=$(docker ps --format '{{.Names}} {{.Ports}}' | grep '4173->' || true)
test -n "$before_4173"
./reset.sh

umask 077
ldap_password=$(sed -n 's/^EARE_LDAP_PASSWORD=//p' /home/cdev/crashtests-ldap-idp/api-ldap.env)
test -n "$ldap_password"
cat > .env.runtime <<EOF
KEYCLOAK_DB_PASSWORD=$(openssl rand -hex 24)
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -hex 24)
EARE_ADMIN_PASSWORD=$(openssl rand -hex 24)
EARE_SESSION_SECRET=$(openssl rand -hex 32)
EARE_KEYCLOAK_CLIENT_SECRET=EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK
EOF
set -a
source .env.runtime
set +a
export EARE_LDAP_PASSWORD="$ldap_password"
test -s .env.runtime
compose=(docker compose --env-file "$PWD/.env.runtime" -p "$project" -f compose.yaml)

"${compose[@]}" up -d --build
keycloak_container=$("${compose[@]}" ps -q keycloak)
api_container=$("${compose[@]}" ps -q eare-api)
test -n "$keycloak_container"
test -n "$api_container"
until curl -fsS http://127.0.0.1:8180/realms/master >/dev/null; do sleep 2; done
KEYCLOAK_CONTAINER="$keycloak_container" \
KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD" \
EARE_KEYCLOAK_CLIENT_SECRET="$EARE_KEYCLOAK_CLIENT_SECRET" \
EARE_LDAP_PASSWORD="$EARE_LDAP_PASSWORD" \
./seed-keycloak.sh
until curl -fsS "$api_url/api/health" >/dev/null; do sleep 2; done

cookie=$(mktemp)
trap 'rm -f "$cookie"; rm -f .env.runtime' EXIT
login_payload=$(printf '{"username":"admin","password":"%s"}' "$EARE_ADMIN_PASSWORD")
curl -fsS -c "$cookie" -H 'Content-Type: application/json' -d "$login_payload" "$api_url/api/auth/login" >/dev/null
curl -fsS -b "$cookie" -c "$cookie" -H 'Content-Type: application/json' \
  -d "{\"new_password\":\"$EARE_ADMIN_PASSWORD\"}" \
  "$api_url/api/auth/change-password" >/dev/null

source_payload='{"provider":"keycloak-crashtest","type":"keycloak","connection":{"base_url":"http://keycloak:8080","realm":"eare-crashtest","client_id":"eare-collector"},"credentials":{"client_secret_env":"EARE_KEYCLOAK_CLIENT_SECRET"},"collection":{"users":true,"groups":true,"memberships":true,"clients":true,"realm_roles":true,"client_roles":true,"user_role_mappings":true,"group_role_mappings":true,"composite_roles":true,"service_accounts":true,"page_size":100,"timeout":300,"allow_partial":false,"read_only_account":true}}'
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d "$source_payload" "$api_url/api/system/sources" >/dev/null
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d "$source_payload" "$api_url/api/system/sources/test" > connection-check.json
grep -q '"status":"success"' connection-check.json

docker exec "$api_container" python -m access_review_engine.cli.main \
  --db /data/access-review.db \
  --config /data/connectors/keycloak-crashtest.yaml \
  sync keycloak-crashtest
curl -fsS -b "$cookie" "$api_url/api/snapshots?limit=10" > initial-snapshots.json
grep -q 'keycloak-crashtest' initial-snapshots.json

echo "PASS: Keycloak/EARE infrastructure, source configuration, Test Connection and initial sync"
echo "4173 unchanged: $before_4173"
