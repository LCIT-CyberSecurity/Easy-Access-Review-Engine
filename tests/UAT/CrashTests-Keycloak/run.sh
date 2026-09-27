#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
project=eare-keycloak-crashtest
compose=(docker compose -p "$project" -f compose.yaml)
api_url=${EARE_URL:-http://127.0.0.1:4175}
realm=eare-crashtest

json_value() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in sys.argv[2].split("."):
    value = value[int(key)] if isinstance(value, list) else value[key]
print(value)
PY
}

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
initial_snapshot_id=$(json_value initial-snapshots.json 'items.-1.id')
test -n "$initial_snapshot_id"

curl -fsS -b "$cookie" -H 'Content-Type: application/json' \
  -d "{\"name\":\"keycloak-crashtest-golden\",\"display_name\":\"Keycloak CrashTest Golden\",\"snapshot_id\":\"$initial_snapshot_id\"}" \
  "$api_url/api/golden-sources/baseline" > golden.json
golden_version_id=$(json_value golden.json 'version.id')
test -n "$golden_version_id"

kc() { docker exec "$keycloak_container" /opt/keycloak/bin/kcadm.sh "$@"; }
user_id() { kc get users -r "$realm" -q username="$1" --fields id --format csv --noquotes | tail -1; }

chloe=$(user_id chloe.bernard)
bruno=$(user_id bruno.leroy)
finance=$(kc get groups -r "$realm" -q search=Finance --fields id --format csv --noquotes | tail -1)
kc add-roles -r "$realm" --uid "$chloe" --cclientid erp --rolename admin >/dev/null
kc delete "users/$bruno/groups/$finance" -r "$realm" >/dev/null

docker exec "$api_container" python -m access_review_engine.cli.main \
  --db /data/access-review.db \
  --config /data/connectors/keycloak-crashtest.yaml \
  sync keycloak-crashtest
curl -fsS -b "$cookie" "$api_url/api/snapshots?limit=10" > observed-snapshots.json
observed_snapshot_id=$(json_value observed-snapshots.json 'items.-1.id')
test -n "$observed_snapshot_id" && test "$observed_snapshot_id" != "$initial_snapshot_id"

campaign_payload=$(printf '{"name":"keycloak-crashtest-campaign","display_name":"Keycloak CrashTest Campaign","snapshot_id":"%s","golden_source_version_id":"%s","pilot":"admin","scope":{"type":"all"},"allow_unresolved_reviewers":true}' "$observed_snapshot_id" "$golden_version_id")
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d "$campaign_payload" \
  "$api_url/api/campaigns" > campaign.json
campaign_id=$(json_value campaign.json id)
test -n "$campaign_id"
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d '{}' \
  "$api_url/api/campaigns/$campaign_id/open" > campaign-open.json
curl -fsS -b "$cookie" "$api_url/api/campaigns/$campaign_id" > campaign-detail.json

unexpected_id=$(python3 - campaign-detail.json <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8"))["reviews"]:
    if item.get("classification") == "unexpected" and item.get("identity_display_name") == "chloe.bernard":
        print(item["id"])
        break
PY
)
missing_id=$(python3 - campaign-detail.json <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8"))["reviews"]:
    if item.get("classification") == "missing" and item.get("identity_display_name") == "bruno.leroy":
        print(item["id"])
        break
PY
)
expected_id=$(python3 - campaign-detail.json <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8"))["reviews"]:
    if item.get("classification") == "expected_and_observed" and item.get("identity_display_name") == "alice.martin":
        print(item["id"])
        break
PY
)
test -n "$unexpected_id" -a -n "$missing_id" -a -n "$expected_id"
curl -fsS -b "$cookie" -H 'Content-Type: application/json' \
  -d '{"value":"revoke","comment":"Keycloak CrashTest drift"}' \
  "$api_url/api/review-items/$unexpected_id/decision" > revoke.json
curl -fsS -b "$cookie" -H 'Content-Type: application/json' \
  -d '{"value":"approve","comment":"Keycloak CrashTest expected access"}' \
  "$api_url/api/review-items/$expected_id/decision" > approve.json
curl -fsS -b "$cookie" "$api_url/api/reports/$campaign_id/results?limit=100" > report.json
grep -q 'unexpected' report.json
grep -q 'missing' report.json
grep -q 'expected_and_observed' report.json

# Exercise scoped collection handling by temporarily removing only group-read
# permissions from the collector service account, then restore them and prove
# that a subsequent FULL collection still succeeds.
docker exec "$keycloak_container" /opt/keycloak/bin/kcadm.sh remove-roles \
  -r "$realm" --uusername service-account-eare-collector \
  --cclientid realm-management --rolename query-groups --rolename view-groups >/dev/null 2>&1 || true
docker exec "$api_container" sh -c \
  "cp /data/connectors/keycloak-crashtest.yaml /tmp/keycloak-partial.yaml && sed -i 's/allow_partial: false/allow_partial: true/' /tmp/keycloak-partial.yaml"
set +e
docker exec "$api_container" python -m access_review_engine.cli.main \
  --db /data/access-review.db \
  --config /tmp/keycloak-partial.yaml \
  sync keycloak-crashtest >/tmp/keycloak-partial.out 2>&1
partial_status=$?
set -e
docker exec "$keycloak_container" /opt/keycloak/bin/kcadm.sh add-roles \
  -r "$realm" --uusername service-account-eare-collector \
  --cclientid realm-management --rolename query-groups --rolename view-groups >/dev/null 2>&1 || true
test "$partial_status" -eq 0
docker exec "$api_container" python -m access_review_engine.cli.main \
  --db /data/access-review.db \
  --config /data/connectors/keycloak-crashtest.yaml \
  sync keycloak-crashtest >/dev/null

after_4173=$(docker ps --format '{{.Names}} {{.Ports}}' | grep '4173->' || true)
test "$before_4173" = "$after_4173"
if docker exec "$api_container" sh -c \
  'grep -R -I -l EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK /data 2>/dev/null | grep .'; then
  echo "Keycloak secret canary leaked into EARE data" >&2
  exit 1
fi

echo "PASS: Keycloak/EARE infrastructure, source configuration, Test Connection and initial sync"
echo "PASS: Golden Source, drift, second sync, campaign, findings, decisions and reporting"
echo "PASS: scoped collection and restored FULL collection"
echo "PASS: 4173 unchanged and secret canary absent from EARE data"
