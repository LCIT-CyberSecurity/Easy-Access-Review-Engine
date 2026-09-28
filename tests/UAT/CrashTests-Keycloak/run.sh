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

assert_latest_import() {
  local file=$1 expected=$2
  python3 - "$file" "$expected" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
items = payload.get("items", [])
if not items:
    raise SystemExit("no import record returned")
latest = max(items, key=lambda item: item.get("completed_at", ""))
if latest.get("status") != "completed":
    raise SystemExit(f"latest import is not completed: {latest.get('status')}")
if latest.get("completeness") != expected:
    raise SystemExit(
        f"latest import completeness is {latest.get('completeness')!r}, expected {expected!r}"
    )
PY
}

assert_effective_roles() {
  local file=$1 expected=$2
  python3 - "$file" "$expected" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
expected = set(sys.argv[2].split(",")) if sys.argv[2] else set()
observed = {
    str(item.get("access_display_name") or item.get("access_name"))
    for item in payload.get("effective_accesses", [])
}
for role in expected:
    if not any(role.casefold() in value.casefold() for value in observed):
        raise SystemExit(f"expected effective role {role!r} not found in {sorted(observed)!r}")
PY
}

assert_effective_roles_absent() {
  local file=$1 forbidden=$2
  python3 - "$file" "$forbidden" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
forbidden = set(sys.argv[2].split(",")) if sys.argv[2] else set()
observed = {
    str(item.get("access_display_name") or item.get("access_name"))
    for item in payload.get("effective_accesses", [])
}
for role in forbidden:
    if any(role.casefold() in value.casefold() for value in observed):
        raise SystemExit(f"forbidden effective role {role!r} remains in {sorted(observed)!r}")
PY
}

assert_scoped_safety() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

def latest(path):
    payload = json.load(open(path, encoding="utf-8"))
    return max(payload.get("items", []), key=lambda item: item.get("created_at", ""))

baseline = latest(sys.argv[1])
scoped = latest(sys.argv[2])
scoped_identities = {row["identifier"]: row for row in scoped["identities"]}
for identifier in ("alice", "bob", "service-account-svc-backup"):
    row = scoped_identities.get(identifier)
    if row is None or row.get("status") == "deleted":
        raise SystemExit(f"baseline identity was deleted or lost during scoped import: {identifier}")

for access_name in (
    "group:",
    "accountant",
    "invoice-read",
    "Backup-Operator",
):
    baseline_names = {
        row["name"] for row in baseline["accesses"]
        if access_name.casefold() in str(row.get("display_name") or row.get("name")).casefold()
    }
    scoped_names = {row["name"] for row in scoped["accesses"]}
    if not baseline_names.issubset(scoped_names):
        raise SystemExit(f"baseline access disappeared during scoped import: {access_name}")

def assignment_key(row):
    return (
        row.get("provider"),
        row.get("access_name"),
        row.get("identity_provider"),
        row.get("identity_identifier"),
    )

def relation_key(row):
    return (
        row.get("parent_provider"),
        row.get("parent_access_name"),
        row.get("child_provider"),
        row.get("child_access_name"),
    )

baseline_assignments = {assignment_key(row) for row in baseline["access_assignments"]}
scoped_assignments = {assignment_key(row) for row in scoped["access_assignments"]}
if not baseline_assignments.issubset(scoped_assignments):
    raise SystemExit("a baseline assignment disappeared during scoped import")
baseline_relations = {relation_key(row) for row in baseline["access_relations"]}
scoped_relations = {relation_key(row) for row in scoped["access_relations"]}
if not baseline_relations.issubset(scoped_relations):
    raise SystemExit("a baseline relation disappeared during scoped import")

if any(row.get("status") == "deleted" for row in scoped["identities"]):
    raise SystemExit("scoped import created a deleted identity")
PY
}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

before_4173=$(docker ps --format '{{.Names}} {{.Ports}}' | grep '4173->' || true)
rm -f .env.runtime
./reset.sh

umask 077
cat > .env.runtime <<EOF
KEYCLOAK_DB_PASSWORD=$(openssl rand -hex 24)
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -hex 24)
EARE_ADMIN_PASSWORD=$(openssl rand -hex 24)
EARE_SESSION_SECRET=$(openssl rand -hex 32)
EARE_KEYCLOAK_CLIENT_SECRET=EARE_KEYCLOAK_SECRET_CANARY_DO_NOT_LEAK
EARE_LDAP_PASSWORD=$(openssl rand -hex 24)
EOF
set -a
source .env.runtime
set +a
test -s .env.runtime
compose=(docker compose --env-file "$PWD/.env.runtime" -p "$project" -f compose.yaml)

"${compose[@]}" up -d --build
keycloak_container=$("${compose[@]}" ps -q keycloak)
api_container=$("${compose[@]}" ps -q eare-api)
ldap_container=$("${compose[@]}" ps -q openldap)
test -n "$keycloak_container"
test -n "$api_container"
test -n "$ldap_container"
docker exec -i "$ldap_container" ldapadd -x -H ldap://127.0.0.1:389 \
  -D cn=admin,dc=eare,dc=test -w "$EARE_LDAP_PASSWORD" \
  -f /dev/stdin < seed/openldap/custom/seed.ldif >/dev/null
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

start_sync() {
  local response job_id status
  response=$(curl -fsS -b "$cookie" -X POST "$api_url/api/sources/keycloak-crashtest/sync")
  printf '%s' "$response" > sync-start.json
  job_id=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$response")
  for _ in $(seq 1 90); do
    curl -fsS -b "$cookie" "$api_url/api/jobs/$job_id" > sync-job.json
    status=$(json_value sync-job.json status)
    case "$status" in
      SUCCEEDED) sync_snapshot_id=$(json_value sync-job.json result.snapshot_id); return 0 ;;
      FAILED) cat sync-job.json >&2; return 1 ;;
    esac
    sleep 2
  done
  echo "sync job timed out" >&2
  return 1
}

start_sync
curl -fsS -b "$cookie" "$api_url/api/snapshots?limit=10" > initial-snapshots.json
curl -fsS -b "$cookie" "$api_url/api/imports?limit=100" > initial-imports.json
assert_latest_import initial-imports.json full
curl -fsS -b "$cookie" "$api_url/api/identities/bob/accesses" > baseline-bob-effective.json
assert_effective_roles baseline-bob-effective.json "accountant,invoice-read"
initial_snapshot_id="$sync_snapshot_id"
test -n "$initial_snapshot_id"

curl -fsS -b "$cookie" -H 'Content-Type: application/json' \
  -d "{\"name\":\"keycloak-crashtest-golden\",\"display_name\":\"Keycloak CrashTest Golden\",\"snapshot_id\":\"$initial_snapshot_id\"}" \
  "$api_url/api/golden-sources/baseline" > golden.json
golden_version_id=$(json_value golden.json 'version.id')
test -n "$golden_version_id"

kc() { docker exec "$keycloak_container" /opt/keycloak/bin/kcadm.sh "$@"; }
user_id() { kc get users -r "$realm" -q username="$1" --fields id --format csv --noquotes | tail -1; }
client_id() { kc get clients -r "$realm" -q clientId="$1" --fields id --format csv --noquotes | tail -1; }

charlie=$(user_id charlie)
bob=$(user_id bob)
erp=$(client_id erp)
erp_admin_role=$(kc get "clients/$erp/roles/admin" -r "$realm" --fields id --format csv --noquotes | tail -1)
finance=$(kc get groups -r "$realm" -q search=Finance --fields id --format csv --noquotes | tail -1)
finance_access="group:${finance}:member"
kc add-roles -r "$realm" --uid "$charlie" --cid "$erp" --roleid "$erp_admin_role" >/dev/null
kc delete "users/$bob/groups/$finance" -r "$realm" >/dev/null

start_sync
curl -fsS -b "$cookie" "$api_url/api/snapshots?limit=10" > observed-snapshots.json
curl -fsS -b "$cookie" "$api_url/api/imports?limit=100" > observed-imports.json
assert_latest_import observed-imports.json full
curl -fsS -b "$cookie" "$api_url/api/identities/bob/accesses" > drift-bob-effective.json
assert_effective_roles_absent drift-bob-effective.json "accountant,invoice-read"
observed_snapshot_id="$sync_snapshot_id"
test -n "$observed_snapshot_id" && test "$observed_snapshot_id" != "$initial_snapshot_id"

campaign_payload=$(printf '{"name":"keycloak-crashtest-campaign","display_name":"Keycloak CrashTest Campaign","snapshot_id":"%s","golden_source_version_id":"%s","pilot":"admin","scope":{"type":"all"},"allow_unresolved_reviewers":true}' "$observed_snapshot_id" "$golden_version_id")
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d "$campaign_payload" \
  "$api_url/api/campaigns" > campaign.json
campaign_id=$(json_value campaign.json id)
test -n "$campaign_id"
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d '{}' \
  "$api_url/api/campaigns/$campaign_id/open" > campaign-open.json
curl -fsS -b "$cookie" "$api_url/api/campaigns/$campaign_id" > campaign-detail.json

unexpected_id=$(python3 - campaign-detail.json "$erp_admin_role" <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8"))["reviews"]:
    if item.get("classification") == "unexpected" and item.get("identity_identifier") == "charlie" and item.get("access_name", "").endswith(sys.argv[2]):
        print(item["id"])
        break
PY
)
missing_id=$(python3 - campaign-detail.json "$finance_access" <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8"))["reviews"]:
    if item.get("classification") == "missing" and item.get("identity_identifier") == "bob" and item.get("access_name") == sys.argv[2]:
        print(item["id"])
        break
PY
)
expected_id=$(python3 - campaign-detail.json <<'PY'
import json
import sys
for item in json.load(open(sys.argv[1], encoding="utf-8"))["reviews"]:
    if item.get("classification") == "expected_and_observed" and item.get("identity_identifier") == "alice" and item.get("access_name", "").startswith("client:"):
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

# Exercise scoped collection handling by temporarily removing only user-read
# permissions from the collector service account.
realm_management=$(client_id realm-management)
collector_user=$(user_id service-account-eare-collector)
kc remove-roles -r "$realm" --uid "$collector_user" --cclientid realm-management \
  --rolename query-users --rolename view-users >/dev/null
mapping_after_remove=$(kc get "users/$collector_user/role-mappings/clients/$realm_management" -r "$realm" --format json)
! grep -q 'query-users' <<<"$mapping_after_remove"
partial_payload=$(python3 -c 'import json,sys; value=json.load(sys.stdin); value["collection"]["allow_partial"]=True; print(json.dumps(value,separators=(",",":")))' <<<"$source_payload")
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d "$partial_payload" \
  "$api_url/api/system/sources" >/dev/null
start_sync
curl -fsS -b "$cookie" "$api_url/api/snapshots?limit=10" > partial-snapshots.json
curl -fsS -b "$cookie" "$api_url/api/imports?limit=100" > partial-imports.json
assert_latest_import partial-imports.json scoped
assert_scoped_safety observed-snapshots.json partial-snapshots.json
curl -fsS -b "$cookie" "$api_url/api/identities/bob/accesses" > partial-bob-effective.json
assert_effective_roles_absent partial-bob-effective.json "accountant,invoice-read"

python3 - partial-imports.json <<'PY'
import json
import sys
latest = max(json.load(open(sys.argv[1], encoding="utf-8"))["items"], key=lambda item:item.get("completed_at", ""))
if latest["completeness"] != "scoped":
    raise SystemExit("partial import was not scoped")
if not latest.get("scope", {}).get("collection_errors"):
    raise SystemExit("partial import did not expose collection_errors")
PY

kc add-roles -r "$realm" --uid "$collector_user" --cclientid realm-management \
  --rolename query-users --rolename view-users >/dev/null
mapping_after_restore=$(kc get "users/$collector_user/role-mappings/clients/$realm_management" -r "$realm" --format json)
grep -q 'query-users' <<<"$mapping_after_restore"
curl -fsS -b "$cookie" -H 'Content-Type: application/json' -d "$source_payload" \
  "$api_url/api/system/sources" >/dev/null
start_sync
curl -fsS -b "$cookie" "$api_url/api/snapshots?limit=10" > restored-snapshots.json
curl -fsS -b "$cookie" "$api_url/api/imports?limit=100" > restored-imports.json
assert_latest_import restored-imports.json full
python3 - restored-imports.json <<'PY'
import json
import sys
latest = max(json.load(open(sys.argv[1], encoding="utf-8"))["items"], key=lambda item:item.get("completed_at", ""))
if latest["completeness"] != "full":
    raise SystemExit("restored import was not full")
PY

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
