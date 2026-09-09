#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

LDAP_URI="${LDAP_URI:-ldap://localhost}"
BASE_DN="${BASE_DN:?BASE_DN is required}"
PROVIDER_NAME="${PROVIDER_NAME:-openldap}"
BIND_DN="${BIND_DN:-}"
LDAP_PASSWORD="${LDAP_PASSWORD:-}"
LDAP_PASSWORD_FILE="${LDAP_PASSWORD_FILE:-}"
LDAP_CA_CERT="${LDAP_CA_CERT:-}"
SEARCH_SCOPE="${SEARCH_SCOPE:-sub}"
LDAP_FILTER="${LDAP_FILTER:-(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))}"
START_TLS="${START_TLS:-0}"
ALLOW_ANONYMOUS="${ALLOW_ANONYMOUS:-0}"
ALLOW_PARTIAL="${ALLOW_PARTIAL:-0}"
PAGE_SIZE="${PAGE_SIZE:-1000}"
CONNECTION_TIMEOUT_SECONDS="${CONNECTION_TIMEOUT_SECONDS:-10}"
SEARCH_TIMEOUT_SECONDS="${SEARCH_TIMEOUT_SECONDS:-120}"
COMMAND_TIMEOUT_SECONDS="${COMMAND_TIMEOUT_SECONDS:-180}"
OUTPUT="${1:-openldap-export.zip}"
if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$PWD/$OUTPUT"
fi
COLLECTOR_VERSION="1"
LDIF_ATTRIBUTES=(objectClass entryUUID uid cn mail description member uniqueMember memberUid)

for value_name in PAGE_SIZE CONNECTION_TIMEOUT_SECONDS SEARCH_TIMEOUT_SECONDS COMMAND_TIMEOUT_SECONDS; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$value_name must be a positive integer" >&2
    exit 2
  fi
  if [[ "$value" -eq 0 ]]; then
    echo "$value_name must be greater than zero" >&2
    exit 2
  fi
done

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

redact_literal() {
  local text="$1"
  local secret="$2"
  local result=""
  if [[ -z "$secret" ]]; then
    printf '%s' "$text"
    return
  fi
  while [[ "$text" == *"$secret"* ]]; do
    result+="${text%%"$secret"*}[REDACTED]"
    text="${text#*"$secret"}"
  done
  printf '%s%s' "$result" "$text"
}

configured_secrets() {
  if [[ -n "$LDAP_PASSWORD" ]]; then
    printf '%s\n' "$LDAP_PASSWORD"
  fi
  if [[ -n "$LDAP_PASSWORD_FILE" && -r "$LDAP_PASSWORD_FILE" ]]; then
    local file_secret
    file_secret="$(tr -d $'\r\n' < "$LDAP_PASSWORD_FILE")"
    if [[ -n "$file_secret" ]]; then
      printf '%s\n' "$file_secret"
    fi
  fi
}

redact_text() {
  local text="$1"
  local secret
  while IFS= read -r secret; do
    text="$(redact_literal "$text" "$secret")"
  done < <(configured_secrets)
  printf '%s' "$text"
}

redact_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    return
  fi
  local content
  content="$(cat "$file")"
  redact_text "$content" > "$file"
}

payload_contains_configured_secret() {
  local file="$1"
  local secret
  while IFS= read -r secret; do
    if grep -Fq -- "$secret" "$file"; then
      return 0
    fi
  done < <(configured_secrets)
  return 1
}

if [[ "$LDAP_URI" == ldaps://* && "$START_TLS" == "1" ]]; then
  echo "OpenLDAP export cannot combine ldaps:// with START_TLS=1" >&2
  exit 2
fi
if [[ -n "$BIND_DN" && "$LDAP_URI" != ldaps://* && "$START_TLS" != "1" ]]; then
  echo "Authenticated OpenLDAP export requires ldaps:// or START_TLS=1" >&2
  exit 2
fi
if [[ -z "$BIND_DN" && "$ALLOW_ANONYMOUS" != "1" ]]; then
  echo "Anonymous OpenLDAP export requires ALLOW_ANONYMOUS=1" >&2
  exit 2
fi
if [[ -n "$BIND_DN" && -z "$LDAP_PASSWORD" && -z "$LDAP_PASSWORD_FILE" ]]; then
  echo "Authenticated OpenLDAP export requires LDAP_PASSWORD or LDAP_PASSWORD_FILE" >&2
  exit 2
fi
export LDAPTLS_REQCERT="demand"
export LDAPTLS_REQSAN="demand"
if [[ -n "$LDAP_CA_CERT" ]]; then
  export LDAPTLS_CACERT="$LDAP_CA_CERT"
fi

password_file=""
if [[ -n "$LDAP_PASSWORD" ]]; then
  password_file="$tmp/ldap-password"
  umask 077
  printf '%s' "$LDAP_PASSWORD" > "$password_file"
  umask 022
elif [[ -n "$LDAP_PASSWORD_FILE" ]]; then
  password_file="$LDAP_PASSWORD_FILE"
fi
export -n LDAP_PASSWORD 2>/dev/null || true

cmd=(ldapsearch -LLL -H "$LDAP_URI" -b "$BASE_DN" -s "$SEARCH_SCOPE" -o "nettimeout=${CONNECTION_TIMEOUT_SECONDS}" -l "$SEARCH_TIMEOUT_SECONDS" -E "pr=${PAGE_SIZE}/noprompt")
if [[ "$START_TLS" == "1" ]]; then
  cmd+=(-ZZ)
fi
if [[ -n "$BIND_DN" ]]; then
  cmd+=(-x -D "$BIND_DN" -y "$password_file")
fi
cmd+=("$LDAP_FILTER" "${LDIF_ATTRIBUTES[@]}")

runner=()
if command -v timeout >/dev/null 2>&1; then
  runner=(timeout --kill-after=5s "${COMMAND_TIMEOUT_SECONDS}s")
fi

set +e
"${runner[@]}" "${cmd[@]}" > "$tmp/directory.ldif" 2> "$tmp/ldapsearch.stderr"
ldap_rc=$?
set -e

redact_file "$tmp/ldapsearch.stderr"

secret_in_payload=0
if payload_contains_configured_secret "$tmp/directory.ldif"; then
  secret_in_payload=1
fi

limited=0
if grep -Eiq 'size limit|sizelimit|time limit|timelimit|administrative limit|truncated' "$tmp/ldapsearch.stderr"; then
  limited=1
fi
collection_errors=0
if [[ "$ldap_rc" -ne 0 || "$limited" -ne 0 || "$secret_in_payload" -ne 0 ]]; then
  collection_errors=1
fi
completeness="full"
if [[ "$collection_errors" -ne 0 ]]; then
  completeness="unknown"
fi

cat > "$tmp/manifest.yaml" <<EOF
schema_version: 1
source_type: openldap
provider: $PROVIDER_NAME
collector_version: $COLLECTOR_VERSION
base_dn: $BASE_DN
ldap_uri_scheme: ${LDAP_URI%%://*}
search_scope: $SEARCH_SCOPE
filter: $LDAP_FILTER
ldapsearch_exit_code: $ldap_rc
limited: $limited
secret_in_authoritative_payload: $secret_in_payload
connection_timeout_seconds: $CONNECTION_TIMEOUT_SECONDS
search_timeout_seconds: $SEARCH_TIMEOUT_SECONDS
command_timeout_seconds: $COMMAND_TIMEOUT_SECONDS
completeness: $completeness
scope:
  type: all
  base_dn: $BASE_DN
  search_scope: $SEARCH_SCOPE
  filter: $LDAP_FILTER
  completeness: $completeness
statistics:
  collection_errors: $collection_errors
EOF

if [[ "$collection_errors" -ne 0 ]]; then
  {
    echo 'ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage'
    msg="$(tr '
' ' ' < "$tmp/ldapsearch.stderr")"
    msg="$(redact_text "$msg")"
    if [[ "$secret_in_payload" -ne 0 ]]; then
      msg="${msg:+$msg }configured connection secret appeared in authoritative LDAP payload; export rejected without redacting collected data"
    fi
    echo "directory,$BASE_DN,,ldapsearch,$ldap_rc,${msg//,/;}"
  } > "$tmp/collection-errors.csv"
else
  echo 'ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage' > "$tmp/collection-errors.csv"
fi

if [[ "$secret_in_payload" -ne 0 ]]; then
  echo "OpenLDAP collection rejected: configured connection secret appeared in authoritative LDAP payload. No export ZIP was written." >&2
  exit 1
fi

if [[ "$collection_errors" -ne 0 && "$ALLOW_PARTIAL" != "1" ]]; then
  echo "OpenLDAP collection failed or was limited. Re-run with ALLOW_PARTIAL=1 to keep a diagnostic ZIP marked completeness: unknown." >&2
  exit 1
fi

(cd "$tmp" && zip -q "$OUTPUT" manifest.yaml directory.ldif collection-errors.csv)
