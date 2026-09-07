#!/usr/bin/env bash
set -euo pipefail

LDAP_URI="${LDAP_URI:-ldap://localhost}"
BASE_DN="${BASE_DN:?BASE_DN is required}"
PROVIDER_NAME="${PROVIDER_NAME:-openldap}"
BIND_DN="${BIND_DN:-}"
SEARCH_SCOPE="${SEARCH_SCOPE:-sub}"
LDAP_FILTER="${LDAP_FILTER:-(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))}"
START_TLS="${START_TLS:-0}"
ALLOW_ANONYMOUS="${ALLOW_ANONYMOUS:-0}"
ALLOW_PARTIAL="${ALLOW_PARTIAL:-0}"
PAGE_SIZE="${PAGE_SIZE:-1000}"
OUTPUT="${1:-openldap-export.zip}"
if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$PWD/$OUTPUT"
fi
COLLECTOR_VERSION="1"
LDIF_ATTRIBUTES=(objectClass entryUUID uid cn mail description member uniqueMember memberUid)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [[ -n "$BIND_DN" && "$LDAP_URI" != ldaps://* && "$START_TLS" != "1" ]]; then
  echo "Authenticated OpenLDAP export requires ldaps:// or START_TLS=1" >&2
  exit 2
fi
if [[ -z "$BIND_DN" && "$ALLOW_ANONYMOUS" != "1" ]]; then
  echo "Anonymous OpenLDAP export requires ALLOW_ANONYMOUS=1" >&2
  exit 2
fi

cmd=(ldapsearch -LLL -H "$LDAP_URI" -b "$BASE_DN" -s "$SEARCH_SCOPE" -E "pr=${PAGE_SIZE}/noprompt")
if [[ "$START_TLS" == "1" ]]; then
  cmd+=(-ZZ)
fi
if [[ -n "$BIND_DN" ]]; then
  cmd+=(-x -D "$BIND_DN" -W)
fi
cmd+=("$LDAP_FILTER" "${LDIF_ATTRIBUTES[@]}")

set +e
"${cmd[@]}" > "$tmp/directory.ldif" 2> "$tmp/ldapsearch.stderr"
ldap_rc=$?
set -e

limited=0
if grep -Eiq 'size limit|sizelimit|time limit|timelimit|administrative limit|truncated' "$tmp/ldapsearch.stderr"; then
  limited=1
fi
collection_errors=0
if [[ "$ldap_rc" -ne 0 || "$limited" -ne 0 ]]; then
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
    msg="$(tr '\n' ' ' < "$tmp/ldapsearch.stderr")"
    echo "directory,$BASE_DN,,ldapsearch,$ldap_rc,${msg//,/;}"
  } > "$tmp/collection-errors.csv"
else
  echo 'ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage' > "$tmp/collection-errors.csv"
fi

if [[ "$collection_errors" -ne 0 && "$ALLOW_PARTIAL" != "1" ]]; then
  echo "OpenLDAP collection failed or was limited. Re-run with ALLOW_PARTIAL=1 to keep a diagnostic ZIP marked completeness: unknown." >&2
  exit 1
fi

(cd "$tmp" && zip -q "$OUTPUT" manifest.yaml directory.ldif collection-errors.csv)
