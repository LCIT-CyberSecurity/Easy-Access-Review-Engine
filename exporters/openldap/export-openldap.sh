#!/usr/bin/env bash
set -euo pipefail

LDAP_URI="${LDAP_URI:-ldap://localhost}"
BASE_DN="${BASE_DN:?BASE_DN is required}"
BIND_DN="${BIND_DN:-}"
OUTPUT="${1:-openldap-export.zip}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/manifest.yaml" <<EOF
provider: ${PROVIDER_NAME:-openldap}
source_type: openldap
completeness: full
scope: all
EOF

if [[ -n "$BIND_DN" ]]; then
  ldapsearch -LLL -H "$LDAP_URI" -D "$BIND_DN" -W -b "$BASE_DN" > "$tmp/directory.ldif"
else
  ldapsearch -LLL -H "$LDAP_URI" -b "$BASE_DN" > "$tmp/directory.ldif"
fi

(cd "$tmp" && zip -q "$OLDPWD/$OUTPUT" manifest.yaml directory.ldif)
