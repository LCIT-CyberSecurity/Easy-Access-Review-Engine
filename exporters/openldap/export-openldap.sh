#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
if [[ -f "$ENV_FILE" ]]; then
  # The dotenv file supplies defaults; explicit process environment values win.
  declare -A provided_environment=()
  recognized_variables=(AURORA_LDAP_URI AURORA_BASE_DN AURORA_PROVIDER_NAME AURORA_BIND_DN AURORA_LDAP_PASSWORD AURORA_LDAP_PASSWORD_FILE AURORA_LDAP_CA_CERT AURORA_SEARCH_SCOPE AURORA_LDAP_FILTER AURORA_START_TLS AURORA_ALLOW_ANONYMOUS AURORA_ALLOW_PARTIAL AURORA_PAGE_SIZE AURORA_CONNECTION_TIMEOUT_SECONDS AURORA_SEARCH_TIMEOUT_SECONDS AURORA_COMMAND_TIMEOUT_SECONDS AURORA_CHECK_ONLY AURORA_EXTRA_GROUP_ATTRIBUTES AURORA_OUTPUT)
  for variable_name in "${recognized_variables[@]}"; do
    if [[ ${!variable_name+x} ]]; then
      provided_environment["$variable_name"]="${!variable_name}"
    fi
  done
  while IFS= read -r dotenv_line || [[ -n "$dotenv_line" ]]; do
    [[ "$dotenv_line" =~ ^[[:space:]]*$ || "$dotenv_line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$dotenv_line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
      variable_name="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      recognized=0
      for candidate in "${recognized_variables[@]}"; do
        [[ "$variable_name" == "$candidate" ]] && recognized=1 && break
      done
      [[ "$recognized" -eq 1 ]] || continue
      if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value="${value:1:${#value}-2}"
      elif [[ "$value" == \'* ]]; then
        value="${value:1}"
        parsed=""
        while [[ -n "$value" ]]; do
          if [[ "${value:0:4}" == "'\\''" ]]; then
            parsed+="'"
            value="${value:4}"
          elif [[ "${value:0:1}" == "'" ]]; then
            value="${value:1}"
            break
          else
            parsed+="${value:0:1}"
            value="${value:1}"
          fi
        done
        value="$parsed"
      fi
      printf -v "$variable_name" '%s' "$value"
    fi
  done < "$ENV_FILE"
  for variable_name in "${!provided_environment[@]}"; do
    printf -v "$variable_name" '%s' "${provided_environment[$variable_name]}"
  done
  unset provided_environment
fi

AURORA_LDAP_URI="${AURORA_LDAP_URI:-ldap://localhost}"
AURORA_BASE_DN="${AURORA_BASE_DN:?AURORA_BASE_DN is required}"
AURORA_PROVIDER_NAME="${AURORA_PROVIDER_NAME:-openldap}"
AURORA_BIND_DN="${AURORA_BIND_DN:-}"
AURORA_LDAP_PASSWORD="${AURORA_LDAP_PASSWORD:-}"
AURORA_LDAP_PASSWORD_FILE="${AURORA_LDAP_PASSWORD_FILE:-}"
AURORA_LDAP_CA_CERT="${AURORA_LDAP_CA_CERT:-}"
AURORA_SEARCH_SCOPE="${AURORA_SEARCH_SCOPE:-sub}"
AURORA_LDAP_FILTER="${AURORA_LDAP_FILTER:-(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup)(objectClass=pwdPolicy))}"
AURORA_START_TLS="${AURORA_START_TLS:-0}"
AURORA_ALLOW_ANONYMOUS="${AURORA_ALLOW_ANONYMOUS:-0}"
AURORA_ALLOW_PARTIAL="${AURORA_ALLOW_PARTIAL:-0}"
AURORA_PAGE_SIZE="${AURORA_PAGE_SIZE:-1000}"
AURORA_CONNECTION_TIMEOUT_SECONDS="${AURORA_CONNECTION_TIMEOUT_SECONDS:-10}"
AURORA_SEARCH_TIMEOUT_SECONDS="${AURORA_SEARCH_TIMEOUT_SECONDS:-120}"
AURORA_COMMAND_TIMEOUT_SECONDS="${AURORA_COMMAND_TIMEOUT_SECONDS:-180}"
AURORA_CHECK_ONLY="${AURORA_CHECK_ONLY:-0}"
AURORA_EXTRA_GROUP_ATTRIBUTES="${AURORA_EXTRA_GROUP_ATTRIBUTES:-}"
AURORA_OUTPUT="${1:-openldap-export.zip}"
if [[ "$AURORA_OUTPUT" != /* ]]; then
  AURORA_OUTPUT="$PWD/$AURORA_OUTPUT"
fi
COLLECTOR_VERSION="1"
LDIF_ATTRIBUTES=(objectClass entryUUID uid cn mail description owner member uniqueMember memberUid pwdMinLength pwdInHistory pwdMinAge pwdMaxAge pwdMaxFailure pwdFailureCountInterval pwdLockout pwdLockoutDuration pwdMustChange pwdAllowUserChange pwdSafeModify pwdPolicySubentry)

IFS=',' read -r -a configured_extra_attributes <<< "$AURORA_EXTRA_GROUP_ATTRIBUTES"
for attribute in "${configured_extra_attributes[@]}"; do
  [[ -z "$attribute" ]] && continue
  if ! [[ "$attribute" =~ ^[A-Za-z][A-Za-z0-9-]{0,63}$ ]]; then
    echo "Invalid additional OpenLDAP attribute" >&2
    exit 2
  fi
  normalized="${attribute,,}"
  normalized="${normalized//-/}"
  case "$normalized" in
    unicodepwd|supplementalcredentials|userpassword|authpassword|ntpwdhistory|dbcspwd|passwordhash|accesstoken|refreshtoken|clientsecret|apikey|privatekey|credentials|sid|objectsid|objectguid|primarygroupid|distinguishedname|dn|entryuuid|member|uniquemember|memberuid|samaccountname|userprincipalname|uid)
      echo "Forbidden additional OpenLDAP attribute" >&2
      exit 2
      ;;
  esac
  if [[ "$normalized" =~ (password|token|secret|privatekey|credential) ]]; then
    echo "Forbidden additional OpenLDAP attribute" >&2
    exit 2
  fi
  LDIF_ATTRIBUTES+=("$attribute")
done

for value_name in AURORA_PAGE_SIZE AURORA_CONNECTION_TIMEOUT_SECONDS AURORA_SEARCH_TIMEOUT_SECONDS AURORA_COMMAND_TIMEOUT_SECONDS; do
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
  if [[ -n "$AURORA_LDAP_PASSWORD" ]]; then
    printf '%s\n' "$AURORA_LDAP_PASSWORD"
  fi
  if [[ -n "$AURORA_LDAP_PASSWORD_FILE" && -r "$AURORA_LDAP_PASSWORD_FILE" ]]; then
    local file_secret
    file_secret="$(tr -d $'\r\n' < "$AURORA_LDAP_PASSWORD_FILE")"
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

if [[ "$AURORA_LDAP_URI" == ldaps://* && "$AURORA_START_TLS" == "1" ]]; then
  echo "OpenLDAP export cannot combine ldaps:// with AURORA_START_TLS=1" >&2
  exit 2
fi
if [[ -n "$AURORA_BIND_DN" && "$AURORA_LDAP_URI" != ldaps://* && "$AURORA_START_TLS" != "1" ]]; then
  echo "Authenticated OpenLDAP export requires ldaps:// or AURORA_START_TLS=1" >&2
  exit 2
fi
if [[ -z "$AURORA_BIND_DN" && "$AURORA_ALLOW_ANONYMOUS" != "1" ]]; then
  echo "Anonymous OpenLDAP export requires AURORA_ALLOW_ANONYMOUS=1" >&2
  exit 2
fi
if [[ -n "$AURORA_BIND_DN" && -z "$AURORA_LDAP_PASSWORD" && -z "$AURORA_LDAP_PASSWORD_FILE" ]]; then
  echo "Authenticated OpenLDAP export requires AURORA_LDAP_PASSWORD or AURORA_LDAP_PASSWORD_FILE" >&2
  exit 2
fi
export LDAPTLS_REQCERT="demand"
export LDAPTLS_REQSAN="demand"
if [[ -n "$AURORA_LDAP_CA_CERT" ]]; then
  export LDAPTLS_CACERT="$AURORA_LDAP_CA_CERT"
fi

password_file=""
if [[ -n "$AURORA_LDAP_PASSWORD" ]]; then
  password_file="$tmp/ldap-password"
  umask 077
  printf '%s' "$AURORA_LDAP_PASSWORD" > "$password_file"
  umask 022
elif [[ -n "$AURORA_LDAP_PASSWORD_FILE" ]]; then
  password_file="$AURORA_LDAP_PASSWORD_FILE"
fi
export -n AURORA_LDAP_PASSWORD 2>/dev/null || true

cmd=(ldapsearch -LLL -x -H "$AURORA_LDAP_URI" -b "$AURORA_BASE_DN" -s "$AURORA_SEARCH_SCOPE" -o "nettimeout=${AURORA_CONNECTION_TIMEOUT_SECONDS}" -l "$AURORA_SEARCH_TIMEOUT_SECONDS" -E "pr=${AURORA_PAGE_SIZE}/noprompt")
if [[ "$AURORA_START_TLS" == "1" ]]; then
  cmd+=(-ZZ)
fi
if [[ -n "$AURORA_BIND_DN" ]]; then
  cmd+=(-D "$AURORA_BIND_DN" -y "$password_file")
fi
cmd+=("$AURORA_LDAP_FILTER" "${LDIF_ATTRIBUTES[@]}")

runner=()
if command -v timeout >/dev/null 2>&1; then
  runner=(timeout --kill-after=5s "${AURORA_COMMAND_TIMEOUT_SECONDS}s")
fi

if [[ "${AURORA_CHECK_ONLY}" == "1" ]]; then
  check_cmd=(ldapsearch -LLL -x -H "${AURORA_LDAP_URI}" -b "${AURORA_BASE_DN}" -s base -o "nettimeout=${AURORA_CONNECTION_TIMEOUT_SECONDS}" -l "${AURORA_SEARCH_TIMEOUT_SECONDS}")
  if [[ "${AURORA_START_TLS}" == "1" ]]; then check_cmd+=(-ZZ); fi
  if [[ -n "${AURORA_BIND_DN}" ]]; then check_cmd+=(-D "${AURORA_BIND_DN}" -y "${password_file}"); fi
  check_cmd+=("(objectClass=*)" dn)
  set +e
  "${runner[@]}" "${check_cmd[@]}" >/dev/null 2>"${tmp}/ldapsearch.stderr"
  check_rc=$?
  set -e
  redact_file "${tmp}/ldapsearch.stderr"
  if [[ "${check_rc}" -ne 0 ]]; then cat "${tmp}/ldapsearch.stderr" >&2; exit "${check_rc}"; fi
  echo "OpenLDAP check succeeded"
  exit 0
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
provider: $AURORA_PROVIDER_NAME
collector_version: $COLLECTOR_VERSION
base_dn: $AURORA_BASE_DN
ldap_uri_scheme: ${AURORA_LDAP_URI%%://*}
search_scope: $AURORA_SEARCH_SCOPE
filter: $AURORA_LDAP_FILTER
ldapsearch_exit_code: $ldap_rc
limited: $limited
secret_in_authoritative_payload: $secret_in_payload
connection_timeout_seconds: $AURORA_CONNECTION_TIMEOUT_SECONDS
search_timeout_seconds: $AURORA_SEARCH_TIMEOUT_SECONDS
command_timeout_seconds: $AURORA_COMMAND_TIMEOUT_SECONDS
completeness: $completeness
scope:
  type: all
  base_dn: $AURORA_BASE_DN
  search_scope: $AURORA_SEARCH_SCOPE
  filter: $AURORA_LDAP_FILTER
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
      msg="${msg:+$msg }configured connection secret appaurorad in authoritative LDAP payload; export rejected without redacting collected data"
    fi
    echo "directory,$AURORA_BASE_DN,,ldapsearch,$ldap_rc,${msg//,/;}"
  } > "$tmp/collection-errors.csv"
else
  echo 'ObjectType,ObjectIdentifier,ObjectSID,Operation,ErrorCode,ErrorMessage' > "$tmp/collection-errors.csv"
fi

if [[ "$secret_in_payload" -ne 0 ]]; then
  echo "OpenLDAP collection rejected: configured connection secret appaurorad in authoritative LDAP payload. No export ZIP was written." >&2
  exit 1
fi

if [[ "$collection_errors" -ne 0 && "$AURORA_ALLOW_PARTIAL" != "1" ]]; then
  echo "OpenLDAP collection failed or was limited. Re-run with AURORA_ALLOW_PARTIAL=1 to keep a diagnostic ZIP marked completeness: unknown." >&2
  exit 1
fi

(cd "$tmp" && zip -q "$AURORA_OUTPUT" manifest.yaml directory.ldif collection-errors.csv)
