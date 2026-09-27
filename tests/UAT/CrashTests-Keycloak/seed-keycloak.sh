#!/usr/bin/env bash
set -euo pipefail

container=${KEYCLOAK_CONTAINER:-eare-keycloak}
realm=${KEYCLOAK_REALM:-eare-crashtest}
admin_password=${KEYCLOAK_ADMIN_PASSWORD:?KEYCLOAK_ADMIN_PASSWORD is required}
collector_secret=${EARE_KEYCLOAK_CLIENT_SECRET:?EARE_KEYCLOAK_CLIENT_SECRET is required}
ldap_password=${EARE_LDAP_PASSWORD:?EARE_LDAP_PASSWORD is required}

kc() {
  docker exec "$container" /opt/keycloak/bin/kcadm.sh "$@"
}

for attempt in {1..10}; do
  if docker exec "$container" /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://127.0.0.1:8080 --realm master --user admin --password "$admin_password" >/dev/null; then
    break
  fi
  if [[ "$attempt" == 10 ]]; then
    echo "Keycloak administrator authentication failed" >&2
    exit 1
  fi
  sleep 2
done
if ! kc get "realms/$realm" >/dev/null 2>&1; then
  kc create realms -s "realm=$realm" -s enabled=true -s sslRequired=NONE >/dev/null
fi

if ! kc get components -r "$realm" -q name=ldap --fields id --format csv --noquotes | grep -q .; then
  docker exec -e LDAP_BIND_PASSWORD="$ldap_password" "$container" bash -c '
    /opt/keycloak/bin/kcadm.sh create components -r "$1" \
      -s name=ldap -s providerId=ldap -s providerType=org.keycloak.storage.UserStorageProvider \
      -s '\''config.connectionUrl=["ldap://eare-crashtests-ldap:389"]'\'' \
      -s '\''config.usersDn=["ou=people,dc=example,dc=test"]'\'' \
      -s '\''config.bindDn=["cn=svc-eare,ou=services,dc=example,dc=test"]'\'' \
      -s "config.bindCredential=[\"$LDAP_BIND_PASSWORD\"]" \
      -s '\''config.usernameLDAPAttribute=["uid"]'\'' -s '\''config.rdnLDAPAttribute=["uid"]'\'' \
      -s '\''config.uuidLDAPAttribute=["entryUUID"]'\'' -s '\''config.userObjectClasses=["inetOrgPerson"]'\'' \
      -s '\''config.editMode=["READ_ONLY"]'\'' -s '\''config.importEnabled=["true"]'\'' \
      -s '\''config.syncRegistrations=["false"]'\'' -s '\''config.searchScope=["2"]'\''
  ' bash "$realm" >/dev/null
  component_id=$(kc get components -r "$realm" -q name=ldap --fields id --format csv --noquotes | tail -1)
  kc create "user-storage/$component_id/sync" -r "$realm" -q action=triggerFullSync >/dev/null
fi

for role in employee accountant invoice-read realm-admin-test; do
  kc get "roles/$role" -r "$realm" >/dev/null 2>&1 || kc create roles -r "$realm" -s "name=$role" >/dev/null
done
kc create roles/accountant/composites -r "$realm" -s name=invoice-read >/dev/null 2>&1 || true
kc create roles/realm-admin-test/composites -r "$realm" -s name=accountant >/dev/null 2>&1 || true

client_id() { kc get clients -r "$realm" -q clientId="$1" --fields id --format csv --noquotes | tail -1; }
create_client() {
  local id
  id=$(client_id "$1")
  if [[ -z "$id" ]]; then
    id=$(kc create clients -r "$realm" -s "clientId=$1" -s "name=$2" -s enabled=true -s publicClient=false -i)
  fi
  printf '%s' "$id"
}

crm=$(create_client crm CRM)
erp=$(create_client erp ERP)
collector=$(client_id eare-collector)
if [[ -z "$collector" ]]; then
  collector=$(kc create clients -r "$realm" -s clientId=eare-collector -s name=EARE -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -s "secret=$collector_secret" -i)
fi
backup=$(client_id svc-backup)
if [[ -z "$backup" ]]; then
  backup=$(kc create clients -r "$realm" -s clientId=svc-backup -s name=Backup -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -i)
fi

for spec in "$crm:sales" "$crm:support" "$crm:admin" "$erp:read" "$erp:finance" "$erp:admin"; do
  IFS=: read -r owner role <<<"$spec"
  kc get "clients/$owner/roles/$role" -r "$realm" >/dev/null 2>&1 || kc create "clients/$owner/roles" -r "$realm" -s "name=$role" >/dev/null
done
kc get "clients/$backup/roles/Backup-Operator" -r "$realm" >/dev/null 2>&1 || kc create "clients/$backup/roles" -r "$realm" -s name=Backup-Operator >/dev/null

group_id() { kc get groups -r "$realm" -q search="$1" --fields id --format csv --noquotes | tail -1; }
finance=$(group_id Finance); [[ -n "$finance" ]] || finance=$(kc create groups -r "$realm" -s name=Finance -i)
europe=$(group_id Finance-Europe); [[ -n "$europe" ]] || europe=$(kc create "groups/$finance/children" -r "$realm" -s name=Finance-Europe -i)
france=$(group_id Finance-France); [[ -n "$france" ]] || france=$(kc create "groups/$europe/children" -r "$realm" -s name=Finance-France -i)
sales=$(group_id Sales); [[ -n "$sales" ]] || sales=$(kc create groups -r "$realm" -s name=Sales -i)
support=$(group_id Support); [[ -n "$support" ]] || support=$(kc create groups -r "$realm" -s name=Support -i)

user_id() { kc get users -r "$realm" -q username="$1" --fields id --format csv --noquotes | tail -1; }
assign_group() { local uid; uid=$(user_id "$1"); [[ -n "$uid" ]] && kc put "users/$uid/groups/$2" -r "$realm" >/dev/null 2>&1 || true; }
assign_group alice.martin "$france"
assign_group bruno.leroy "$finance"
assign_group emma.laurent "$sales"
assign_group david.robert "$support"

assign_realm() { local uid; uid=$(user_id "$1"); [[ -n "$uid" ]] && kc create "users/$uid/role-mappings/realm" -r "$realm" -s "name=$2" >/dev/null 2>&1 || true; }
assign_client() { local uid; uid=$(user_id "$1"); [[ -n "$uid" ]] && kc create "users/$uid/role-mappings/clients/$3" -r "$realm" -s "name=$2" >/dev/null 2>&1 || true; }
assign_realm bob.leroy accountant
assign_client alice.martin sales "$crm"
assign_client svc-backup Backup-Operator "$backup"

rm_id=$(client_id realm-management)
collector_user=$(kc get "clients/$collector/service-account-user" -r "$realm" --fields id --format csv --noquotes | tail -1)
for role in view-users query-users view-groups query-groups view-clients view-realm; do
  [[ -n "$collector_user" ]] && kc add-roles -r "$realm" \
    --uusername service-account-eare-collector --cclientid realm-management \
    --rolename "$role" >/dev/null 2>&1 || true
done

echo "Keycloak realm $realm seeded with read-only LDAP federation and EARE clients."
