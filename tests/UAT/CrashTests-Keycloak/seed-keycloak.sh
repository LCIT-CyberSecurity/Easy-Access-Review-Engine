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
      -s '\''config.connectionUrl=["ldap://openldap:389"]'\'' \
      -s '\''config.usersDn=["ou=people,dc=eare,dc=test"]'\'' \
      -s '\''config.bindDn=["cn=admin,dc=eare,dc=test"]'\'' \
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
kc add-roles -r "$realm" --rname accountant --rolename invoice-read >/dev/null
kc add-roles -r "$realm" --rname realm-admin-test --rolename accountant >/dev/null

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
kc update "clients/$crm" -r "$realm" -s authorizationServicesEnabled=false >/dev/null
kc update "clients/$erp" -r "$realm" -s authorizationServicesEnabled=true >/dev/null
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
erp_accountant=$(kc get "clients/$erp/roles/ERP-Accountant" -r "$realm" --fields id --format csv --noquotes | tail -1)
if [[ -z "$erp_accountant" ]]; then
  erp_accountant=$(kc create "clients/$erp/roles" -r "$realm" -s name=ERP-Accountant -i)
fi

authz_resource() {
  local client=$1 name=$2 id
  id=$(kc get "clients/$client/authz/resource-server/resource" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  [[ -n "$id" ]] || id=$(kc create "clients/$client/authz/resource-server/resource" -r "$realm" -s "name=$name" -i)
  printf '%s' "$id"
}
authz_scope() {
  local client=$1 name=$2 id
  id=$(kc get "clients/$client/authz/resource-server/scope" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  [[ -n "$id" ]] || id=$(kc create "clients/$client/authz/resource-server/scope" -r "$realm" -s "name=$name" -i)
  printf '%s' "$id"
}
authz_policy() {
  local client=$1 name=$2 role_id=$3 id
  id=$(kc get "clients/$client/authz/resource-server/policy" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  if [[ -z "$id" ]]; then
    id=$(kc create "clients/$client/authz/resource-server/policy/role" -r "$realm" \
      -s "name=$name" -s "config.roles=[{\"id\":\"$role_id\"}]" -i)
  fi
  printf '%s' "$id"
}
invoices=$(authz_resource "$erp" Invoices)
suppliers=$(authz_resource "$erp" Suppliers)
read_scope=$(authz_scope "$erp" read)
approve_scope=$(authz_scope "$erp" approve)
accountant_policy=$(authz_policy "$erp" ERP-Accountant-policy "$erp_accountant")
if ! kc get "clients/$erp/authz/resource-server/permission" -r "$realm" -q name=ERP-Invoices-permission >/dev/null 2>&1; then
  kc create "clients/$erp/authz/resource-server/permission/resource" -r "$realm" \
    -s name=ERP-Invoices-permission \
    -s "resources=[\"$invoices\"]" \
    -s "scopes=[\"$read_scope\",\"$approve_scope\"]" \
    -s "policies=[\"$accountant_policy\"]" >/dev/null
fi
if ! kc get "clients/$erp/authz/resource-server/policy" -r "$realm" -q name=ERP-complex-policy >/dev/null 2>&1; then
  complex_policy=$(kc create "clients/$erp/authz/resource-server/policy/aggregate" -r "$realm" \
    -s name=ERP-complex-policy -s "config.policies=[\"$accountant_policy\"]" -i)
  kc create "clients/$erp/authz/resource-server/permission/resource" -r "$realm" \
    -s name=ERP-Suppliers-complex-permission \
    -s "resources=[\"$suppliers\"]" -s "scopes=[\"$approve_scope\"]" \
    -s "policies=[\"$complex_policy\"]" >/dev/null
fi
kc get "clients/$backup/roles/Backup-Operator" -r "$realm" >/dev/null 2>&1 || kc create "clients/$backup/roles" -r "$realm" -s name=Backup-Operator >/dev/null

group_id() { kc get groups -r "$realm" -q search="$1" --fields id --format csv --noquotes | tail -1; }
finance=$(group_id Finance); [[ -n "$finance" ]] || finance=$(kc create groups -r "$realm" -s name=Finance -i)
europe=$(group_id Finance-Europe); [[ -n "$europe" ]] || europe=$(kc create "groups/$finance/children" -r "$realm" -s name=Finance-Europe -i)
france=$(group_id Finance-France); [[ -n "$france" ]] || france=$(kc create "groups/$europe/children" -r "$realm" -s name=Finance-France -i)
sales=$(group_id Sales); [[ -n "$sales" ]] || sales=$(kc create groups -r "$realm" -s name=Sales -i)
support=$(group_id Support); [[ -n "$support" ]] || support=$(kc create groups -r "$realm" -s name=Support -i)

user_id() { kc get users -r "$realm" -q username="$1" --fields id --format csv --noquotes | tail -1; }
assign_group() { local uid; uid=$(user_id "$1"); [[ -n "$uid" ]] || { echo "missing Keycloak user $1" >&2; exit 1; }; kc update "users/$uid/groups/$2" -r "$realm" >/dev/null; }
assign_group alice "$france"
assign_group bob "$finance"
assign_group charlie "$sales"
assign_group diane "$support"

assign_group_realm_role() {
  kc add-roles -r "$realm" --gid "$1" --rolename "$2" >/dev/null
}
assign_group_client_role() {
  kc add-roles -r "$realm" --gid "$1" --cclientid "$(kc get clients/"$3" -r "$realm" --fields clientId --format csv --noquotes | tail -1)" \
    --rolename "$2" >/dev/null
}
assign_group_realm_role "$finance" accountant
assign_group_client_role "$sales" sales "$crm"
assign_group_client_role "$support" support "$crm"

assign_realm() {
  local uid; uid=$(user_id "$1")
  [[ -n "$uid" ]] && kc add-roles -r "$realm" --uid "$uid" --rolename "$2" >/dev/null
}
assign_client() {
  local uid client_name; uid=$(user_id "$1")
  client_name=$(kc get clients/"$3" -r "$realm" --fields clientId --format csv --noquotes | tail -1)
  [[ -n "$uid" ]] && kc add-roles -r "$realm" --uid "$uid" --cclientid "$client_name" \
    --rolename "$2" >/dev/null
}
assign_client alice sales "$crm"
backup_user=$(kc get "clients/$backup/service-account-user" -r "$realm" --fields username --format csv --noquotes | tail -1)
[[ "$backup_user" == service-account-svc-backup ]] || { echo "svc-backup service account missing" >&2; exit 1; }
assign_client service-account-svc-backup Backup-Operator "$backup"

rm_id=$(client_id realm-management)
collector_user=$(kc get "clients/$collector/service-account-user" -r "$realm" --fields id --format csv --noquotes | tail -1)
for role in view-users query-users query-groups query-clients view-clients view-realm; do
  [[ -n "$collector_user" ]] && kc add-roles -r "$realm" \
    --uusername service-account-eare-collector --cclientid realm-management \
    --rolename "$role" >/dev/null
done

echo "Keycloak realm $realm seeded with read-only LDAP federation and EARE clients."
