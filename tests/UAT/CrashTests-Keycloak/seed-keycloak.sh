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
component_id=$(kc get components -r "$realm" -q name=ldap --fields id --format csv --noquotes | tail -1)
if ! kc get components -r "$realm" -q name=ldap-groups --fields id --format csv --noquotes | grep -q .; then
  kc create components -r "$realm" -s name=ldap-groups \
    -s "parentId=$component_id" -s providerId=group-ldap-mapper \
    -s providerType=org.keycloak.storage.ldap.mappers.LDAPStorageMapper \
    -s 'config."groups.dn"=["ou=groups,dc=eare,dc=test"]' \
    -s 'config."group.name.ldap.attribute"=["cn"]' \
    -s 'config."group.object.classes"=["groupOfNames"]' \
    -s 'config."membership.ldap.attribute"=["member"]' \
    -s 'config."membership.attribute.type"=["DN"]' \
    -s 'config.mode=["LDAP_ONLY"]' \
    -s 'config."user.roles.retrieve.strategy"=["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"]' \
    -s 'config."preserve.group.inheritance"=["false"]' >/dev/null
fi
mapper_id=$(kc get components -r "$realm" -q name=ldap-groups --fields id --format csv --noquotes | tail -1)
kc create "user-storage/$component_id/mappers/$mapper_id/sync" -r "$realm" \
  -q direction=fedToKeycloak >/dev/null

for role in employee accountant invoice-read realm-admin-test; do
  kc get "roles/$role" -r "$realm" >/dev/null 2>&1 || kc create roles -r "$realm" -s "name=$role" >/dev/null
done
echo "Seed stage: realm roles"
kc add-roles -r "$realm" --rname accountant --rolename invoice-read >/dev/null
kc add-roles -r "$realm" --rname realm-admin-test --rolename accountant >/dev/null
echo "Seed stage: clients"

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
echo "Seed stage: Authorization Services clients"
kc update "clients/$crm" -r "$realm" -s authorizationServicesEnabled=false >/dev/null
kc update "clients/$erp" -r "$realm" -s serviceAccountsEnabled=true >/dev/null
kc update "clients/$erp" -r "$realm" -s authorizationServicesEnabled=true >/dev/null
collector=$(client_id eare-collector)
if [[ -z "$collector" ]]; then
  collector=$(kc create clients -r "$realm" -s clientId=eare-collector -s name=EARE -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -s "secret=$collector_secret" -i)
fi
backup=$(client_id svc-backup)
if [[ -z "$backup" ]]; then
  backup=$(kc create clients -r "$realm" -s clientId=svc-backup -s name=Backup -s enabled=true -s publicClient=false -s serviceAccountsEnabled=true -i)
fi

for spec in "$crm:CRM-Sales" "$crm:CRM-Support" "$crm:CRM-Admin" "$erp:ERP-Reader" "$erp:ERP-Accountant" "$erp:ERP-Admin"; do
  IFS=: read -r owner role <<<"$spec"
  kc get "clients/$owner/roles/$role" -r "$realm" >/dev/null 2>&1 || kc create "clients/$owner/roles" -r "$realm" -s "name=$role" >/dev/null
done
erp_reader=$(kc get "clients/$erp/roles/ERP-Reader" -r "$realm" --fields id --format csv --noquotes | tail -1)
erp_accountant=$(kc get "clients/$erp/roles/ERP-Accountant" -r "$realm" --fields id --format csv --noquotes | tail -1)
erp_admin=$(kc get "clients/$erp/roles/ERP-Admin" -r "$realm" --fields id --format csv --noquotes | tail -1)

authz_resource() {
  local client=$1 name=$2 id
  id=$(kc get "clients/$client/authz/resource-server/resource" -r "$realm" -q name="$name" --fields _id --format csv --noquotes | tail -1)
  if [[ -z "$id" ]]; then
    kc create "clients/$client/authz/resource-server/resource" -r "$realm" -s "name=$name" >/dev/null
    id=$(kc get "clients/$client/authz/resource-server/resource" -r "$realm" -q name="$name" --fields _id --format csv --noquotes | tail -1)
  fi
  [[ -n "$id" ]] || { echo "missing AuthZ resource $name" >&2; return 1; }
  printf '%s' "$id"
}
authz_scope() {
  local client=$1 name=$2 id
  id=$(kc get "clients/$client/authz/resource-server/scope" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  if [[ -z "$id" ]]; then
    kc create "clients/$client/authz/resource-server/scope" -r "$realm" -s "name=$name" >/dev/null
    id=$(kc get "clients/$client/authz/resource-server/scope" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  fi
  [[ -n "$id" ]] || { echo "missing AuthZ scope $name" >&2; return 1; }
  printf '%s' "$id"
}
authz_policy() {
  local client=$1 name=$2 role_id=$3 id
  id=$(kc get "clients/$client/authz/resource-server/policy" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  if [[ -z "$id" ]]; then
    kc create "clients/$client/authz/resource-server/policy/role" -r "$realm" \
      -s "name=$name" -s "roles=[{\"id\":\"$role_id\"}]" >/dev/null
    id=$(kc get "clients/$client/authz/resource-server/policy" -r "$realm" -q name="$name" --fields id --format csv --noquotes | tail -1)
  fi
  [[ -n "$id" ]] || { echo "missing AuthZ policy $name" >&2; return 1; }
  printf '%s' "$id"
}
echo "Seed stage: AuthZ resources"
invoices=$(authz_resource "$erp" Invoices)
suppliers=$(authz_resource "$erp" Suppliers)
payments=$(authz_resource "$erp" Payments)
arbitrary_resource=$(authz_resource "$erp" object-441)
echo "Seed stage: AuthZ scopes"
read_scope=$(authz_scope "$erp" read)
write_scope=$(authz_scope "$erp" write)
approve_scope=$(authz_scope "$erp" approve)
delete_scope=$(authz_scope "$erp" delete)
validate_scope=$(authz_scope "$erp" invoice.validate)
arbitrary_scope=$(authz_scope "$erp" perform_operation_xyz)
echo "Seed stage: AuthZ policies"
reader_policy=$(authz_policy "$erp" ERP-Reader-policy "$erp_reader")
accountant_policy=$(authz_policy "$erp" ERP-Accountant-policy "$erp_accountant")
admin_policy=$(authz_policy "$erp" ERP-Admin-policy "$erp_admin")
authz_permission() {
  local name=$1 resource=$2 scopes=$3 policy=$4
  if ! kc get "clients/$erp/authz/resource-server/permission" -r "$realm" -q "name=$name" \
    --fields id --format csv --noquotes | grep -q .; then
    kc create "clients/$erp/authz/resource-server/permission/resource" -r "$realm" \
      -s "name=$name" -s "resources=[\"$resource\"]" \
      -s "scopes=$scopes" -s "policies=[\"$policy\"]" >/dev/null
  fi
}
echo "Seed stage: AuthZ permissions"
authz_permission ERP-Reader-Invoices "$invoices" "[\"$read_scope\"]" "$reader_policy"
authz_permission ERP-Accountant-Invoices "$invoices" "[\"$read_scope\",\"$approve_scope\"]" "$accountant_policy"
authz_permission ERP-Accountant-Suppliers "$suppliers" "[\"$read_scope\"]" "$accountant_policy"
authz_permission ERP-Admin-Invoices "$invoices" "[\"$read_scope\",\"$write_scope\",\"$approve_scope\",\"$delete_scope\"]" "$admin_policy"
authz_permission ERP-Admin-Suppliers "$suppliers" "[\"$read_scope\",\"$write_scope\",\"$delete_scope\"]" "$admin_policy"
authz_permission ERP-Reader-Arbitrary "$arbitrary_resource" "[\"$arbitrary_scope\"]" "$reader_policy"
authz_permission ERP-Reader-Resource-Only "$arbitrary_resource" "[]" "$reader_policy"
complex_policy=$(kc get "clients/$erp/authz/resource-server/policy" -r "$realm" \
  -q name=ERP-complex-policy --fields id --format csv --noquotes | tail -1)
if [[ -z "$complex_policy" ]]; then
  dynamic_policy=$(kc get "clients/$erp/authz/resource-server/policy" -r "$realm" \
    -q name='Default Policy' --fields id --format csv --noquotes | tail -1)
  [[ -n "$dynamic_policy" ]] || { echo "missing Keycloak dynamic policy" >&2; exit 1; }
  kc create "clients/$erp/authz/resource-server/policy/aggregate" -r "$realm" \
    -s name=ERP-complex-policy -s "policies=[\"$dynamic_policy\"]" >/dev/null
  complex_policy=$(kc get "clients/$erp/authz/resource-server/policy" -r "$realm" \
    -q name=ERP-complex-policy --fields id --format csv --noquotes | tail -1)
fi
authz_permission ERP-Payments-complex "$payments" "[\"$approve_scope\"]" "$complex_policy"
dynamic_policy=$(kc get "clients/$erp/authz/resource-server/policy" -r "$realm" \
  -q name='Default Policy' --fields id --format csv --noquotes | tail -1)
[[ -n "$dynamic_policy" ]] || { echo "missing Keycloak default dynamic policy" >&2; exit 1; }
if ! kc get "clients/$erp/authz/resource-server/permission" -r "$realm" \
  -q name=ERP-Reader-Multi-Policy --fields id --format csv --noquotes | grep -q .; then
  kc create "clients/$erp/authz/resource-server/permission/resource" -r "$realm" \
    -s name=ERP-Reader-Multi-Policy -s "resources=[\"$arbitrary_resource\"]" \
    -s "scopes=[\"$validate_scope\"]" \
    -s "policies=[\"$reader_policy\",\"$dynamic_policy\"]" \
    -s decisionStrategy=UNANIMOUS >/dev/null
fi
kc update "clients/$erp/authz/resource-server" -r "$realm" \
  -s policyEnforcementMode=ENFORCING -s decisionStrategy=UNANIMOUS >/dev/null
echo "Seed stage: group-role mappings"
kc get "clients/$backup/roles/Backup-Operator" -r "$realm" >/dev/null 2>&1 || kc create "clients/$backup/roles" -r "$realm" -s name=Backup-Operator >/dev/null

group_id() { kc get groups -r "$realm" -q search="$1" --fields id --format csv --noquotes | tail -1; }
finance=$(group_id Finance)
sales=$(group_id Sales)
support=$(group_id Support)
it=$(group_id IT)
auditors=$(group_id Auditors)
for group in "$finance" "$sales" "$support" "$it" "$auditors"; do
  [[ -n "$group" ]] || { echo "LDAP group federation is incomplete" >&2; exit 1; }
done

user_id() { kc get users -r "$realm" -q username="$1" --fields id --format csv --noquotes | tail -1; }

assign_group_realm_role() {
  kc add-roles -r "$realm" --gid "$1" --rolename "$2" >/dev/null
}
assign_group_client_role() {
  kc add-roles -r "$realm" --gid "$1" --cclientid "$(kc get clients/"$3" -r "$realm" --fields clientId --format csv --noquotes | tail -1)" \
    --rolename "$2" >/dev/null
}
assign_group_client_role "$finance" ERP-Accountant "$erp"
assign_group_client_role "$sales" CRM-Sales "$crm"
assign_group_client_role "$support" CRM-Support "$crm"
assign_group_client_role "$it" ERP-Admin "$erp"

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
assign_client alice ERP-Accountant "$erp"
backup_user=$(kc get "clients/$backup/service-account-user" -r "$realm" --fields username --format csv --noquotes | tail -1)
[[ "$backup_user" == service-account-svc-backup ]] || { echo "svc-backup service account missing" >&2; exit 1; }
assign_client service-account-svc-backup Backup-Operator "$backup"

rm_id=$(client_id realm-management)
collector_user=$(kc get "clients/$collector/service-account-user" -r "$realm" --fields id --format csv --noquotes | tail -1)
for role in \
  view-users query-users query-groups query-clients view-clients view-realm \
  manage-clients view-authorization; do
  [[ -n "$collector_user" ]] && kc add-roles -r "$realm" \
    --uusername service-account-eare-collector --cclientid realm-management \
    --rolename "$role" >/dev/null
done

echo "Keycloak realm $realm seeded with read-only LDAP federation and EARE clients."
