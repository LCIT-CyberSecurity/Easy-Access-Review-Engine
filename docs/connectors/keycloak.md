# Keycloak V1 / V2 connector

The connector is read-only and uses the Keycloak Admin REST API. One EARE
provider is bound to exactly one realm; changing the realm for an existing
provider is rejected as `KEYCLOAK_REALM_SCOPE_CHANGED`.

Configure `type: keycloak` with `connection.base_url`, `connection.realm`,
`connection.client_id`, and `credentials.client_secret_env`. The environment
variable contains the client secret and is never written to YAML, artifacts,
the database, logs, or exception messages. Production deployments should use
HTTPS with certificate verification enabled; HTTP is intended only for a local
test lab.

The collector requests users, groups and nested groups, memberships, clients,
realm roles, client roles, user and group mappings, composite relations and
service accounts. It emits the versioned Keycloak artifact consumed by the
Keycloak normalizer. Direct mappings are observations (`AccessAssignment`); group and
composite inheritance remains in `AccessRelation` and is calculated by EARE.

## Keycloak V1

V1 collects users, groups, memberships, clients, realm roles, client roles,
user and group mappings, composite roles and service accounts.

## Keycloak V2 / Authorization Services

Authorization Services is optional. When enabled for a client, the connector
also collects resources, authorization scopes, policies and permissions in
explicit JSONL artifact files. Each record retains the realm, native client
UUID, readable `clientId`, native object ID and source relationships.

Authorization Services not enabled is not an error. A client is recorded as
`not_enabled`; this does not degrade an otherwise complete V1 snapshot. If an
enabled resource server cannot be read, the artifact records an explicit
`error` state and remains scoped/non-authoritative for safe replay.

EARE does not infer functional permissions from role names. A functional right
is derived only for a positive, single-role RBAC policy whose resource and
scope references resolve unambiguously to existing Keycloak objects. Resource
maps to the generic `Target`, a known system scope maps to an existing
`Capability`, and the Keycloak scope remains in `native_permission`. Roles
remain EARE `Access` objects; permissions and policies are not converted into
Access objects.

Complex or dynamic Keycloak policies are preserved as source evidence and are
not flattened into static role permissions unless the relationship can be
determined safely. This includes aggregate, group/user, time, JavaScript,
attribute-based and unknown policy providers.

All paginated surfaces are read to completion. Retries are bounded and limited
to 429/502/503/504 and transport failures represented by the HTTP client. A
failed required surface cannot produce a `full` artifact. Scoped artifacts are
not authoritative for deletion/revocation.

The collector account should be a dedicated confidential client with service
account and only the realm-management permissions needed by the enabled
surfaces. On Keycloak 25, the lab grants `view-authorization` for the AuthZ
objects and `manage-clients` for the resource-server settings endpoint. The
collector still performs no Admin API write operation; the only POST is the
OAuth token request.

Unsupported: Organizations, fine-grained admin permissions as audited
objects, automatic AD/LDAP identity reconciliation, provisioning, writes to
Keycloak, and multiple realms in one EARE source.
