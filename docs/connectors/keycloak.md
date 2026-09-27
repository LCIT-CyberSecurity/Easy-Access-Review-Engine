# Keycloak V1 connector

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
service accounts. It emits the versioned Keycloak artifact consumed by the V0
normalizer. Direct mappings are observations (`AccessAssignment`); group and
composite inheritance remains in `AccessRelation` and is calculated by EARE.

All paginated surfaces are read to completion. Retries are bounded and limited
to 429/502/503/504 and transport failures represented by the HTTP client. A
failed required surface cannot produce a `full` artifact. Scoped artifacts are
not authoritative for deletion/revocation.

The collector account should be a dedicated confidential client with service
account and only the realm-management view/query permissions needed by the
enabled surfaces. No Admin API write operation is used; the only POST is the
OAuth token request.

Unsupported in V1: Organizations, Authorization Services, fine-grained admin
permissions as audited objects, automatic AD/LDAP identity reconciliation,
provisioning, writes to Keycloak, and multiple realms in one EARE source.
