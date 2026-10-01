# Keycloak V1 / V2 / V3 connector

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

## Keycloak Authorization Services V3

V3 keeps the native Authorization Services evidence separate from its cautious
interpretation. The path is:

`Keycloak Admin REST → JSONL artifact → Keycloak importer → generic EARE Target / Capability / FunctionalRight → Golden / Campaign / Review`.

Resources become generic `Target` nodes (`Keycloak` service, client/application
component, native resource identifier). Scopes remain native actions and become
system Capabilities only when an explicit EARE mapping exists; otherwise EARE
creates a stable custom Capability whose human label is the native scope name.
The scope ID is retained as `native_permission`. Roles remain `Access` objects
and assignments remain `Identity → Access`.

The reviewer-facing model has three possible completeness states:

- `complete`: every derived Resource + Scope right is statically demonstrated;
- `partial`: some rights are demonstrated, while other permissions depend on
  conditional or complex policy evaluation;
- `not_defined`: no static FunctionalRight can safely be produced. Native
  permissions, policies, relationships and source evidence remain available;
  this does not mean that the access has no rights.

Collection completeness and semantic completeness are separate. A `full`
collection can legitimately produce a `partial` or `not_defined` functional
model. During resolution EARE considers the Resource Server enforcement mode
and decision strategies. A present Resource Server with an omitted
`policyEnforcementMode` uses Keycloak's documented `ENFORCING` default; an
absent Resource Server record is treated as unknown. `ENFORCING` is required
for a complete claim. `PERMISSIVE` downgrades the model because the collected
permissions may not describe every effective decision, while `DISABLED`
produces evidence-only authorization semantics and no effective static rights.
Permissions overlapping the same Resource + Scope are analysed together.
`UNANIMOUS` and `CONSENSUS`, unknown strategies, and any unresolved competitor
prevent an unjustified `complete` result. With `AFFIRMATIVE`, an overlap can
remain complete only when every competing permission is a positive,
single-role RBAC permission with no unresolved policy combination.

Keycloak's default decision strategy is `UNANIMOUS` for permissions and
policies. Multi-policy, multi-role and aggregate policies remain evidence and
are not flattened into a role right merely because one referenced role is
known. EARE does not reproduce the Keycloak PDP: it does not evaluate runtime
identity or resource context, JavaScript, dynamic attributes, external/custom
policy providers, or other runtime conditions. Unknown future strategy values
fail closed to `partial`/`not_defined`.

A resource-based permission with no scope is retained as native evidence but
does not invent a `read` (or any other) Capability. Multi-policy, multi-role
and aggregate policies retain their referenced native role IDs and downgrade
the affected Access when the relationship cannot be proven statically. EARE
does not execute the Keycloak PDP, runtime context rules or JavaScript policies.

Role names, resource names and scope names are never used as authorization
rules. Native IDs are preferred for role-policy matching, so equal display
names in separate clients do not collide. Positive single-role RBAC policies
can be resolved; multi-policy, aggregate, group/user, client, time, JavaScript,
attribute/context and unknown providers are preserved as evidence unless their
relationship is mathematically unambiguous.

The Review screen presents the generic `What this access allows` context before
technical evidence. Technical details retain the client, permission, policy,
resource, scopes and decision strategy so an administrator can trace every
derived right without exposing internal IDs as business labels.
