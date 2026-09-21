# EARE Model Evolution — Golden Source V2

**Status:** normative design and implementation contract  
**Date:** 2026-09-21  
**Baseline:** `5c827dded982223fb1ad752869c3903c1394e8da`

## 1. Purpose and scope

This specification additively evolves EARE's core into a provider-agnostic
access-review model that can represent directory, identity, SaaS, cloud,
database, Linux, file, Kubernetes, and offline/custom access sources. It extends
the current model; it does not replace its identity, access, assignment,
relation, snapshot, or Golden contracts. Semantic stability, historical
integrity, and conservative conclusions take priority over guessing.

The core and generic services operate on canonical EARE concepts. They must not
branch on provider names, provider types, native permission spellings, SIDs,
DNs, membership attributes, cloud actions, or other source-native constructs.
Collectors, importers, source adapters, and explicit mapping layers translate
those constructs and may preserve native evidence in `native_id`, `Permission`,
`Origin.raw`, and `metadata`.

## 2. Existing invariants (preserved)

- A Provider identifies the system/source boundary. Provider names are part of
  Identity and Access identity.
- Identity matching remains provider-aware: `(provider, identifier)` is the
  current reference. Equal logins on distinct providers are distinct identities.
- Access matching remains provider-aware. `Access.key()` remains exactly
  `f"{provider}:{name}"`; no Golden or functional concept changes it.
- Permission is the native technical permission. Its `identifier` is never
  rewritten during normalization or mapping (examples: `member`, `SELECT`,
  `s3:GetObject`, `invoice.validate`, `sudo`, `pods/exec`).
- AccessAssignment records direct assignment only. Derived access is not
  materialized as a direct assignment.
- AccessRelation describes an Access-to-Access edge. `GRANTS` remains the
  supported positive relation and existing key semantics remain stable.
- EffectiveAccess is calculated from assignments and relations; it is not an
  independent source of truth.
- Snapshot is immutable observed evidence. GoldenSourceVersion is immutable
  expected evidence. New collection or current model edits never rewrite either
  historical record.
- Comments, provenance, labels, and display names do not affect technical keys,
  matching, or effective-right calculation.

## 3. Canonical graph and concepts

The generic graph is `Identity -> AccessAssignment -> Access ->
AccessRelation(GRANTS) -> Access -> Permission + Target`. The same graph covers
directory group nesting, application roles, cloud roles, database roles, Linux
groups/sudo, and cross-provider edges (for example, a directory group granting
an application role). Provider-native data is interpreted at the adapter
boundary; graph calculation receives only model objects.

- **Provider**: the source/system that owns an observed object (for example
  `openldap-corp`, `nexabyte-crm`, `postgres-prod`, `aws-prod`).
- **Identity**: provider-aware principal, with native identifiers preserved as
  evidence, not universal keys.
- **Access**: reviewable entitlement/role/group, provider-aware by its existing
  key. Its `access_owner` remains the one owner reference in this branch.
- **Permission**: native technical action.
- **Capability**: optional normalized functional action (section 6).
- **Target**: the object an authorization applies to (section 5).
- **AccessAssignment**: direct possession of an Access.
- **AccessRelation**: how one Access grants another Access.
- **EffectiveAccess**: derived reachability result with preserved paths.
- **Snapshot**: observed immutable evidence.
- **Golden**: expected immutable reference, versioned independently from
  mutable current observations.

Thus: Permission = native technical action; Capability = optional normalized
functional action; Target = object on which the action applies;
AccessAssignment = direct possession of an Access; AccessRelation = how one
Access grants another Access; EffectiveAccess = derived result; Snapshot =
observed immutable evidence; Golden = expected immutable reference.

## 4. Target semantics and canonical contract

Target has exactly three semantic slots: `service`, `component`, and `resource`.
These are not configurable physical hierarchy depths. Service means an
application, information system, platform, or technical service; component
means a subsystem, module, database, namespace, tenant, or logical component;
resource means the actual object targeted by authorization. Deeper paths use a
stable fully-qualified resource identifier (for example
`Documents/Budget/2026/budget.xlsx`), not new Target levels.

Business context is not automatically a Target. “Approve invoices for the
French subsidiary” has Target `ERP > Invoices`, Capability `approve`, and a
possible future Scope `legal entity = France`. Generic Scope is explicitly not
implemented here. A subsidiary/tenant can be Target only where it is itself a
real technical authorization object.

Examples:

| Context | service | component | resource |
|---|---|---|---|
| CRM | `nexabyte-crm` (`application`) | optional | `contacts` (`business_object`) |
| Database | `postgresql` (`database_service`) | `salesdb` (`database`) | `salesdb.public.orders` (`database_table`) |
| File | `fileserver` (`file_service`) | `finance-share` (`share`) | `/2026/Budgets/budget.xlsx` (`file`) |
| Directory delegation | `corp-ad` (`directory_service`) | `corp.example.com` (`ad_domain`) | `OU=France,...` (`organizational_unit`) |
| Kubernetes | `kubernetes-prod` | `namespace/prod` | `pod/backend-123` |

For newly manually defined nodes, the canonical object has `identifier`,
optional `display_name`, recommended `type`, and optional extension `metadata`.
Manual identifiers are required, non-empty, and machine/stable. Canonical
reference/key helpers and safe semantic comparison use only slot and canonical
identifier, never display name. Human-readable paths may use labels, falling
back to identifiers. New manual values are normalized/validated at creation;
historical loose JsonDict Target nodes remain readable and are not rewritten.
Canonical Target identity never replaces Access.key().

## 5. Native Permission and functional Capability

Permission remains provider-native and unchanged. Capability is a separate,
optional, normalized functional action. The functional right semantic unit is
`Target + Capability`, never Capability alone: `Contacts / read`,
`Invoices / write`, `Users / admin`, or `public.orders / read`.

The initial system catalogue is deliberately small: `read`, `write`, `delete`,
`execute`, `approve`, `admin`, `grant`. Each entry has stable immutable-after-
use ID, editable label, required description, active flag, and system/custom
classification. Custom entries (for example `sign`, `export`, `publish`,
`reconcile`) are allowed. Used entries are deactivated, not destructively
deleted. There is no `membership` capability: membership describes assignment,
not functional authorization.

Native-permission-to-capability mapping is optional, explicit, and supports
many native permissions mapping to one capability (for example PostgreSQL
`SELECT -> read`, `INSERT/UPDATE -> write`; AWS `s3:GetObject -> read`; app
`invoice.validate -> approve`). Its representation must allow future one-to-many
semantics. Mapping is `UNMAPPED` when uncertain; no mapping is invented, and
`member` never implies a functional capability. Mapping never mutates native
Permission.identifier. Capability normalization is lossy: `Read` on S3 and
`Read` on PostgreSQL are not the same technical permission.

## 6. Golden V1 and V2

Golden V1 is the current expected direct assignment list plus authentication
policy and version metadata/annotations. It remains readable byte-for-byte as
historical evidence; missing V2 model fields mean `schema_version = 1` and
functional completeness `NOT_DEFINED`, not an empty complete model. Existing
checksums are never recalculated in place.

Golden V2 is additive and freezes, per version: `schema_version`, existing
assignments, expected Access definitions, expected Access relations, functional
Target+Capability rights, authentication policy, completeness, provenance,
version comment, assignment comments, and version-aware Access comments.
Reuse Access and AccessRelation semantics where native expected objects exist.
Where a manual functional right has no honest native Permission, represent
`Target + Capability` explicitly; do not fabricate an Access or Permission.
Expected Access metadata (including owner and comments) is copied/frozen into
the new version rather than dereferencing mutable current state later.

Golden versions are immutable. Source changes, Access changes, Capability label
edits, and later imports cannot alter a prior version's assignments, definitions,
relations, rights, completeness, provenance, or comments. Manual Golden
enrichment is valid even when a source cannot expose business semantics.
Observed/manual reconciliation is diagnostic only: matching facts can be shown
as aligned; conflicts are shown as differences; neither side silently replaces
the other.

## 7. Completeness, provenance, and comparison

Functional model completeness is independent from collection completeness and
has exactly three values:

- `NOT_DEFINED`: EARE does not know the Access's functional rights. It does not
  mean an empty set and generates no functional mismatch conclusion.
- `PARTIAL`: listed rights are known, but not exhaustive. Listed rights can be
  checked; additional observed rights are `UNKNOWN / NOT_ASSERTED`, never
  automatically `UNEXPECTED`.
- `COMPLETE`: explicit assertion that the list is exhaustive. An observed
  functional right absent from this version may be `UNEXPECTED`.

Rights do not automatically promote a model to `COMPLETE`. Completeness may be
asserted only explicitly or by a source with authoritative semantics whose
exhaustiveness is established. Lack of information remains unknown.

Fact provenance is `OBSERVED`, `MANUAL`, or `MAPPED`; a mixed display may be
computed. Provenance is distinct from SOURCE/provider ownership and excluded
from technical identity. Example: an OpenLDAP group can be OBSERVED, its CRM
Target/right definitions MANUAL, and a PostgreSQL native action to capability
association MAPPED.

The existing direct comparison (Golden expected assignment vs observed
assignment) remains unchanged: matching remains `EXPECTED_AND_OBSERVED`, and
existing missing/unexpected/scope behavior stays intact. A separate functional
comparison/read model compares target+capability rights only when the model
assertion permits it. V1/NOT_DEFINED yields no mismatch; PARTIAL does not
assert absence; COMPLETE can report unexpected observed rights. Initially these
diagnostics do not become campaign ReviewItems or remediation actions.

## 8. Comments, owners, and structural editing

Keep the version comment (“why did this Golden version change?”) and existing
assignment annotation (“why should this identity have this Access?”). Add
version-aware Access comments (“what is this Access for?”), free text capped at
the existing annotation limit. All are historical annotations and never affect
keys, matching, or effective rights. Preserve `Access.access_owner`; do not add
parallel application/resource/technical/business owner fields. Owner can be
observed or manually enriched and should refer to a known Identity when
available.

Structural authoring is auto-first: select known Accesses, Identities,
Providers, Targets, Owners, and catalogued Capabilities first. Creating an
unobserved Access or Target or adding a custom Capability is an explicit
secondary action. Free text is for comments/descriptions, not unconstrained
structural key editing.

## 9. Persistence, authorization, and compatibility

Persistence changes are additive and idempotent. Existing SQLite databases,
snapshots, Golden V1 versions, and API representations continue loading; no
snapshot rewrite, Golden history rewrite, or destructive table/data migration is
permitted. V2 data, comments, provenance, completeness, capability catalogue,
and mappings survive restart. Historical immutable facts are stored inline or
as immutable version references, not resolved from mutable live catalogues.

All Golden and capability mutations remain internal, session-authenticated
WebUI operations and reuse existing RBAC/provider-scope authorization.
Cross-provider graph reads must authorize all providers referenced by the graph,
not just the root provider. `/api/v1` remains read-only; external bearer tokens
must not gain access to internal write routes. Public OpenAPI/Swagger exposure
restrictions stay intact. Golden/Snapshot data must not contain secrets.

## 10. Positive grants and unsupported models

EARE is provider-agnostic but is not a universal policy evaluation engine. The
current graph evaluates positive `GRANTS` relationships well for groups,
roles, nested access, and cross-provider graphs. It does not fully evaluate
explicit DENY, ABAC, policy conditions, runtime context, AWS SCP/permission
boundaries/resource policy/session policy interactions, Azure policy, Kubernetes
admission/policy semantics, or JIT/temporal access. Use `NOT_DEFINED`, `PARTIAL`,
`UNKNOWN`, or `UNSUPPORTED` rather than claiming full authorization knowledge.

Future additive extension points include Scope (country, business unit, legal
entity, environment/data perimeter), DENY, conditions, ABAC, temporal/JIT, SoD,
resource hierarchy, and policy evaluation. They are not implemented here; this
work must not pre-engineer a universal policy language or arbitrary Target depth.

## 11. User experience and test contract

Keep the existing Golden tabs: Expected access rights, Who holds them, Changes
since last collection, Authentication policy, Version history. The expected
rights table emphasizes Access, type, Target, effective-right count, owner,
source, model completeness, expected holders, and Access comment. Native values
remain in technical details; `member` is not shown as a business right. Counts
open a bounded/detail view showing Target, Capability, provenance, native
permission when known, and provider/source. Model state is `Not defined`,
`Partial · N rights`, or `N rights` for complete. Users explicitly select
completeness; it is never inferred. Holder view remains identity-centric and
keeps assignment comments.

Automated invariants cover provider-qualified Identity/Access keys, unchanged
Access.key, native Permission preservation, display/provenance/comment
exclusion, canonical and historical Target behavior, immutable snapshots and
Golden versions, V1 as NOT_DEFINED, completeness comparison, no silent
reconciliation, unknown preservation, custom/stable capabilities, no membership
capability, cross-provider graph edges, cycle/path handling, collision
rejection, and secret exclusion. The same generic graph service must work for
AD/LDAP, CRM, AWS, database, Linux, and cross-provider fixtures without
provider-specific branches. Large graph checks avoid brittle timing thresholds.

CrashTests-CRM is extended, not replaced, to cover CRM role rights, manual
OpenLDAP group enrichment, NOT_DEFINED/PARTIAL/COMPLETE, owner/comment scopes,
custom Capability, cross-provider grants, and database/file Targets. Docker/AD/
OpenLDAP integration results must be reported as NOT RUN with reason and command
where dependencies are unavailable; they must never be represented as passed.
