# Easy Access Review Engine - Global Specification

**Date:** 2026-09-08  
**Status:** Current implementation specification, aligned with branch `fix/ad-collector-hardening-v2`  
**Repository:** `LCIT-CyberSecurity/Easy-Access-Review-Engine`  
**Document scope:** Product behavior, implemented MVP boundaries, safety invariants, and future constraints.

---

## 1. Purpose

Easy Access Review Engine (EARE) is an open source access review, comparison and recertification engine. It is designed to import observed access data from identity and directory systems, normalize that data into a provider-neutral model, compare it against an optional Golden Source, support access review campaigns, record decisions, and export evidence for audit and remediation.

The project is intentionally not a full IAM or IGA platform. It does not own identities, authenticate users, provide SSO, manage passwords, replace directories, or directly provision and revoke access in source systems. Its core mission is narrower and safer:

```text
observe -> normalize -> compare -> review -> decide -> report -> export remediation
```

This matters because access review tooling must avoid creating false certainty. A partial directory export, an ambiguous LDAP DN, a legacy Golden Source without stable identifiers, or a failed collector run must not be converted into authoritative truth. The engine favors conservative states such as `unknown_due_to_scope` and unresolved observations over guessed matches.

---

## 2. Current MVP Reality

The current repository implements a Python MVP with a provider-neutral domain model, file-based Active Directory and OpenLDAP imports, SQLite persistence, Golden Source comparison, snapshots, campaigns, decisions, remediation generation, and portable reports.

Implemented source paths:

- Active Directory ZIP imports produced by `exporters/active-directory/export-active-directory.ps1`.
- OpenLDAP ZIP imports produced by `exporters/openldap/export-openldap.sh`.
- Raw OpenLDAP LDIF imports for simple local workflows.

Implemented governance paths:

- import observed data;
- reconcile identities and access objects using stable provider IDs where available;
- persist current authoritative state only when the import is authoritative for its scope;
- keep non-authoritative observations diagnostic rather than authoritative;
- compare observed state with an optional Golden Source;
- create immutable snapshots;
- open review campaigns from snapshots;
- record decisions;
- close campaigns only when every review item has a decision;
- generate remediation actions;
- write standalone HTML, CSV and JSON report outputs;
- promote safe snapshots or reviewed campaigns into new Golden Source versions.

Implemented validation baseline on this branch:

```text
109 passed, 0 failed
```

Environment limitations from the last local validation:

- `pwsh` was not available, so Pester tests were not executed locally.
- `ruff`, `mypy` and `shellcheck` were not installed locally.
- `bash -n exporters/openldap/export-openldap.sh` passed.
- Python syntax compilation of changed files passed.

---

## 3. Explicit Non-Goals

EARE must not become a monolithic IAM platform. The following are outside the current core product scope:

- SSO or identity provider functionality.
- Password management.
- PAM/JIT access management.
- Real-time provisioning as a mandatory core feature.
- Direct revocation execution in source systems as part of the core engine.
- Effective NTFS permission calculation.
- Effective GPO, AD ACL or Kerberos delegation access calculation.
- Azure/Entra effective permission calculation.
- A universal graph engine for every possible access path in every system.
- HR master-data governance.
- Replacement of Active Directory, OpenLDAP, Entra ID, Keycloak, cloud IAM or application IAM.

Future provisioning connectors may exist as optional extensions, but the review engine must remain useful and safe without them.

---

## 4. Core Model Invariant

The central business model is strict and provider-neutral:

```text
Provider -> Identity -> AccessAssignment -> Access -> Resource
```

This model must remain stable. It is the main design boundary that prevents source-specific details from leaking into the core governance engine.

### 4.1 Provider

A `Provider` represents a source system, domain, tenant, directory or security boundary.

Examples:

- `corp-ad`
- `emea-ad`
- `openldap-prod`
- future Entra tenant
- future Keycloak realm
- future cloud account or project

Provider-specific connection secrets must not be stored in snapshots, Golden Source versions, business exports or report artifacts.

### 4.2 Identity

An `Identity` represents a principal that can hold or receive access. In the current implementation, identity types are:

- `user_account`
- `technical_account`
- `shared_account`
- `group`

Identity status values are:

- `active`
- `disabled`
- `deleted`
- `unknown`

Important distinction:

```text
Identity.status == unknown
```

means the identity object exists but its lifecycle state is not known. It is not the same as:

```text
unknown_identity
```

`unknown_identity` is a finding used only when an assignment references an identity that cannot be resolved to a known identity object.

### 4.3 Access

An `Access` represents an entitlement, permission, role, group, policy or access-control object. For the current AD and OpenLDAP support, group membership is represented as an access where:

```text
Access.control_object.type = group
Access.permission.identifier = member
```

The access is not the assignment. It describes what can be held. The assignment describes who holds it and through which origin.

### 4.4 AccessAssignment

An `AccessAssignment` links an identity to an access. It also carries the origin of that observation.

This separation is mandatory because the same identity can receive the same logical access through multiple distinct paths. Example:

```text
Jean Dupont -> direct member of GG_FINANCE
Jean Dupont -> member of GG_MANAGERS -> GG_FINANCE
```

Both paths can matter in a review. The engine therefore preserves origin details on `AccessAssignment`, not on `Access`.

### 4.5 Resource

A `Resource` represents the target of an access where such target data exists. The current AD/OpenLDAP group-membership flows often model the group/control object more directly than a separate resource, but the model keeps `Resource` available for application, cloud, database or filesystem extensions.

---

## 5. Stable Identifiers And Mutable Names

Stable identifiers are required for safe reconciliation across renames and object recreation.

Current stable native IDs:

- Active Directory identity: SID.
- Active Directory group-backed access: group SID.
- OpenLDAP identity: `entryUUID`.
- OpenLDAP group-backed access: group `entryUUID`.

Mutable names include:

- AD `SamAccountName`;
- AD group names;
- LDAP DN;
- LDAP `uid`;
- LDAP `cn`;
- display names;
- generated human-readable access names.

A mutable name can help display, review and legacy compatibility, but it must not prove object identity when a stable ID is available or expected.

This rule protects against a common high-risk scenario:

```text
Old object: Finance, SID-X
Object deleted
New object: Finance, SID-Y
```

The name is the same, but the object is not. A legacy Golden Source containing only `Finance / jdupont` cannot prove that `Finance SID-Y` is the expected historical object. The engine must not silently classify that as `expected_and_observed`.

---

## 6. Import Batches, Scope And Completeness

Every import creates an `ImportBatch`. It records at least:

- provider;
- source type;
- status;
- checksum;
- completeness;
- scope;
- started/completed timestamps.

Completeness values:

- `full`
- `scoped`
- `unknown`

A collection can be authoritative only when the provider, completeness, scope and collection-error state prove that the imported data is exhaustive for the relevant provider scope.

### 6.1 Full Import

A full authoritative import can replace current assignments for the imported provider scope. It can also support `missing` conclusions because absence is meaningful inside that scope.

### 6.2 Scoped Import

A scoped import contains a real subset. It can show observed assignments in that subset, but absence outside or beyond that subset is not proof.

### 6.3 Unknown Import

An unknown import is diagnostic or incomplete. It must not replace authoritative current state. It can still produce useful observations and findings, but it must not create false compliance or false missing conclusions.

Mandatory invariant:

```text
Non-authoritative data must never become authoritative current state by itself.
```

---

## 7. Persistence Model

The current persistence layer uses SQLite from the Python standard library. Rows are stored as canonical JSON payloads while keeping explicit tables that mirror future relational boundaries.

Current table boundaries include:

- providers;
- identities;
- resources;
- accesses;
- access assignments;
- imports;
- Golden Sources;
- Golden Source versions;
- Golden Source assignments;
- snapshots;
- snapshot identities/resources/accesses/assignments;
- campaigns;
- review items;
- decisions;
- audit events;
- remediation actions.

Persistence rules:

- Provider imports are scoped by provider.
- Importing one provider must not delete another provider's current assignments.
- Authoritative assignment replacement is limited to the provider being imported.
- Non-authoritative imports retain observations in import metadata rather than replacing current authoritative assignments.
- Snapshots and Golden Source versions are append-only at the application level.

The current repository is not yet using active SQLAlchemy/Alembic migrations, even though those dependencies are part of the intended application stack.

---

## 8. Active Directory Support

The AD collector/exporter path is file-based. The PowerShell exporter writes a ZIP archive and the Python importer reads that archive.

Current export files:

```text
manifest.yaml
users.csv
groups.csv
service_accounts.csv
computers.csv
memberships.csv
collection-errors.csv
```

Older V1 archives without optional files remain importable.

### 8.1 AD Observations

The current AD implementation supports:

- users from `Get-ADUser`;
- groups from `Get-ADGroup`;
- direct group memberships from `Get-ADGroupMember`;
- nested group edges preserved as observed edges, without recursive flattening;
- disabled accounts;
- unknown enabled state when the `Enabled` field is absent, empty or invalid;
- locked account metadata/findings;
- expired account metadata/findings;
- gMSA/MSA service accounts as technical accounts;
- computer principals used in group memberships;
- primary group memberships represented as normal assignments;
- Foreign Security Principals preserved by SID when unresolved;
- cross-domain resolution by SID when a matching identity is known from another provider;
- built-in account detection using SID/RID rather than localized names;
- optional deterministic classification rules for classic service/shared user accounts.

### 8.2 AD Safety Rules

AD identity reconciliation uses SID as the stable native ID. This means:

- same SID plus renamed account keeps the same internal identity;
- same SID plus renamed group keeps the same internal access object;
- same name plus new SID is a different object;
- deletion is inferred only from authoritative full provider collection;
- failed or partial collection does not create false `missing` conclusions.

### 8.3 AD Collector Failure Behavior

Membership collection errors must not be hidden. The exporter fails closed by default:

- group member collection errors are recorded;
- `collection-errors.csv` is written;
- `manifest.yaml` is not marked `completeness: full` when errors exist;
- the exporter exits non-zero unless partial output is explicitly allowed.

When partial output is explicitly allowed, the resulting import is diagnostic and marked non-authoritative.

---

## 9. OpenLDAP Support

OpenLDAP support is also file-based. The exporter produces LDIF in a ZIP archive, and the importer normalizes LDIF entries into the core model.

Supported entry and group patterns:

- `inetOrgPerson`;
- `account`;
- `posixAccount`;
- `groupOfNames`;
- `groupOfUniqueNames`;
- `posixGroup`;
- `member`;
- `uniqueMember`;
- `memberUid`.

Supported LDIF behavior:

- continuation lines;
- base64 values where useful;
- escaped DN values;
- multi-valued RDN canonicalization;
- attribute options;
- lowercase or mixed-case object classes;
- operational attributes such as `entryUUID`;
- ignored unused binary attributes;
- rejection of change records.

### 9.1 OpenLDAP Stable Identity

OpenLDAP uses `entryUUID` as stable `native_id`. DN, `uid` and `cn` are treated as mutable. Consequences:

- moving a user to a new DN with the same `entryUUID` preserves the identity;
- renaming a group with the same `entryUUID` preserves the access object;
- recreating a group with the same `cn` and a new `entryUUID` creates a different access object;
- duplicate or ambiguous `memberUid` values are not guessed.

### 9.2 OpenLDAP Authoritative Scope

The engine tracks the first supported authoritative OpenLDAP scope. That scope includes:

- canonical `base_dn`;
- `search_scope`;
- normalized filter.

The default EAR OpenLDAP filter is accepted as authoritative when used with a full provider-wide collection.

A reduced base DN, `search_scope=one`, or restrictive filter is treated as scoped, not authoritative. This prevents a smaller LDAP query from deleting or marking missing objects that were simply outside the query.

Members outside the source scope do not automatically degrade a full source collection when they are explicitly out of scope.

---

## 10. Unresolved Principal Handling

Unresolved assignments are expected in real directories. Examples:

- AD Foreign Security Principal from a domain not imported yet.
- LDAP group member DN from another directory/provider.
- LDAP `memberUid` with no matching user entry.
- LDAP `memberUid` that matches multiple possible identities.

Resolution rules:

- AD unresolved foreign principals resolve by unique SID.
- OpenLDAP member DNs resolve by canonical DN when unique.
- OpenLDAP `entryUUID` references resolve by unique native ID.
- OpenLDAP `memberUid` resolves only when unique in the relevant provider context.
- Ambiguous matches stay unresolved.
- Missing matches stay unresolved.
- The engine does not invent providers.

### 10.1 Authoritative vs Historical Unresolved

The current implementation makes a strict distinction between:

```text
authoritative unresolved assignment
```

and:

```text
historical non-authoritative unresolved observation
```

Authoritative unresolved assignments are already part of current state. If the referenced identity later becomes known, the assignment can be resolved in `access_assignments`.

Historical non-authoritative unresolved observations come only from `unknown`, `partial` or `scoped` imports. They may be retained and later enriched for diagnostics, but they must not be inserted into current authoritative `access_assignments` unless a later authoritative import from the source provider confirms that the relationship still exists.

Retained non-authoritative unresolved observations carry provenance such as:

- `authoritative_source=false`;
- `batch_id`;
- `source_provider`;
- `source_completeness`;
- `source_scope`.

This prevents a stale partial observation from reappearing as current truth after an unrelated provider import makes the referenced identity resolvable.

---

## 11. Golden Source

A Golden Source is optional. Without a Golden Source, observed access is classified as `no_reference`; it is not automatically unauthorized.

Implemented Golden Source objects:

- `GoldenSource`
- `GoldenSourceVersion`
- `GoldenSourceAssignment`

A Golden Source version is immutable and checksummed. It may come from manual creation, snapshot promotion or campaign promotion.

### 11.1 Golden Assignment Keys

Legacy Golden assignments may contain only name-based fields:

```text
access_provider
access_name
identity_provider
identity_identifier
```

Recent Golden assignments may also contain stable fields:

```text
access_native_id
access_permission
identity_native_id
```

Stable keys are preferred because they survive rename events.

### 11.2 Golden Comparison Rules

The comparison rules are conservative:

- Stable Golden plus stable observed data compares by stable key.
- Stable Golden does not silently match a different stable observed object by name.
- Legacy Golden plus observed data without stable keys may use legacy fallback when non-ambiguous.
- Legacy Golden without stable key plus observed data with a stable key must not produce `expected_and_observed` by name alone.
- If identity cannot be proven, the result stays conservative, currently `unknown_due_to_scope` for the legacy expected row and `unexpected` for the observed stable object where applicable.
- Duplicate stable keys in a Golden Source version are rejected explicitly.

This protects against old baselines that did not record SID or `entryUUID` values.

### 11.3 Golden Promotion

Snapshot promotion is allowed only when the snapshot is safe to promote.

Current rules:

- snapshots with `collection_incomplete` cannot be promoted;
- provider-scoped snapshots cannot overwrite a previous Golden containing other providers;
- provider-scoped promotion is allowed when the existing Golden only contains that provider;
- full/global snapshots can be promoted normally.

Campaign promotion rules:

- `approve` keeps access expected;
- `revoke` removes access from the next Golden version;
- `not_applicable` does not create an automatic Golden change;
- pending decisions block campaign promotion.

---

## 12. Comparison States

Implemented comparison states:

- `expected_and_observed`
- `unexpected`
- `missing`
- `unknown_due_to_scope`
- `no_reference`

### expected_and_observed

The access assignment is expected by the Golden Source and observed in the snapshot. If stable identifiers exist, the match must be based on stable identifiers.

### unexpected

The access assignment is observed but not present in the selected Golden Source. This does not automatically mean malicious access; it means the current Golden Source does not expect it.

### missing

The Golden Source expects the assignment, but the authoritative import scope proves it is absent. This state must never be produced from partial, scoped or unknown collection alone.

### unknown_due_to_scope

The engine cannot safely prove whether the assignment is compliant or missing because the import scope/completeness is insufficient, or because a legacy Golden cannot prove object identity against stable observed data.

### no_reference

No Golden Source was provided. The observed assignment is inventory/review data, not unauthorized access.

---

## 13. Findings

Findings are separate from comparison states. They represent review-relevant conditions independent from whether an assignment is expected.

Current findings:

- `disabled_with_access`
- `deleted_with_access`
- `account_locked`
- `account_expired`
- `technical_account_without_owner`
- `shared_account_without_owner`
- `invalid_owner`
- `unknown_identity`
- `unresolved_foreign_principal`
- `collection_incomplete`
- `unknown_member_type`

Important rules:

- `unknown_identity` is only for unresolved identity references.
- `Identity.status == unknown` must not create `unknown_identity` by itself.
- `collection_incomplete` indicates the import cannot support authoritative absence conclusions.
- Findings must not be used to hide incorrect comparison logic.

---

## 14. Snapshots

A `Snapshot` is immutable review evidence. It captures:

- providers;
- identities;
- resources;
- accesses;
- access assignments;
- source import IDs;
- comparison states;
- checksum.

A snapshot is the basis of a campaign. Once a campaign is opened, later imports must not change what reviewers saw or decided.

Current cross-provider resolution rule:

- if authoritative unresolved assignments are resolved during persistence, the snapshot is created from the final authoritative assignment state;
- this keeps the database and snapshot consistent;
- it avoids artificial `unknown_identity` findings when an assignment has just been resolved.

---

## 15. Campaigns, Review Items And Decisions

Implemented campaign statuses:

- `draft`
- `open`
- `closed`
- `cancelled`

Opening a campaign creates review items from snapshot comparison rows.

Reviewer resolution order:

```text
access_owner -> account_owner -> campaign default reviewer -> campaign manager
```

A campaign cannot open if reviewers are unresolved unless `allow_unresolved_reviewers` is explicitly enabled.

Decision values:

- `approve`
- `revoke`
- `not_applicable`

Decision rules:

- `revoke` requires a comment;
- `not_applicable` requires a comment;
- closing a campaign requires all review items to have decisions;
- campaign promotion is blocked while decisions are pending.

The current model has `AuditEvent`, and service functions can create audit events, but a complete production-grade audit event for every sensitive operation is still roadmap work.

---

## 16. Remediation

The MVP generates remediation actions. It does not execute them.

Current remediation behavior:

- `unexpected` plus reviewer decision `revoke` produces a revoke remediation action;
- expected-but-missing plus reviewer decision `approve` produces a grant remediation action.

This keeps execution responsibility outside the core engine. Provider-specific remediation scripts or ticket integrations can consume the exported actions later.

---

## 17. Reporting

The main report is a standalone, filterable HTML file. Supporting outputs include CSV and JSON.

Current report artifacts:

```text
campaign-report.html
campaign-results.csv
campaign-results.json
remediation.csv
golden-source-diff.csv
```

The report groups review data around owners, services/accesses and identities. Dynamic values are escaped so imported descriptions or names cannot inject HTML/script content into the generated report.

---

## 18. Import And File Security

Current import security controls:

- source type read from `manifest.yaml`;
- ZIP filename allowlists;
- duplicate ZIP filename rejection;
- Zip Slip/path traversal rejection;
- file-count and size limits;
- declared uncompressed size limits;
- manifest validation;
- collection-error count consistency checks;
- LDIF change record rejection;
- no execution of imported archive content.

Current exporter safety controls:

- AD membership collection errors fail closed by default;
- AD partial output requires explicit opt-in;
- OpenLDAP exporter avoids sensitive password and binary-heavy attributes;
- OpenLDAP exporter rejects incompatible `ldaps://` plus StartTLS configuration.

Security principle:

```text
A broken or incomplete collection must produce uncertainty, not false compliance.
```

---

## 19. CLI And API

The CLI provides minimal administrative workflows. Current documented examples include:

```bash
access-review import corp-ad-export.zip
access-review findings-list
access-review import directory.ldif --provider internal-ldap
access-review campaign-export reports/
```

The API module exists as a thin interface layer. It is not yet a complete production API surface.

Future CLI/API work should expose more service operations without duplicating business logic in interface layers.

---

## 20. Test Coverage Reality

The test suite currently validates the critical safety behavior of the MVP.

Covered AD areas:

- ZIP import validation;
- recent AD extract shapes;
- SID-based identity reconciliation;
- SID-based access reconciliation;
- same-name/new-SID recreation behavior;
- disabled/unknown enabled states;
- locked and expired account findings;
- gMSA/MSA and computers as technical accounts;
- built-in account detection by SID/RID;
- primary group membership;
- Foreign Security Principal preservation;
- cross-domain SID resolution;
- full/scoped/unknown completeness behavior;
- provider-scoped assignment replacement.

Covered OpenLDAP areas:

- ZIP and raw LDIF import paths;
- supported object classes and group types;
- LDIF continuation, base64, attribute options and case handling;
- canonical DN resolution;
- escaped and multi-valued RDN handling;
- `entryUUID` identity/access reconciliation;
- same CN/new UUID recreation behavior;
- `member`, `uniqueMember` and `memberUid` resolution;
- ambiguous `memberUid` handling;
- authoritative scope tracking;
- reduced base DN/search scope/filter safety;
- unresolved cross-provider resolution;
- non-authoritative unresolved retention without authoritative replay.

Covered Golden/campaign/reporting areas:

- stable Golden comparison across rename;
- stable mismatch detection across recreation;
- legacy Golden conservative fallback;
- duplicate stable Golden key rejection;
- snapshot promotion guards;
- provider-scoped Golden promotion guard;
- campaign open/close rules;
- decision comment requirements;
- remediation generation;
- HTML report escaping and required sections.

---

## 21. Roadmap

### Phase 1 - Reliable Core

Current MVP mostly covers this phase:

- provider-neutral model;
- SQLite persistence;
- AD importer/exporter;
- OpenLDAP importer/exporter;
- Golden Source versions;
- comparison states;
- snapshots;
- campaigns;
- decisions;
- remediation export;
- standalone reporting;
- minimal CLI/API;
- safety tests for incomplete collection and stable IDs.

Remaining Phase 1 hardening:

- run Pester in a real Windows/PowerShell environment;
- run `ruff`, `mypy` and `shellcheck` with dev tools installed;
- add larger-volume performance tests;
- improve end-to-end CLI coverage;
- document operational deployment patterns.

### Phase 2 - UX And Additional Connectors

Potential future work:

- complete lightweight web UI;
- Entra ID connector;
- Keycloak connector;
- AWS IAM connector;
- GCP IAM connector;
- Google Workspace connector;
- Linux/database/application importers;
- reusable classification templates;
- richer report filters and exports.

### Phase 3 - Advanced Governance

Potential future work:

- recurring recertification;
- multi-stage reviews;
- reviewer delegation;
- reminders and SLA tracking;
- policy or risk-based review;
- plugin SDK;
- ITSM integration;
- optional controlled provisioning plugins.

Any extension must preserve the provider-neutral model and fail-closed comparison rules.

---

## 22. Non-Negotiable Invariants

These invariants must be preserved by every future change:

```text
Provider -> Identity -> AccessAssignment -> Access -> Resource
```

```text
Assignment origin belongs to AccessAssignment.
```

```text
AD SID and OpenLDAP entryUUID are stable native IDs.
```

```text
SamAccountName, cn, uid, DN and display names are mutable.
```

```text
Ambiguous matches stay unresolved or unknown.
```

```text
Non-authoritative observations cannot silently become authoritative current state.
```

```text
Legacy Golden data without stable IDs cannot prove object identity by name alone.
```

```text
MISSING requires authoritative scope.
```

```text
Without a Golden Source, observed access is no_reference, not unauthorized.
```

```text
Snapshots and Golden Source versions are immutable review evidence.
```

```text
Importing one provider must not destroy another provider's current state.
```

---

## 23. Residual Real-World Risks

The current implementation is ready for a controlled real AD/OpenLDAP pilot, but field validation is still required for infrastructure-specific risks:

- silent LDAP ACL omissions that hide entries from the collector;
- custom LDAP schemas and non-standard group membership attributes;
- very large directories and high-volume membership exports;
- complex multi-domain AD topologies;
- complex multi-directory LDAP topologies;
- operational Windows AD module differences not reproduced in local tests;
- organization-specific account classification policies.

These are not reasons to block a pilot, but they must be validated during pilot execution.

---

## 24. Readiness Verdict

The current branch satisfies the key safety criterion:

```text
No data coming only from a non-authoritative collection, and no legacy Golden assignment lacking stable identifiers, should be silently transformed into authoritative truth.
```

Current verdict:

```text
READY FOR REAL AD/OPENLDAP PILOT
```
