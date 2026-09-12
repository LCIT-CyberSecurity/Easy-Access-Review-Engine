# EARE Engineering Design

## 1. Purpose and design boundary

Easy Access Review Engine (EARE) is an access review and recertification engine. It observes
access assignments, compares them with an optional Golden Source, opens review campaigns, records
decisions and produces evidence/remediation exports.

The core deliberately does not evaluate every provider's native authorization language. Provider
specific conditions, policy statements, deny rules, boundaries, SCPs, PIM state and other native
details remain available in `Origin.raw` or `metadata` when they are needed for traceability.

The design goal is:

```text
The smallest model that can represent real access certification cases
without silently losing identity, scope, provenance or review meaning.
```

AD and OpenLDAP are the integrated connectors. AWS, Azure, GCP, Entra ID, Keycloak, Kubernetes and
GitHub are model stress-test domains only in this V1 scope.

## 1.1 Synthetic Schemas

### Model objects

```text
Provider
  +-- Identity --+                          +-- Target?
  |              +-- AccessAssignment ----> Access --+-- Permission?
  +--------------+                          +-- ControlObject?
                                                   |
                              AccessRelation grants +--> Access
```

### Certification

```text
AD/OpenLDAP importers
          |
          v
Observed state -> immutable Snapshot -> Golden comparison
                                      |
                                      v
                              Campaign / ReviewItem
                                      |
                                      v
                              Decision / Report / Remediation
```

### CRM: direct versus effective

```text
Emma --direct--> CRM-Sales --grants--> contacts:read
                              \-------> contacts:write

Golden:   Emma -> CRM-Sales
Effective: Emma -> CRM-Sales -> contacts:read + contacts:write
```

## 2. System context

```text
+--------------------+       +-----------------------+
| AD / OpenLDAP      | ----> | ImportResult          |
| exporters or LDIF  |       | normalized observations|
+--------------------+       +-----------+-----------+
                                        |
                                        v
                              +-----------------------+
                              | Application           |
                              | scope/completeness   |
                              | reconciliation        |
                              +---+---------------+---+
                                  |               |
                   +--------------+               +----------------+
                   v                                               v
          +------------------+                            +------------------+
          | SQLite Repository|                            | Domain Services  |
          | JSON payloads    |                            | comparison       |
          | explicit tables  |                            | effective graph  |
          +--------+---------+                            +--------+---------+
                   |                                               |
                   v                                               v
          +------------------+                            +------------------+
          | Snapshot         | -------------------------> | Campaign         |
          | immutable state  |                            | ReviewItem       |
          +--------+---------+                            | Decision         |
                   |                                        +--------+---------+
                   v                                                 |
          +------------------+                                       v
          | Golden Source    |                            +------------------+
          | versioned expected|                            | Reports /         |
          | direct assignments|                            | Remediation /     |
          +------------------+                            | Audit             |
                                                          +------------------+
```

## 3. Module responsibilities

### `domain.py`

Defines provider-neutral entities, value objects, enums, stable serialization and checksums.
Business rules that describe the shape of the model belong here, not in importers.

### `importers/`

Translate trusted offline exports into `ImportResult` objects. AD and OpenLDAP importers preserve
native identifiers, raw provenance and collection limitations. They do not write SQLite directly
and do not calculate review findings.

### `application.py`

Orchestrates import persistence. It applies provider scope and completeness, reconciles identities,
Access objects, assignments and relations, retains non-authoritative unresolved observations and
creates a snapshot from the resulting state.

### `services.py`

Contains effective-access traversal, comparison states, Golden Source versioning, campaigns,
decisions, remediation and owner/finding rules. It operates on domain objects and stays independent
from ZIP, LDIF and SQLite details.

### `storage.py`

Provides the current SQLite repository. Payloads are canonical JSON, while tables and indexes keep
future relational boundaries explicit. Hydration functions preserve legacy optional fields.

### `reporting.py`

Builds HTML, CSV and JSON evidence. Dynamic values are escaped and sensitive authentication fields
are allow-listed. Missing authentication observations are rendered explicitly as `Not collected`.

### `authentication.py`

Compares AuthenticationPosture independently from authorization. AuthenticationPosture is collected
by AD/OpenLDAP importers and carried through snapshots and Golden policies without being merged into
Access or AccessRelation.

## 4. Core object model

```text
Provider
  +--> Identity(provider, identifier, native_id, status, type)
  +--> Access(provider, name, control_object?, target?, permission?, metadata)

Identity + Access
  +--> AccessAssignment(origin, direct observation)

Access(parent) + Access(child)
  +--> AccessRelation(type=grants, origin, metadata)

Assignments + Relations
  +--> EffectiveAccessEvaluation
        +--> EffectiveAccess
              +--> AccessPath(s)
```

### Access semantics

An Access is an entitlement that can be observed, compared and certified. It may be:

```text
Opaque:       PREMIUM_USER       target=null       permission=null
Composite:    CRM-Sales          target=null       permission=null
Target-only:  Contacts            target=Contacts   permission=null
Fine-grained: Contacts:Read       target=Contacts   permission=read
Provider-specific:
              FinanceBucket:GetObject
              target=arn:aws:s3:::finance/*
              permission=s3:GetObject
```

`Target` is optional and identifies a real target supplied by the provider. `Permission` is
optional, singular and provider-specific. `ControlObject` describes the object represented by the
Access when that object exists. No universal permission enum is required.

### Direct versus effective

```text
Alice --direct AccessAssignment--> CRM-Sales
CRM-Sales --AccessRelation grants--> Contacts:Read

DIRECT:   CRM-Sales
EFFECTIVE: CRM-Sales, Contacts:Read
```

Effective Access is calculated and retains one or more provenance paths. Derived rights are never
persisted as direct AccessAssignment objects.

### Access identity and collision policy

The historical logical key remains `(provider, name)` for SQLite and legacy compatibility. Stable
provider identifiers help reconcile renames, for example an AD SID or OpenLDAP `entryUUID`, but a
native ID is not automatically a universal Access identity.

Reconciliation is conservative:

```text
existing target=null, permission=null
incoming target=Contacts, permission=read
                         => enrich existing Access

existing target=Contacts, permission=read
incoming target=null, permission=null
                         => retain known values

existing target=Contacts, permission=read
incoming target=Invoices, permission=read
                         => ACCESS_DEFINITION_COLLISION
```

Known incompatible target or permission values are never silently overwritten or merged.

## 5. Import and reconciliation flow

```text
archive/LDIF
    |
    v
ImportResult
    +-- provider
    +-- identities
    +-- accesses
    +-- direct assignments
    +-- direct relations or None
    +-- AuthenticationPosture
    +-- ImportBatch(scope, completeness)
    |
    v
provider scope normalization
    |
    +-- FULL: replace authoritative state in scope
    +-- SCOPED: update only declared scope
    +-- UNKNOWN: retain authoritative state
    |
    v
reconcile identities/accesses/assignments/relations
    |
    v
persist current state + append immutable snapshot
```

`access_relations = None` means the collector does not provide graph information and must not alter
known authoritative relations. `access_relations = []` from an authoritative full graph means the
observed graph is explicitly empty and current relations in that provider scope may be removed.
Snapshots are different: an empty relation list is a valid frozen state, and an old snapshot without
the field hydrates as empty for backward compatibility.

A non-authoritative relation observation is additive: observed relations may be added or refreshed,
but relations absent from a scoped, partial or unknown observation are retained. The same conservative
delete rule applies to identities and direct assignments. `persist_import_result` wraps the provider,
import batch, business objects and immutable snapshot in one SQLite transaction. A rejected import
therefore records no successful ImportBatch and leaves no partial business state.

## 6. Effective graph design

Only direct `AccessRelation(type=grants)` edges are stored. Traversal starts at direct assignments.
The traversal:

- uses stable sorted input and output ordering;
- deduplicates effective Access by identity and Access reference;
- keeps all provenance paths up to a configured path limit;
- detects a repeated Access within the current path;
- emits a deterministic cycle diagnostic and stops that path;
- reports orphan relations without materializing them;
- supports multi-level composition and multiple paths.

Example:

```text
Alice -> CRM-Manager -> CRM-Sales -> Contacts:Write
```

If both `CRM-Sales` and `CRM-Support` grant `Contacts:Read`, the result contains one effective
Access with two paths. If role composition changes while an assignment remains unchanged, the
change appears in the effective-access diff as composition drift.

## 7. Golden Source and campaign design

```text
Observed direct assignments + current graph
                    |
                    v
              Immutable Snapshot
                    |
                    +--> compare direct assignments with Golden version
                    |
                    v
                 Campaign
              + ReviewItem
              + Decision
              + remediation export
                    |
                    v
              new Golden version
```

The Golden Source primarily certifies direct expected assignments:

```text
Golden expected: Alice -> CRM-Sales
```

It does not expand automatically into:

```text
Alice -> Contacts:Read
Alice -> Contacts:Write
```

Those rights are derived from the current relation graph. A campaign can therefore review role
composition drift while retaining the original direct expectation. Golden versions, snapshots,
review items and decisions preserve their historical state; later imports do not mutate what a
reviewer saw.

## 8. Persistence and compatibility

The repository uses SQLite with canonical JSON payloads and explicit tables for providers,
identities, accesses, assignments, relations, imports, snapshots, Golden versions, campaigns,
review items, decisions and remediation actions.

Compatibility rules:

- no destructive migration is introduced by model hardening;
- the logical Access key remains `(provider, name)`; `native_id` does not create a second key dimension;
- incompatible definitions under one logical key raise `ACCESS_DEFINITION_COLLISION`;
- permission is optional and absent permission is serialized as absent, never as an implicit `member`;
- legacy Access without target or permission remains readable;
- legacy snapshots without `access_relations` remain readable;
- legacy Golden assignments remain name-based when stable identifiers are absent;
- direct Golden assignments remain direct after reload;
- serialization and checksums use stable ordering;
- AccessRelation duplicates are rejected or deduplicated by their semantic relation key.

## 9. Security boundaries

- Do not persist or render passwords, tokens, API keys, private keys or password hashes.
- Do not dump arbitrary provider metadata in diagnostics.
- Validate ZIP names, sizes and archive members before import.
- Treat unresolved, scoped and unknown observations conservatively.
- Do not turn a partial collection into deletion, missing access or revoke.
- Keep authorization model data separate from AuthenticationPosture.
- Escape report values and neutralize spreadsheet formulas in CSV exports.

## 10. Verification strategy

The repository's CrashTests-CRM exercise the core composition model with baseline, wrong/missing role,
multiple roles, direct permission, role composition, drift, multipaths, cycles, disabled/deleted
identities, rename, technical/shared accounts, scopes, snapshots, Golden, campaigns, remediation
and persistence.

The pre-hardening baseline was `204 passed, 0 failed, 7 skipped`. The current implementation work
adds dedicated P1 import tests and is not considered releasable while the historical AD test that
relies on two same-key Access objects remains unresolved.

AD and OpenLDAP tests cover the integrated connectors. Future-provider scenarios are deterministic
model fixtures only; no AWS, Azure, GCP, Entra ID, Keycloak, Kubernetes or GitHub connector is
implemented.

## 11. V1 decision and known limitation

The current hardening result is GO for the V1 core model. Same-name AD object recreation is handled
by replacing the current Access under the unique `(provider, name)` key, while a stable native ID
continues to preserve rename reconciliation. Incompatible target or permission definitions are
rejected explicitly. The full suite is `229 passed, 0 failed, 7 skipped`; the skips require external
PowerShell or Docker environments.
