# EARE Current Implementation Specification

**Status:** current implementation and integration-test specification  
**Date:** 2026-09-25  
**Branch:** `feat/eare-guided-assistant`

This document records the behavior that must remain true for the current EARE
WebUI, API, OpenLDAP integration, Golden V2 editor, EARE Guide and Reports
workspace. It complements the provider-neutral model specification and the
Golden V2 specification; it does not replace `domain.py` or redefine any stable
domain key.

## 1. Scope and non-goals

EARE collects observed evidence, stores immutable Snapshots, compares
observations with an expected Golden Source, runs campaigns, records review
decisions, creates remediation actions and presents governance evidence.

The current implementation does not:

- modify LDAP, Active Directory, applications, cloud providers or databases;
- execute remediation from Reports;
- treat a report deliverable as the Reports WebUI;
- replace canonical Identity, Access, Permission, Capability, Target, Snapshot,
  assignment, relation, campaign or decision semantics;
- store source passwords in connector YAML, Snapshots, Golden versions or
  report artifacts.

## 2. Runtime topology

The supported Docker topology is:

```text
browser :4173
    -> eare-webui (Nginx static WebUI and /api proxy)
    -> eare-api :8000
       -> SQLite /data/access-review.db
       -> read-only collector/exporter
       -> OpenLDAP over LDAPS or StartTLS
```

The WebUI does not need direct LDAP network access. The API container needs a
connector file, the referenced runtime secret, the LDAP CA bundle when needed,
Docker DNS/network access to LDAP, and `ldapsearch`, `bash`, `zip` and the
collector runtime.

The integration URL is normally `http://vm-integrations:4173`. Port `4174` is
a separate optional integration stack and must not be treated as the latest
version unless its containers are explicitly running.

## 3. OpenLDAP connector contract

An OpenLDAP source is configured as follows:

```yaml
provider: crashtest-ldap
type: openldap
connection:
  uri: ldaps://crashtests-ldap:636
  base_dn: dc=example,dc=test
  bind_dn: cn=svc-eare,ou=services,dc=example,dc=test
collection:
  search_scope: sub
  page_size: 1000
  connection_timeout: 10
  search_timeout: 120
  command_timeout: 180
  allow_partial: false
credentials:
  password_env: EARE_LDAP_PASSWORD
```

These values are an integration example, not production credentials. The
password is injected into the API process and is never placed in the connector
file. Authenticated clear-text LDAP is rejected. LDAPS and StartTLS cannot be
combined. Certificate and hostname verification are strict.

The connector test and synchronization paths use the same collector. A
successful connection test proves network, TLS, bind and collector startup;
only synchronization proves that the resulting artifact can also be imported.

## 4. Synchronization state machine

The WebUI `Synchronize` action calls:

```text
POST /api/sources/{provider}/sync
  -> QUEUED
  -> RUNNING / Collecting read-only source data
  -> RUNNING / Importing and creating Snapshot
  -> SUCCEEDED with snapshot_id
```

Failures are retained as `FAILED` job state with an operator-visible error.
Temporary artifacts are deleted in a `finally` block. A successful sync creates
an immutable Snapshot; it does not edit an existing Snapshot and does not write
to the source.

The importer is the same application service used by offline imports. There is
no second remote business engine and the FastAPI route does not invoke the CLI.

## 5. SQLite concurrency contract

SQLite is the current MVP state store. The WebUI can issue several read
requests concurrently while a user queues synchronization. Schema initialization
and the web-job queue therefore use a bounded busy timeout. Short write
contention is waited out rather than returned as an immediate HTTP 500.

This is contention tolerance, not database repair. Persistent locks require
checking for a second process using the data volume, unfinished transactions,
disk errors and container health. API and worker connections must be closed
through their existing context managers.

## 6. Golden V2 functional editor

The editor state is the API payload, not legacy mono-right fields:

```text
rights[]
grants[]
completeness
version_comment
access identifiers
```

Save eligibility validates every direct functional right:

- `capability_id` is non-empty;
- the Target has at least one of `service`, `component` or `resource`;
- every present Target node has a non-empty identifier.

An empty `rights` list is allowed for `not_defined` when accepted by the
backend. `PARTIAL` and `COMPLETE` follow existing backend validation and
comparison semantics. Adding a right creates one editable row; removing a
right removes only that row; unrelated rights remain unchanged.

`native_permission` is preserved when an existing right is loaded and saved. A
validated expected right may be normalized to `MANUAL` provenance because a
human validated the expected state. Native evidence is retained:

```text
human validation -> expected provenance MANUAL
native permission -> retained as evidence, for example SELECT
```

## 7. Golden availability and Guide scope

An Administrator can use an active Golden version regardless of provider scope.
For an Operator, availability is derived from current expected content:

- assignment access and identity providers;
- expected Access definition providers;
- expected relation parent and child providers;
- functional model and Access comment providers when present.

Historical `source_type=from_scratch` or an old `source_snapshot_id` is not an
authorization grant. An empty from-scratch version has no safe provider scope
and is not broadened to every Operator. A from-scratch version that later
contains an in-scope `crm` expected right remains available after a manual
descendant version is created.

## 8. Reports workspace contract

Reports is a native EARE governance/restitution screen. It reads existing
campaign-results and remediation APIs and contains:

- campaign selector and campaign profile;
- executive KPIs;
- deterministic observations;
- observed/expected outcome classifications;
- separate review decisions: Approved, Revoked, Not applicable and Pending;
- remediation counts and a human-first action preview;
- coverage and traceability evidence;
- detailed results with search, filters, sorting and pagination.

The remediation preview is not semantically capped: totals come from the full
filtered action set, while a compact table may show only a preview. `Exported`
is not `Completed`. The Actions page remains the operational follow-up screen.

Standalone HTML/PDF/CSV/JSON endpoints remain deliverables. The Reports page
must never render them with an iframe, object, embed, injected generated HTML
or PDF preview.

## 9. Security and data handling

Source credentials are runtime configuration, not business data. Logs and
diagnostics must redact configured passwords. LDAP collection is read-only and
TLS validation fails closed. Provider scope is enforced server-side for source,
Golden, campaign, review, action and report access. UI visibility is never a
substitute for API authorization.

Snapshots and Golden versions remain immutable evidence. A later synchronization
creates new observed evidence and cannot rewrite a campaign already opened
against an earlier Snapshot.

## 10. Required regression checks

The implementation is conformant only when the following are checked:

- an authenticated OpenLDAP bind succeeds over the configured TLS endpoint;
- a real collector run produces an artifact and the existing importer creates a
  Snapshot with identities and accesses;
- a WebUI synchronization survives concurrent page refresh requests;
- Golden V2 multi-right Save validates `rights[]` and retains
  `native_permission`;
- a from-scratch-to-manual Golden descendant remains available only when its
  current provider content is in Operator scope;
- Reports contains native restitution sections and no embedded report;
- HTML, PDF, CSV and JSON standalone exports remain available;
- `src/access_review_engine/domain.py` remains unchanged.
