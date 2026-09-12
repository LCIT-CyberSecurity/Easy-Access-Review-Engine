# EARE User Guide

## 1. What EARE Does

Easy Access Review Engine helps answer three operational questions:

1. What access is currently observed?
2. Does that access match what is expected?
3. What should be approved, investigated, removed, or documented?

EARE stores observations, compares them with an optional Golden Source, opens review campaigns, preserves decisions, and generates reusable reports for audit and remediation. It is built to reduce manual spreadsheet work, shorten review cycles, improve evidence quality, and make access reviews repeatable.

You can feed EARE in two ways:

- import an existing export produced by another trusted process;
- use direct read-only access to the IDP through the provided collectors, then import the generated artifact.

Both paths use the same normalization, reconciliation, Golden Source comparison, campaign, and reporting engine.

## 2. Core Concepts

```text
Provider
  +-- Identity --------------------+
  |                                |
  +-- Access                       +-- direct AccessAssignment
        +-- Target?                |
        +-- Permission?            v
        +-- Origin / metadata    Access
                                  |
                     AccessRelation: grants
                                  |
                                  v
                         effective access + provenance

Snapshot -> Golden Source -> Campaign -> Decision -> Report
```

- `Provider` identifies the source, such as `corp-ad` or `ldap-prod`.
- `Identity` is the reviewed subject: user, group, service account, shared account, or technical account.
- `Access` is the entitlement being reviewed: group membership, role, permission set, or fine-grained permission.
- `AccessAssignment` says who directly holds an Access.
- `AccessRelation` explains what one Access grants to another Access.
- Effective access is calculated from assignments and relations; it is not stored as fake direct access.

## 3. Golden Source

The Golden Source is the expected access baseline. It is optional, versioned, and immutable per version.

It can be created from:

- an existing access configuration or reference baseline;
- a CSV file maintained by IAM, application owners, or auditors;
- a from-scratch baseline built progressively from reviewed observations.

This lets teams start with what they already have, then improve quality over time without blocking the first review campaign.

It lets EARE classify observed access as:

```text
expected_and_observed   expected and present
unexpected              present but not expected
missing                 expected but absent from an authoritative collection
unknown_due_to_scope    no safe conclusion because collection is scoped or unknown
no_reference            observed without any Golden Source reference
```

Stable native identifiers, such as AD SID or OpenLDAP `entryUUID`, let EARE keep matching across reliable renames without turning those identifiers into new business keys.

## 4. CLI Overview

The CLI is designed to simplify day-to-day operations. It wraps the existing EARE engine so operators can configure connectors, collect evidence, import artifacts, run analysis, manage Golden Source versions, and export reports with clear commands instead of manual scripting.

The recommended command name is:

```bash
eare
```

The compatibility alias remains:

```bash
access-review
```

Available command groups:

```bash
eare provider ...
eare analyze ...
eare golden ...
eare campaign ...
eare export ...
```

Current compatibility commands include:

```bash
access-review validate <file>
access-review import <file>
access-review findings-list
access-review identities-list
access-review access-effective <identity>
access-review campaign-export <output-dir>
```

## Interactive Menu

Run eare without arguments in a terminal to open the human-friendly menu:

Easy Access Review Engine

1. Providers
2. Analyze
3. Golden Source
4. Campaigns
5. Exports
6. Quit

The menu calls the same command handlers as direct CLI usage. In CI, pipes, and other non-interactive contexts, eare without arguments prints help and exits instead of waiting for input.

Provider workflows use the canonical namespace:

eare provider list
eare provider init corp-ad --type active_directory
eare provider setup
eare provider check --all
eare provider sync corp-ad
eare provider sync corp-ad --dry-run

## 5. Configuration, Secrets, and State

EARE separates configuration, secrets, and business state:

```text
YAML connector files  -> provider configuration
.env / environment    -> secrets
SQLite database       -> EARE state: imports, snapshots, Golden Source, campaigns, decisions
```

Connector YAML files should describe provider settings only. They must not contain passwords, tokens, private keys, API keys, or client secrets.

Secrets belong in environment variables or local files referenced by environment variables. For OpenLDAP, the exporter supports `LDAP_PASSWORD` and `LDAP_PASSWORD_FILE`.

## 6. Check, Collect, Sync, Import

EARE supports both operating models:

- **offline import**, when you already have an export file;
- **direct read-only IDP access**, when EARE can query the provider through the existing collector/exporter.

The CLI commands are available shortcuts around the same engine, not a second implementation.

### check

`check` is diagnostic. It validates configuration and, when supported, asks the existing collector to verify the provider. It must not modify SQLite or the provider.

```bash
eare provider check corp-ad
eare provider check ldap-prod
```

Running `check` is useful, but it is not required before `sync`.

### collect

`collect` uses direct read-only IDP access through the existing exporter and writes an artifact. It does not import into SQLite. Use it when collection and import are separated by process, approval, or change-control requirements.

```bash
eare provider collect corp-ad --output /tmp/corp-ad.zip
eare provider collect ldap-prod --output /tmp/ldap-prod.zip
```

### import

`import` loads an existing artifact into EARE by calling the application import engine. Use it when the evidence already exists as a ZIP, LDIF, CSV-derived artifact, or another supported extraction.

```bash
eare provider import corp-ad-export.zip
eare provider import directory.ldif --provider ldap-prod
```

The import path reuses `import_file_to_repository(...)`; the CLI must not reimplement reconciliation.

### sync

`sync` is the main operator workflow for repeatable direct read-only IDP collection. It combines configuration, collection, and import:

```bash
eare provider sync corp-ad
eare provider sync ldap-prod
eare provider sync --all
```

Multi-provider sync is sequential. If one provider fails, previous successful providers remain processed; there is no global multi-provider transaction.

## 7. Dry Run

`--dry-run` does not simulate changes to AD or LDAP. EARE collectors are already read-only.

For EARE, dry-run means:

```text
perform the real read-only collection
parse and normalize the real artifact
run the real import and reconciliation engine
show what would change in EARE
leave the real SQLite database unchanged
```

The safe MVP strategy is to run the real engine against an isolated temporary SQLite database copy. If the real database does not exist yet, EARE can dry-run against a temporary empty database and report what would be created.

Examples:

```bash
eare provider import corp-ad-export.zip --dry-run
eare provider sync corp-ad --dry-run
eare provider sync --all --dry-run
```

For scoped or unknown collections, dry-run must preserve the same safety rules as real imports: no false deletion, no false missing access, and no authoritative conclusion outside the observed scope.

## 8. Analyze

`analyze` is local only. It reads existing EARE state and must not contact AD, LDAP, or any connector.

```bash
eare analyze
eare analyze --provider corp-ad
eare analyze --identity alice
eare analyze --access Finance
```

If no snapshot exists, the CLI explains that no local analysis is available and suggest `eare provider sync <provider>` or `eare provider import <file>`.

## 9. Active Directory Collection

Use the existing exporter; do not reimplement AD collection in Python. The exporter performs read-only queries and produces an artifact that EARE imports through the same engine as offline files.

```powershell
.\export-active-directory.ps1 `
  -ProviderName corp-ad `
  -Output corp-ad-export.zip `
  -Server dc01.corp.local `
  -OperationTimeoutSeconds 300
```

`-AllowPartial` allows a diagnostic export after collection errors. It does not make the collection authoritative and must not be used to infer deletion.

## 10. OpenLDAP Collection

Use the existing shell exporter; do not reimplement LDAP collection in Python. The exporter performs read-only LDAP queries and produces an artifact that EARE imports through the same engine as offline files.

```dotenv
LDAP_URI=ldaps://ldap.example.test
BASE_DN=dc=example,dc=test
PROVIDER_NAME=ldap-prod
PAGE_SIZE=500
CONNECTION_TIMEOUT_SECONDS=10
SEARCH_TIMEOUT_SECONDS=60
SEARCH_SCOPE=sub
LDAP_FILTER=(objectClass=*)
```

Authenticated bind requires LDAPS or StartTLS. TLS verification remains strict. `ALLOW_PARTIAL=1` keeps a diagnostic artifact after an error, but completeness becomes conservative.

## 11. Completeness and Scope

Collection completeness drives safety:

| State | Meaning |
| --- | --- |
| `FULL` | absence can replace authoritative state inside the declared scope |
| `SCOPED` / `PARTIAL` | only observed objects inside the scope are updated |
| `UNKNOWN` | existing knowledge is preserved; no implicit deletion |

A scoped or unknown collection must never erase objects outside scope or produce certain missing access for unobserved data.

## 12. Campaigns and Reports

A campaign is opened from an immutable snapshot. Later imports do not mutate what reviewers saw.

Review items include identity, access, expected/observed state, classification, findings, reviewer, decision, and comment.

Reports include:

- campaign result HTML;
- CSV and JSON exports;
- findings and classifications;
- reviewer decisions;
- remediation exports.

EARE exports remediation evidence. It does not apply remediation directly to directories.

## 13. Security Notes

Never put secrets in connector YAML, exports, snapshots, reports, or diagnostics.

Collection errors should be treated as incomplete evidence, not proof that access is absent.

EARE improves review reliability by preserving provenance and using conservative behavior for incomplete data.


## Remediation Exports

After decisions have been recorded, export review-driven remediation actions without changing the provider:

`bash
eare export revocations --output reports/revocations.csv
`

The export is generated through the existing remediation service. EARE never applies revocations directly to an IDP.
