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

## 12. Campaign workflow, reports and remediation

The WebUI follows this workflow:

`Sources & IdPs → Synchronize → Golden Source → Campaigns → New campaign → Preview → Open → My Reviews → Campaign progress → Close → Remediation actions → Reports`

### Running a campaign step by step

Use this procedure when you need to run a normal access review from the WebUI.

#### 1. Prepare the observed state

1. Open **Sources & IdPs** and verify that every provider in scope is configured.
2. Select **Synchronize** and wait until the collection is complete. Do not start a campaign from a failed or incomplete collection unless the scope and its limitations are understood.
3. Open **Golden Source** and verify the expected access version that should be used as the reference. A campaign may be run without a Golden Source, but the result will then contain `No reference` findings rather than an expected-state comparison.

#### 2. Create the campaign

Open **Campaigns → New campaign**. Complete the five preparation steps:

1. **Scope** — enter the campaign name and choose **all authorized sources**, **selected providers**, or **selected accesses**. These choices keep their existing meaning.
2. **Observed state** — select the Snapshot to review. Check its date, identity and providers before continuing.
3. **Expected state** — select the Golden Source version, or explicitly choose **No Golden** when this is an observation-only review.
4. **Reviewers** — select the campaign pilot and resolve reviewers. The pilot coordinates the campaign; access owners and group/role owners remain the people who certify their assigned items.
5. **Preview & launch** — enter the due date and inspect the preview before opening.

The preview must be treated as a check, not as a save operation. It shows the scope, Snapshot, Golden version, review-item count, reviewer count, resolved and unresolved reviewers, important findings and whether opening is allowed. If the preview is not correct, go back and edit the draft.

#### 3. Preview versus open

**Preview** calculates what would be reviewed and does not create review evidence. **Open campaign** starts the campaign and freezes its evidence. Opening materializes the ReviewItems, resolves assignments and preserves the Snapshot and business context used by the reviewers. A later provider synchronization cannot rewrite what this campaign is reviewing.

Only open the campaign after checking:

- the selected providers and accesses;
- the Snapshot date and collection completeness;
- the expected Golden version;
- the number of review items;
- the resolved/unresolved reviewers;
- the due date and pilot.

#### 4. Run the review

Reviewers use **My Reviews**. For each assigned item, inspect the identity, source, access or group/role, application/target and expected versus observed state.

Choose one decision:

- **Approve** — keep the access as certified;
- **Revoke** — the administrator must remove the access, group membership or role;
- **Not applicable** — the item is outside the reviewer’s responsibility or scope.

**Revoke** and **Not applicable** require a reason. Reviewers can follow their pending count from **My Reviews**. The campaign pilot can follow total reviews, decided items, pending items, percentage complete, findings, due date, overdue status and the prominent **Who still has to decide** view from the campaign page.

#### 5. Close the campaign

When all required decisions are recorded, return to the campaign page and choose **Close campaign**. The confirmation explains that closing:

- stops further review decisions;
- freezes the campaign result and historical evidence;
- generates remediation actions;
- does not modify any provider.

A campaign with pending reviews cannot be closed. After closure, the result panel shows the number of decisions and generated remediation actions.

#### 6. Give administrators the remediation plan

Open **Actions** or the remediation section of the closed campaign. This is an operational queue, not the audit report. It answers: **what must be changed, where, for whom and why?**

Use the filters to isolate a provider, action, status or campaign. For example, an AD administrator can select `AD-CORP` and `REVOKE`. The queue uses the historical context captured when the campaign opened, including the source/provider, identity, access/group/role, application/target, permission, decision reason, decision maker and campaign.

Use **Download remediation CSV** to send the actionable list to technical administrators. Exporting an action changes its status to `exported` only where the existing lifecycle permits it; it does not mean that the provider change was completed.

#### 7. Read and distribute the final report

Open **Reports**, choose the closed campaign and select **View report**. The HTML report is displayed directly in the page. The available downloads are **HTML**, **PDF**, **CSV** and **JSON**.

The final campaign report is for governance, audit, compliance, RSSI, management and auditors. It contains campaign metadata, counts, expected/observed comparison, findings and review evidence including reviewer decisions and comments. It is deliberately different from the remediation plan; do not ask technical administrators to extract operational work from the audit report.

#### 8. Optional: promote decisions to Golden

From the closed campaign, **Promote decisions to Golden** creates a new immutable expected-state version based on the campaign decisions. It does not execute remediation, modify AD/LDAP/cloud/SaaS providers or prove that a technical change was applied.

Closing a campaign and promoting decisions are independent operations:

`Close campaign → create remediation actions`

`Promote to Golden → update the expected state`

Promotion is optional and must only be done after the pilot or governance owner confirms that the campaign decisions should become the next baseline.

The campaign screen makes the following steps visible:

1. **Prepare** — choose the scope, immutable observed Snapshot, optional Golden version, pilot and reviewers.
2. **Review** — reviewers certify each access as Approve, Revoke or Not applicable.
3. **Close** — once every review is decided, closing freezes the result and stops new decisions.
4. **Remediate** — closing generates operational actions for administrators. EARE never writes to AD, LDAP, AWS or SaaS providers.
5. **Report** — the final governance/audit report is available as an in-application preview and as HTML, PDF, CSV and JSON downloads.
6. **Update baseline** — optionally promote decisions to a new immutable Golden version.

Preview is non-persistent: it calculates what would be reviewed. Opening the campaign freezes the Snapshot evidence, materializes ReviewItems, resolves reviewers and captures historical business context. Later synchronizations do not rewrite that campaign.

The **Final Campaign Report** is evidence for governance, audit, compliance, management and auditors. The **Remediation Plan** is an operational queue for IAM, directory and application administrators. They are separate outputs; a report is not a remediation plan.

Promoting decisions to Golden is also separate from remediation. Promotion changes the expected state by creating a new immutable Golden version; it does not execute, verify or mark technical remediation as completed.

Review items include identity, access, expected/observed state, classification, findings, reviewer, decision and comment. Technical and business values from the Snapshot remain unchanged; only interface labels are translated.

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


## Golden Source Creation

A Golden Source can start empty for a from-scratch review or be created from a CSV reference file:

`bash
eare golden create baseline
eare golden create baseline --csv expected-access.csv
eare golden edit baseline --csv updated-access.csv
`

CSV files use the columns access_provider, access_name, identity_provider, and identity_identifier. Optional native identifier columns are supported for stable matching. Each CSV operation creates an immutable Golden Source version.

## Golden functional model (V2)

Golden Source versions can record what an Access is expected to grant as well as who should hold it. A functional right is a Target plus Capability, such as `Invoices / approve`; a capability alone is not an authorization identity. Native permissions such as `SELECT`, `member`, and `s3:GetObject` retain their technical meaning.

## Language selection

The WebUI language is selected from the current-user menu. Available languages are English, Français, Español, Português, Italiano and العربية. English is used by default and whenever a translation is unavailable. The choice applies immediately and is persisted as a browser UI preference only; business data, technical values and user-entered comments are never translated. Arabic switches the interface to right-to-left layout.

# EARE Guide

EARE Guide is an optional, deterministic helper available from the authenticated header. It explains what is ready, what is missing, and the next authorized EARE screen for the current role and scope. It is guidance, not authorization: it cannot grant permissions or execute governance actions.

The Guide is role-aware. Administrators are guided toward environment configuration and handing campaign governance to an Operator; Operators are guided through collection, Golden Source preparation, and campaigns; Group owners see their assigned reviews; Business Administrators and Remediation Managers see only authorized operational actions. Source and campaign scope filtering is enforced by the backend.

The first introduction can be skipped, and the Guide can be disabled from its drawer. EARE derives progress from current data rather than storing a wizard step. It never modifies a source system or performs a business decision automatically.
