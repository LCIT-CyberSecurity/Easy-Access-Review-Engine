# Easy Access Review Engine

**Easy Access Review Engine (EARE)** is an open source, universal access review system.

It helps IAM, SecOps, audit, and compliance teams turn technical access evidence into reliable, traceable, automated reviews.

EARE helps you:

- collect identities, groups, roles, entitlements, and access relationships;
- work either from an existing export or from direct read-only access to the IDP through the provided collectors;
- normalize heterogeneous sources into a common model that is independent from any single IDP;
- compare observed access with a versioned **Golden Source**;
- detect unexpected, missing, incomplete, or risky access;
- calculate effective access from groups, roles, and access relations;
- generate automated HTML, CSV, and JSON reports for audit and remediation;
- run access review campaigns and preserve decisions over time.

The goal is practical: save a lot of manual review time, improve reliability, reduce spreadsheet-driven errors, accelerate audit preparation, and strengthen operational security.

## Why EARE?

Access reviews are often slow, fragile, and tied to manual exports. The same questions keep coming back:

```text
Who has access to what?
Is this access expected?
Why does this access exist?
What should be approved, investigated, or removed?
```

EARE provides a common engine for those questions, whether the source is Active Directory, OpenLDAP, a business application, an IAM platform, a SaaS tool, or a future connector.

The core is intentionally IDP-agnostic:

- a Provider represents the source;
- an Identity represents the subject;
- an Access represents the entitlement;
- an AccessAssignment represents direct assignment;
- an AccessRelation represents groups, roles, and access composition.

This makes EARE useful across environments instead of locking review logic to one directory or one vendor.

## Golden Source

The Golden Source describes the expected access state.

It can be built from several starting points:

- an existing configuration or access baseline already maintained by the organization;
- a CSV file prepared by IAM, application owners, or auditors;
- a clean from-scratch baseline created progressively from reviewed observations.

It is:

- versioned;
- immutable per version;
- comparable with observed snapshots;
- resilient to reliable renames when the source provides a stable native identifier, such as an Active Directory SID or an OpenLDAP `entryUUID`.

EARE can distinguish:

- expected and observed access;
- unexpected access;
- expected but missing access;
- unknown cases caused by scoped or incomplete collection.

## Automated Reporting

EARE produces reports that can be shared directly with auditors, reviewers, and remediation teams:

- standalone HTML report;
- CSV export;
- JSON export;
- access deviations;
- security findings;
- campaign results;
- remediation exports.

Reports preserve the full review trail: observation, comparison, reviewer, decision, comment, and status.

## Flexible Collection

EARE is designed to fit real operating constraints. You can use it in two complementary ways:

1. **Start from an existing extraction**
   - import an Active Directory ZIP;
   - import an OpenLDAP ZIP;
   - import an OpenLDAP LDIF;
   - reuse exports produced by another secured process.

2. **Use direct read-only access to the IDP**
   - connect to Active Directory with a read-only account;
   - connect to OpenLDAP with a read-only bind account;
   - use the provided collectors as the acquisition layer that turns those read-only queries into importable artifacts;
   - keep collection accounts separate from remediation or administration accounts.

This makes adoption easier: teams can begin with offline files, then move to repeatable read-only collection when they are ready. Collectors are read-only. EARE observes, compares, supports decisions, and exports remediation evidence. It does not provision accounts and does not modify directories.

## CLI

The CLI is the user-facing orchestration layer for the EARE engine. It is there to make daily work faster: initialize connector configuration, run checks, collect evidence, import data, analyze results, manage the Golden Source, and export reports without manually wiring each step.

The target interface is:

```bash
eare config ...
eare check ...
eare collect ...
eare sync ...
eare import ...
eare analyze ...
eare golden ...
eare campaign ...
eare export ...
```

The legacy alias remains available:

```bash
access-review ...
```

Main command groups:

- `config` manages connector YAML files;
- `check` diagnoses a connector without changing EARE state;
- `collect` runs a read-only collector and writes an artifact;
- `sync` runs collection plus import;
- `import` imports an existing extraction;
- `analyze` analyzes local EARE state without contacting a provider;
- `golden` manages the Golden Source;
- `campaign` manages review campaigns;
- `export` produces reports and remediation exports.

`--dry-run` is for import and sync workflows. It runs the real engine against an isolated temporary database copy to explain what would change, while leaving the real EARE database untouched.

## Quick Start

The fastest useful path is: install EARE, choose where evidence comes from, import it, inspect the first findings, and optionally create a Golden Source baseline.

### 1. Install the CLI

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[app]"
access-review --help
```

By default EARE stores its local state in `access-review.db`. To use another database file, pass `--db` before the command:

```bash
access-review --db eare-prod.db import corp-ad-export.zip
```

### 2. Choose the evidence source

Use an existing export when another process already extracts the data:

```bash
access-review validate corp-ad-export.zip
access-review import corp-ad-export.zip
```

Or use direct read-only IDP access to produce an importable artifact.

Active Directory example:

```bash
pwsh ./exporters/active-directory/export-active-directory.ps1 \
  -ProviderName corp-ad \
  -Output corp-ad-export.zip \
  -Server dc01.corp.local

access-review import corp-ad-export.zip
```

OpenLDAP remote read-only example:

```bash
export LDAP_URI=ldaps://ldap.example.com:636
export BASE_DN=dc=example,dc=com
export PROVIDER_NAME=ldap-prod
export BIND_DN=cn=eare-readonly,ou=service-accounts,dc=example,dc=com
export LDAP_PASSWORD_FILE=/run/secrets/eare-ldap-readonly-password

./exporters/openldap/export-openldap.sh
access-review import ldap-prod.zip --provider ldap-prod
```

In this example EARE connects remotely to the IDP with a dedicated read-only bind account. The password value stays outside the command line and outside the repository; only the file path is referenced. Secrets belong in environment variables, `.env`, or secret-mounted files, never in connector YAML, reports, or SQLite.

### 3. Inspect results immediately

```bash
access-review findings-list
access-review identities-list --provider corp-ad
access-review access-effective alice --provider corp-ad
```

These commands help you move quickly from raw directory data to reviewable evidence: identities, observed access, findings, and effective access paths.

### 4. Optional: create a Golden Source baseline

A Golden Source is optional, but it is what turns EARE from inventory into expected-vs-observed review.

You can build it from:

- an existing access reference or application configuration;
- a CSV maintained by IAM, application owners, or auditors;
- a from-scratch baseline created by importing reality, reviewing it, then promoting the validated snapshot or campaign.

Recommended first rollout:

```text
import current evidence
review findings with owners
approve the expected access
promote the reviewed baseline into Golden Source v1
run the next import against that Golden Source
```

The Golden Source workflow is described in [Golden Source](docs/golden-source.md). If you start without a Golden Source, EARE still saves time by producing inventory, findings, effective access, and reports; comparison states become more powerful once the baseline exists.

### 5. Export a report

When a campaign exists, export the review evidence:

```bash
access-review campaign-export reports/
```

`reports/campaign-report.html` is standalone and opens without a backend.

## Documentation

- [User Guide](docs/user-guide.md)
- [Architecture and Engineering](docs/engineering.md)
- [Golden Source](docs/golden-source.md)
- [Active Directory](docs/active-directory.md)
- [OpenLDAP](docs/openldap.md)

The user guide covers configuration, collection, import, sync, dry-run, local analysis, Golden Source, campaigns, and reporting.

## Active Directory Support

The Active Directory V1 connector targets recent AD DS environments through the PowerShell ActiveDirectory module. It covers:

- users, groups, and direct memberships;
- nested groups and access relations;
- disabled, locked, or expired accounts;
- MSA/gMSA technical accounts;
- computer principals in groups;
- Foreign Security Principals;
- cross-domain SID resolution when both providers are imported;
- built-in accounts detected by SID/RID;
- authentication posture when collected.

## OpenLDAP Support

The OpenLDAP V1 connector uses `ldapsearch` through the provided shell exporter. It covers:

- `inetOrgPerson`, `posixAccount`, `groupOfNames`, `groupOfUniqueNames`, and `posixGroup`;
- `member`, `uniqueMember`, and `memberUid` memberships;
- `entryUUID`-based rename stability;
- strict TLS for LDAPS or StartTLS;
- reduced scopes and unknown collections without destructive deletion.

## Intentional Limits

EARE does not claim to compute every effective permission for every technology.

The project does not modify directories and does not provision access. It observes, compares, supports review, preserves decisions, and exports remediation evidence.

The V1 scope intentionally excludes:

- direct AD/OpenLDAP modification;
- provisioning;
- effective NTFS/GPO/AD ACL computation;
- PAM/JIT workflows;
- full cloud effective-permission engines;
- complex workflow automation.

That restraint is deliberate: it keeps the model reliable, auditable, and extensible.
