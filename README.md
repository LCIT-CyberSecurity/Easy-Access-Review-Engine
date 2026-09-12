# Easy Access Review Engine

**Easy Access Review Engine (EARE)** is an open source, universal access review system.

It helps IAM, SecOps, audit, and compliance teams turn technical access evidence into reliable, traceable, automated reviews.

EARE helps you:

- collect identities, groups, roles, entitlements, and access relationships;
- normalize heterogeneous sources into a common model that is independent from any single IDP;
- compare observed access with a versioned **Golden Source**;
- detect unexpected, missing, incomplete, or risky access;
- calculate effective access from groups, roles, and access relations;
- generate automated HTML, CSV, and JSON reports for audit and remediation;
- run access review campaigns and preserve decisions over time.

The goal is practical: save time, improve reliability, reduce manual errors, and strengthen operational security.

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

EARE supports two collection modes:

1. **Remote read-only collection through existing exporters**
   - Active Directory with `exporters/active-directory/export-active-directory.ps1`;
   - OpenLDAP with `exporters/openldap/export-openldap.sh`.

2. **Import from an existing extraction**
   - Active Directory ZIP;
   - OpenLDAP ZIP;
   - OpenLDAP LDIF.

Collectors are read-only. EARE observes, compares, supports decisions, and exports remediation evidence. It does not provision accounts and does not modify directories.

## CLI

The CLI is the user-facing orchestration layer for the EARE engine.

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

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[app,dev]"
python3 pytest.py
```

Import an Active Directory export:

```bash
access-review import corp-ad-export.zip
access-review findings-list
```

Import an OpenLDAP LDIF:

```bash
access-review import directory.ldif --provider internal-ldap
```

Export a campaign report:

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
