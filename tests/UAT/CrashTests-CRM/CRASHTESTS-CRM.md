# CrashTests-CRM

`CrashTests-CRM` is a reproducible UAT lab for Easy Access Review Engine using a fictitious
NexaByte IT CRM scenario.

The lab validates the generic EARE model:

- source collection to generic EARE model to review;
- Provider, Identity, Access, ControlObject, Permission, Target, Origin;
- direct and effective access;
- AccessAssignment and AccessRelation;
- role composition, multi-path provenance and cycles;
- Golden Source import/promotion/diff;
- snapshots, immutable review scope, campaigns, decisions and remediation;
- SQLite persistence and restart behavior;
- full, scoped and unknown collection semantics.

It does not introduce a CRM-specific production connector or CRM-specific core model.

## Commands

From the repository root:

```bash
tests/UAT/CrashTests-CRM/bootstrap_debian13.sh
```

Then:

```bash
tests/UAT/CrashTests-CRM/run.sh
```

Direct pytest run:

```bash
python3 -m pytest \
  tests/UAT/CrashTests-CRM/crashtests \
  -v
```

Remote execution example:

```bash
ssh vm-integrations \
  'cd ~/Easy-Access-Review-Engine && tests/UAT/CrashTests-CRM/run.sh'
```

## Docker Lab

The lab image is pinned to:

```text
debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
```

The container exposes no network port and uses `network_mode: none`. It does not mount the Docker
socket, the host home directory, SSH keys, tokens, credentials or environment files.

The CRM filesystem is under `/srv/crm` inside the container and is backed by the dedicated Docker
volume `eare-crashtests-crm-data`. Files are owned by `root:root` inside the container so access is
governed by role groups and POSIX ACLs, not by file ownership of the fictitious users.

Reset command:

```bash
docker compose -f tests/UAT/CrashTests-CRM/compose.yaml up -d --build --force-recreate
```

## Dataset

The deterministic seed creates:

- 20 human users;
- 1 technical account: `svc-crm-import`;
- 1 shared account: `crm-shared-sales`;
- 50 fictitious clients: `CLIENT-001` to `CLIENT-050`;
- Linux groups representing CRM roles;
- POSIX ACLs matching `policy/role-permissions.csv`.

All names, emails, license values, clients and business records are fictitious. Emails use
`example.test`. License strings are demo values and are not real software keys.

## Scope Exclusions

`CrashTests-CRM` does not validate technology-specific IAM behavior.

Active Directory is out of scope:

- real Domain Controller;
- real AD SID behavior;
- PrimaryGroupID;
- FSP;
- trusts;
- Domain Local, Global and Universal groups;
- Kerberos;
- ADWS.

Those tests belong to `CrashTests-AD`.

OpenLDAP is out of scope:

- real slapd;
- server-generated entryUUID;
- member, uniqueMember and memberUid behavior;
- real LDAP pagination;
- StartTLS;
- LDAPS;
- server-side LDAP ACLs.

Those tests belong to `CrashTests-OpenLDAP`.

## Artifacts

Each run writes troubleshooting artifacts under:

```text
tests/UAT/CrashTests-CRM/artifacts/
```

Expected files include:

- `summary.json`;
- `pytest.xml`;
- `eare.stdout.log`;
- `eare.stderr.log`;
- `docker.log`;
- `container-inspect.json`;
- `filesystem-acl.txt`;
- `users.txt`;
- `groups.txt`;
- `role-memberships.txt`;
- `observed.json`;
- `golden-diff.json`;
- `remediation.csv`;
- `campaign-report.html`.

Artifacts are ignored by Git and must not contain secrets.

## CrashTest IDs

- CT-CRM-001: baseline real equals Golden;
- CT-CRM-002: wrong role is unexpected;
- CT-CRM-003: missing role is missing;
- CT-CRM-004: legitimate multi-role effective union;
- CT-CRM-005: direct sensitive permission;
- CT-CRM-006: role composition;
- CT-CRM-007: role composition drift;
- CT-CRM-008: multiple paths;
- CT-CRM-009: AccessRelation cycle;
- CT-CRM-010: disabled user;
- CT-CRM-011: deleted user;
- CT-CRM-012: rename with stable native ID;
- CT-CRM-013: username recreation with new native ID;
- CT-CRM-014: technical account without owner then fixed owner;
- CT-CRM-015: invalid owner;
- CT-CRM-016: shared account owner policy finding;
- CT-CRM-017: non-authoritative unknown collection;
- CT-CRM-018: scoped collection;
- CT-CRM-019: snapshot immutability;
- CT-CRM-020: initial Golden promotion;
- CT-CRM-021: imported Golden reference;
- CT-CRM-022: campaign creation;
- CT-CRM-023: approve decision;
- CT-CRM-024: revoke decision;
- CT-CRM-025: campaign close;
- CT-CRM-026: remediation;
- CT-CRM-027: promote campaign;
- CT-CRM-028: effective Golden change;
- CT-CRM-029: SQLite persistence/restart;
- CT-CRM-030: real filesystem access;
- CT-CRM-031: permission collision;
- CT-CRM-032: AccessRelation removal;
- CT-CRM-033: partial AccessRelation collection;
- CT-CRM-034: orphan relation;
- CT-CRM-035: large composition.
