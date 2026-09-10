# CrashTests-OpenLDAP

`CrashTests-OpenLDAP` validates EARE against a real OpenLDAP environment on the current Debian
stable family.

Current target, verified on official Debian release information:

```text
Debian 13.6 "trixie"
```

The suite is separate from `CrashTests-CRM`. It is intended to validate OpenLDAP-specific behavior:

- real slapd export/import;
- server-side `entryUUID`;
- `member`, `uniqueMember` and `memberUid`;
- DN escaping and multi-valued RDNs;
- scoped and unknown collections;
- StartTLS/LDAPS behavior when configured by the environment;
- OpenLDAP-specific archive routing into the generic EARE model.

The suite must still map collected data into generic EARE concepts: Provider, Identity, Access,
AccessAssignment, AccessRelation, Origin, Golden Source, snapshots and campaigns.

## Commands

From the repository root:

```bash
tests/UAT/CrashTests-OpenLDAP/Run_CrashTests-OpenLDAP.sh
```

Direct pytest run:

```bash
python3 -m pytest \
  tests/UAT/CrashTests-OpenLDAP/crashtests \
  -v
```

Remote execution example:

```bash
ssh vm-integrations \
  'cd ~/Easy-Access-Review-Engine && tests/UAT/CrashTests-OpenLDAP/Run_CrashTests-OpenLDAP.sh'
```

## Docker Target

The OpenLDAP UAT base image is pinned to the same Debian 13 slim digest used by the CRM UAT:

```text
debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
```

No host home directory, SSH key, credentials, environment file or Docker socket may be mounted.

## Artifacts

Artifacts are written under:

```text
tests/UAT/CrashTests-OpenLDAP/artifacts/
```

Expected files include `pytest.xml`, `slapd-version.txt`, `ldapsearch-rootdse.ldif`,
`export.zip`, `observed.json`, `snapshot.json`, `findings.json` and `eare.stdout.log`.
