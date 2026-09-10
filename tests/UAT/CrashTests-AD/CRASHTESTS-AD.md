# CrashTests-AD

`CrashTests-AD` validates EARE against a real Active Directory Domain Services environment.

Current target, verified against Microsoft documentation:

```text
Windows Server 2025
AD DS forest/domain functional level: Windows Server 2025
```

This suite is intentionally not containerized as a Linux Docker service. Active Directory requires
a real Windows Server domain controller or an integration VM managed outside the repository.

The suite is separate from `CrashTests-CRM`. It validates AD-specific behavior:

- real domain controller export;
- real SID and ObjectGUID values;
- PrimaryGroupID;
- foreign security principals;
- trusts and cross-domain references when available;
- Domain Local, Global and Universal groups;
- disabled, locked, expired and deleted accounts;
- managed service accounts;
- nested group membership;
- authoritative, scoped and unknown collections.

The collected data must still enter EARE through the generic model: Provider, Identity, Access,
AccessAssignment, AccessRelation, Origin, Golden Source, snapshots and campaigns.

## Commands

From the repository root:

```bash
tests/UAT/CrashTests-AD/run.sh
```

Direct pytest run:

```bash
python3 -m pytest \
  tests/UAT/CrashTests-AD/crashtests \
  -v
```

Remote execution example:

```bash
ssh vm-integrations \
  'cd ~/Easy-Access-Review-Engine && tests/UAT/CrashTests-AD/run.sh'
```

## Environment Contract

The runner expects PowerShell to be available as `pwsh` and an integration domain controller to be
configured outside the repository. Do not store credentials, IP addresses, hostnames, passwords,
tokens or SSH keys in this directory.

Use generic environment variables in local automation if needed:

```text
EARE_AD_UAT_HOST
EARE_AD_UAT_DOMAIN
```

Do not commit their values.

## Artifacts

Artifacts are written under:

```text
tests/UAT/CrashTests-AD/artifacts/
```

Expected files include `pytest.xml`, `ad-environment.json`, `ad-export.zip`, `observed.json`,
`snapshot.json`, `findings.json`, `eare.stdout.log` and `eare.stderr.log`.
