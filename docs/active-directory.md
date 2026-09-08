# Active Directory

Exporter:

```powershell
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip
```

Optional domain controller targeting:

```powershell
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip -Server dc01.corp.local
```

The exporter is a remote acquisition layer. It queries AD through the standard Windows
ActiveDirectory module, writes the existing ZIP/CSV export format, and the normal offline importer
then runs the regular normalization, DB, snapshot, Golden and campaign pipeline. There is no second
remote business pipeline.

Flow:

```text
remote Active Directory -> collector script -> existing AD ZIP/CSV format -> existing importer and offline pipeline
```

The exporter is designed for Windows PowerShell 5.1 and the ActiveDirectory module available on
recent Windows Server releases. It does not require PowerShell 7.

## Completeness and Fail Closed

A ZIP is `completeness: full` only when every supported collection step completes without diagnostic
errors. The collector marks the export `unknown` when group membership collection fails, computer
enumeration fails, or the configured operation timeout is exceeded. The script exits non-zero unless
`-AllowPartial` is explicitly used.

The `-OperationTimeoutSeconds` option defaults to 300 seconds and acts as a simple global guard
between AD operations. It prevents a partial or interrupted collection from being represented as a
full authoritative export.

## Security of Remote AD Access

The script does not implement a custom transport. It relies on the Windows ActiveDirectory module and
its normal domain controller connection handling. Avoid passing credentials on the command line. Run
under an account/session configured for secure AD authentication, and target a trusted domain
controller with `-Server` when operationally required.

Collection diagnostics include object type, object identifier, SID, operation and safe error text.
They do not include environment dumps or credentials.

## ZIP content

Current exports contain:

```text
manifest.yaml
users.csv
groups.csv
service_accounts.csv
computers.csv
memberships.csv
collection-errors.csv
```

V1 ZIPs without the optional files remain importable.

## Supported observations

- Users from `Get-ADUser -Filter *` with SID as native identity, ObjectGUID in metadata,
  `PrimaryGroupID`, `LockedOut`, `ServicePrincipalName`, expiration and creation timestamps.
- Groups from `Get-ADGroup -Filter *` with `GroupScope` and `GroupCategory` preserved in metadata.
- Direct group memberships from `Get-ADGroupMember`; recursive expansion is intentionally not used.
- gMSA/MSA from `Get-ADServiceAccount -Filter *`, classified as `technical_account`.
- Computer principals from exhaustive `Get-ADComputer -Filter *`, not only computers referenced by
  group memberships.
- Primary group memberships represented with `MembershipType=primary_group` for users, computers and
  managed service accounts when the primary group SID resolves to a collected group.
- Foreign Security Principals preserved by `MemberSID` even when unresolved.
- Cross-domain memberships resolved by `native_id`/SID when the referenced provider identity is
  already known or imported later.
- Built-in accounts detected from SID/RID, not localized names.
- Optional deterministic classification rules for classic service/shared user accounts.

If a membership references a `GroupSID` absent from the collected groups, the importer keeps an
explicit diagnostic in import scope and downgrades effective completeness to `unknown`; it does not
silently publish a full authoritative import.

## Not claimed

This AD support reviews observed entitlements represented by the core model. It does not calculate:

- effective NTFS permissions;
- GPO permissions;
- AD ACL effective rights;
- Kerberos delegation effective access;
- Azure/Entra permissions;
- PAM/JIT state;
- provisioning or revocation execution.

## Classification rules

Ordinary `Get-ADUser` rows remain `user_account` by default. Classic service and shared account
classification is optional and deterministic:

```yaml
identity_classification:
  technical_account:
    samaccountname_prefixes:
      - "svc_"
      - "svc-"
    dn_contains:
      - "OU=Service Accounts"
    has_service_principal_name: true
  shared_account:
    samaccountname_prefixes:
      - "shared_"
      - "generic_"
```

Managed service accounts and computers are always technical accounts without requiring these rules.
