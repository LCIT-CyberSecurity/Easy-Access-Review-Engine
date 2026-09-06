# Active Directory

Exporter:

```powershell
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip
```

Optional domain controller targeting:

```powershell
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip -Server dc01.corp.local
```

The exporter is designed for Windows PowerShell 5.1 and the ActiveDirectory module available on
recent Windows Server releases. It does not require PowerShell 7.

## Fail-closed collection

Membership collection errors are not hidden. The default behavior is fail closed:

- `Get-ADGroupMember` uses terminating errors for each group collection attempt;
- a collection error is written to `collection-errors.csv`;
- `manifest.yaml` is never written as `completeness: full` when collection errors exist;
- the script exits non-zero unless `-AllowPartial` is explicitly used.

With `-AllowPartial`, the ZIP is diagnostic and marked `completeness: unknown`. Such imports must not
produce false `missing` findings.

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

- Users from `Get-ADUser` with SID as native identity, ObjectGUID in metadata, `PrimaryGroupID`,
  `LockedOut`, `ServicePrincipalName`, expiration and creation timestamps.
- Groups from `Get-ADGroup` with `GroupScope` and `GroupCategory` preserved in metadata.
- Direct group memberships from `Get-ADGroupMember`; recursive expansion is intentionally not used.
- gMSA/MSA from `Get-ADServiceAccount`, classified as `technical_account`.
- Computer principals observed as group members, collected with `Get-ADComputer` and classified as
  `technical_account`.
- Primary group memberships represented with `MembershipType=primary_group`.
- Foreign Security Principals preserved by `MemberSID` even when unresolved.
- Cross-domain memberships resolved by `native_id`/SID when the referenced provider identity is
  already known.
- Built-in accounts detected from SID/RID, not localized names.
- Optional deterministic classification rules for classic user-based service/shared accounts.

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
