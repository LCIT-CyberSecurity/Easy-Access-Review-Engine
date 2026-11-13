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

## Web Connector Transports

The Web UI connector can use either the existing `adws` protocol or read-only LDAP collection. LDAP
requires a Base DN and supports `none` (plain LDAP on port 389), `starttls` (LDAP upgraded on port
389), or `ldaps` (TLS from connection start, normally port 636). For example:

```yaml
type: active_directory
connection:
  protocol: ldap
  server: dc01.corp.local
  base_dn: DC=corp,DC=local
  tls_mode: none
credentials:
  username_env: AURORA_AD_USERNAME
  password_env: AURORA_AD_PASSWORD
```

The referenced environment variables must be available to the Aurora API service for preview and
synchronization. In the connection test drawer, credentials can also be entered for that test only;
they are not saved with the connector. The collector reads LDAP attributes and creates the same AD
ZIP format used by the existing importer. TLS modes require a working certificate and a name that
matches the server; an optional CA certificate file can be supplied through
`connection.tls_ca_cert_file_env`.

## Completeness and Fail Closed

A ZIP is `completeness: full` only when every supported collection step completes without diagnostic
errors. The collector marks the export `unknown` when group membership collection fails, computer
enumeration fails, or the configured operation timeout is exceeded. The script exits non-zero unless
`-AllowPartial` is explicitly used.

The `-OperationTimeoutSeconds` option defaults to 300 seconds. Each remote AD cmdlet call is run
through a controlled PowerShell runspace and is stopped if that single operation exceeds the timeout.
A timed-out operation is recorded as a collection diagnostic, downgrades the export to `unknown`, and
can never produce a `full` authoritative export. `-OperationTimeoutSeconds 0` disables this timeout
for tests/debugging and is not recommended for production collection.

## Security of Remote AD Access

The PowerShell exporter uses the current Windows identity/session and standard ActiveDirectory
module authentication. The Web UI's LDAP mode uses a read-only LDAP bind and keeps the password out
of connector YAML. Plain LDAP sends credentials without encryption; use it only on a trusted network.
For encrypted LDAP, the domain controller must have LDAPS or StartTLS correctly configured and its
certificate must be trusted by the Aurora API service.

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
