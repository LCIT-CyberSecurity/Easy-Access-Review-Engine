# Active Directory

Aurora supports two ways to collect Active Directory data:

1. **Direct LDAP/LDAPS/StartTLS** from the Aurora API container on Linux or Docker. This is the
   standard method for a new source. No PowerShell runtime or Windows AD module is needed by Aurora.
2. **Offline PowerShell export and ZIP import** for isolated networks or domain controllers that
   cannot be reached from Aurora.

Both methods produce the same AD ZIP/CSV format and use the same Aurora importer, snapshots,
Golden Source and review pipeline. Existing `adws` connector configurations remain supported as a
legacy mode; new sources default to direct LDAP with LDAPS.

## Choose the connection method

| Method | Where it runs | Transport | Use it when |
| --- | --- | --- | --- |
| LDAP | Aurora API container | TCP 389, no TLS | Lab or isolated trusted network only |
| StartTLS | Aurora API container | TCP 389, upgraded to TLS | The DC supports StartTLS and has a valid certificate |
| LDAPS | Aurora API container | TCP 636, TLS from connection start | Recommended for new direct connections |
| PowerShell ZIP export | Windows host with AD module | Current Windows session | Aurora cannot connect to the directory |
| Legacy ADWS | Aurora backend with PowerShell | ADWS, normally TCP 9389 | Existing configurations during migration |

LDAP without TLS sends the bind password and directory data without encryption. Use it only when
explicitly selected on a trusted lab network. Aurora does not downgrade a failed TLS connection to
plain LDAP.

## Configure the domain controller for LDAPS or StartTLS

AD DS needs a suitable server certificate before it can negotiate LDAPS or StartTLS. The certificate
must meet these requirements:

- Its subject CN or a DNS Subject Alternative Name contains the domain controller's fully qualified
  DNS name, such as `dc01.corp.local`.
- Its Enhanced Key Usage includes **Server Authentication** (`1.3.6.1.5.5.7.3.1`).
- The matching private key is installed and available to the AD DS service.
- Aurora's container trusts the issuing CA chain.
- The server accepts TCP 636 for LDAPS and TCP 389 for LDAP/StartTLS from the Aurora API container.

On a domain controller enrolled in a Microsoft Enterprise CA, an administrator can request the
**Domain Controller** certificate template using `certlm.msc`:

1. Open **Certificates (Local Computer)** and select **Personal → Certificates**.
2. Choose **All Tasks → Request New Certificate**.
3. Select the Active Directory enrollment policy and the **Domain Controller** template, then enroll.
4. Confirm that the certificate has the controller FQDN, a private key and the Server Authentication
   purpose. The template supplies the required DNS SAN and EKU.
5. If the LDAP service does not start using the new certificate, restart the domain controller during
   an approved maintenance window. AD DS can also use a certificate installed in the NTDS service's
   Personal store; it checks that store before the local computer store.

For a private CA, install its root/intermediate certificates in the Aurora API container's trust
store, or mount a CA PEM file and configure `tls_ca_cert_file_env` below. Do not disable certificate
or hostname validation to make a connection pass. Microsoft documents the [LDAPS certificate
requirements and enrollment process](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/configure-ldap-signing-certificates?tabs=microsoft-enterprise-ca).

Verify LDAPS from a Windows administration workstation with `ldp.exe`: connect to the controller's
FQDN on port `636` with **SSL** enabled and confirm RootDSE information appears. Test again from the
Aurora container; a successful Windows-only check does not prove the container trusts the certificate
chain or can resolve the same DNS name.

## Configure the Aurora connector

Create a new **Active Directory** source in the Web UI, or start from this YAML shape:

```yaml
provider: corp-ad
type: active_directory
connection:
  protocol: ldap
  server: dc01.corp.local
  base_dn: DC=corp,DC=local
  tls_mode: ldaps
  # Optional: use when the DC certificate chains to a private CA.
  tls_ca_cert_file_env: AURORA_AD_LDAP_CA_CERT_FILE
credentials:
  username_env: AURORA_LDAP_USERNAME
  password_file_env: AURORA_LDAP_PASSWORD_FILE
collection:
  timeout: 300
  allow_partial: false
  read_only_account: true
```

Use the full DNS name in `connection.server` for TLS so it matches the certificate. `base_dn` is the
directory naming context to collect, written as an LDAP distinguished name. For example,
`DC=corp,DC=local`.

Set `connection.tls_mode` to exactly one of:

- `ldaps`: encrypted connection from the start, normally port 636. Recommended.
- `starttls`: connect with LDAP on port 389, then require TLS before binding.
- `none`: plain LDAP on port 389. Only for explicitly approved lab use.

Do not set `tls_mode: none` to work around an LDAPS certificate error in production. Fix the DC
certificate and CA trust instead.

### Make the secret available to Docker

The connector YAML contains environment-variable names, never the password. The referenced values
must be available inside the **Aurora API service container** for test, preview and synchronization.
Prefer a Docker secret or a protected password file readable by the API service's UID. For example,
with a Compose secret:

```yaml
services:
  aurora-api:
    environment:
      AURORA_LDAP_USERNAME: svc-aurora@corp.local
      AURORA_LDAP_PASSWORD_FILE: /run/secrets/aurora-ad-password
      AURORA_AD_LDAP_CA_CERT_FILE: /run/secrets/corp-root-ca.pem
    secrets:
      - aurora-ad-password
      - corp-root-ca

secrets:
  aurora-ad-password:
    file: ${AURORA_AD_PASSWORD_FILE:?set the protected secret file path}
  corp-root-ca:
    file: ${AURORA_AD_CA_FILE:?set the CA PEM file path}
```

Set `AURORA_AD_PASSWORD_FILE` and `AURORA_AD_CA_FILE` in the deployment environment to protected
host file paths; do not put secret contents in Compose YAML, connector YAML, shell arguments, logs,
or this documentation. Ensure the API container can read the mounted files. If the DC uses a public
CA already trusted by the container, omit `tls_ca_cert_file_env` and the CA mount.

In the UI, `username_env` and `password_file_env` are the variable **names**, not their values. The
UI's test-credentials fields are temporary for a connection test; they are not saved and do not
replace the service's secret for preview or synchronization.

### Web UI workflow

1. Open **Sources** and create an **Active Directory** source.
2. Select **LDAP / LDAPS direct**. `ADWS historique` is retained for existing deployments and needs
   PowerShell; the offline PowerShell exporter described below is separate.
3. Enter the controller FQDN, Base DN and desired transport. Use LDAPS for production.
4. Set the username and password-file environment-variable names. Confirm the account is dedicated
   and read-only. The confirmation checkbox is an operator declaration; it does not change AD ACLs.
5. Save the source, then run **Test connection**. This performs an authenticated LDAP read, not just
   a TCP port check.
6. Use source inspection to search users and groups and discover available attributes. Map business
   fields from group attributes when needed.
7. Run **Preview** and check the normalized users, groups and memberships.
8. Run **Synchronize**. Review the collection status and diagnostics before promoting a snapshot to
   Golden Source.

Expected errors include:

- **Required secret environment variable is not set**: the referenced variable is absent from the
  API container, or its password-file path variable was not injected.
- **Invalid credentials (49 / data 52e)**: AD rejected the bind name or password. Check the account
  UPN and secret file contents; do not switch to a Domain Admin service credential.
- **Certificate verify or name mismatch**: use the DC FQDN in `server`, install the CA chain in the
  container, and check the certificate SAN/EKU/expiry.
- **LDAP result 52 during StartTLS**: the DC could not initialize its TLS side. Check that it has an
  eligible server certificate and that TCP 389 is reachable from the API container.
- **Can't contact LDAP server on LDAPS**: check port 636, certificate selection and trust from the
  API container. The fact that TCP 636 accepts connections alone does not prove a valid TLS session.
- **No such object / Base DN error**: verify the Base DN spelling and that the bind account can read
  it.
- **Timeout or partial collection**: check the DC and Docker network, then use the diagnostic in
  the result. A failed page or member range must not be treated as a full snapshot.

## Collection, normalization and completeness

The Linux collector uses `ldapsearch` from the backend image, performs a bind, and writes the common
AD ZIP format. Searches use the critical LDAP paged-results control. AD group values returned as
`member;range=N-*` are fetched range by range; any missing, overlapping, skipped or malformed range
is a collection error. The ZIP records exact `membership_rows`. The older `memberships` statistic is
retained for compatibility with historical PowerShell archives whose count semantics differed.

The collector preserves user, group, computer, MSA/gMSA, SID, ObjectGUID and distinguished-name
observations. It imports direct memberships, primary-group memberships and nested groups as explicit
access relations. It preserves foreign security principal SIDs and records unresolved references
without inventing identities. Empty groups remain in the access catalogue.

`completeness: full` is emitted only for a domain Base DN when the domain object is found, critical
pages finish, group member ranges are verified and no collection diagnostics remain. A narrower Base
DN is scoped. With `allow_partial: false` (default), an LDAP collection error prevents an archive from
being published. When partial collection is explicitly enabled, Aurora writes an `unknown` archive
with `collection-errors.csv`; it cannot be promoted as a complete authoritative snapshot. Historical
ZIPs remain importable.

### Business mapping and Golden Source V2

Map AD group attributes to business context such as application, resource, owner and declared
business permission. The technical permission observed by this connector remains `member`. For
example, a mapped value `ReadWrite` is source metadata; it is not proof of effective `read` and
`write` rights in the application. Validated functional rights belong to the separate Golden Source
V2 functional model.

After promotion, group display/context, expected access definitions, relations and functional-model
annotations use Aurora's source-agnostic model. Changes to a Golden version preserve its existing V2
functional context unless an operator explicitly edits that context.

## Offline PowerShell export and historical ADWS

Run the existing exporter on a Windows host with the ActiveDirectory PowerShell module:

```powershell
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip -Server dc01.corp.local
```

The script uses the current Windows identity/session and the standard AD module. Import the resulting
ZIP into Aurora through the regular import workflow. This mode is useful for isolated networks; it
does not require Aurora's Linux backend to have PowerShell installed.

The legacy `adws` protocol remains accepted for existing source configuration and continues to use
the PowerShell inspection/export path. Migrate a source deliberately by selecting LDAP, confirming
Base DN and secret references, testing the read-only bind, previewing the result and then syncing.
Do not remove historical ZIP files: they remain supported by the importer.

The PowerShell exporter uses a per-operation timeout (default 300 seconds). `-AllowPartial` writes
diagnostics and marks the resulting archive unknown; it does not create a full authoritative export.

## Observed AD data and limits

The connector observes users (including disabled accounts), groups, direct group members, nested
groups, primary groups, computers, MSA/gMSA, SIDs, ObjectGUIDs, DNs and supported account metadata.
It does not add OU browsing or OU management.

This connector does not calculate effective NTFS permissions, GPO permissions, AD ACL rights,
Kerberos delegation, Azure/Entra permissions, PAM/JIT state or perform provisioning/revocation in AD.
All AD operations in this connector are reads; no AD objects or group memberships are modified.
