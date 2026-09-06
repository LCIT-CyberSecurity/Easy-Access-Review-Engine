# Testing With A Real Active Directory

These checks validate the exporter against a real AD DS environment. They are integration checks and
must not be required for normal Linux CI.

## Target platforms

- Windows Server 2022 AD DS with Windows PowerShell 5.1 and ActiveDirectory module.
- Windows Server 2025 AD DS with Windows PowerShell 5.1 and ActiveDirectory module.

## Objects to create

Use a disposable lab domain and fictitious names only.

- Users: active user, disabled user, expired user, locked user.
- Built-ins: Administrator RID 500, Guest RID 501, krbtgt RID 502 already exist in normal domains.
- Groups: Global Security, Universal Security, DomainLocal Security, Distribution group.
- Nested group edge: user -> GG_FINANCE -> GG_ALL_FINANCE.
- gMSA: `gmsa_web$` member of a security group.
- MSA: `msa_batch$` member of a security group.
- Computer: `PC001$` member of a security group.
- Classic service user: `svc_sql` under `OU=Service Accounts` with an SPN.
- Primary group case: user with `PrimaryGroupID` pointing to a known group.
- Foreign Security Principal: trust or synthetic lab membership that creates a FSP object.

## Procedure

1. Run the exporter:

   ```powershell
   .\export-active-directory.ps1 -ProviderName lab-ad -Output lab-ad-export.zip -Server dc01.lab.local
   ```

2. If the script exits non-zero, inspect the console error and `collection-errors.csv` from a rerun
   using `-AllowPartial`:

   ```powershell
   .\export-active-directory.ps1 -ProviderName lab-ad -Output lab-ad-diagnostic.zip -Server dc01.lab.local -AllowPartial
   ```

3. Import the ZIP on the Python side:

   ```bash
   access-review import lab-ad-export.zip
   access-review findings-list
   ```

4. Verify:

   - manifest is `completeness: full` only when `collection-errors.csv` is empty;
   - direct nested group edges are present and not recursively flattened;
   - gMSA/MSA/computer identities are technical accounts;
   - SID rename reconciliation keeps the internal identity stable across T0/T1;
   - partial/diagnostic ZIPs never produce false `missing` classifications.
