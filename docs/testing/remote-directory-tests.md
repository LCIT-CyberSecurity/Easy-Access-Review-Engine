# Remote Directory Test Levels

## Unit / functional

Run the fast suite with the repository runner:

```bash
python3 -m pytest
```

If the real `pytest` package is installed, `pytest` can be used as well. Local tests that require
external tools must report `SKIP`, never `PASS`, when those tools are missing.

## Integration

PowerShell/Pester tests require `pwsh` and Pester:

```powershell
Invoke-Pester -Path tests/powershell/export-active-directory.Tests.ps1
```

The OpenLDAP/slapd integration placeholder in `tests/integration/` requires Docker and a local test
image seeded with LDIF/TLS fixtures. It is intentionally skipped when Docker or the image is absent;
the normal suite does not pull images or require network access.

## Application / E2E

`tests/e2e/test_application_lifecycle.py` covers the EARE lifecycle from import through SQLite,
snapshot, Golden, campaign decisions, remediation, reports, and campaign promotion.

## Performance smoke

The performance smoke is manual and separate from the functional suite:

```bash
PYTHONPATH=src python3 scripts/performance_smoke.py
```

It generates 10,000 identities, 2,000 groups/accesses and 100,000 assignments, then reports import
time, Golden promotion time, DB size and process RSS. Results are machine-specific and are intended
to spot large regressions, not enforce a precise benchmark contract.

## Manual AD Lab Smoke Test

Use a disposable lab domain. Recommended dataset:

- 10 users, including active, disabled, locked and expired accounts.
- 2 computers, including one with no explicit group membership.
- 1 gMSA and, if available, 1 sMSA.
- Global, Universal and DomainLocal groups, including one nested group.
- PrimaryGroupID coverage for users, computers and managed service accounts.
- FSP/cross-domain membership if a second lab domain is available.

Procedure:

1. Run the collector from a domain-joined host:

   ```powershell
   .\export-active-directory.ps1 -ProviderName lab-ad -Output lab-ad-export.zip -Server dc01.lab.local
   ```

2. Inspect the ZIP for `manifest.yaml`, `users.csv`, `groups.csv`, `service_accounts.csv`,
   `computers.csv`, `memberships.csv` and `collection-errors.csv`.
3. Verify `Get-ADComputer -Filter *` results are present, including computers with no explicit group
   membership.
4. Import the ZIP with the normal application path.
5. Confirm `completeness: full` only when `collection-errors.csv` has no rows; otherwise rerun with
   `-AllowPartial` and verify the import is `unknown`, not authoritative full.
