# PR: Access Review MVP V1

## Summary

This PR introduces the first MVP of a Python open source access review engine. It establishes a
provider-neutral core model, file-based Active Directory and OpenLDAP imports, comparison against an
optional Golden Source, immutable snapshots, campaign/review decision services, remediation
generation and portable HTML/CSV/JSON reporting.

## Main changes

- Add provider-neutral domain objects for providers, identities, resources, accesses, assignments,
  imports, Golden Source versions, snapshots, campaigns, review items, decisions, audit events and
  remediation actions.
- Add comparison logic for `expected_and_observed`, `unexpected`, `missing`,
  `unknown_due_to_scope` and `no_reference`.
- Add cumulative findings for disabled/deleted identities with access, missing technical/shared
  account owners, invalid owners and unknown identities.
- Add immutable snapshot and Golden Source version services, including snapshot and campaign
  promotion logic.
- Add campaign opening, reviewer resolution, decision validation/history semantics and campaign
  close guards.
- Add remediation action generation for revoke and missing-grant approval cases.
- Add secure AD ZIP importer with allowlisted filenames, Zip Slip protection, manifest validation
  and native description preservation.
- Add AD-oriented tests based on recent Microsoft Learn ActiveDirectory cmdlet shapes, covering
  direct nested memberships, disabled users, optional descriptions, multiple extract variants, SID
  rename reconciliation and scoped import deletion safety.
- Add OpenLDAP LDIF importer for `inetOrgPerson`, `groupOfNames`, `groupOfUniqueNames`,
  `posixGroup`, `member`, `uniqueMember` and `memberUid`.
- Add OpenLDAP 2.6-oriented tests based on official LDIF/ldapsearch/slapcat shapes, covering
  multi-value attributes, operational attributes, lowercase objectClass, attribute options,
  continuation lines, base64 values and nested groups without flattening.
- Add autonomous filterable HTML report and CSV/JSON campaign result exports.
- Add MVP SQLite storage layer preserving the target table boundaries.
- Add minimal CLI/API entry points and exporter scripts for AD/OpenLDAP.
- Add documentation for architecture, model, AD, OpenLDAP, Golden Source and reports.

## Security notes

- ZIP imports reject path traversal and unexpected filenames.
- Import size is bounded by a configurable maximum.
- Provider-specific fields are kept in `metadata` or `origin.raw`; no AD/LDAP-specific fields are
  added to the core model.
- The MVP produces remediation actions but never executes provisioning or revocation.

## Tests run

```bash
python3 -m pytest
python3 -m compileall src tests pytest.py
```

Current result:

```text
20 passed, 0 failed
```

## Checks not run

The following tools were not available in the local environment:

```bash
ruff check .
ruff format --check .
mypy src/
pytest --cov
```

## Known MVP gaps

- The active persistence implementation uses the Python stdlib SQLite module. SQLAlchemy 2.x and
  Alembic are declared as application dependencies and remain the intended migration path.
- The REST API is read-oriented and minimal.
- Several CLI command families are represented by service implementations but are not fully wired
  end-to-end in the command parser.
- The synthetic test suite covers critical behavior, but not yet the requested 10k/100k performance
  target or the full 85%/95% coverage goals.
