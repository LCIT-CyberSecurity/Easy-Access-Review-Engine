# Architecture

Detailed design and implementation contracts live in [engineering.md](engineering.md).

## Model Invariants

The application core is provider-agnostic. Active Directory, OpenLDAP, and future providers are importers or connectors that translate native objects into the normalized EARE model.

Provider-specific fields stay in `metadata` or `origin.raw`. The core does not add AD, LDAP, cloud, or application-specific columns.

An AD or LDAP group membership is an `AccessAssignment`. Nested groups and roles are represented through `AccessRelation` edges. Effective access is calculated from those inputs and keeps provenance paths.

## Current Scope

The V1 core supports:

- immutable snapshots;
- versioned Golden Source;
- campaigns and decisions;
- conservative scoped and unknown imports;
- stable rename reconciliation through provider native identifiers;
- collision detection;
- effective-access calculation through access relations.

AWS, Azure, GCP, Entra ID, Keycloak, Kubernetes, and GitHub are currently model stress fixtures, not integrated native collectors.

## Collection Layer

Remote collection is only an acquisition layer:

```text
remote source -> exporter -> archive/LDIF -> importer -> normalized model
```

Active Directory and OpenLDAP collectors do not create a second domain model and do not implement review logic.

## Module Boundaries

- `domain`: domain objects, enums, fingerprints, and deterministic checksums.
- `storage`: local SQLite MVP persistence.
- `importers`: translation from AD/OpenLDAP artifacts to the normalized model.
- `application`: import orchestration and persistence boundaries.
- `services`: comparison, Golden Source, campaign, effective-access, and remediation services.
- `reporting`: HTML/CSV/JSON report generation.
- `api` and `cli`: thin interfaces that orchestrate services without business logic.

## Completeness

Each import carries `completeness` and `scope`:

- `full`: authoritative inside the declared scope;
- `scoped`: intentionally partial;
- `unknown`: collection error, timeout, limit, truncation, or inconsistent evidence.

Partial exports must not produce false `missing` results or false deletions.

## Security

ZIP inputs are read with filename allowlists, size limits, Zip Slip detection, and no execution of embedded content. Native descriptions are preserved when available and must be escaped in reports.
