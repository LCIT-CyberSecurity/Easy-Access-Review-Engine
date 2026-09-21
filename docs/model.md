# Access Review Model

EARE models reviewable entitlements generically. It does not copy the native IAM model of every technology into the core.

The main domain objects are `Provider`, `Identity`, `Access`, `AccessAssignment`, and `AccessRelation`.

`Access` is a reviewable entitlement. It can represent a group, role, permission set, application right, database grant, or opaque entitlement.

`AccessAssignment` records direct observed assignment from an Identity to an Access.

`AccessRelation` records access composition. The MVP relation type is `grants`:

```text
CRM-Sales grants Contacts:Read
```

Effective access is calculated from direct assignments plus access relations. Derived access is not persisted as direct assignments.

## Stable References

Historical business references remain based on:

```text
Identity -> (provider, identifier)
Access   -> (provider, name)
```

`native_id` is a reconciliation aid for stable provider identifiers such as AD SID or OpenLDAP `entryUUID`. It is not a second business key.

## Golden Source and Snapshots

A snapshot stores observed state at one point in time. A Golden Source version stores expected direct assignments. Campaigns review a snapshot and their decisions do not mutate historical evidence.

## Composition

An assignment such as:

```text
Emma -> CRM-Sales
CRM-Sales grants contacts:read
```

means Emma effectively has `contacts:read`, but the certified direct assignment remains `Emma -> CRM-Sales`.

This preserves provenance and avoids permanently duplicating derived rights.

## Safety Invariants

- Scoped or unknown collections are non-destructive.
- Historical snapshots remain immutable.
- Access rename reconciliation through stable `native_id` updates current-state references only.
- Rename collisions are rejected explicitly.
- Access definitions with incompatible known target or permission are rejected.
- Cycles are bounded during effective-access calculation and reported as diagnostics.

## Functional semantics

Permission = native technical action. Capability = optional normalized functional action. Target = object on which the action applies. AccessAssignment = direct possession of an Access. AccessRelation = how one Access grants another Access. EffectiveAccess = derived result. Snapshot = observed immutable evidence. Golden = expected immutable reference.

Golden V2 freezes expected definitions, relations, Target+Capability rights, provenance, completeness, and comments per version. NOT_DEFINED is not empty, PARTIAL does not assert absence, and COMPLETE is an explicit exhaustive assertion. See the [normative V2 specification](specs/2026-09-21-model-evolution-golden-v2.md).
