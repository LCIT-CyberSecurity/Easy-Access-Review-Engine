# Golden Source

A Golden Source is optional. Its versions are immutable and explicitly activated.

Supported promotions are:

- observed snapshot promotion;
- reviewed campaign promotion.

The default campaign promotion mode replaces the reviewed scope without silently deleting unrelated providers.

```text
Observed import -> immutable Snapshot -> GoldenSourceVersion
                                      ^
                                      |
                         reviewed Campaign decisions
```

The Golden Source primarily certifies direct `AccessAssignment` objects, for example:

```text
Alice -> CRM-Sales
```

It does not need to list every effective access granted by `CRM-Sales`. Effective access can be calculated by applying the access-relation graph to direct assignments.

A role composition change can therefore alter effective access while the direct Golden assignment remains unchanged. EARE can expose that drift without rewriting the Golden Source as derived assignments.

## Comparison States

```text
Golden expected + observed snapshot -> expected_and_observed
Observed without Golden             -> no_reference or unexpected
Golden expected but absent          -> missing when authoritative
Scoped or unknown evidence          -> unknown_due_to_scope
```

Direct `read` and `write` Access objects remain distinct for Golden Source, campaigns, decisions, and remediation.
