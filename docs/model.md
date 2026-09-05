# Model

Les objets coeur sont: `Provider`, `Identity`, `Resource`, `Access`, `AccessAssignment`,
`ImportBatch`, `GoldenSource`, `GoldenSourceVersion`, `GoldenSourceAssignment`, `Snapshot`,
`Campaign`, `ReviewItem`, `Decision`, `AuditEvent` et `RemediationAction`.

`AccessAssignment` est l'objet central: une identite possede un acces via un `origin` precis. Il n'y
a pas d'unicite forcee `(access, identity)` afin de conserver plusieurs chemins vers le meme droit.
