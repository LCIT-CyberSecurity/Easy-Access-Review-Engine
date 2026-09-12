# Golden Source

Une Golden Source est optionnelle. Ses versions sont immuables et activees explicitement. Les
promotions supportees sont snapshot observe et campagne validee. Le mode par defaut est
`replace_scope`; `full_replace` est disponible sur demande explicite.


## Schema de fonctionnement

```text
+------------------+       +------------------+       +----------------------+
| Import observe   | ----> | Snapshot immutable| ----> | GoldenSourceVersion  |
| AD / OpenLDAP    |       | AccessAssignment |       | assignments attendus |
| + AccessRelation |       | + graphe courant |       | + checksum           |
+------------------+       +------------------+       +----------+-----------+
                                                               |
                                                               v
                                                    +----------------------+
                                                    | Campagne de revue    |
                                                    | findings + decisions |
                                                    +----------+-----------+
                                                               |
                                      promote campagne validee |
                                                               v
                                                    +----------------------+
                                                    | Version GoldenSource |
                                                    | suivante             |
                                                    +----------------------+
```

## Ce que la Golden certifie

La Golden Source certifie principalement les `AccessAssignment` directs, par exemple:

```text
Emma -> CRM-Sales
```

Elle ne doit pas etre transformee automatiquement en:

```text
Emma -> contacts:read
Emma -> contacts:write
```

Ces deux acces sont derives par les relations:

```text
CRM-Sales grants contacts:read
CRM-Sales grants contacts:write
```

Un changement de composition peut donc produire un drift des acces effectifs sans changer
l'assignment direct de la Golden. La campagne permet de revoir cet ecart; une promotion cree une
nouvelle version immutable au lieu de modifier l'historique.

## Etats de comparaison

```text
Golden attend + snapshot observe       -> expected_and_observed
Golden absent + snapshot observe       -> no_reference
Golden attend + absence authoritative  -> missing
Collection scoped/unknown              -> unknown_due_to_scope
Snapshot observe hors Golden           -> unexpected
```

Un Access direct `read` et un Access direct `write` restent deux elements distincts pour la Golden,
la campagne, la decision et la remediation.
