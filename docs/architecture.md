# Architecture

## Invariants du modele

Le coeur de l'application ne connait aucun fournisseur technique particulier. Active Directory,
OpenLDAP, Entra ID, Keycloak, AWS, Azure, GCP, Google Workspace ou un autre systeme doivent etre
ajoutes comme importeurs/connecteurs qui traduisent les objets natifs vers le modele normalise.

Modele durable:

```text
Provider
   -> Identity
   -> AccessAssignment
   -> Access
      -> Control Object
      -> Permission
      -> Target Resource
```

Cycle durable:

```text
Observed State
    <-> GoldenSourceVersion
    -> Comparison
    -> Snapshot
    -> Campaign
    -> ReviewItem
    -> Decision
    -> Report / Remediation / Audit
```

Les champs specifiques a un fournisseur restent dans `metadata` ou `origin.raw`. Le coeur n'ajoute
pas de champ AD, LDAP, cloud ou application-specifique. Une appartenance AD/LDAP a un groupe est un
`Access` dont `control_object.type = group` et `permission.identifier = member`; l'appartenance
observee est un `AccessAssignment`. Les groupes peuvent eux-memes etre titulaires d'assignments, ce
qui preserve les groupes imbriques sans aplatir les chemins.

## Collecte distante

La collecte distante reste une couche d'acquisition uniquement:

```text
remote directory -> collector script -> existing offline export format -> existing importer and offline pipeline
```

Les collecteurs Active Directory et OpenLDAP ne creent ni second modele de donnees ni moteur metier
remote. Ils produisent les fichiers deja acceptes par les importeurs offline, puis les memes etapes
normalisees gerent DB, snapshot, Golden Source, campagnes et findings.

## Frontieres

- `domain`: objets metier, enums, fingerprints et checksums deterministes.
- `storage`: persistance SQLite locale du MVP. Les tables suivent les frontieres prevues pour une
  migration SQLAlchemy/Alembic.
- `importers`: traduction des exports AD/OpenLDAP/YAML/JSON/CSV vers le modele normalise.
- `services`: comparaison, snapshots immuables, Golden Source versionnee, campagnes, decisions,
  remediations, rapports et audit.
- `api` et `cli`: interfaces fines qui orchestrent les services sans contenir de logique metier.

## Scope et completude

Chaque import cree un `ImportBatch` avec `completeness` et `scope`. Les valeurs conservees sont:

- `full`: le collecteur et l'importeur peuvent raisonnablement traiter le provider comme complet
  pour le scope declare.
- `scoped`: l'import couvre volontairement un sous-ensemble et ne doit pas remplacer l'etat global.
- `unknown`: erreur, timeout, limite serveur, page manquante, resultat tronque ou incoherence de
  collecte; l'import ne doit pas etre authoritative.

Un export partiel ne produit pas de faux `missing`: si la Golden Source attend un acces hors du scope
autoritaire de l'import, la classification est `unknown_due_to_scope`.

## Immutabilite

Les snapshots, les `GoldenSourceVersion` et les `ReviewItem` sont append-only au niveau applicatif.
Une decision ne remplace jamais l'historique: chaque changement cree une nouvelle ligne. L'activation
d'une version de Golden Source est separee de sa creation.

## Securite des imports

Les ZIP sont lus avec allowlist de noms de fichiers, limite de taille, detection Zip Slip et sans
execution de contenu. Les descriptions natives sont conservees lorsqu'elles existent et restent
`null` lorsqu'elles sont absentes.
