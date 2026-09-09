# Model

EARE modelise des habilitations reviewable de facon generique, sans reproduire toute la logique IAM native de chaque technologie. Les collectors peuvent conserver la complexite native dans `origin` et `metadata`.

## Entites principales

Les entites principales du modele d'habilitation sont: `Provider`, `Identity`, `Access`, `AccessAssignment` et `AccessRelation`.

`Access` est une habilitation identifiable et reviewable. Un Access peut representer un groupe, un role, un permission set ou un droit atomique, par exemple:

```text
GG_FINANCE:member
Sales-Manager
AWS-FinanceRole
customers:write
server01:sudo
database-prod:SELECT
```

`AccessAssignment` represente une attribution directe ou observee d'un Access a une Identity. C'est l'objet certifiable par la Golden Source pour le MVP. Il n'y a pas d'unicite forcee `(access, identity)` afin de conserver plusieurs origines observees vers le meme droit direct.

`AccessRelation` represente une composition generique entre deux Access:

```text
Access parent
  grants Access enfant
```

Le type de relation MVP est limite a `grants`. Une relation porte un `origin` et des `metadata` pour conserver la provenance, par exemple `AD nested group`, `AWS role policy`, `CRM role definition`, `database role inheritance` ou `Linux group/sudo mapping`. Le core ne cree pas d'objets specifiques comme `Role`, `Policy`, `PermissionSet`, `RoleBinding` ou `EffectivePermission`: ces concepts restent modelises par `Access`, `Origin` et `metadata`.

Les descripteurs `ControlObject`, `Permission`, `Target` et `Origin` restent attaches aux Access ou aux relations. Ils decrivent l'objet controle, la permission, la cible et la provenance sans transformer le core en modele IAM specifique a un provider.

## Acces directs et effectifs

Un acces direct est observe comme attribue a une Identity:

```text
Bob -> Sales-Manager
```

Un acces effectif est obtenu directement ou par composition `grants`:

```text
Bob -> Sales-Manager -> customers:write
```

Les droits derives ne sont pas transformes automatiquement en `AccessAssignment` persistants. Le modele prefere stocker les assignments directs et les relations, puis calculer les droits effectifs a partir du graphe. Cela preserve la provenance et evite de dupliquer durablement des droits derives.

Plusieurs permissions sur la meme ressource doivent rester des Access distincts:

```text
customers:read
customers:write
customers:export
```

Si un provider encode deja la permission dans `access_name`, ce format reste compatible. L'identite stable d'un Access ne doit pas confondre `resource=customers permission=read` avec `resource=customers permission=write`.

## Exemples

RBAC applicatif:

```text
Identity Bob
  assigned Sales-Manager
Sales-Manager grants customers:read
Sales-Manager grants customers:write
Sales-Manager grants customers:export
Sales-Manager grants reports:read
```

Active Directory:

```text
Bob assigned GG_FINANCE:member
GG_FINANCE:member grants GG_ERP_USERS:member
```

Cela permet de distinguer le membership direct de l'acces effectif issu d'une imbrication, sans reconstruire tout le graphe AD dans le core.

AWS:

```text
Alice assigned FinanceManagerRole
FinanceManagerRole grants bucket-finance:s3:GetObject
FinanceManagerRole grants bucket-finance:s3:PutObject
FinanceManagerRole grants key-finance:kms:Decrypt
```

Les IAM Policy, Trust Policy, SCP, Permission Boundary, Resource Policy, conditions et explicit deny restent hors du core MVP.

Database et Linux suivent le meme modele:

```text
DB Role: analyst grants table-orders:SELECT
linux-group:ops grants server01:sudo
```

## Calcul et diagnostics

Le calcul effectif construit une adjacency map des `AccessRelation grants`, part des `AccessAssignment` directs, puis parcourt le graphe avec un visited set par chemin. Il supporte plusieurs niveaux, par exemple `A grants B grants C`.

Un meme droit effectif apparait une seule fois par identite, mais conserve tous ses chemins de provenance. Par exemple `Bob -> Role-A -> customers:read` et `Bob -> Role-B -> customers:read` produisent un seul effective access `customers:read` avec deux chemins.

Les cycles ne sont pas rejetes par defaut, car certains providers peuvent techniquement en contenir. Le calcul est borne: lorsqu'un chemin revisite un Access deja present dans ce chemin, le parcours de ce chemin s'arrete et un diagnostic `cycle_detected` est emis. Le nombre de chemins conserves par acces effectif est aussi borne par `max_paths_per_access` pour eviter une explosion dans les graphes denses; un diagnostic `path_limit_reached` indique ce cas. Les relations vers des Access absents sont ignorees conservativement et signalees par `unresolved_access_relation`.

## Golden Source

Pour le MVP, la Golden Source continue de certifier les `AccessAssignment` directs. Une Golden peut donc contenir:

```text
Bob -> Sales-Manager
```

sans devoir lister:

```text
Bob -> customers:read
Bob -> customers:write
Bob -> reports:read
```

Les droits effectifs issus de la Golden peuvent etre calcules en appliquant le graphe de relations a ses assignments directs. Si la composition d'un role change entre deux versions de relations, l'affectation directe peut rester inchangee alors que les droits effectifs changent. Le service de diff effectif expose cette information sans creer automatiquement un finding metier.

Les snapshots et bases legacy qui ne contiennent pas `AccessRelation` sont interpretes comme `access_relations = []`.
