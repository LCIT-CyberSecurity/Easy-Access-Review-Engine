# Guide utilisateur EARE

## 1. A quoi sert EARE ?

Easy Access Review Engine (EARE) aide a repondre a trois questions:

1. Quels acces sont actuellement observes ?
2. Ces acces correspondent-ils a ce qui est attendu ?
3. Que doit-on approuver, revoir ou retirer ?

EARE conserve les observations, les compare a une Golden Source optionnelle, ouvre des campagnes
de revue et produit des rapports reutilisables pour l'audit et la remediation.

## 2. Schema synthetique

```text
Provider
  +-- Identity --------------------+
  |                                |
  +-- Access                       +-- AccessAssignment direct
        +-- Target?                |
        +-- Permission?            v
        +-- Origin / metadata   Access
                                  |
                     AccessRelation: grants
                                  |
                                  v
                         Access effectif + provenance

Snapshot -> Golden Source -> Campaign -> Decision -> Report
```

Lecture rapide:

- les objets du haut decrivent ce qui existe dans la source;
- `AccessAssignment` dit qui detient directement un Access;
- `AccessRelation` explique ce qu'un Access composite accorde;
- l'acces effectif est calcule a partir des deux;
- la Golden Source decrit l'attendu, puis la campagne collecte les decisions.

## 3. Les elements du modele

### Provider: d'ou vient l'information ?

Un Provider est une source d'identites et d'acces. Exemples:

```text
corp-ad       Active Directory
internal-ldap OpenLDAP
```

Le Provider evite de confondre deux objets qui portent le meme nom dans deux systemes differents.

### Identity: qui peut recevoir un acces ?

Une Identity est un sujet de revue:

```text
Alice Martin       user
svc-backup         technical account
CRM-Sales          group ou principal composite
managed-app-prod   service principal futur
```

Une Identity possede un identifiant dans son Provider, un statut (`active`, `disabled`, `deleted`,
`unknown`) et, lorsque la source le fournit, un identifiant natif stable comme un SID AD ou un
`entryUUID` OpenLDAP.

### Access: quelle habilitation est revue ?

Un Access est l'habilitation observable et certifiable. Il peut etre opaque, composite ou detaille:

```text
PREMIUM_USER                         habilitation opaque
CRM-Sales                            role composite
Contacts                             cible connue, action inconnue
Contacts:Read                        droit fin
FinanceBucket:GetObject              droit provider-specific
```

Un Access n'est pas une personne et n'est pas encore l'attribution a une personne. Il decrit ce qui
peut etre detenu.

### Target: sur quoi porte l'acces ?

`Target` est optionnel. Il sert uniquement lorsqu'une cible identifiable est fournie par la source:

```text
Contacts
Invoices
/srv/finance
arn:aws:s3:::finance/*
namespace/prod/pods
```

Pour un role opaque comme `CRM-Sales`, `Target` peut rester vide. EARE ne doit pas inventer une
cible.

### Permission: quelle action est accordee ?

`Permission` est optionnelle et singuliere. Elle decrit une action lorsqu'elle est connue:

```text
read       write       member       SELECT
get        list        s3:GetObject
```

Les permissions restent provider-specific. `Contacts:Read` et `Contacts:Write` sont deux Access
separables, meme si l'interface les affiche ensemble.

### AccessAssignment: qui detient directement quoi ?

```text
Alice -> CRM-Sales
```

Cette fleche est un `AccessAssignment`. C'est l'information principalement certifiee par la Golden
Source. L'assignment conserve aussi son origine, par exemple groupe AD, groupe LDAP ou attribution
directe.

### AccessRelation: qu'accorde un role ou un groupe ?

```text
CRM-Sales --grants--> Contacts:Read
CRM-Sales --grants--> Contacts:Write
```

C'est une relation entre deux Access, pas une nouvelle attribution a Alice. Elle peut etre composee
sur plusieurs niveaux:

```text
Alice -> CRM-Manager -> CRM-Sales -> Contacts:Read
```

### Origin et metadata: pourquoi cette information existe-t-elle ?

`Origin` indique la provenance de l'observation. `metadata` conserve des details provider-specific
qui doivent rester tracables sans etre interpretes par le coeur:

```text
Origin:   AD nested group
metadata: group SID, condition native, source file, collection context
```

Ces champs ne transforment pas EARE en moteur universel de policy.

## 4. Les notions essentielles

### Provider

Un Provider est une source d'identites et d'acces, par exemple un domaine Active Directory ou un
annuaire OpenLDAP.

### Identity

Une Identity est la personne, le groupe ou le compte observe dans la source. Les comptes
techniques, comptes partages et groupes peuvent etre identifies selon les informations disponibles.

### Access

Un Access est une habilitation que l'on peut observer et revoir. Il peut etre:

```text
PREMIUM_USER                         habilitation opaque
CRM-Sales                            role ou acces composite
Contacts                             cible connue, action inconnue
Contacts:Read                        cible Contacts, action read
FinanceBucket:GetObject              cible AWS, action provider-specific
```

`Target` et `Permission` sont facultatifs. Une source qui ne fournit pas le detail d'une cible ou
d'une action peut donc rester exploitable sans inventer d'information.

### Attribution directe et acces effectif

Une attribution directe est ce que la source donne directement a l'identite:

```text
Emma -> CRM-Sales
```

Un acces effectif peut venir de la composition du role:

```text
Emma -> CRM-Sales -> contacts:read
```

L'acces effectif explique pourquoi le droit est present; il ne remplace pas l'attribution directe.

## 5. Parametrage utilisateur

### Parametres de la commande EARE

La base SQLite est configurable avec `--db`. Le parametre global se place avant la sous-commande:

```bash
access-review --db data/review.db import corp-ad-export.zip
access-review --db data/review.db findings-list
access-review --db data/review.db access-effective "Alice Martin" --provider corp-ad
```

Pour un import, les parametres disponibles sont:

| Parametre | Utilite | Exemple |
| --- | --- | --- |
| `--provider` | nom du Provider pour un fichier LDIF OpenLDAP | `--provider internal-ldap` |
| `--classification-rules` | fichier JSON de classification optionnelle des comptes AD | `--classification-rules rules.json` |
| `--db` | chemin de la base SQLite | `--db data/eare.db` |

Le Provider est lu dans le manifeste d'un export ZIP. Pour un LDIF, il est fourni par
`--provider` et vaut `openldap` par defaut. Le fichier SQLite est cree s'il n'existe pas; choisir un
chemin stable permet de conserver les snapshots, la Golden Source et les campagnes entre deux
imports.

Valider un fichier sans l'importer dans SQLite:

```bash
access-review validate corp-ad-export.zip
access-review validate directory.ldif
```

Cette commande verifie le format et les protections de l'archive. Elle ne produit ni snapshot ni
modification de la base.

### Classification optionnelle des comptes AD

Par defaut, un utilisateur AD est conserve comme `user_account`. Pour reconnaitre des comptes de
service ou partages selon des regles deterministes, fournir un fichier JSON:

```json
{
  "identity_classification": {
    "technical_account": {
      "samaccountname_prefixes": ["svc_", "svc-"],
      "dn_contains": ["OU=Service Accounts"],
      "has_service_principal_name": true
    },
    "shared_account": {
      "samaccountname_prefixes": ["shared_", "generic_"]
    }
  }
}
```

Puis:

```bash
access-review import corp-ad-export.zip --classification-rules rules.json
```

Ces regles modifient la classification de l'Identity, pas son Access ni ses permissions. Les
comptes geres AD (MSA/gMSA) et les ordinateurs sont deja traites comme comptes techniques par le
collecteur.

### Parametres des collecteurs

Les parametres de collecte sont appliques avant l'import, sur la machine qui interroge la source.

Pour Active Directory:

```powershell
.\export-active-directory.ps1 `
  -ProviderName corp-ad `
  -Output corp-ad-export.zip `
  -Server dc01.corp.local `
  -OperationTimeoutSeconds 300
```

`-Server` est optionnel et permet de cibler un controleur de domaine. Le timeout par operation vaut
300 secondes par defaut. `-AllowPartial` autorise la production d'un export diagnostique incomplet;
il ne le transforme pas en collecte `FULL` et ne doit pas etre utilise pour conclure a une
suppression.

Pour OpenLDAP, les variables de l'environnement du collecteur configurent la connexion, la securite
et le perimetre:

```dotenv
LDAP_URI=ldaps://ldap.example.test
BASE_DN=dc=example,dc=test
PROVIDER_NAME=internal-ldap
PAGE_SIZE=500
CONNECTION_TIMEOUT_SECONDS=10
SEARCH_TIMEOUT_SECONDS=60
SEARCH_SCOPE=sub
LDAP_FILTER=(objectClass=*)
```

`START_TLS=1` est reserve a une URI `ldap://`. Un bind authentifie exige LDAPS ou StartTLS; la
verification TLS reste active. `ALLOW_PARTIAL=1` conserve un export apres erreur mais sa completude
devient prudente (`UNKNOWN`). Les secrets doivent rester dans un fichier local non versionne, par
exemple `LDAP_PASSWORD_FILE`; ne jamais les mettre dans le manifeste, une commande ou un rapport.

### Completude et perimetre

Le manifeste ou le collecteur peut qualifier une collecte:

| Etat | Effet dans EARE |
| --- | --- |
| `FULL` | l'absence observee peut remplacer l'etat autoritatif dans le perimetre collecte |
| `SCOPED` ou `PARTIAL` | seuls les objets observes dans le perimetre sont mis a jour |
| `UNKNOWN` | les informations deja connues sont conservees; aucune suppression implicite |

Pour les relations, `None` signifie que le collecteur n'a pas fourni cette information. `[]` signifie
que le graphe observe est explicitement vide, mais sa suppression n'est appliquee que par une collecte
`FULL` et autoritative dans le perimetre concerne. Une relation absente d'une collecte partielle n'est
donc pas une relation supprimee.

Le meme principe protege les identites, Access et assignments: `SCOPED`, `PARTIAL` ou `UNKNOWN` ne
doivent jamais effacer ce qui se trouve hors perimetre ou ce qui n'a pas pu etre observe.

## 6. Parcours habituel

```text
Collecter -> Importer -> Observer -> Comparer -> Revoir -> Decider -> Exporter
```

### Etape 1: importer une collecte

Pour Active Directory, utiliser l'exporteur prevu puis importer le ZIP:

```bash
access-review import corp-ad-export.zip
```

Pour OpenLDAP, importer un LDIF:

```bash
access-review import directory.ldif --provider internal-ldap
```

Une collecte peut etre complete, limitee a un perimetre ou inconnue. Une collecte incomplete ne doit
pas provoquer automatiquement de faux acces manquants ou de fausses suppressions.

### Etape 2: consulter l'etat observe

Commencer par verifier:

- le Provider et le perimetre de collecte;
- les identites actives, desactivees, supprimees ou inconnues;
- les Access directs;
- les relations de composition;
- les acces effectifs et leur provenance;
- les diagnostics de collecte ou de collision.

### Etape 3: comparer avec la Golden Source

Une Golden Source represente les attributions attendues, par exemple:

```text
Golden attend: Emma -> CRM-Sales
```

Elle ne liste pas obligatoirement tous les droits produits par le role. EARE calcule les acces
effectifs a partir de la composition observee.

## 7. Comprendre les resultats

```text
expected_and_observed  acces attendu et observe
unexpected             acces observe mais non attendu
missing                acces attendu absent d'une collecte authoritative
unknown_due_to_scope   impossible de conclure avec le perimetre collecte
no_reference           aucune Golden Source disponible
```

`unexpected` ne signifie pas automatiquement fraude. Cela signifie que l'acces n'est pas present
dans la reference selectionnee et doit etre examine.

`missing` n'est fiable que lorsqu'une collecte complete et authoritative prouve l'absence. Une
collecte limitee ou inconnue produit un resultat prudent.

## 8. Golden Source

La Golden Source est la reference des attributions attendues. Ses versions sont historiques et ne
sont pas modifiees retroactivement.

```text
Observation -> Snapshot -> comparaison Golden -> campagne -> nouvelle version eventuelle
```

Dans le cas CRM:

```text
Golden:  Emma -> CRM-Sales
Role:    CRM-Sales grants contacts:read
         CRM-Sales grants contacts:write
```

Si `contacts:write` est ajoute au role, EARE peut signaler un changement d'acces effectif meme si
l'attribution directe d'Emma n'a pas change.

## 9. Campagnes de revue

Une campagne est ouverte a partir d'un snapshot. Elle contient les elements a examiner par les
reviewers:

- identite et statut;
- Access observe;
- attendu vs observe;
- origine et provenance;
- finding eventuel;
- decision et commentaire.

Une campagne ouverte reste fondee sur son snapshot. Les imports suivants ne changent pas ce que le
reviewer a vu.

Decisions disponibles:

- `approve`: conserver ou accepter l'acces;
- `revoke`: preparer la suppression de l'acces;
- `not_applicable`: ne pas appliquer la decision a cet element.

Les permissions `read` et `write` restent distinctes afin de permettre une decision ou une
remediation partielle.

## 10. Rapports et remediation

EARE peut produire des rapports HTML, CSV et JSON ainsi que des exports de remediation.

```bash
access-review campaign-export reports/
```

Les rapports montrent notamment:

- la matrice des acces;
- les roles et permissions;
- les findings;
- les decisions;
- la posture d'authentification lorsqu'elle est disponible;
- les valeurs non collectees explicitement.

Une recommandation de remediation ne signifie pas qu'EARE execute automatiquement une revocation
sur le systeme source. L'export doit etre controle et applique selon les procedures de l'organisation.

## 11. Active Directory et OpenLDAP

### Active Directory

Le support actuel couvre notamment les utilisateurs, groupes, imbrications, groupes primaires,
ordinateurs, comptes de service, comptes geres, Foreign Security Principals, renommages, comptes
desactives et certaines observations d'authentification.

### OpenLDAP

Le support actuel couvre notamment `entryUUID`, les renommages, `member`, `uniqueMember`, `memberUid`,
les membres non resolus, la pagination, les collectes partielles et les modes TLS/StartTLS/LDAPS.

## 12. Limites importantes

EARE ne remplace pas le moteur d'autorisation natif. Il ne calcule pas automatiquement:

- les ACL NTFS ou AD effectives;
- les permissions Azure/Entra runtime;
- l'evaluation complete des policies AWS/GCP;
- les conditions PIM/JIT comme moteur de decision;
- les politiques Kubernetes ou GitHub comme moteur d'execution.

Les technologies AWS, Azure, GCP, Entra ID, Keycloak, Kubernetes et GitHub sont actuellement des
cas de test du modele, pas des connecteurs integres.

## 13. Securite et donnees sensibles

Les mots de passe, tokens, cles privees, API keys, secrets clients et hashes ne doivent pas etre
mis dans les exports de collecte, les snapshots, les rapports ou les diagnostics. Les erreurs de
collecte doivent etre traitees comme des etats incomplets, pas comme une preuve d'absence d'acces.
