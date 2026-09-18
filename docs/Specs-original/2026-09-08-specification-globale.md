# Easy Access Review Engine — Spécification globale

**Date :** 2026-09-08  
**Statut :** Spécification cible / vision produit  
**Portée :** Vision fonctionnelle et architecture cible du projet Easy Access Review Engine  
**Branche de référence :** `fix/ad-collector-hardening-v1`

---

## 1. Objet du document

Ce document décrit la cible fonctionnelle et technique à terme d'**Easy Access Review Engine** (EARE).

EARE est un moteur open source léger de **revue, certification et recertification des habilitations**, conçu pour fonctionner indépendamment des solutions IAM/IGA existantes.

L'objectif n'est pas de devenir une solution IAM complète ni de provisionner directement les droits dans les systèmes sources. EARE doit permettre de répondre simplement et de manière auditable aux questions suivantes :

- quelles identités existent dans chaque système ;
- quelles habilitations sont réellement observées ;
- quelles habilitations devraient exister lorsqu'une référence est disponible ;
- quelles différences existent entre la réalité et la référence ;
- qui est propriétaire de chaque compte et de chaque habilitation ;
- qui doit revoir et valider les accès ;
- quelles décisions ont été prises ;
- quelles révocations ou corrections doivent ensuite être appliquées ;
- quelle preuve de revue peut être conservée pour l'audit ou la conformité.

Le produit doit rester **simple à déployer, compréhensible, Git-friendly, API-first et indépendant des technologies d'identité sous-jacentes**.

---

## 2. Positionnement

### 2.1 Ce que fait EARE

EARE couvre principalement :

1. la collecte ou l'import des identités et habilitations ;
2. leur normalisation dans un modèle commun ;
3. la conservation de l'origine technique des accès ;
4. la comparaison entre l'observé et une Golden Source optionnelle ;
5. la génération de constats et d'écarts ;
6. la création de campagnes de revue ;
7. la prise de décision par les reviewers ;
8. la génération de rapports et de preuves ;
9. la génération d'actions de remédiation ;
10. la promotion d'un état validé vers une nouvelle version de Golden Source.

### 2.2 Ce que EARE ne doit pas devenir

EARE n'a pas vocation, dans son cœur produit, à devenir :

- un annuaire ;
- un fournisseur d'identité ;
- un moteur SSO ;
- une solution PAM ;
- un moteur de provisioning temps réel ;
- un gestionnaire de mots de passe ;
- un moteur complet de gouvernance RH ;
- une solution de calcul universel des droits effectifs de tous les systèmes ;
- un remplacement d'Active Directory, Entra ID, LDAP, Keycloak, AWS IAM ou équivalent.

Le principe reste : **observer, normaliser, comparer, faire revoir, tracer et exporter les corrections**.

---

## 3. Principes structurants

### 3.1 Modèle provider-agnostic

Le modèle métier doit rester indépendant de la technologie source.

Chaîne principale :

```text
Provider
  ↓
Identity
  ↓
AccessAssignment
  ↓
Access
  ↓
Resource
```

Gouvernance :

```text
Observed data
    ↕
GoldenSourceVersion
    ↓
Comparison
    ↓
Snapshot
    ↓
Campaign
    ↓
ReviewItem
    ↓
Decision
    ↓
Report / Remediation / Audit
```

### 3.2 Séparation Access / AccessAssignment

Un **Access** représente une habilitation ou un contrôle d'accès logique.

Un **AccessAssignment** représente l'attribution réelle de cet accès à une identité.

Cette séparation est obligatoire car une même habilitation peut être obtenue par plusieurs chemins.

Exemple :

```text
Jean Dupont
  ├─ membre direct de GG_FINANCE
  └─ membre de GG_MANAGERS → GG_FINANCE
```

Les deux chemins doivent pouvoir être conservés séparément.

L'origine appartient donc à `AccessAssignment`, pas à `Access`.

### 3.3 Conservation de l'origine

Chaque attribution doit pouvoir conserver son origine technique :

- direct ;
- group ;
- nested group ;
- role ;
- policy ;
- primary group ;
- inherited ;
- autre origine native du provider.

Un `origin_fingerprint` doit permettre de distinguer plusieurs chemins conduisant au même accès.

### 3.4 Fail closed sur la complétude

Invariant majeur :

> Une absence d'observation ne peut être considérée comme `missing` que si la collecte est connue comme exhaustive pour le périmètre concerné.

Donc :

```text
collecte complète et authoritative
→ MISSING possible

collecte partielle / scoped / unknown / erreur
→ UNKNOWN / collection_incomplete
→ jamais de faux MISSING
```

La sûreté de la conclusion est plus importante que la quantité de constats produits.

---

## 4. Objets métier principaux

## 4.1 Provider

Un Provider représente un système source ou un domaine de sécurité.

Exemples :

- Active Directory ;
- OpenLDAP ;
- Entra ID ;
- Keycloak ;
- AWS IAM ;
- GCP IAM ;
- Google Workspace ;
- Linux ;
- base de données ;
- application métier.

Champs principaux :

- identifiant interne ;
- nom unique ;
- type ;
- description ;
- métadonnées ;
- état ;
- informations de dernière collecte.

Les secrets de connexion ne doivent jamais être intégrés aux fichiers métier exportables ou à la Golden Source.

---

## 4.2 Identity

Une Identity représente un principal technique pouvant posséder ou recevoir un accès.

Types V1 :

- `user_account` ;
- `technical_account` ;
- `shared_account` ;
- `group`.

Évolutions possibles sans casser le modèle :

- machine/computer spécifique ;
- service principal ;
- workload identity ;
- managed identity ;
- sujet/personne logique séparé.

Champs structurants :

- UUID interne stable ;
- provider ;
- identifier lisible ;
- native_id stable fourni par le provider ;
- type ;
- status ;
- display_name ;
- description ;
- account_owner ;
- built_in ;
- subject_id optionnel ;
- metadata provider-specific.

États minimaux :

- `active` ;
- `disabled` ;
- `deleted` ;
- `unknown`.

Règles d'owner :

- user_account : owner généralement non requis ;
- technical_account non built-in : owner requis ;
- shared_account : owner requis ;
- group : owner requis par défaut selon politique ;
- owner valide = user_account actif ;
- auto-ownership interdit.

---

## 4.3 Resource

Resource représente la cible logique d'un accès.

Exemples :

- application ;
- partage de fichiers ;
- bucket ;
- projet cloud ;
- serveur ;
- base de données ;
- environnement ;
- tenant ;
- service métier.

Le modèle doit rester générique et permettre des métadonnées spécifiques à chaque provider.

---

## 4.4 Access

Access représente une habilitation ou un objet de contrôle.

Il doit pouvoir représenter aussi bien :

- un groupe AD ;
- un rôle Keycloak ;
- un rôle applicatif ;
- une permission cloud ;
- un permission set ;
- une policy ;
- un rôle SQL ;
- une ACL normalisée ;
- un groupe LDAP.

Champs principaux :

- UUID ;
- provider de contrôle ;
- nom ;
- display_name ;
- description ;
- access_owner ;
- control_object type ;
- control_object identifier ;
- permission ;
- resource cible ;
- metadata.

`access_owner` représente le propriétaire fonctionnel ou métier de l'habilitation et constitue normalement le reviewer par défaut.

---

## 4.5 AccessAssignment

AccessAssignment relie une Identity à un Access.

Il conserve :

- Identity ;
- Access ;
- provider de l'identité ;
- origine ;
- origin_fingerprint ;
- nature directe ou indirecte ;
- données brutes utiles ;
- ImportBatch source.

Il doit être possible d'avoir plusieurs AccessAssignments entre une même identité et un même Access si les chemins sont différents.

---

## 4.6 ImportBatch

Chaque collecte/import doit créer un ImportBatch traçable.

Champs majeurs :

- provider ;
- date ;
- source ;
- checksum ;
- completeness ;
- scope ;
- statistiques ;
- erreurs de collecte ;
- version de schéma ;
- version du collecteur.

Valeurs de completeness :

- `full` ;
- `scoped` ;
- `unknown`.

Une importation scoped doit préciser son scope de manière exploitable par le moteur de comparaison.

---

## 5. Golden Source

### 5.1 Principe

La Golden Source est optionnelle.

EARE doit fonctionner dans deux modes :

```text
Observed only
→ inventaire + findings + revue

Observed + Golden Source
→ inventaire + comparaison + revue de conformité
```

Sans Golden Source, un accès observé ne doit jamais être qualifié automatiquement d'« unauthorized ».

Il doit être classé `no_reference`.

### 5.2 Versionnement

La Golden Source doit être immuable par version.

Objets :

- GoldenSource ;
- GoldenSourceVersion ;
- GoldenSourceAssignment.

Chaque version doit conserver :

- parent_version_id ;
- checksum ;
- date ;
- auteur ;
- commentaire ;
- origine ;
- source snapshot/campaign éventuelle.

### 5.3 Sources possibles

- import manuel ;
- promotion d'un snapshot observé ;
- promotion d'une campagne fermée ;
- génération dérivée ;
- future importation depuis une source externe de référence.

### 5.4 Promotion depuis une campagne

Règle cible :

- `approve` → accès conservé / attendu ;
- `revoke` → accès retiré de la référence ;
- `not_applicable` → pas de modification automatique ;
- `pending` → promotion bloquée.

Pour un accès expected mais missing :

- approve = l'accès reste attendu, donc une action de grant peut être générée ;
- revoke = il n'est plus attendu et doit disparaître de la Golden Source.

---

## 6. Comparaison Observed / Golden Source

Catégories minimales :

- `expected_and_observed` ;
- `unexpected` ;
- `missing` ;
- `unknown_due_to_scope` ;
- `no_reference`.

La comparaison doit prendre en compte :

- provider ;
- identity stable ;
- access ;
- resource ;
- scope ;
- completeness ;
- éventuellement le chemin lorsque nécessaire.

Le moteur doit distinguer clairement :

```text
absence réellement démontrée
```

de :

```text
absence non observable avec certitude
```

---

## 7. Findings

Les Findings représentent les problèmes détectés indépendamment de la Golden Source.

Exemples cibles :

- disabled_with_access ;
- deleted_with_access ;
- account_locked ;
- account_expired ;
- technical_account_without_owner ;
- shared_account_without_owner ;
- group_without_owner ;
- invalid_owner ;
- unknown_identity ;
- unresolved_foreign_principal ;
- orphaned_access ;
- collection_incomplete ;
- duplicate/native-id conflict ;
- stale identity ou stale access à terme.

Les findings doivent rester séparés des catégories de comparaison.

---

## 8. Snapshot

Un Snapshot représente l'état immuable utilisé pour une campagne.

Il doit figer exactement :

- providers ;
- identities ;
- accesses ;
- assignments ;
- owners ;
- origins ;
- findings ;
- métadonnées utiles ;
- Golden Source version utilisée ;
- ImportBatch sources ;
- checksum déterministe.

Une campagne ne doit jamais changer parce qu'un nouvel import arrive après son ouverture.

---

## 9. Campaign

États minimaux :

- `draft` ;
- `open` ;
- `closed` ;
- `cancelled`.

Une Campaign :

- référence un Snapshot précis ;
- référence une GoldenSourceVersion précise si utilisée ;
- possède un périmètre ;
- possède un reviewer par défaut / campaign manager ;
- génère des ReviewItems immuables.

Une campagne ne doit pas s'ouvrir si des reviewers obligatoires sont non résolus, sauf override explicite et audité.

---

## 10. ReviewItem et Decision

### 10.1 ReviewItem

ReviewItem est la représentation immuable de ce que le reviewer voit et décide.

Il doit inclure au minimum :

- identity ;
- access ;
- resource ;
- access_owner ;
- account_owner ;
- origine ;
- classification de comparaison ;
- findings associés ;
- état observé / attendu ;
- reviewer attendu.

### 10.2 Decision

Décisions :

- `approve` ;
- `revoke` ;
- `not_applicable`.

`pending` = absence de décision.

Règles :

- commentaire obligatoire pour revoke ;
- commentaire obligatoire pour not_applicable ;
- historique des modifications ;
- acteur authentifié ;
- contrôle que l'acteur peut décider sur l'item ;
- contrôle que la campagne est ouverte ;
- décisions auditées.

### 10.3 Résolution du reviewer

Ordre cible par défaut :

```text
access_owner
→ account_owner
→ reviewer campagne
→ campaign manager / admin fallback
```

Cet ordre doit être configurable à terme.

---

## 11. Remediation

Le MVP et le cœur produit doivent fonctionner en **export de remédiation**, sans provisioning direct obligatoire.

Exemples :

```text
revoke unexpected access
→ revoke action

approve expected-but-missing
→ grant action
```

Formats :

- CSV ;
- JSON ;
- API ;
- éventuellement formats provider-specific.

À terme, des connecteurs de provisioning pourront être ajoutés comme extension, mais doivent rester découplés du moteur de revue.

---

## 12. Reporting

Le rapport est un livrable central du produit.

### 12.1 Vue principale

Organisation recommandée :

```text
access_owner
  → service / resource
    → entitlement / access / control object
      → identities
```

### 12.2 Informations attendues

Résumé :

- nombre de providers ;
- identities ;
- observed assignments ;
- expected assignments ;
- compliant ;
- unexpected ;
- missing ;
- unknown_due_to_scope ;
- findings ;
- approve ;
- revoke ;
- not_applicable ;
- pending.

Par habilitation :

- nom ;
- description ;
- access_owner ;
- provider ;
- control object ;
- permission ;
- resource ;
- Golden Source version ;
- identities observées ;
- identities attendues ;
- écarts ;
- findings ;
- décision ;
- commentaire.

### 12.3 Filtres

À terme :

- owner ;
- service ;
- resource ;
- provider ;
- control object type ;
- entitlement ;
- identity ;
- identity status ;
- expected/observed ;
- classification ;
- decision ;
- finding.

### 12.4 Exports

Au minimum :

- `campaign-report.html` ;
- `campaign-results.csv` ;
- `campaign-results.json` ;
- `remediation.csv` ;
- `golden-source-diff.csv`.

Le HTML doit être autonome, lisible et filtrable.

---

## 13. Connecteurs et imports

### 13.1 Philosophie

Le moteur de collecte doit être séparé du moteur de gouvernance.

Chaîne :

```text
native system
→ collector/exporter
→ normalized import
→ validation
→ persistence
→ comparison/campaign
```

### 13.2 Priorités

Phase initiale :

- Active Directory ;
- OpenLDAP ;
- imports normalisés CSV/YAML/JSON.

Cible ultérieure :

- Entra ID ;
- Keycloak ;
- AWS IAM ;
- GCP IAM ;
- Google Workspace ;
- Linux ;
- bases de données ;
- applications métier ;
- API générique/plugin SDK.

### 13.3 Fonctions attendues d'un connecteur

À terme :

- `validate_connection` ;
- `discover_provider` ;
- `list_identities` ;
- `list_accesses` ;
- `list_assignments` ;
- retour du scope ;
- retour de la completeness ;
- erreurs structurées ;
- version du collecteur.

---

## 14. Active Directory — cible

Le support AD doit fonctionner au minimum avec les environnements Windows Server modernes et couvrir :

- users ;
- groups ;
- nested groups ;
- disabled accounts ;
- locked accounts ;
- expired accounts ;
- classic service accounts ;
- gMSA ;
- sMSA ;
- computer principals utilisés dans les groupes ;
- built-in accounts ;
- PrimaryGroupID ;
- Foreign Security Principals ;
- multi-domain lorsque les providers nécessaires sont importés ;
- renommage avec conservation de l'identité grâce au SID ;
- suppression uniquement lorsque la collecte est authoritative.

SID constitue le `native_id` principal stable d'une Identity AD.

EARE ne prétend pas calculer automatiquement tous les droits effectifs NTFS, GPO, AD ACL ou Kerberos.

---

## 15. OpenLDAP — cible

Le support OpenLDAP doit couvrir :

- inetOrgPerson ;
- account/posixAccount lorsque configuré ;
- groupOfNames ;
- groupOfUniqueNames ;
- posixGroup ;
- nested groups ;
- member ;
- uniqueMember ;
- memberUid ;
- entryUUID ;
- résolution des memberships par DN normalisé ;
- attributs opérationnels utiles explicitement collectés ;
- classification configurable ;
- gestion correcte du LDIF, base64, binary attributes et DN échappés.

La DN ou un identifiant garanti unique doit permettre d'éviter les collisions liées aux `uid`/`cn` dupliqués entre OUs.

---

## 16. API

Le produit doit exposer une API HTTP simple couvrant à terme :

- providers ;
- identities ;
- resources ;
- accesses ;
- assignments ;
- imports ;
- Golden Sources ;
- comparisons ;
- findings ;
- snapshots ;
- campaigns ;
- review items ;
- decisions ;
- reports ;
- remediation ;
- audit events.

L'API doit utiliser JSON et rester indépendante de l'interface utilisateur.

---

## 17. CLI

La CLI doit permettre les workflows administratifs principaux sans interface graphique.

Exemples cibles :

```text
eare provider add
eare import ad ...
eare import ldap ...
eare compare ...
eare golden-source create ...
eare golden-source promote ...
eare campaign create ...
eare campaign open ...
eare campaign close ...
eare report generate ...
eare remediation export ...
```

La CLI doit être utilisable en CI/CD et scripts d'exploitation.

---

## 18. Interface Web

L'interface Web doit rester volontairement simple.

Fonctions cibles :

- tableau de bord ;
- imports ;
- inventaire des identities/accesses ;
- findings ;
- comparaison ;
- Golden Source ;
- création de campagne ;
- interface reviewer ;
- suivi des décisions ;
- rapport ;
- export remédiation.

Le produit ne doit pas dépendre d'un framework frontend lourd pour fonctionner.

Une architecture serveur simple avec FastAPI/Jinja2/HTMX ou équivalent reste adaptée tant que l'UX est suffisante.

---

## 19. Auditabilité

Toutes les opérations sensibles doivent générer un AuditEvent :

- import ;
- changement d'owner ;
- création/modification de Golden Source ;
- promotion ;
- création/ouverture/fermeture campagne ;
- décision ;
- modification de décision ;
- override ;
- export remédiation ;
- changement de configuration sensible.

Chaque événement doit contenir :

- acteur ;
- date ;
- action ;
- objet ;
- ancien état si pertinent ;
- nouvel état ;
- corrélation/campaign/import id ;
- métadonnées utiles.

---

## 20. Sécurité

Principes :

- aucun secret dans les exports métier ;
- validation stricte des ZIP/imports ;
- protection Zip Slip ;
- limites de taille ;
- parsing robuste CSV/YAML/JSON/LDIF ;
- aucune insertion HTML non échappée dans les rapports ;
- authentification de l'API/Web à terme ;
- contrôle d'autorisation des reviewers ;
- séparation admin/reviewer ;
- protection des décisions et snapshots contre les modifications a posteriori ;
- checksums déterministes pour les objets immuables.

---

## 21. Persistance

Cible :

- SQLite par défaut pour simplicité ;
- compatibilité PostgreSQL ;
- SQLAlchemy 2.x ;
- Alembic ;
- aucune logique destructive globale lors des imports.

Règle absolue multi-provider :

> L'import d'un provider ne doit jamais supprimer ou altérer les données observées appartenant à un autre provider hors du scope explicitement concerné.

---

## 22. Formats

### Configuration humaine

YAML privilégié pour :

- configuration ;
- classification ;
- règles ;
- mapping ;
- connecteurs.

### Échange machine

JSON privilégié pour :

- API ;
- objets normalisés ;
- exports structurés.

### Données tabulaires

CSV pour :

- imports simples ;
- exports ;
- remédiation ;
- rapports détaillés.

Excel pourra être proposé plus tard comme couche de confort, jamais comme format canonique du moteur.

---

## 23. Workflow utilisateur cible

### Sans Golden Source

```text
1. exporter/collecter
2. importer
3. valider les données
4. consulter l'inventaire et les findings
5. créer un snapshot
6. lancer une campagne
7. revoir les accès
8. fermer la campagne
9. exporter le rapport/remédiation
10. éventuellement promouvoir l'état validé en Golden Source
```

### Avec Golden Source

```text
1. exporter/collecter
2. importer
3. sélectionner la Golden Source active
4. comparer observed vs expected
5. traiter findings et écarts
6. créer un snapshot
7. lancer une campagne
8. décider approve/revoke/not_applicable
9. fermer la campagne
10. générer remédiation
11. générer rapport
12. créer éventuellement une nouvelle Golden Source version
```

---

## 24. Roadmap fonctionnelle indicative

### Phase 1 — Core fiable

- modèle métier ;
- persistence ;
- imports normalisés ;
- AD ;
- OpenLDAP ;
- Golden Source ;
- comparison ;
- campaigns ;
- decisions ;
- HTML report ;
- remediation export ;
- CLI ;
- API de base ;
- audit trail.

### Phase 2 — UX et connecteurs

- interface Web complète ;
- Entra ID ;
- Keycloak ;
- AWS IAM ;
- GCP IAM ;
- Google Workspace ;
- templates de classification ;
- améliorations reporting.

### Phase 3 — Gouvernance avancée

- recertifications récurrentes ;
- campagnes multi-stage ;
- délégation reviewer ;
- reminders ;
- SLA ;
- policy engine ;
- risk-based review ;
- API/plugin SDK ;
- connectors supplémentaires ;
- intégration tickets/remédiation.

### Phase 4 — Extensions optionnelles

- provisioning contrôlé via plugins ;
- intégration ITSM ;
- workflows RH ;
- moteur d'analyse de chemins complexes ;
- enrichissement par sources externes ;
- recommandations assistées.

Ces extensions ne doivent pas transformer le cœur du produit en IAM monolithique.

---

## 25. Critères de réussite du projet

EARE est considéré comme réussi si :

1. un administrateur peut collecter des habilitations sans déployer une infrastructure IAM complexe ;
2. plusieurs technologies peuvent être normalisées dans un modèle commun ;
3. les chemins d'accès techniques restent traçables ;
4. une collecte partielle ne produit jamais une conclusion de conformité fausse ;
5. les comptes techniques et partagés peuvent être gouvernés par owner ;
6. une campagne produit une preuve immuable et auditable ;
7. le reviewer comprend immédiatement ce qu'il valide ;
8. les décisions débouchent sur une remédiation exploitable ;
9. une Golden Source peut être construite progressivement à partir de la réalité ;
10. l'outil reste léger, open source et exploitable sans dépendance à un éditeur IAM.

---

## 26. Invariants à préserver dans toutes les évolutions

```text
Provider → Identity → AccessAssignment → Access → Resource
```

```text
L'origine d'une attribution appartient à AccessAssignment.
```

```text
native_id permet de suivre une identité malgré un renommage lorsque le provider fournit un identifiant stable.
```

```text
Une collecte non authoritative ne produit jamais de MISSING certain.
```

```text
La Golden Source est versionnée et immuable.
```

```text
Une campagne travaille sur un Snapshot immuable.
```

```text
Une Decision référence un ReviewItem précis.
```

```text
Importer un provider ne détruit jamais les données d'un autre provider.
```

```text
Sans Golden Source, un accès observé est no_reference et non unauthorized.
```

```text
Le cœur du produit révise et gouverne les accès ; il ne dépend pas du provisioning.
```

---

## 27. Organisation des futures spécifications

Les spécifications détaillées doivent être stockées dans :

```text
docs/specifications/
```

Convention de nommage :

```text
YYYY-MM-DD-description.md
```

Exemples :

```text
2026-09-08-specification-globale.md
2026-09-09-modele-identites.md
2026-09-10-golden-source.md
2026-09-11-campagnes-revue.md
2026-09-12-active-directory.md
2026-09-13-openldap.md
2026-09-14-reporting.md
2026-09-15-api-cli.md
```

Chaque nouvelle décision structurante doit être documentée dans une spécification datée afin de conserver l'historique des choix du projet.
