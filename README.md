# Easy Access Review Engine

MVP Python open source pour importer des exports AD/OpenLDAP, normaliser les acces, comparer avec
une Golden Source optionnelle, lancer une campagne de recertification et produire un rapport HTML
autonome.

## Demarrage rapide

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[app,dev]"
pytest
```

Importer un ZIP Active Directory:

```bash
access-review import corp-ad-export.zip
access-review findings-list
```

Importer un LDIF OpenLDAP:

```bash
access-review import directory.ldif --provider internal-ldap
```

Exporter un rapport de campagne:

```bash
access-review campaign-export reports/
```

Le fichier `reports/campaign-report.html` est autonome et s'ouvre sans backend.

## Experience AD

1. Lancer `exporters/active-directory/export-active-directory.ps1`.
2. Recuperer `corp-ad-export.zip`.
3. Importer le ZIP.
4. Consulter les ecarts/anomalies.
5. Creer et ouvrir une campagne.
6. Saisir les decisions.
7. Generer HTML/CSV/JSON/remediation.
8. Promouvoir le snapshot ou la campagne en Golden Source.

Le modele interne reste generique: les informations AD specifiques sont conservees dans `metadata`
ou `origin.raw`.


La conception detaillee est documentee dans [docs/engineering.md](docs/engineering.md), avec les
frontieres de modules, le graphe d'acces effectif, la Golden Source, la persistance SQLite, les
regles de compatibilite et les limites V1.


Le parcours fonctionnel est decrit dans le [guide utilisateur](docs/user-guide.md). La documentation
technique pour les developpeurs reste dans [docs/engineering.md](docs/engineering.md).


## Modele de composition et stabilisation V1

Le coeur conserve un modele minimal: `Provider`, `Identity`, `Access`, `AccessAssignment` et
`AccessRelation`. Un `Access` peut etre opaque, composite ou fin; `target` et `permission` sont
optionnels. Les relations `grants` composent les acces et le calcul effectif conserve la provenance
sans creer d'assignments derives.

La branche `improve-model` durcit la reconciliation sans migration destructive de la cle historique
`(provider, name)`: les enrichissements sont conservateurs et les collisions de target/permission
sont refusees explicitement. AD et OpenLDAP restent les connecteurs integres. Les autres technologies
servent uniquement de fixtures de stress du modele.


## Active Directory support

The AD V1 importer/exporter targets file-based collection from recent enterprise AD DS deployments
(Windows Server 2019, 2022 and 2025 ActiveDirectory module shapes). Supported observations include:

- users, groups and direct nested group edges;
- disabled accounts without confusing them with locked or expired accounts;
- gMSA/MSA as `technical_account` identities;
- computer principals referenced by group memberships;
- primary group memberships reconstructed as normal assignments with `MembershipType=primary_group`;
- Foreign Security Principals preserved by SID when unresolved;
- cross-domain membership resolution by SID when both providers are available;
- built-in accounts detected by SID/RID;
- deterministic optional classification rules for classic service/shared user accounts;
- locked and expired account findings.

The project does not claim to compute effective NTFS permissions, GPO permissions, AD ACL effective
rights, Kerberos delegation effective access, Azure/Entra permissions, PAM/JIT or provisioning.
