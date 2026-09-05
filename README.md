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
