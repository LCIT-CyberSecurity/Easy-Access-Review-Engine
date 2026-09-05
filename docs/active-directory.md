# Active Directory

Exporter:

```powershell
.\export-active-directory.ps1 -ProviderName corp-ad -Output corp-ad-export.zip
```

Le ZIP contient `manifest.yaml`, `users.csv`, `groups.csv` et `memberships.csv`. Les memberships sont
directs, jamais recursifs. `Description`, `DisplayName`, `Name` et les SID sont conserves quand ils
existent.
