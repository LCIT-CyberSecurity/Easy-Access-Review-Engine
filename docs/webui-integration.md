# Full-stack WebUI integration stack

This stack runs the EARE API and WebUI on one browser origin. Nginx serves the compiled SPA and proxies `/api` to the internal FastAPI service. SQLite is persisted in the named `eare-data` volume.

## Start

From the repository root, prepare deployment-only secrets and start the stack:

```bash
cp .env.example .env
# Edit .env and replace every replace-with-* value.
docker compose -f web/compose.yaml up -d --build
```

Open `http://<integration-host>:4173/`. The WebUI login uses `EARE_ADMIN_USERNAME` and `EARE_ADMIN_PASSWORD` only for the first administrator bootstrap. Subsequent users are managed from Administration.

Useful checks:

```bash
docker compose -f web/compose.yaml ps
curl --fail http://<integration-host>:4173/healthz
curl --fail http://<integration-host>:4173/api/health
```

Stop the stack without removing the SQLite volume:

```bash
docker compose -f web/compose.yaml down
```

The backend image includes `bash`, `coreutils`, `zip` and `ldap-utils` (`ldapsearch`) for the OpenLDAP exporter. The AD exporter remains dependent on the PowerShell ActiveDirectory module and the Windows AD integration environment; the Linux backend image does not pretend to provide that module. Keep AD collection on the existing Windows/PowerShell integration path until a supported remote collector is defined.

Do not commit `.env`, database files or collector credentials.
