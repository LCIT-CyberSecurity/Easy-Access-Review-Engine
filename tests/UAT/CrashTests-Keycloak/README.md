# Keycloak crash-test lab

This lab is isolated as the Compose project `eare-keycloak-crashtest`. It uses
its own named volumes and publishes the EARE UI on `127.0.0.1:4175`; it does
not call `docker compose` for any other project and never removes arbitrary
volumes. In particular, a running `4173` stack is left untouched.

The stack contains OpenLDAP, PostgreSQL, Keycloak, the EARE API and the EARE
web UI. Docker is required. `reset.sh` removes only this Compose project's
containers and its two explicitly named volumes.

The realm seed is deliberately not hidden in an opaque binary. The intended
seed is `eare-crashtest`, with LDAP federation in read-only mode, the users,
groups, roles, composites and service account described by the Keycloak V1
documentation. The API collector uses the realm's service-account client and
stores its secret only in `EARE_KEYCLOAK_CLIENT_SECRET`.

The live lab is intended to be run on a Docker host. It is fully self-contained
and seeds the complete workflow automatically:

```bash
./reset.sh
./run.sh
```

The runner seeds LDAP, configures Keycloak federation and RBAC, creates the
source through the EARE API, runs the full and scoped collections, creates the
Golden Source and campaign, injects the Charlie/Bob drift, records decisions,
checks reporting, and verifies restoration to FULL. It also verifies that the
existing 4173 stack is unchanged. The collector is additionally covered by the
offline fake-Admin-API tests in `tests/test_keycloak_collector.py`.
