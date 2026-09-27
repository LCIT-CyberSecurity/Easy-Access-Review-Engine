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

The current repository environment does not provide Docker, so the live
OpenLDAP → Keycloak → EARE workflow is not certified by CI here. Do not report
the live lab as passing until the following has been exercised on a Docker
host:

```bash
./reset.sh
./run.sh
```

Then seed Keycloak, configure the source through the normal EARE API/UI
workflow, run the full collection, create the Golden Source, inject the
Charlie/Bob drift, run the second collection and campaign, and verify the
partial-collection false-delete test. The collector itself is covered by the
offline fake-Admin-API tests in `tests/test_keycloak_collector.py`.
