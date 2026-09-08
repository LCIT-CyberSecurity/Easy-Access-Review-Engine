# OpenLDAP

`exporters/openldap/export-openldap.sh` is a remote acquisition layer. It reads OpenLDAP with
`ldapsearch`, writes the existing ZIP/LDIF export format, and the normal offline importer consumes
that export. There is no second remote business pipeline.

Flow:

```text
remote OpenLDAP -> collector script -> existing OpenLDAP ZIP/LDIF format -> existing importer and offline pipeline
```

The importer supports `inetOrgPerson`, `posixAccount`, `groupOfNames`, `groupOfUniqueNames`,
`posixGroup`, `member`, `uniqueMember` and `memberUid`.

## Memberships

- `member` resolves by DN.
- `uniqueMember` resolves by DN. If the LDAP value uses standard Name And Optional UID syntax
  (`DN#UID`), the DN part is used for identity resolution and the optional UID is preserved in
  assignment raw metadata.
- `memberUid` resolves only when exactly one local identity has the UID. No candidate or multiple
  candidates stay unresolved; the importer does not guess.
- `entryUUID` remains the preferred native stable identifier when present. A rename keeps the same
  identity; a recreation with the same DN/CN and a new `entryUUID` becomes a new identity.

## `.env`

The collector may load a local `.env` file before reading process environment variables. The real
`.env` file is ignored by Git. Use `.env.example` as a template and keep only fake values in tracked
files.

Variables used by the OpenLDAP collector:

- `LDAP_URI`, for example `ldaps://ldap.example.test` or `ldap://ldap.example.test` with StartTLS.
- `BASE_DN`, required search base.
- `PROVIDER_NAME`, provider name written to the manifest.
- `BIND_DN`, optional bind DN.
- `LDAP_PASSWORD` or `LDAP_PASSWORD_FILE`, used only when `BIND_DN` is set. The script passes the
  secret to `ldapsearch` through a password file, not as a visible process argument.
- `LDAP_CA_CERT`, optional CA bundle/path exported as `LDAPTLS_CACERT`.
  TLS certificate and hostname verification remain required by default.
- `START_TLS`, set to `1` for StartTLS on `ldap://`.
- `ALLOW_ANONYMOUS`, must be `1` to allow anonymous collection.
- `ALLOW_PARTIAL`, must be `1` to keep a diagnostic ZIP after collection errors.
- `PAGE_SIZE`, `CONNECTION_TIMEOUT_SECONDS`, `SEARCH_TIMEOUT_SECONDS`, `COMMAND_TIMEOUT_SECONDS`,
  `SEARCH_SCOPE`, `LDAP_FILTER`.

## TLS and Fail Closed

Authenticated binds require either LDAPS (`ldaps://`) or StartTLS (`ldap://` with `START_TLS=1`). An
authenticated clear-text LDAP bind is rejected by default. Combining LDAPS and StartTLS is rejected.
TLS verification is strict by default: the collector exports `LDAPTLS_REQCERT=demand` and
`LDAPTLS_REQSAN=demand`, so `ldapsearch` must validate the certificate, trust chain and hostname.
`LDAP_CA_CERT` can add the expected CA bundle/path. No TLS verification bypass is provided by default.

The collector uses paged search (`-E pr=PAGE_SIZE/noprompt`) and configurable timeouts. LDAP errors,
time limits, size limits, truncation and command timeout mark the export as `completeness: unknown`.
Without `ALLOW_PARTIAL=1`, such failures exit non-zero instead of producing an apparently full export.

Secrets are not written to the manifest. Captured LDAP stderr and collection diagnostics are redacted
with literal matching against configured passwords. `directory.ldif` is authoritative payload and is
not silently redacted. If a configured connection secret appears in the LDIF, the collector fails
closed and writes no export ZIP instead of fabricating altered directory data.
