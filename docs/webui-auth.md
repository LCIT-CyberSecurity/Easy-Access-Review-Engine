# EARE WebUI authentication

The WebUI uses an HTTP-only, signed session cookie. It does not trust `X-EARE-Role` or `X-EARE-Scopes` headers.

Provision the first administrator explicitly before starting the API:

```text
EARE_ADMIN_USERNAME=admin
EARE_ADMIN_PASSWORD=<12-or-more-character-secret>
EARE_SESSION_SECRET=<random-secret>
```

The bootstrap variables are used only when the application user table is empty. Passwords are stored as PBKDF2-SHA256 hashes and are never returned by the API. Set `EARE_COOKIE_SECURE=1` when serving over HTTPS.

## Local accounts and directory accounts

Every EARE user signs in either with a local account or with an account taken from an LDAP directory. This is about signing in to EARE; the directories EARE audits are configured in **Sources & IdPs** and are unrelated, even when they point at the same server.

A directory account stores no password in EARE. At sign-in, EARE resolves the account in the directory and binds as that account to verify the password, through `ldapsearch`, so the project keeps no LDAP dependency and no password ever reaches a command line. A login that matches more than one directory entry never authenticates.

Roles and scopes are always managed in EARE, never derived from directory groups. Keep at least one local administrator: it is the way back in when the directory is unreachable.

## Configure a directory

In **System → Authentication**, add an LDAP directory:

| Field | Meaning |
| --- | --- |
| Name | Identifies the directory in EARE, and is what the user list shows as the sign-in source |
| LDAP URI | For example `ldaps://ldap.example.org` |
| Base DN | Where accounts are searched, for example `dc=example,dc=org` |
| Login attribute | `uid`, or `sAMAccountName` on Active Directory |
| User filter | Optional, defaults to `(objectClass=person)` |
| Service account DN | Optional, needed when the directory refuses anonymous searches |
| Password environment variable | Name of the server variable holding the service account password |

The service account password stays in the server environment, like collector secrets:

```text
EARE_DIRECTORY_PASSWORD=<service-account-secret>
```

**Test connection** checks the configuration, including the password variable, before saving. Clearing **Allow people from this directory to sign in** immediately blocks every account from that directory without deleting them.

## Import accounts

In **System → Users & permissions**, the button **+ From \<directory\>** searches the directory and imports the selected person. The administrator then assigns the role and, for a `BUSINESS_ADMIN`, the scopes. Only imported accounts can sign in: no account is created on the fly at first sign-in.

A `GROUP_OWNER` username must match the reviewer identifier used by the audited source, otherwise no review is assigned to that person.
