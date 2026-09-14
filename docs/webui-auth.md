# EARE WebUI authentication

The WebUI uses an HTTP-only, signed session cookie. It does not trust `X-EARE-Role` or `X-EARE-Scopes` headers.

Provision the first administrator explicitly before starting the API:

```text
EARE_ADMIN_USERNAME=admin
EARE_ADMIN_PASSWORD=<12-or-more-character-secret>
EARE_SESSION_SECRET=<random-secret>
```

The bootstrap variables are used only when the application user table is empty. Passwords are stored as PBKDF2-SHA256 hashes and are never returned by the API. Set `EARE_COOKIE_SECURE=1` when serving over HTTPS.
