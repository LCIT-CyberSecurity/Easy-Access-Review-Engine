# OpenID Connect SSO for Aurora

Aurora supports three independent ways to authenticate: local accounts, LDAP/LDAPS directory accounts, and one active OpenID Connect (OIDC) provider. SAML is not supported. OIDC authenticates a person; Aurora continues to own roles, scopes, and every authorization decision.

## Security and account association

An OIDC identity is identified by its validated `iss` (issuer) and `sub` (subject), never by email or username. A user must already exist in **System → Users & permissions**, be enabled, and have an explicit OIDC identity link made by an Aurora administrator. First sign-in never creates an Aurora user, matches by email, imports IdP groups, or grants a role. Aurora loads the linked account's existing local role and scopes.

The OIDC client secret is not stored in Aurora's database or returned by its API. Configure a secret reference in the provider form and make the referenced value available to the API process. For example:

```sh
AURORA_OIDC_CLIENT_SECRET_FILE=/run/secrets/aurora_oidc_client_secret
```

Then choose the file-reference option and set the reference name to `AURORA_OIDC_CLIENT_SECRET_FILE`. The referenced environment value must be a path readable by the API. Alternatively set `AURORA_OIDC_CLIENT_SECRET` to the secret and choose the environment-variable option. Use a secret manager or container secret, restrict file permissions, rotate the IdP secret and update the secret source. Never put the secret in Git or in a browser-visible setting.

For a deployment behind HTTPS, set `AURORA_PUBLIC_BASE_URL` to Aurora's externally reachable HTTPS origin, for example `https://aurora.example.org`, and set `AURORA_COOKIE_SECURE=1`. The callback is generated as:

```text
https://aurora.example.org/api/auth/oidc/callback
```

Register that exact URI at the provider. Ensure the browser and the Aurora API can both resolve and reach the configured issuer. Keep normal certificate verification enabled. Aurora uses Authorization Code Flow with PKCE S256, random state and nonce, one-time short-lived transactions, validated issuer/audience/signature/expiry, and the provider's JWKS. There is no silent HTTP or TLS-verification fallback.

## Configure a provider in Aurora

1. Sign in with an Aurora administrator and open **System → Authentication**.
2. Choose **Configure SSO** or **Edit**.
3. Select Microsoft Entra ID, Keycloak, Google, or Generic OIDC; enter a display name, issuer, client ID, and secret reference.
4. Copy the generated callback URI into the OIDC client's redirect URI list.
5. Choose **Test connection**. This checks OIDC discovery and public metadata only; it does not authenticate a user.
6. Save and explicitly enable the provider. Only one provider is active at a time. The login page then offers the provider button while retaining **Local sign-in**.
7. In **System → Users & permissions**, edit the pre-created Aurora account and associate the external subject (`sub`) for the exact provider issuer. Verify the association with the IdP's stable subject value, not a display name or email.
8. Test a real browser login and verify that the user's existing Aurora role and scopes are applied.

Aurora requires at least one enabled local `ADMIN` account with a valid local password before OIDC can be enabled. This account remains the recovery path if the IdP is unavailable. Do not disable, convert to LDAP/SSO, or remove its password. OIDC and LDAP users must not use another account's local password.

## Keycloak

Create a realm and a confidential OpenID Connect client. Set the client authentication on, enable Standard Flow (Authorization Code), and register Aurora's exact callback URI as a valid redirect URI. Configure the client's valid web origins narrowly for the Aurora origin. Require PKCE with `S256` when the Keycloak version/client policy exposes that option. Give the client only the standard `openid`, `profile`, and `email` scopes needed for login. A display name and email claim are optional; the stable subject is mandatory.

Enter the realm issuer, for example:

```text
https://sso.example.org/realms/aurora
```

The issuer must exactly match the `issuer` in the realm's `/.well-known/openid-configuration` response. Do not enter the Keycloak admin URL or a client URL. Create and authorize the corresponding Aurora user separately, then link the Keycloak `sub` to that account.

For a laboratory-only HTTP endpoint, HTTP is rejected by default. It can be enabled for explicitly allowlisted hosts using `AURORA_OIDC_ALLOW_HTTP=1` and `AURORA_OIDC_ALLOWED_HOSTS=<exact-host>`. Never retain that exception for production or expose a lab provider to untrusted networks.

## Microsoft Entra ID

Register an application in the intended Entra tenant, select the Web platform, and add Aurora's exact HTTPS callback URI. Use the tenant-specific v2 issuer:

```text
https://login.microsoftonline.com/<tenant-id>/v2.0
```

Select **Microsoft Entra ID**, enter the tenant ID (Aurora expands it to the v2 issuer), the Application (client) ID, and a client-secret environment/file reference. Restrict supported account types to the intended organization. Create the Aurora user and link the validated Entra `sub`; do not use email, UPN, or `preferred_username` as the link key. Entra must issue an ID token to the web client. The implementation is covered by automated provider/claim validation, but a real tenant sign-in still needs tenant credentials and a live redirect test.

## Google Identity / Workspace

Create an OAuth client of type **Web application**, register Aurora's exact HTTPS callback URI, and enter issuer `https://accounts.google.com`. Use the client ID and secret reference. Restrict access through the Workspace/Google Cloud configuration appropriate to your organization. Create and link the Aurora account using its validated subject (`sub`). Google sign-in availability does not add Google groups or roles to Aurora.

## Generic OIDC

Choose **Generic OIDC** and enter the provider's exact HTTPS issuer URL. It must publish a standard `/.well-known/openid-configuration` document with authorization, token, and JWKS endpoints on trusted hosts. Aurora currently expects a confidential client using `client_secret_basic` or `client_secret_post` and an ID token signed using a supported RSA, EC, or RSA-PSS algorithm. The authorization response must return `code` and the same `state`; the ID token must contain `iss`, `sub`, `aud`, `exp`, `iat`, and the transaction `nonce`.

## Test and recovery

**Test connection** verifies that discovery metadata is reachable and internally consistent. It is not an end-to-end SSO test. To test authentication, use the browser login button, authenticate at the provider, return through the callback, and confirm the linked Aurora user and local role. A successful API discovery check alone must never be described as a successful SSO sign-in.

If the IdP is down, use **Local sign-in** with the local administrator. Open **System → Authentication** to disable or correct the active provider. The local session, users, roles, LDAP configuration, review data, and source data are not replaced by an OIDC login. To recover a forgotten local password, use the documented `aurora ... system reset-password` CLI procedure; changing an environment variable does not reset an existing account.

Common failures:

| Symptom | Check |
| --- | --- |
| `sso_not_configured` | The provider is not enabled and active. |
| `sso_configuration` | The secret reference is missing or invalid, or the callback/public base URL is not usable. |
| `sso_unavailable` | The API cannot reach discovery, DNS failed, TLS validation failed, or the provider endpoint is not trusted. |
| `invalid_sso_response` | The state is wrong/expired/replayed, or the callback browser does not have its flow cookie. Restart from the Aurora login page in the same browser. |
| `sso_authentication_failed` | Check the client's redirect URI, secret, PKCE/flow settings, issuer, audience, clocks, and signing keys. |
| `sso_account_not_linked` | An administrator must explicitly link the validated issuer and `sub` to a pre-created Aurora user. Email matching is intentionally not performed. |
| `sso_account_disabled` | Re-enable the Aurora account only after confirming it should have access. |

OIDC provider configuration, active selection, account links, and temporary login transactions are stored in Aurora's system database. Back up that database as part of normal Aurora backups. Disabling a provider prevents new OIDC logins; existing sessions remain subject to Aurora's normal session checks and account session-version revocation.

## Current limits

- One OIDC provider can be active per Aurora instance; other configurations may remain saved and inactive.
- No automatic account provisioning, email-based linking, IdP role/group mapping, or SAML support.
- A real Entra tenant and AD-federated Keycloak test require access to those external lab configurations.
- Private-network OIDC endpoints require an explicit host allowlist; HTTP is limited to an explicit lab exception.
