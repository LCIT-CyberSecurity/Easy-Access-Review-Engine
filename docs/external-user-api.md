# External user API (read-only)

EARE exposes a separate user API at `/api/v1`. Interactive WebUI traffic remains session-cookie authenticated; a Personal API Token never authenticates `/api/*` routes. Swagger UI is at `/swagger` and its filtered OpenAPI document is at `/openapi.json`. These paths are served by the WebUI reverse proxy, not the internal backend port.

## Enable access and create a key

The API is off by default. An administrator must enable **External user API** in **System → Users & permissions**, then enable **API access** on an individual EARE user. These are independent switches. Disabling the global switch suspends keys; disabling a user's API access revokes their keys. After access is enabled, the user signs in to EARE and creates their own key from the account menu. A key is shown once, expires after 90 days, and can be regenerated or revoked by its owner. Administrators can revoke keys but cannot read their secret.

The two Docker WebUI stacks keep separate databases and settings. Use the port of the stack you enabled:

- Standard stack: `http://127.0.0.1:4173/swagger` and `http://127.0.0.1:4173/openapi.json`
- Aurora stack: `http://127.0.0.1:4175/swagger` and `http://127.0.0.1:4175/openapi.json`

The global switch controls whether the external API and its documentation exist. The per-user **API access** switch only authorizes that account to generate and use a Bearer API key; enabling it does not enable the global API.

Keys have the form `eare_pat_…`; EARE stores only a SHA-256 hash. Roles and authorized domains are loaded from the current user record on every request, not embedded in the key. A role/scope change therefore applies immediately.

```http
Authorization: Bearer eare_pat_<secret>
```

## Read endpoints

All list endpoints accept `limit` (default 100, maximum 500) and `offset` (default 0).

- `GET /api/v1/me`
- `GET /api/v1/golden-sources`
- `GET /api/v1/golden-sources/{source_id}`
- `GET /api/v1/golden-sources/{source_id}/versions`
- `GET /api/v1/golden-sources/{source_id}/versions/{version_id}` (Golden assignments are paginated)
- `GET /api/v1/campaigns`
- `GET /api/v1/campaigns/{campaign_id}`
- `GET /api/v1/campaigns/{campaign_id}/summary`
- `GET /api/v1/campaigns/{campaign_id}/review-items`
- `GET /api/v1/review-items/{review_item_id}`

The namespace contains no create, update, decision, import, remediation, source-configuration or other write operations. Internal token management uses session-authenticated `/api/me/api-token` and `/api/system/...` routes and is not included in public Swagger.

## Authorization

The token is only an authentication mechanism; it is not a role. The attached user's existing EARE role and provider scopes control reads:

- `ADMIN` can read all public resources.
- `OPERATOR` can read only fully authorized campaigns. Campaign authorization reuses EARE's existing all-or-nothing checks and includes campaign scope, both providers on persisted ReviewItems, and—when available—the Snapshot providers for `scope=all`. An absent historical Snapshot falls back to persisted ReviewItems; no historical campaign is recalculated from current Golden data.
- `GROUP_OWNER` can read only ReviewItems assigned to their username. Campaign-wide detail and summary remain unavailable.
- `BUSINESS_ADMIN` receives no campaign or Golden access through this API; existing remediation access remains outside the read-only V1 allowlist.

A campaign spanning an unauthorized provider is denied in full; it is never silently truncated. The same cross-provider boundary applies when an access is from one provider and the assigned identity is from another.

## Operational security

The API does not inspect target-application ACLs and does not modify EARE data. Sensitive source configuration and secrets are not exposed. List limits reduce accidental bulk extraction, but this MVP does not implement an application-level rate limiter; deployments should apply rate limiting at the reverse proxy and serve EARE over HTTPS. The interactive WebUI, its session authentication, and existing internal API remain available when the external API kill switch is off.
