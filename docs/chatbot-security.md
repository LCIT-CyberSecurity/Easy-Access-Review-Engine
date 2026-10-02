# EARE Assistant security model

The authorization layer is the security boundary. The LLM is untrusted and cannot authorize
itself, change tool policy, construct URLs, or perform business writes.

## Data access

Availability is separate from EARE data authorization:

1. `EARE_CHATBOT_ENABLED` is the deployment hard switch.
2. `system_settings.chatbot_enabled` is the ADMIN-controlled global switch.
3. `system_users.chatbot_access_enabled` authorizes an individual user.
4. OpenAI provider/model/key readiness is checked locally without a network healthcheck.

Hiding the launcher is only UX. The server enforces the effective decision on
`/api/chatbot/message`, `/api/chatbot/actions`, `/api/chatbot/brief`, and
`/api/chatbot/report`, returning a generic 403 when disabled. The status endpoint is
authenticated and safe for refresh-driven UI state. Assistant access never expands
role, provider scope, ReviewItem, Golden or campaign permissions, and Guide remains
independent.

- ADMIN uses the existing administrator read boundaries.
- OPERATOR is filtered through the shared Campaign authorization functions. `all`, `providers`,
  and `accesses` scopes are resolved server-side; an empty unresolved provider set fails closed.
- GROUP_OWNER sees only ReviewItems assigned to the authenticated username. Campaign summaries,
  totals, findings, pending/decided counts and reviewer coverage are calculated after that filter.
- BUSINESS_ADMIN and remediation roles receive only their existing WebUI/API projections.

Every tool revalidates its arguments and receives a fresh authorization context before execution.
Client route/object hints are never authority. An unauthorized object returns an unavailable DTO
without confirming whether it exists.

Dashboard aggregates are role-bounded before counting: group owners receive assigned review work,
while BUSINESS_ADMIN and REMEDIATION_MANAGER receive no campaign/review/source/snapshot/Golden
metrics. Golden required domains are resolved by the shared API/chatbot helper from both access and
identity providers; empty operator domains fail closed.

## Untrusted content and secrets

Imported names, groups, comments, roles, descriptions and connector data are treated as DATA.
They are explicitly wrapped before provider transmission. Direct and indirect injection
heuristics are supplemental; they cannot elevate server-side tool privileges. Bearer tokens,
API keys, client secrets, passwords, token assignments and private-key PEM blocks are redacted
before provider calls, traces, audits or frontend output.

The provider registry rejects unsupported provider names instead of silently selecting OpenAI.
OpenAI V1 uses only the Responses API, `store=false`, strict custom EARE tools, bounded output,
and in-memory replay of required opaque output/reasoning items. Reasoning state is not stored.

## Retention and limits

Message and trace retention is controlled by `EARE_CHATBOT_TRACE_RETENTION_DAYS`; cleanup is
bounded and removes old orphan conversations while leaving `audit_events` untouched. Tool DTOs
are count- and size-bounded. The assistant is read-only: approval, revocation, assignment,
Golden mutation, collection, RBAC, deletion and connector writes are not exposed.

Operational defaults are: 8,000 characters per message, 12 history messages, 24,000 context
characters, 3 tool rounds, 6 tool calls, 100 result items, 800 output tokens and a 20-second
provider timeout. These values can be tuned with the `EARE_CHATBOT_*` environment settings;
the hard security controls listed above remain enforced.

Threats covered in V1:

- direct and indirect prompt injection: user and imported EARE strings are untrusted data;
- broken object authorization: campaign/provider scope is rechecked for every request/tool;
- cross-user leakage: conversations are keyed by authenticated subject;
- secret leakage: bearer tokens, key blocks and credential-like values are redacted;
- malicious tool calls: strict allowlist, bounded rounds, explicit arguments and server-side DTOs;
- malicious output and XSS: no arbitrary URLs/HTML/actions are accepted;
- denial of service: bounded message/history/output/tool rounds and provider timeout;
- provider outage: safe sanitized error and no authorization fallback;
- logging leakage: traces store sanitized question/answer and never credentials/configuration.

The remaining V1 limitations are heuristic injection detection, no moderation provider,
and no admin trace viewer. Operational limits are configurable through the environment,
but authorization, scope enforcement, tool allowlists, schema validation, secret filtering,
safe navigation, provider credential isolation and conversation ownership are hard controls
and cannot be disabled by configuration. The requested remote Docker alias `4175` must be reachable
from the deployment network for environment-specific verification. Production deployment should use the existing audit retention
policy and a managed secret environment. `store=false` is a privacy default, not a
Zero Data Retention guarantee.

## Trust boundary

```text
Browser
  |
  v
EARE API -> authentication/current principal
          -> AssistantContext and authorization
          -> ToolBroker/read projections
          -> DTO allowlist and data firewall
          -> LLM provider
```

Imported provider strings and user text remain untrusted data at every stage. Security
events contain metadata and safe references only. Conversation content can be disabled with
`EARE_CHATBOT_STORE_MESSAGE_CONTENT=false`; in that mode raw message and trace content is
not persisted, while security metadata remains available for audit.
