# EARE Product Chatbot V1

The chatbot is a bounded, read-only EARE capability. It explains product screens,
authorized dashboard/campaign/Golden/review/source data, deterministic Guidance
recommendations, and safe internal navigation actions. It is not a general chatbot.

## Architecture and authorization

Chatbot availability has three independent gates plus local provider readiness:

```text
EARE_CHATBOT_ENABLED
        -> system_settings.chatbot_enabled
        -> system_users.chatbot_access_enabled
        -> local OpenAI provider configuration
```

The deployment switch is environment-only and is never changed by the WebUI. The
global setting is ADMIN-only and defaults to false. Every user, including ADMIN,
must have the per-user Chatbot flag enabled. Revocation is evaluated from the
current database state on every chatbot request and does not require logout.
The API key is never stored in SQLite; the administration screen exposes only
provider, model and a Ready/Not configured state.

The server resolves the authenticated session on every request. The client cannot
set role, scopes, tenant, organization, or permissions. Each business tool receives
a server-derived authorization context and returns an explicit aggregate DTO. Campaign
visibility reuses `campaign_required_providers()` and `can_access_campaign()`, including
`all`, `providers`, and `accesses` scopes. An unresolved provider set fails closed for operators.
GROUP_OWNER metrics are calculated only from assigned ReviewItems; unavailable objects are
reported as unavailable without confirming their existence. Other roles retain WebUI/API bounds.
Golden authorization is shared with the API: required domains include both assignment access and
identity providers. Operators fail closed when a Golden has no resolvable provider.

The model never receives a database connection, raw model, MCP credential, or generic
query tool. MCP remains a separate report-only interface. Guidance remains deterministic
and usable without an LLM.

## OpenAI V1

```text
EARE_CHATBOT_ENABLED=true
EARE_CHATBOT_PROVIDER=openai
EARE_OPENAI_API_KEY=<server-injected-secret>
EARE_OPENAI_MODEL=<server-configured-model>
EARE_CHATBOT_TIMEOUT=20
EARE_CHATBOT_MAX_TOOL_ROUNDS=3
EARE_CHATBOT_MAX_TOOL_CALLS=6
EARE_CHATBOT_MAX_CONTEXT_CHARS=24000
EARE_CHATBOT_MAX_RESULT_ITEMS=100
EARE_CHATBOT_STORE_MESSAGE_CONTENT=true
EARE_CHATBOT_LOG_CONVERSATIONS=true
EARE_CHATBOT_LOG_TOOL_CALLS=true
EARE_CHATBOT_TRACE_RETENTION_DAYS=30
```

The provider uses the Responses API with custom EARE function tools only. OpenAI
built-ins (web search, file search, computer use, code interpreter, remote MCP) are
not enabled. Each function has a strict schema and server-side argument validation. Responses use `store=false`; this prevents use of OpenAI remote response
storage as conversation state but is not a claim of Zero Data Retention. EARE owns its
bounded history and sanitized traces. Stateless tool continuation replays required opaque output
items in memory, including reasoning items; reasoning content is never persisted.
Multiple tool calls replay the provider reasoning/function items once, then append outputs in the
same call order. The server derives bounded object context from routes such as
`/campaigns/<id>`; the derived ID remains only a hint until object authorization succeeds.

The controlled endpoints `/api/chatbot/brief` and `/api/chatbot/report` expose a deterministic
`AssistantBrief` with dashboard, review progress and Golden-quality projections. The Markdown
report is generated server-side from authorized DTOs; the chatbot cannot choose a filesystem
path or write an arbitrary file.

The API key is server-side only and is never returned or logged. If the provider is
disabled, unconfigured, or unavailable, the deterministic security behavior remains
active and the user receives a safe unavailable message.

## Context contract

The browser sends only a bounded route and optional selected object reference. The server
rebuilds the authorized context from the current authenticated principal and EARE read
models before calling the provider. The model receives only allowlisted aggregate DTOs,
validated page help, deterministic Guidance and validated semantic action IDs. It never
receives ORM objects, provider credentials, connector configuration, raw database data or
the full page payload.

The chatbot is business read-only. It can explain, summarize, guide and prepare a
controlled Markdown/JSON-style brief, but it cannot approve, revoke, edit Golden Source,
change campaigns, launch remediation, import data or modify providers.

## Deterministic diagnostics and evaluations

The chatbot exposes bounded projections for campaign readiness, campaign finding summaries,
Golden quality and source/snapshot status. These calculations remain in EARE; the LLM only
explains their results. Finding explanations are defined for the EARE comparison categories
(`expected_and_observed`, `unexpected`, `missing`, `unknown_due_to_scope` and `no_reference`).
Unknown categories remain explicit and are never guessed.

Reproducible product evaluations live in `tests/chatbot/evals/`. They cover scope
classification, authorized campaign facts, inaccessible campaigns, readiness blockers,
Golden quality gaps, finding explanations, source filtering and prompt-injection/out-of-scope
classification. Assertions target structured facts and authorization outcomes rather than
provider wording.

Contextual UI suggestions are role-aware: operational campaign, Golden and source suggestions
are shown to ADMIN/OPERATOR users, review suggestions are available to review users, and
remediation suggestions are limited to roles that can view remediation.

The raw Responses REST body is parsed through `output[]` message items and only
`message.content[].type == "output_text"` fragments become the user answer. Reasoning,
function-call arguments and other output items are never treated as answer text. Usage
is aggregated across all tool rounds.

## Safety and retention

Input size, Unicode normalization, out-of-scope classification, suspicious injection
heuristics, and secret redaction run before provider access. EARE payloads are wrapped as
`{type: "eare_data", untrusted: true, tool, data}` and are DATA, not instructions. Outputs
reject dangerous schemes/HTML and unknown actions. Conversation rows are scoped by user ID;
retention cleanup applies to messages, traces and old orphan conversations. V1 has no business-
data cache and no write tools.

Future extension points are `AnthropicProvider`, `MistralProvider`, `GeminiProvider`,
private/BYO providers, and `OpenAIModerationProvider`; none are implemented in V1.
