# EARE Access Review & Identity Governance Assistant

The chatbot is a bounded, read-only EARE copilot. It explains product screens and
the EARE model, answers access-review/IAM/IAG questions, analyzes authorized
dashboard/campaign/Golden/review/source data, recommends safe next steps, and offers
validated internal navigation actions. It is not a general-purpose chatbot and never
performs business changes.

There are three response modes:

- product and domain knowledge, answered directly without private data when possible;
- analysis of the user's authorized EARE projections through bounded read-only tools;
- workflow and navigation guidance using server-validated semantic actions.

When a provider returns no usable text, the backend and WebUI both return a visible,
controlled message instead of rendering an empty assistant bubble. Provider failures,
tool denials and empty provider responses remain distinct in server diagnostics.

Clearly unrelated questions are handled locally, before any provider call. The response starts
with `Hors périmètre du Chatbot EARE`, uses `intent=OUT_OF_SCOPE` and
`security_state=out_of_scope`; the drawer displays a neutral “Hors périmètre” marker.

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

ADMIN users can run `POST /api/chatbot/provider-test`. Unlike configuration readiness, this
performs a tiny bounded Responses API call. It returns only provider, model, success and a safe
category (`authentication_error`, `permission_denied`, `rate_limited`, `timeout`,
`network_error`, `provider_error`, `invalid_response` or `invalid_tool_response`). Raw provider
errors, headers and credentials are never returned or audited.

## Semantic catalog and tools

`chatbot/semantic_catalog.py` defines the logical EARE vocabulary independently from SQL.
`Permission` is a source-native technical right, `FunctionalRight` is the functional
`Target + Capability` representation, and `Access` is the reviewed object. Functional rights
are never inferred from role names. Built-in capabilities are documented but extensible.

The provider can request only allowlisted, server-side tools:

- `search_authorized_accesses`, `get_authorized_access`;
- `search_authorized_identities`, `get_authorized_identity`;
- `search_authorized_reviews`, `get_authorized_review`;
- `search_authorized_campaigns`, `get_authorized_campaign`;
- `search_authorized_remediations`, `get_authorized_perimeter`;
- `get_authentication_posture_summary`, `aggregate_authorized_data`;
- `search_access_control_knowledge`, `get_ui_help`.

Every result is authorized before transmission, bounded, secret-filtered and marked as untrusted
EARE data. There is no SQL tool, arbitrary URL tool, database connection or physical database
schema in the provider context. Organization and InformationSystem remain filters/classification
scopes; this layer does not turn them into new permissions.

## Verified knowledge and citations

The versioned JSON catalog under `chatbot/knowledge/` stores lightweight `KnowledgeSource` and
`KnowledgeEntry` records. Initial entries cover official CNIL, ANSSI, ENISA, NIST, ISO and HDS
material. Publishers are data, not a code whitelist, so another verified publisher can be added
without changing the search implementation. Entries paraphrase guidance and do not reproduce
long standards text.

Normative sources in `AssistantResponse.sources` come only from
`search_access_control_knowledge` results used during that response. IDs are deduplicated and
bounded; source URLs must be credential-free HTTPS both when loading the catalog and when shown
in the drawer. When no verified entry supports a request, the tool returns an explicit catalog
limitation instead of inviting the model to invent a citation. Reports include only sources used
for their recommendations and distinguish deterministic EARE sections from advice.

## Administration Guardrails

`Administration → Users & permissions → Chatbot → Guardrails` stores functional policy in the
existing `system_settings` table. ADMIN can enable the coarse product/access-control/IAG/
authentication/privileged-access/external-guidance domains, select verified publishers, and
bound tool calls, rounds, results, history, retention and conversation/tool logging.

Read-only behavior, server identity, authorization/scope enforcement, secret filtering, prompt
injection protection, the tool allowlist, absence of arbitrary SQL/URLs and bounded outputs are
displayed as locked controls and cannot be disabled through the API. Infrastructure secrets and
provider settings remain environment configuration.

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

Contextual UI suggestions are role-aware: operational campaign, Golden, source and perimeter suggestions
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

The assistant can explain `Identity`, `Access`, `AccessAssignment`, `Permission`,
`Capability`, `Target`, `FunctionalRight`, `Golden Source`, `Snapshot`, `Campaign`,
`ReviewItem`, `Decision`, `Organization` and `InformationSystem`. Organizations and
information systems remain classification and targeting scopes, never permissions.
Campaign lookup is limited to campaigns visible to the current principal and returns
only bounded identifiers, names and statuses needed for a controlled link.

Future extension points are `AnthropicProvider`, `MistralProvider`, `GeminiProvider`,
private/BYO providers, and `OpenAIModerationProvider`; none are implemented in V1.
