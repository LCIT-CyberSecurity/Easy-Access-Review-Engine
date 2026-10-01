# EARE Product Assistant V1

The assistant is a bounded, read-only EARE capability. It explains product screens,
authorized dashboard/campaign/Golden/review/source data, deterministic Guidance
recommendations, and safe internal navigation actions. It is not a general chatbot.

## Architecture and authorization

The server resolves the authenticated session on every request. The client cannot
set role, scopes, tenant, organization, or permissions. Each business tool receives
a server-derived authorization context and returns an explicit aggregate DTO. Campaign
visibility reuses the existing campaign authorization rules; unavailable objects are
reported as unavailable without confirming their existence.

The model never receives a database connection, raw model, MCP credential, or generic
query tool. MCP remains a separate report-only interface. Guidance remains deterministic
and usable without an LLM.

## OpenAI V1

```text
EARE_CHATBOT_ENABLED=true
EARE_CHATBOT_PROVIDER=openai
EARE_OPENAI_API_KEY=sk-test-example-not-a-real-key
EARE_OPENAI_MODEL=<server-configured-model>
EARE_CHATBOT_TIMEOUT=20
EARE_CHATBOT_MAX_TOOL_ROUNDS=3
EARE_CHATBOT_TRACE_RETENTION_DAYS=30
```

The provider uses the Responses API with custom EARE function tools only. OpenAI
built-ins (web search, file search, computer use, code interpreter, remote MCP) are
not enabled. Responses use `store=false`; this prevents use of OpenAI remote response
storage as conversation state but is not a claim of Zero Data Retention. EARE owns its
bounded history and sanitized traces.

The API key is server-side only and is never returned or logged. If the provider is
disabled, unconfigured, or unavailable, the deterministic security behavior remains
active and the user receives a safe unavailable message.

## Safety and retention

Input size, Unicode normalization, out-of-scope classification, suspicious injection
heuristics, and obvious secret redaction run before provider access. EARE payloads are
DATA, not instructions. Outputs reject dangerous schemes/HTML and unknown actions.
Conversation rows are scoped by user ID; trace retention is configurable (30 days by
default). V1 has no business-data cache and no write tools.

Future extension points are `AnthropicProvider`, `MistralProvider`, `GeminiProvider`,
private/BYO providers, and `OpenAIModerationProvider`; none are implemented in V1.
