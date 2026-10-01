# EARE Assistant security model

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
and no admin trace viewer. Production deployment should use the existing audit retention
policy and a managed secret environment. `store=false` is a privacy default, not a
Zero Data Retention guarantee.
