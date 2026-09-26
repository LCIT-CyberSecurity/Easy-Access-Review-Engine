# MCP read-only reports

EARE MCP V1 exposes only structured report data already available through the
authorized EARE reporting model. It is deliberately **report-only**, strictly
read-only, and does not expose a generic EARE query interface.

## Security model

- The server is disabled by default (`mcp_enabled=false`).
- Each user must separately have `mcp_access_enabled=true`.
- MCP uses dedicated `eare_mcp_...` credentials; REST `eare_pat_...` keys and
  browser sessions are rejected.
- Tokens are hashed, shown once, expire after 90 days, and a new token revokes
  the previous active token.
- Role and provider-scope authorization is reloaded from EARE on every request.
- Missing and unauthorized reports are intentionally indistinguishable.
- Responses use explicit allowlists and never include raw metadata, origins,
  connector configuration, credentials, or secrets.

The endpoint is `/mcp` (for the local standard stack, `http://127.0.0.1:4173/mcp`).
Remote deployments must use HTTPS at the reverse proxy. The server uses the
official Python MCP SDK Streamable HTTP transport with Host/Origin protections.

## Tools

The only tools exposed are:

`eare_get_current_user`, `eare_list_reports`, `eare_get_report_summary`,
`eare_get_report_details`, `eare_get_report_findings`,
`eare_get_report_decisions`, and `eare_get_report_remediation_summary`.

All collections use a default page size of 25 and a maximum of 100. MCP cannot
list or fetch identities, accesses, snapshots, campaigns, Golden Sources, or
ReviewItems directly. Those values can appear only when they are part of the
authorized report projection.

MCP does not generate reports and never writes PDF, HTML, CSV, JSON files. It
has no collection, synchronization, decision, approval, remediation, import,
export, filesystem, arbitrary HTTP, SQL, or shell capability. The only
technical writes are token `last_used_at` and bounded MCP audit events.

## Administration

An administrator enables the server separately from the External User API in
Users & permissions. Each user has an independent MCP access switch. Generate a
key only for a user who needs report access, copy it immediately, and revoke it
when no longer needed. No real credentials or keys belong in source control,
GitHub Actions variables committed to the repository, fixtures, or docs.
