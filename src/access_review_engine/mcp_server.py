"""Official MCP SDK adapter for the EARE report-only surface."""
from __future__ import annotations

import time
from typing import Any, Callable

try:
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.server.transport_security import TransportSecuritySettings
except ModuleNotFoundError:  # pragma: no cover - app extra is required in deployments
    Context = Any  # type: ignore[misc,assignment]
    MCPServer = None  # type: ignore[assignment]
    TransportSecuritySettings = None  # type: ignore[assignment]

from access_review_engine.mcp_reports import McpReportService, ReportNotFound
from access_review_engine.storage import Repository
from access_review_engine.system_admin import authenticate_mcp_token, mcp_enabled

MCP_TOOL_NAMES = (
    "eare_get_current_user",
    "eare_list_reports",
    "eare_get_report_summary",
    "eare_get_report_details",
    "eare_get_report_findings",
    "eare_get_report_decisions",
    "eare_get_report_remediation_summary",
)


def _header(headers: Any, name: str) -> str | None:
    if not headers:
        return None
    for key, value in headers.items():
        normalized_key = key.decode("latin-1") if isinstance(key, bytes) else str(key)
        if normalized_key.casefold() == name.casefold():
            return value.decode("latin-1") if isinstance(value, bytes) else str(value)
    return None


def authenticate_request(system_conn: Any, headers: Any) -> dict[str, Any] | None:
    if not mcp_enabled(system_conn):
        return None
    authorization = _header(headers, "authorization")
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[7:].strip()
    if not token.startswith("eare_mcp_"):
        return None
    return authenticate_mcp_token(system_conn, token)


class McpAuthMiddleware:
    def __init__(self, app: Any, system_conn: Any) -> None:
        self.app = app
        self.system_conn = system_conn

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("path") != "/mcp":
            body = b"Not found"
            await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"text/plain"), (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        principal = authenticate_request(self.system_conn, dict(scope.get("headers", [])))
        if principal is None:
            body = b"MCP authentication required"
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", b"Bearer"), (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        scope["eare.mcp_principal"] = principal
        await self.app(scope, receive, send)


def _allowed_hosts() -> list[str]:
    import os
    configured = [item.strip() for item in os.getenv("EARE_MCP_ALLOWED_HOSTS", "").split(",") if item.strip()]
    return configured or ["127.0.0.1:*", "localhost:*", "[::1]:*"]


def build_mcp_asgi(db_path: str, system_conn: Any) -> tuple[Any, Any]:
    if MCPServer is None or TransportSecuritySettings is None:
        raise RuntimeError("The MCP SDK is required; install the application dependencies")
    server = MCPServer(
        name="EARE Reports",
        version="1.0.0",
        instructions="EARE MCP V1 is authenticated, report-only, structured-data-only, and read-only.",
    )
    service = McpReportService(db_path)

    def principal(ctx: Context) -> dict[str, Any]:
        current = authenticate_request(system_conn, ctx.headers)
        if current is None:
            raise PermissionError("MCP authentication required")
        return current

    def call(ctx: Context, tool: str, report_id: str | None, operation: Callable[[dict[str, Any]], dict[str, object]]) -> dict[str, object]:
        started = time.monotonic()
        subject: dict[str, Any] | None = None
        try:
            subject = principal(ctx)
            result = operation(subject)
            count = result.get("total", len(result.get("items", []))) if isinstance(result, dict) else 0
            _audit(db_path, "mcp.tool_succeeded", subject, tool, report_id, int(count), started)
            return result
        except ReportNotFound:
            _audit(db_path, "mcp.tool_denied", subject, tool, report_id, 0, started)
            raise PermissionError("report not found")
        except (PermissionError, ValueError):
            _audit(db_path, "mcp.tool_denied", subject, tool, report_id, 0, started)
            raise
        except Exception:
            _audit(db_path, "mcp.tool_failed", subject, tool, report_id, 0, started)
            raise

    @server.tool(name="eare_get_current_user", structured_output=True)
    async def get_current_user(ctx: Context) -> dict[str, object]:
        user = principal(ctx)
        return {"username": user["username"], "display_name": user["display_name"], "role": user["role"], "authorized_scopes": user["scopes"]}

    @server.tool(name="eare_list_reports", structured_output=True)
    async def list_reports(ctx: Context, limit: int = 25, offset: int = 0) -> dict[str, object]:
        return call(ctx, "eare_list_reports", None, lambda user: service.list_reports(user, limit, offset))

    @server.tool(name="eare_get_report_summary", structured_output=True)
    async def get_report_summary(ctx: Context, report_id: str) -> dict[str, object]:
        return call(ctx, "eare_get_report_summary", report_id, lambda user: service.summary(user, report_id))

    @server.tool(name="eare_get_report_details", structured_output=True)
    async def get_report_details(ctx: Context, report_id: str, limit: int = 25, offset: int = 0, classification: str | None = None, provider: str | None = None, identity: str | None = None, access: str | None = None) -> dict[str, object]:
        return call(ctx, "eare_get_report_details", report_id, lambda user: service.details(user, report_id, limit, offset, classification, provider, identity, access))

    @server.tool(name="eare_get_report_findings", structured_output=True)
    async def get_report_findings(ctx: Context, report_id: str, limit: int = 25, offset: int = 0, classification: str | None = None, provider: str | None = None, identity: str | None = None, access: str | None = None) -> dict[str, object]:
        return call(ctx, "eare_get_report_findings", report_id, lambda user: service.findings(user, report_id, limit, offset, classification, provider, identity, access))

    @server.tool(name="eare_get_report_decisions", structured_output=True)
    async def get_report_decisions(ctx: Context, report_id: str, limit: int = 25, offset: int = 0, decision: str | None = None) -> dict[str, object]:
        return call(ctx, "eare_get_report_decisions", report_id, lambda user: service.decisions(user, report_id, limit, offset, decision))

    @server.tool(name="eare_get_report_remediation_summary", structured_output=True)
    async def get_report_remediation_summary(ctx: Context, report_id: str, limit: int = 25, offset: int = 0) -> dict[str, object]:
        return call(ctx, "eare_get_report_remediation_summary", report_id, lambda user: service.remediation_summary(user, report_id, limit, offset))

    transport_security = TransportSecuritySettings(
        allowed_hosts=_allowed_hosts(),
        allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
        enable_dns_rebinding_protection=True,
    )
    app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=False, transport_security=transport_security)
    return server, McpAuthMiddleware(app, system_conn)


def _audit(db_path: str, event_type: str, principal: dict[str, Any] | None, tool: str, report_id: str | None, result_count: int, started: float) -> None:
    from access_review_engine.domain import AuditEvent
    with Repository(db_path) as repo:
        repo.insert_append_only("audit_events", AuditEvent(
            event_type=event_type,
            actor=principal.get("username") if principal else None,
            object_type="mcp_tool",
            object_id=report_id,
            details={"tool": tool, "result_count": result_count, "duration_ms": round((time.monotonic() - started) * 1000)},
        ))
