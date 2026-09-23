from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import csv
import difflib
import unicodedata
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import tempfile
import time
import yaml
from pathlib import Path
from typing import Any

try:
    from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
    from fastapi.openapi.docs import get_swagger_ui_html
    from fastapi.responses import HTMLResponse, StreamingResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
except ModuleNotFoundError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment]
    Body = Depends = Request = Response = HTTPException = HTMLResponse = StreamingResponse = None  # type: ignore[assignment,misc]
    get_swagger_ui_html = HTTPAuthorizationCredentials = HTTPBearer = None  # type: ignore[assignment,misc]

from access_review_engine.application import import_file_to_repository
from access_review_engine.access_context import access_context_for_payload, access_enrichment, capture_campaign_access_contexts, save_access_enrichment
from access_review_engine.campaign_authorization import CampaignScopeError, campaign_required_providers, can_access_campaign, normalize_campaign_scope
from access_review_engine.authentication import compare_authentication_posture
from access_review_engine.collector_runner import RunnerError, run_exporter
from access_review_engine.config_loader import connector_path, load_connector, secret_environment, validate_connector
from access_review_engine.connector_capabilities import connector_capabilities
from access_review_engine.domain import (
    Access,
    AccessAssignment,
    ControlObject,
    AccessRelation,
    AccessRelationType,
    Capability,
    ExpectedAccessModel,
    FunctionalModelCompleteness,
    FunctionalRight,
    GoldenAccessComment,
    Origin,
    OwnerRef,
    PermissionCapabilityMapping,
    Provenance,
    Target,
    now_utc,
    normalize_manual_target_node,
    target_path,
)
from access_review_engine.golden_annotations import annotation_for_assignment, copy_assignment_annotations, normalize_assignment_comment, set_assignment_annotation
from access_review_engine.reporting import build_report_rows, identity_names_from_snapshot, render_pdf_report, report_summary, write_reports
from access_review_engine.services import audit, calculate_effective_accesses, close_campaign, compare_snapshot, create_decision, create_golden_source, create_golden_version, golden_diff, golden_version_from_snapshot, open_campaign, promote_campaign, promote_snapshot, remediation_from_decisions
from access_review_engine.source_inspector import SourceInspectorError, browse_source_tree, discover_source_attributes, get_source_object, search_source_objects, source_object_kinds
from access_review_engine.source_mapping import mapping_diagnostics
from access_review_engine.storage import Repository, hydrate_access, hydrate_authentication_posture, hydrate_campaign, hydrate_decision, hydrate_golden_source, hydrate_golden_version, hydrate_review_item, hydrate_snapshot
from access_review_engine.web_jobs import create_job, get_events, get_job, update_progress
from access_review_engine.web_read_models import _add_review_provenance, _display_names, _latest_decisions, projected_rows, review_item_view, review_summary
from access_review_engine.web_use_cases import latest_snapshot, list_payloads, prepare_campaign_review, preview_campaign_review, preview_import, snapshot_collection_scope
from access_review_engine.directory_auth import DirectoryError, authenticate as directory_authenticate, search_accounts as directory_accounts, test_directory, validate_directory
from access_review_engine.system_admin import LOCAL_SOURCE, api_token_summary, authenticate_api_token, authenticate_user, change_password as update_password, create_api_token, enabled_admins, ensure_bootstrap_user, external_user_api_enabled, init_system, list_idps, list_users, reset_password, revoke_api_tokens, set_enabled, set_external_user_api_enabled, upsert_idp, upsert_user


SESSION_COOKIE = "eare_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
ROLES = ("ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN", "REMEDIATION_MANAGER")


@dataclass(frozen=True)
class WebPrincipal:
    subject: str
    role: str
    scopes: frozenset[str]
    username: str = ""
    display_name: str = ""
    must_change_password: bool = False

    def can_access(self, scope: str | None) -> bool:
        return self.role == "ADMIN" or not scope or "*" in self.scopes or scope in self.scopes


def _encode_session(principal: dict[str, Any], secret: bytes) -> str:
    payload = {"sub": principal["subject"], "username": principal["username"], "display_name": principal["display_name"], "role": principal["role"], "scopes": principal["scopes"], "must_change_password": bool(principal.get("must_change_password", False)), "exp": int(time.time()) + SESSION_TTL_SECONDS}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def _decode_session(token: str | None, secret: bytes) -> WebPrincipal | None:
    if not token or "." not in token:
        return None
    body, signature = token.rsplit(".", 1)
    expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if int(payload["exp"]) < int(time.time()) or payload["role"] not in ROLES:
            return None
        return WebPrincipal(str(payload["sub"]), str(payload["role"]), frozenset(str(item) for item in payload.get("scopes", [])), str(payload.get("username", "")), str(payload.get("display_name", "")), bool(payload.get("must_change_password", False)))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _require(user: WebPrincipal | None, roles: tuple[str, ...] = (), scope: str | None = None) -> WebPrincipal:
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if user.must_change_password:
        raise HTTPException(status_code=403, detail="Password change required")
    if roles and user.role not in roles and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Insufficient role")
    if not user.can_access(scope):
        raise HTTPException(status_code=403, detail="Scope is not authorized")
    return user


def _finding_tracking_key(campaign_id: str | None, row: dict[str, Any]) -> str:
    values = [
        campaign_id or "",
        row.get("access_provider"), row.get("access_name"),
        row.get("identity_provider"), row.get("identity_identifier"),
        row.get("classification"),
    ]
    return hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def create_app(db_path: str | None = None):
    if FastAPI is None:
        raise RuntimeError("Install the 'app' extra to use the REST API")
    db_path = db_path or os.environ.get("EARE_DB_PATH", "access-review.db")
    app = FastAPI(title="Easy Access Review Engine", version="0.3.0", docs_url=None, redoc_url=None, openapi_url=None)
    system_conn = sqlite3.connect(db_path, check_same_thread=False)
    system_conn.row_factory = sqlite3.Row
    init_system(system_conn)
    ensure_bootstrap_user(system_conn)
    session_secret = os.environ.get("EARE_SESSION_SECRET", "").encode() or secrets.token_bytes(32)
    connector_directory = Path(db_path).resolve().parent / "connectors"

    def _load_web_connector(provider: str) -> dict[str, Any]:
        try:
            return load_connector(provider, connector_path(provider, connector_directory))
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    def _validate_web_connector(payload: dict[str, Any]) -> dict[str, Any]:
        candidate = dict(payload)
        provider = str(candidate.get("provider", "")).strip().lower()
        candidate["provider"] = provider
        try:
            validate_connector(candidate, provider)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        candidate.pop("_path", None)
        candidate.pop("capabilities", None)
        return candidate

    def _public_connector(payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        result.pop("_path", None)
        credentials = result.get("credentials")
        if isinstance(credentials, dict):
            result["credentials"] = {key: value for key, value in credentials.items() if key.endswith("_env")}
        result["capabilities"] = asdict(connector_capabilities(str(result.get("type", ""))))
        return result

    def current_user(request: Request) -> WebPrincipal | None:
        """Decode the session, then confirm the account is still allowed what it claims.

        The cookie is self-contained, so a disabled account or a changed role would otherwise
        keep its previous rights until the cookie expires.
        """
        principal = _decode_session(request.cookies.get(SESSION_COOKIE), session_secret)
        if principal is None:
            return None
        stored = next((item for item in list_users(system_conn) if item.get("username") == principal.username), None)
        if stored is None or not stored.get("enabled"):
            return None
        return WebPrincipal(
            principal.subject,
            str(stored.get("role", principal.role)),
            frozenset(str(scope) for scope in stored.get("scopes", [])),
            principal.username,
            str(stored.get("display_name", principal.display_name)),
            bool(stored.get("must_change_password", False)),
        )

    api_bearer = HTTPBearer(auto_error=False, scheme_name="BearerToken")

    def current_api_user(
        credentials: HTTPAuthorizationCredentials | None = Depends(api_bearer),
    ) -> WebPrincipal:
        """Authenticate only the external v1 routes; session auth remains cookie-only."""
        if credentials is None or credentials.scheme.casefold() != "bearer":
            raise HTTPException(status_code=401, detail="Bearer API key required", headers={"WWW-Authenticate": "Bearer"})
        authenticated = authenticate_api_token(system_conn, credentials.credentials)
        if authenticated is None:
            raise HTTPException(status_code=401, detail="Invalid or inactive API key", headers={"WWW-Authenticate": "Bearer"})
        if authenticated.get("must_change_password"):
            raise HTTPException(status_code=403, detail="Password change required")
        return WebPrincipal(
            str(authenticated["subject"]),
            str(authenticated["role"]),
            frozenset(str(scope) for scope in authenticated.get("scopes", [])),
            str(authenticated["username"]),
            str(authenticated["display_name"]),
            bool(authenticated.get("must_change_password", False)),
        )

    def _directory_config(name: str, *, require_enabled: bool = True) -> dict[str, Any] | None:
        config = next((item for item in list_idps(system_conn) if item.get("name") == name), None)
        if config is None or (require_enabled and not config.get("enabled")):
            return None
        return config

    def _directory_login(source: str, username: str, external_id: str | None, password: str) -> bool:
        """Verify a directory account against its directory at sign-in time."""
        config = _directory_config(source)
        if config is None:
            return False
        try:
            return directory_authenticate(config, username, password, distinguished_name=external_id) is not None
        except DirectoryError:
            return False

    def _stored_user(username: str) -> dict[str, Any] | None:
        return next((item for item in list_users(system_conn) if item.get("username") == str(username).strip().lower()), None)

    def record_audit(
        repo: Repository,
        request: Request,
        event_type: str,
        object_type: str | None = None,
        object_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        principal = current_user(request)
        event = audit(event_type, object_type, object_id)
        event.actor = principal.subject if principal else None
        event.details = details or {}
        repo.insert_append_only("audit_events", event)

    def record_sign_in_event(event_type: str, actor: str, details: dict[str, Any] | None = None) -> None:
        """Sign-in events name their own actor: there is no session to read them from yet."""
        event = audit(event_type, "user", actor)
        event.actor = actor
        event.details = details or {}
        with Repository(db_path) as repo:
            repo.insert_append_only("audit_events", event)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    def column_filters(request: Request) -> dict[str, str]:
        """Per-column filters travel as f.<column>=<text>, next to search and sort."""
        return {key[2:]: value for key, value in request.query_params.items() if key.startswith("f.") and value}

    def page(table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None, campaign: str | None = None, sort: str | None = None, order: str | None = None, classification: str | None = None, filters: dict[str, str] | None = None):
        return projected_rows(db_path, table, limit=max(1, min(limit, 500)), offset=max(0, offset), search=search, status=status, provider=provider, campaign=campaign, sort=sort, order=order, classification=classification, filters=filters)

    def scoped_page(principal: WebPrincipal, table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None, campaign: str | None = None, sort: str | None = None, order: str | None = None, classification: str | None = None, filters: dict[str, str] | None = None):
        allowed_campaigns = None
        if principal.role == "OPERATOR" and table in {"campaigns", "review_items", "decisions", "remediation_actions"}:
            with Repository(db_path) as repo:
                allowed_campaigns = _authorized_campaign_ids(principal, repo)
            if campaign and table in {"review_items", "decisions", "remediation_actions"}:
                _require_campaign_id_access(principal, campaign)
        allowed_providers = None if principal.role == "ADMIN" or "*" in principal.scopes else principal.scopes if principal.role in {"OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"} else None
        return projected_rows(db_path, table, limit=max(1, min(limit, 500)), offset=max(0, offset), search=search, status=status, provider=provider, campaign=campaign, sort=sort, order=order, classification=classification, filters=filters, reviewer_username=principal.username if principal.role == "GROUP_OWNER" else None, allowed_providers=allowed_providers, allowed_campaign_ids=allowed_campaigns)

    def require_table_access(principal: WebPrincipal, table: str) -> None:
        if principal.role == "BUSINESS_ADMIN" and table != "remediation_actions":
            raise HTTPException(status_code=403, detail="This role can only access remediation actions")
        if principal.role == "GROUP_OWNER" and table != "review_items":
            raise HTTPException(status_code=403, detail="This role can only access assigned reviews")

    @app.post("/api/auth/login")
    def login(payload: dict[str, Any] = Body(...), response: Response = None):  # type: ignore[assignment]
        username, password = payload.get("username"), payload.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or not username.strip() or not password:
            raise HTTPException(status_code=400, detail="Username and password are required")
        principal = authenticate_user(system_conn, username, password, _directory_login)
        if principal is None:
            record_sign_in_event("auth.sign_in_failed", username.strip().lower())
            raise HTTPException(status_code=401, detail="Invalid credentials")
        record_sign_in_event("auth.signed_in", principal["username"], {"role": principal["role"], "auth_source": principal.get("auth_source", LOCAL_SOURCE)})
        response.set_cookie(SESSION_COOKIE, _encode_session(principal, session_secret), httponly=True, secure=os.environ.get("EARE_COOKIE_SECURE") == "1", samesite="strict", max_age=SESSION_TTL_SECONDS, path="/")
        return {"subject": principal["subject"], "username": principal["username"], "display_name": principal["display_name"], "role": principal["role"], "scopes": principal["scopes"], "must_change_password": bool(principal.get("must_change_password", False))}

    @app.post("/api/auth/change-password")
    def change_password(request: Request, payload: dict[str, Any] = Body(...), response: Response = None):  # type: ignore[assignment]
        principal = current_user(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        password = payload.get("new_password")
        stored = _stored_user(principal.username)
        if stored is not None and (stored.get("auth_source") or LOCAL_SOURCE) != LOCAL_SOURCE:
            raise HTTPException(status_code=400, detail="Directory accounts change their password in their directory")
        try:
            updated = update_password(system_conn, principal.username, password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        record_sign_in_event("auth.password_changed", str(updated["username"]))
        response.set_cookie(SESSION_COOKIE, _encode_session(updated, session_secret), httponly=True, secure=os.environ.get("EARE_COOKIE_SECURE") == "1", samesite="strict", max_age=SESSION_TTL_SECONDS, path="/")
        return {"subject": updated["subject"], "username": updated["username"], "display_name": updated["display_name"], "role": updated["role"], "scopes": updated["scopes"], "must_change_password": False}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response):
        principal = current_user(request)
        if principal is not None:
            record_sign_in_event("auth.signed_out", principal.username)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/auth/session")
    def session(request: Request):
        principal = current_user(request)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return asdict(principal)

    @app.get("/api/me")
    def me(request: Request):
        return asdict(_require(current_user(request)))

    @app.get("/api/me/api-token")
    def me_api_token(request: Request):
        principal = _require(current_user(request))
        stored = _stored_user(principal.username)
        if stored is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return {
            "api_access_enabled": bool(stored.get("api_access_enabled")),
            "external_user_api_enabled": external_user_api_enabled(system_conn),
            "token": api_token_summary(system_conn, str(stored["id"])),
        }

    @app.post("/api/me/api-token")
    def me_api_token_create(request: Request, response: Response):
        principal = _require(current_user(request))
        stored = _stored_user(principal.username)
        if stored is None or not stored.get("enabled"):
            raise HTTPException(status_code=401, detail="Authentication required")
        if not stored.get("api_access_enabled"):
            raise HTTPException(status_code=403, detail="API access is disabled by an administrator")
        if not external_user_api_enabled(system_conn):
            raise HTTPException(status_code=403, detail="External user API is currently disabled")
        previous_token = system_conn.execute(
            "SELECT id, token_prefix FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (str(stored["id"]),),
        ).fetchone()
        try:
            created = create_api_token(system_conn, str(stored["id"]))
        except ValueError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            if previous_token is not None:
                record_audit(repo, request, "api.token_revoked", "api_token", str(previous_token["id"]), {"token_prefix": str(previous_token["token_prefix"]), "reason": "rotated"})
            record_audit(repo, request, "api.token_created", "api_token", created["id"], {"user_id": stored["id"], "token_prefix": created["prefix"]})
        response.headers["Cache-Control"] = "no-store"
        return {"api_key": created["token"], "prefix": created["prefix"], "created_at": created["created_at"], "expires_at": created["expires_at"]}

    @app.delete("/api/me/api-token")
    def me_api_token_revoke(request: Request):
        principal = _require(current_user(request))
        stored = _stored_user(principal.username)
        if stored is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        token = system_conn.execute(
            "SELECT id, token_prefix FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (str(stored["id"]),),
        ).fetchone()
        revoked = revoke_api_tokens(system_conn, str(stored["id"]))
        if token is not None:
            with Repository(db_path) as repo:
                record_audit(repo, request, "api.token_revoked", "api_token", str(token["id"]), {"token_prefix": str(token["token_prefix"])})
        return {"revoked": revoked > 0}

    def _authorized_domain_options(repo: Repository) -> list[dict[str, Any]]:
        """Combine observed providers with configured connector instances without exposing config."""
        safe_fields = ("id", "name", "type", "display_name", "health", "last_sync", "identity_count", "access_count")
        providers: dict[str, dict[str, Any]] = {}
        for row in repo.list_payloads("providers"):
            name = str(row.get("name") or "").strip()
            if name:
                providers[name] = {key: row[key] for key in safe_fields if key in row}
                providers[name]["configured"] = False
        if connector_directory.is_dir():
            for path in sorted(connector_directory.glob("*.yaml")):
                try:
                    config = load_connector(path.stem, path)
                except (OSError, ValueError):
                    continue
                name = str(config.get("provider") or "").strip()
                if not name:
                    continue
                existing = providers.get(name, {})
                providers[name] = {
                    **existing,
                    "name": name,
                    "type": str(config.get("type") or existing.get("type") or ""),
                    "display_name": str(existing.get("display_name") or config.get("display_name") or name),
                    "configured": True,
                }
        return [providers[name] for name in sorted(providers)]

    def _pending_reviews_by_reviewer() -> dict[str, int]:
        """Count the reviews still waiting on each reviewer, in open campaigns only."""
        counts: dict[str, int] = {}
        with Repository(db_path) as repo:
            open_campaigns = {str(row.get("id")) for row in repo.list_payloads("campaigns") if row.get("status") == "open"}
            decided = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
            for row in repo.list_payloads("review_items"):
                identity = str((row.get("reviewer") or {}).get("identity", "")).lower()
                if identity and str(row.get("campaign_id")) in open_campaigns and str(row.get("id")) not in decided:
                    counts[identity] = counts.get(identity, 0) + 1
        return counts

    @app.put("/api/system/settings/external-user-api")
    def system_external_api_toggle(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise HTTPException(status_code=400, detail="enabled must be a boolean")
        previous = external_user_api_enabled(system_conn)
        set_external_user_api_enabled(system_conn, enabled)
        if previous != enabled:
            with Repository(db_path) as repo:
                record_audit(repo, request, "api.global_enabled" if enabled else "api.global_disabled", "system_setting", "external_user_api_enabled")
        return {"external_user_api_enabled": enabled}

    @app.post("/api/system/users/{username}/api-token/revoke")
    def system_user_api_token_revoke(username: str, request: Request):
        principal = _require(current_user(request), ("ADMIN",))
        stored = _stored_user(username)
        if stored is None:
            raise HTTPException(status_code=404, detail="User not found")
        token = system_conn.execute(
            "SELECT id, token_prefix FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
            (str(stored["id"]),),
        ).fetchone()
        revoked = revoke_api_tokens(system_conn, str(stored["id"]))
        if token is not None:
            with Repository(db_path) as repo:
                record_audit(repo, request, "api.token_revoked", "api_token", str(token["id"]), {"user_id": stored["id"], "token_prefix": str(token["token_prefix"]), "revoked_by": principal.username})
        return {"revoked": revoked > 0}

    @app.get("/api/system")
    def system_overview(request: Request):
        _require(current_user(request), ("ADMIN",))
        pending = _pending_reviews_by_reviewer()
        users = [{**user, "pending_reviews": pending.get(str(user.get("username", "")).lower(), 0)} for user in list_users(system_conn)]
        with Repository(db_path) as repo:
            providers = _authorized_domain_options(repo)
        return {"users": users, "identity_providers": list_idps(system_conn), "providers": providers, "roles": sorted(ROLES), "external_user_api_enabled": external_user_api_enabled(system_conn)}

    @app.get("/api/campaign-pilots")
    def campaign_pilots(request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        items = [
            {
                "username": str(user.get("username")),
                "display_name": str(user.get("display_name") or user.get("username")),
                "role": str(user.get("role")),
            }
            for user in list_users(system_conn)
            if user.get("enabled") and user.get("role") in {"ADMIN", "OPERATOR"}
        ]
        return {"items": sorted(items, key=lambda item: str(item["display_name"]).casefold())}

    @app.post("/api/system/users/{username}/reassign-reviews")
    def system_user_reassign_reviews(username: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Hand the pending reviews of one person to another, so a leaver cannot block a campaign."""
        from access_review_engine.domain import OwnerRef

        _require(current_user(request), ("ADMIN",))
        origin = str(username).strip().lower()
        target = str(payload.get("to", "")).strip().lower()
        stored_target = _stored_user(target)
        if not target or stored_target is None or not stored_target.get("enabled"):
            raise HTTPException(status_code=400, detail="Choose an enabled EARE user to take the reviews over")
        if target == origin:
            raise HTTPException(status_code=400, detail="Choose a different user")
        moved = 0
        with Repository(db_path) as repo:
            open_campaigns = {str(row.get("id")) for row in repo.list_payloads("campaigns") if row.get("status") == "open"}
            decided = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
            for row in repo.list_payloads("review_items"):
                reviewer = row.get("reviewer") or {}
                if str(reviewer.get("identity", "")).lower() != origin:
                    continue
                # Decided items keep their reviewer: they are evidence of who decided what.
                if str(row.get("id")) in decided or str(row.get("campaign_id")) not in open_campaigns:
                    continue
                item = hydrate_review_item(row)
                item.reviewer = OwnerRef(provider=str(reviewer.get("provider") or item.identity_provider), identity=target)
                repo.upsert("review_items", item)
                moved += 1
            record_audit(repo, request, "review.reassigned", "user", origin, {"to": target, "review_items": moved})
        return {"from": origin, "to": target, "review_items": moved}

    def _guard_admin_access(principal: WebPrincipal, username: str, *, role: str | None = None, enabled: bool = True) -> None:
        """Refuse a change that would lock the administrator, or EARE itself, out."""
        target = str(username).strip().lower()
        stored = _stored_user(target)
        if stored is None:
            return
        losing_admin = str(stored.get("role")) == "ADMIN" and (not enabled or (role is not None and role != "ADMIN"))
        if not losing_admin:
            return
        if target == principal.username:
            raise HTTPException(status_code=409, detail="You cannot remove your own administrator access. Ask another administrator.")
        if enabled_admins(system_conn, excluding=target) == 0:
            raise HTTPException(status_code=409, detail="This is the last administrator who can sign in. Give another user the ADMIN role first.")

    @app.post("/api/system/users")
    def system_user_create(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN",))
        source = str(payload.get("auth_source") or LOCAL_SOURCE).strip() or LOCAL_SOURCE
        if source != LOCAL_SOURCE and _directory_config(source) is None:
            raise HTTPException(status_code=400, detail="This directory is not configured or not enabled")
        _guard_admin_access(principal, payload.get("username", ""), role=str(payload.get("role", "")).upper() or None, enabled=bool(payload.get("enabled", True)))
        role = str(payload.get("role", "")).upper()
        raw_scopes = payload.get("scopes", [])
        if role in {"OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"}:
            if not isinstance(raw_scopes, list) or any(not isinstance(value, str) for value in raw_scopes):
                raise HTTPException(status_code=400, detail="Authorized domains must be a list of provider names")
            with Repository(db_path) as repo:
                configured = {str(row.get("name")) for row in _authorized_domain_options(repo)}
            requested = {value.strip() for value in raw_scopes if value.strip()}
            if "*" in requested or requested - configured:
                raise HTTPException(status_code=400, detail="Authorized domains must be configured providers")
        previous_user = _stored_user(str(payload.get("username", "")))
        previous_api_access = bool(previous_user and previous_user.get("api_access_enabled"))
        previous_token = api_token_summary(system_conn, str(previous_user["id"])) if previous_user else {"active": False}
        try:
            result = upsert_user(system_conn, payload)
            with Repository(db_path) as repo:
                record_audit(repo, request, "system.user_upserted", "user", str(result.get("username", "")), {"role": result.get("role", ""), "auth_source": result.get("auth_source", LOCAL_SOURCE)})
                if previous_user is not None and previous_api_access != bool(result.get("api_access_enabled")):
                    record_audit(repo, request, "api.access_enabled" if result.get("api_access_enabled") else "api.access_disabled", "user", str(result.get("username", "")))
                    if previous_token.get("active") and not result.get("api_access_enabled"):
                        record_audit(repo, request, "api.token_revoked", "user", str(result.get("username", "")), {"reason": "api_access_disabled"})
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/users/{username}/disable")
    def system_user_disable(username: str, request: Request):
        principal = _require(current_user(request), ("ADMIN",))
        _guard_admin_access(principal, username, enabled=False)
        previous_user = _stored_user(username)
        previous_token = api_token_summary(system_conn, str(previous_user["id"])) if previous_user else {"active": False}
        try:
            result = set_enabled(system_conn, username, False)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            record_audit(repo, request, "system.user_disabled", "user", result["username"])
            if previous_token.get("active"):
                record_audit(repo, request, "api.token_revoked", "user", result["username"], {"reason": "account_disabled"})
        return result

    @app.post("/api/system/users/{username}/enable")
    def system_user_enable(username: str, request: Request):
        _require(current_user(request), ("ADMIN",))
        try:
            result = set_enabled(system_conn, username, True)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            record_audit(repo, request, "system.user_enabled", "user", result["username"])
        return result

    @app.post("/api/system/users/{username}/reset-password")
    def system_user_reset_password(username: str, request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        try:
            result = reset_password(system_conn, username, payload.get("password"))
        except ValueError as exc:
            status = 404 if str(exc) == "user not found" else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            record_audit(repo, request, "system.user_password_reset", "user", result["username"])
        return result

    def _validated_idp(payload: dict[str, Any]) -> dict[str, Any]:
        candidate = {**payload, "name": str(payload.get("name", "")).strip(), "kind": str(payload.get("kind", "")).upper()}
        if candidate["kind"] == "LDAP":
            try:
                validate_directory(candidate)
            except DirectoryError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        return candidate

    @app.post("/api/system/identity-providers")
    def system_idp_create(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        try:
            result = upsert_idp(system_conn, _validated_idp(payload))
            with Repository(db_path) as repo:
                record_audit(repo, request, "system.identity_provider_upserted", "identity_provider", str(result.get("name", "")), {"kind": result.get("kind", ""), "enabled": result.get("enabled", False)})
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/identity-providers/test")
    def system_idp_test(request: Request, payload: dict[str, Any] = Body(...)):
        """Check a directory configuration before it is saved."""
        _require(current_user(request), ("ADMIN",))
        try:
            return test_directory(_validated_idp(payload))
        except DirectoryError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/system/identity-providers/{name}/accounts")
    def system_idp_accounts(name: str, request: Request, search: str = "", limit: int = 25):
        """List directory accounts an administrator can import as EARE users."""
        _require(current_user(request), ("ADMIN",))
        config = _directory_config(name, require_enabled=False)
        if config is None:
            raise HTTPException(status_code=404, detail="Directory not found")
        try:
            accounts = directory_accounts(config, search, limit)
        except DirectoryError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        known = {str(user.get("username")) for user in list_users(system_conn)}
        return {"items": [{**account, "imported": account["login"].lower() in known} for account in accounts], "directory": name}

    @app.get("/api/system/sources")
    def system_sources(request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        connector_directory.mkdir(parents=True, exist_ok=True)
        sources = []
        for path in sorted(connector_directory.glob("*.yaml")):
            try:
                sources.append(_public_connector(load_connector(path.stem, path)))
            except ValueError:
                continue
        return {"sources": sources}

    @app.post("/api/system/sources")
    def system_source_save(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        candidate = _validate_web_connector(payload)
        path = connector_path(str(candidate["provider"]), connector_directory)
        previous_mapping = None
        if path.is_file():
            try:
                previous_mapping = load_connector(str(candidate["provider"]), path).get("business_mapping")
            except ValueError:
                previous_mapping = None
        connector_directory.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(candidate, sort_keys=False), encoding="utf-8")
        with Repository(db_path) as repo:
            event_type = "source.mapping_changed" if previous_mapping != candidate.get("business_mapping") else "source.configuration_saved"
            record_audit(repo, request, event_type, "provider", str(candidate["provider"]), {"type": candidate["type"], "mapping_changed": previous_mapping != candidate.get("business_mapping")})
        return _public_connector(load_connector(str(candidate["provider"]), path))

    @app.post("/api/system/sources/test")
    def system_source_test(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        candidate = _validate_web_connector(payload)
        try:
            secret_environment(candidate)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        candidate["_check_only"] = True
        with tempfile.TemporaryDirectory(prefix="eare-source-check-") as directory:
            output = Path(directory) / "connection-check.zip"
            try:
                result = run_exporter(candidate, output)
            except (RunnerError, ValueError) as exc:
                raise HTTPException(status_code=502, detail="Source connection test failed") from exc
        if result.returncode:
            raise HTTPException(status_code=502, detail="Source connection test failed")
        try:
            discovered = discover_source_attributes(candidate, "group")
            diagnostics = mapping_diagnostics(str(candidate["type"]), candidate, discovered)
            mapping_warning = any(row.get("status") in {"not_found", "warning"} for row in diagnostics)
        except SourceInspectorError:
            diagnostics = []
            mapping_warning = True
        return {
            "status": "healthy",
            "connection": {"status": "success", "message": "Connection test succeeded"},
            "provider": candidate["provider"],
            "mapping": {"warning": mapping_warning, "diagnostics": diagnostics},
            "message": "Connection test succeeded",
        }

    @app.get("/api/system/sources/{provider}/inspect/kinds")
    def source_inspector_kinds(provider: str, request: Request):
        _require(current_user(request), ("ADMIN",))
        return {"items": source_object_kinds(_load_web_connector(provider))}

    @app.get("/api/system/sources/{provider}/inspect/tree")
    def source_inspector_tree(provider: str, request: Request, parent: str = "", limit: int = 100):
        _require(current_user(request), ("ADMIN",))
        try:
            return browse_source_tree(_load_web_connector(provider), parent, limit)
        except SourceInspectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/system/sources/{provider}/inspect/objects")
    def source_inspector_search(provider: str, request: Request, kind: str = "group", search: str = "", limit: int = 25, offset: int = 0):
        _require(current_user(request), ("ADMIN",))
        try:
            return search_source_objects(_load_web_connector(provider), kind, search, limit, offset)
        except SourceInspectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/system/sources/{provider}/inspect/objects/{kind}/{identifier:path}")
    def source_inspector_detail(provider: str, kind: str, identifier: str, request: Request):
        _require(current_user(request), ("ADMIN",))
        try:
            return get_source_object(_load_web_connector(provider), kind, identifier)
        except SourceInspectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    @app.get("/api/system/sources/{provider}/inspect/attributes")
    def source_inspector_attributes(provider: str, request: Request, kind: str = "group"):
        _require(current_user(request), ("ADMIN",))
        try:
            attributes = discover_source_attributes(_load_web_connector(provider), kind)
        except SourceInspectorError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        return {"kind": kind, "attributes": attributes}

    @app.post("/api/golden-sources/baseline")
    def create_baseline(request: Request, payload: dict[str, Any] | None = Body(default=None)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            snapshots = repo.list_payloads("snapshots")
            if not snapshots:
                raise HTTPException(status_code=409, detail="No snapshot is available to create a baseline")
            requested = payload or {}
            snapshot_id = requested.get("snapshot_id")
            selected = next((row for row in snapshots if row.get("id") == snapshot_id), None) if snapshot_id else snapshots[-1]
            if selected is None:
                raise HTTPException(status_code=404, detail="Requested snapshot not found")
            snapshot = hydrate_snapshot(selected)
            name = str(requested.get("name") or "").strip()
            if not name:
                raise HTTPException(status_code=400, detail="Golden Source name is required")
            display_name = str(requested.get("display_name") or name).strip()
            existing = repo.find_by_name("golden_sources", name)
            source = hydrate_golden_source(existing) if existing else create_golden_source(name, display_name)
            previous = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            try:
                version = promote_snapshot(source, snapshot, previous)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            version.comment = str(requested.get("comment") or "").strip() or version.comment
            copy_assignment_annotations(repo, max(previous, key=lambda item: item.version) if previous else None, version)
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.version_created", "golden_source_version", version.id, {"source_id": source.id, "version": version.version})
            return {"source": asdict(source), "version": asdict(version), "snapshot_id": snapshot.id}

    @app.post("/api/golden-sources/from-scratch")
    def create_empty_golden_source(request: Request, payload: dict[str, Any] | None = Body(default=None)):
        """Create a real immutable empty v1 before any source has been collected."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        requested = payload or {}
        name = str(requested.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Golden Source name is required")
        display_name = str(requested.get("display_name") or name).strip()
        with Repository(db_path) as repo:
            if repo.find_by_name("golden_sources", name):
                raise HTTPException(status_code=409, detail="A Golden Source with this name already exists")
            source = create_golden_source(name, display_name)
            version = create_golden_version(
                source,
                [],
                "from_scratch",
                comment=str(requested.get("comment") or "Empty expected state created in the WebUI"),
            )
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(
                repo,
                request,
                "golden_source.version_created",
                "golden_source_version",
                version.id,
                {"source_id": source.id, "version": version.version, "origin": "from_scratch"},
            )
            return {"source": asdict(source), "version": asdict(version)}

    @app.get("/api/golden-sources/{name}/compare")
    def compare_baseline(name: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source_payload = repo.find_by_name("golden_sources", name)
            if not source_payload:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            if not versions:
                raise HTTPException(status_code=409, detail="Golden Source has no version to compare")
            snapshot = hydrate_snapshot(repo.list_payloads("snapshots")[-1]) if repo.list_payloads("snapshots") else None
            if snapshot is None:
                raise HTTPException(status_code=409, detail="A snapshot is required for comparison")
            try:
                current = golden_version_from_snapshot(source, snapshot, versions)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            active = max(versions, key=lambda item: item.version)
            return {"name": name, "active_version": active.version, "active_golden_version_id": active.id, "observed_snapshot_id": snapshot.id, "changes": golden_diff(active, current)}


    @app.post("/api/golden-sources/{name}/confirm-version")
    def confirm_golden_version(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        snapshot_id = payload.get("observed_snapshot_id")
        expected_id = payload.get("active_golden_version_id")
        if not isinstance(snapshot_id, str) or not isinstance(expected_id, str):
            raise HTTPException(status_code=400, detail="Comparison context is required")
        with Repository(db_path) as repo:
            source_payload = repo.find_by_name("golden_sources", name)
            if not source_payload:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            active = max(versions, key=lambda item: item.version) if versions else None
            snapshots = repo.list_payloads("snapshots")
            current_snapshot = snapshots[-1] if snapshots else None
            if current_snapshot is None or current_snapshot.get("id") != snapshot_id or active is None or active.id != expected_id:
                raise HTTPException(status_code=409, detail="The observed or expected data changed since this comparison. Please compare again before confirming.")
            snapshot = hydrate_snapshot(current_snapshot)
            try:
                version = promote_snapshot(source, snapshot, versions)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            version.comment = str(payload.get("comment") or "").strip() or version.comment
            copy_assignment_annotations(repo, active, version)
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.version_confirmed", "golden_source_version", version.id, {"source_id": source.id, "version": version.version, "snapshot_id": snapshot_id})
            return {"source": asdict(source), "version": asdict(version), "observed_snapshot_id": snapshot_id, "active_golden_version_id": expected_id}
    def _golden_context(repo: Repository, name: str):
        """Return the Golden Source, its versions and the active one."""
        payload = repo.find_by_name("golden_sources", name)
        if not payload:
            raise HTTPException(status_code=404, detail="Golden Source not found")
        source = hydrate_golden_source(payload)
        versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
        active = next((item for item in versions if item.id == source.active_version_id), None) or (max(versions, key=lambda item: item.version) if versions else None)
        return source, versions, active

    @app.get("/api/golden-sources/{name}/assignments")
    def golden_assignments(name: str, request: Request, search: str | None = None, limit: int = 25, offset: int = 0, sort: str | None = None, order: str | None = None):
        """Read what the Golden Source currently expects, so it can be reviewed in the WebUI."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            from access_review_engine.web_read_models import _display_names

            identity_names, access_names = _display_names(repo)
            # What an expected access actually is stays on the Access object, collected once.
            access_payloads = repo.list_payloads("accesses")
            catalog = {(str(row.get("provider")), str(row.get("name"))): row for row in access_payloads}
            catalog_by_native = {
                (str(row.get("provider")), str((row.get("control_object") or {}).get("native_id"))): row
                for row in access_payloads
                if isinstance(row.get("control_object"), dict) and (row.get("control_object") or {}).get("native_id")
            }
            rows = []
            for item in sorted(active.assignments, key=lambda entry: entry.key()):
                row = asdict(item)
                # Show the names people recognise; collectors key objects by their native id.
                row["identity_display_name"] = identity_names.get((item.identity_provider, item.identity_identifier)) or item.identity_identifier
                row["access_display_name"] = access_names.get((item.access_provider, item.access_name)) or item.access_name
                described = catalog.get((item.access_provider, item.access_name)) or catalog_by_native.get((item.access_provider, str(item.access_native_id))) or {}
                row["access_description"] = described.get("description")
                row["access_target"] = described.get("target")
                row["access_owner"] = described.get("access_owner")
                row["access_id"] = described.get("id")
                row["business_context"] = access_context_for_payload(repo, described)
                annotation = annotation_for_assignment(repo, active.id, item)
                row["golden_comment"] = annotation.get("comment") if annotation else None
                if not row.get("access_permission"):
                    permission = described.get("permission")
                    row["access_permission"] = (permission or {}).get("display_name") or (permission or {}).get("identifier") if isinstance(permission, dict) else permission
                rows.append(row)
            covered = sorted({str(item.access_provider) for item in active.assignments})
            applications = {
                str(row.get("business_context", {}).get("fields", {}).get("application", {}).get(origin, {}).get("value"))
                for row in rows
                for origin in ("manual", "source")
                if row.get("business_context", {}).get("fields", {}).get("application", {}).get(origin, {}).get("value")
            }
            expected_identities = {
                (str(item.identity_provider), str(item.identity_identifier))
                for item in active.assignments
            }
            expected_accesses = {
                (str(item.access_provider), str(item.access_name))
                for item in active.assignments
            }
            campaign_name = next((str(row.get("name")) for row in repo.list_payloads("campaigns") if str(row.get("id")) == str(active.source_campaign_id)), None)
            snapshots = repo.list_payloads("snapshots")
            collected = [str(item.get("name")) for item in (snapshots[-1].get("providers", []) if snapshots else [])]
            if search:
                needle = search.casefold()
                rows = [row for row in rows if needle in " ".join(str(value or "") for value in row.values()).casefold()]
            from access_review_engine.web_read_models import apply_field_filters

            rows = apply_field_filters(rows, column_filters(request))
            if sort:
                from access_review_engine.web_read_models import sorted_rows

                rows = sorted_rows(rows, sort, order)
            bounded = max(1, min(limit, 500))
            start = max(0, offset)
            return {
                "items": rows[start : start + bounded],
                "total": len(rows),
                "limit": bounded,
                "offset": start,
                "sort": sort or "",
                "order": (order or "asc").lower(),
                "version": active.version,
                "version_id": active.id,
                "source_type": active.source_type,
                "created_at": active.created_at,
                "created_by": active.created_by,
                "source_snapshot_id": active.source_snapshot_id,
                "source_campaign_id": active.source_campaign_id,
                "source_campaign_name": campaign_name,
                "comment": active.comment,
                "providers": covered,
                "assignment_count": len(active.assignments),
                "identity_count": len(expected_identities),
                "access_count": len(expected_accesses),
                "application_count": len(applications),
                "collected_providers": collected,
                "collected_at": snapshots[-1].get("created_at") if snapshots else None,
                "versions": [{"id": item.id, "version": item.version, "source_type": item.source_type, "created_at": item.created_at, "assignments": len(item.assignments), "comment": item.comment} for item in sorted(versions, key=lambda item: item.version)],
            }

    @app.get("/api/golden-sources/{name}/authentication")
    def golden_authentication(name: str, request: Request):
        """Expected authentication controls against the ones the collection observed."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            snapshots = repo.list_payloads("snapshots")
            covered = sorted({str(item.access_provider) for item in active.assignments}) if active else []
            # Read the posture of a collection that covers what this expected state describes.
            relevant = [row for row in snapshots if not covered or {str(item.get("name")) for item in row.get("providers", [])} & set(covered)]
            observed_payload = next((row.get("authentication_posture") for row in reversed(relevant) if row.get("authentication_posture")), None)
            collected_at = next((row.get("created_at") for row in reversed(relevant) if row.get("authentication_posture")), None)
        expected = active.golden_authentication_policy if active else None
        observed = hydrate_authentication_posture(observed_payload) if observed_payload else None
        rows = compare_authentication_posture(expected, observed)
        return {
            "version": active.version if active else None,
            "expected": asdict(expected) if expected else None,
            "observed": asdict(observed) if observed else None,
            "collected_at": collected_at,
            "providers": covered,
            "controls": rows,
            "summary": {
                "compliant": sum(1 for row in rows if row["assessment"] == "compliant"),
                "deviation": sum(1 for row in rows if row["assessment"] == "deviation"),
                "unknown": sum(1 for row in rows if row["assessment"] in {"unknown", "not_collected"}),
            },
        }

    @app.post("/api/golden-sources/{name}/authentication")
    def golden_adopt_authentication(name: str, request: Request, payload: dict[str, Any] | None = Body(default=None)):
        """Record the observed authentication posture as the expected one, in a new version."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            snapshots = repo.list_payloads("snapshots")
            observed_payload = next((row.get("authentication_posture") for row in reversed(snapshots) if row.get("authentication_posture")), None)
            if observed_payload is None:
                raise HTTPException(status_code=409, detail="No collection has reported an authentication posture yet")
            posture = hydrate_authentication_posture(observed_payload)
            version = create_golden_version(source, set(active.assignments), "manual", versions, parent_version_id=active.id, comment=str((payload or {}).get("comment") or "Authentication policy taken from the collected posture"), golden_authentication_policy=posture)
            copy_assignment_annotations(repo, active, version)
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.authentication_policy_set", "golden_source_version", version.id, {"source_id": source.id, "version": version.version})
            return {"version": version.version, "version_id": version.id, "controls": len(posture.controls)}

    @app.get("/api/golden-sources/{name}/accesses")
    def golden_accesses(name: str, request: Request, search: str | None = None, limit: int = 25, offset: int = 0, sort: str | None = None, order: str | None = None):
        """The expected accesses themselves: each role or group, what it allows, and how many people hold it."""
        from access_review_engine.web_read_models import _display_names, sorted_rows

        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            identity_names, access_names = _display_names(repo)
            access_payloads = repo.list_payloads("accesses")
            catalog = {(str(row.get("provider")), str(row.get("name"))): row for row in access_payloads}
            catalog_by_native = {
                (str(row.get("provider")), str((row.get("control_object") or {}).get("native_id"))): row
                for row in access_payloads
                if isinstance(row.get("control_object"), dict) and (row.get("control_object") or {}).get("native_id")
            }
            access_comments = {
                (item.access_provider, item.access_name): item.comment
                for item in active.access_comments
            }
            grouped: dict[tuple[str, str], dict[str, Any]] = {}
            for item in active.assignments:
                key = (item.access_provider, item.access_name)
                row = grouped.get(key)
                if row is None:
                    described = catalog.get(key) or catalog_by_native.get((item.access_provider, str(item.access_native_id))) or {}
                    permission = described.get("permission")
                    row = grouped[key] = {
                        "access_provider": item.access_provider,
                        "access_name": item.access_name,
                        "access_display_name": access_names.get(key) or item.access_name,
                        "access_description": described.get("description"),
                        "access_target": described.get("target"),
                        "access_owner": (described.get("access_owner") or {}).get("identity") if isinstance(described.get("access_owner"), dict) else None,
                        "access_permission": item.access_permission or ((permission or {}).get("display_name") or (permission or {}).get("identifier") if isinstance(permission, dict) else permission),
                        "access_comment": access_comments.get(key),
                        "access_id": described.get("id"),
                        "business_context": access_context_for_payload(repo, described),
                        "technical_grant": "Group membership" if str((permission or {}).get("identifier") if isinstance(permission, dict) else permission).casefold() == "member" else "Direct assignment",
                        "expected_identities": 0,
                        "identities": [],
                    }
                row["expected_identities"] += 1
                row["identities"].append({
                    "identity_provider": item.identity_provider,
                    "identity_identifier": item.identity_identifier,
                    "identity_display_name": identity_names.get((item.identity_provider, item.identity_identifier)) or item.identity_identifier,
                })
            rows = sorted(grouped.values(), key=lambda row: str(row["access_display_name"]).casefold())
            for row in rows:
                row["identities"].sort(key=lambda entry: str(entry["identity_display_name"]).casefold())
            application_options = sorted({
                str(context.get("value"))
                for row in rows
                for context in (row.get("business_context", {}).get("fields", {}).get("application", {}).values() if isinstance(row.get("business_context"), dict) else [])
                if isinstance(context, dict) and context.get("value") not in {None, ""}
            }, key=str.casefold)
            permission_options = sorted({
                value
                for row in rows
                for value in (
                    row.get("access_permission"),
                    *[
                        str(context.get("value"))
                        for context in (row.get("business_context", {}).get("fields", {}).get("business_permission", {}).values() if isinstance(row.get("business_context"), dict) else [])
                        if isinstance(context, dict) and context.get("value") not in {None, ""}
                    ],
                )
                if value not in {None, ""}
            }, key=str.casefold)
            if search:
                needle = search.casefold()
                rows = [row for row in rows if needle in " ".join(str(row.get(field) or "") for field in ("access_display_name", "access_name", "access_description", "access_provider", "access_permission")).casefold()]
            from access_review_engine.web_read_models import apply_field_filters

            rows = apply_field_filters(rows, column_filters(request))
            if sort:
                rows = sorted_rows(rows, sort, order)
            bounded, start = max(1, min(limit, 500)), max(0, offset)
            return {"items": rows[start : start + bounded], "total": len(rows), "limit": bounded, "offset": start, "version": active.version, "sort": sort or "", "order": (order or "asc").lower(), "application_options": application_options, "permission_options": permission_options}

    @app.post("/api/golden-sources/{name}/access-comment")
    def golden_access_comment(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Create a new immutable Golden version with one access-level comment."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        provider = str(payload.get("access_provider") or "").strip()
        access_name = str(payload.get("access_name") or "").strip()
        if not provider or not access_name:
            raise HTTPException(status_code=400, detail="Access provider and name are required")
        try:
            comment = normalize_assignment_comment(payload.get("comment"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            if principal.role != "ADMIN" and not principal.can_access(provider):
                raise HTTPException(status_code=403, detail="Scope is not authorized")
            key = (provider, access_name)
            current = next((item.comment for item in active.access_comments if (item.access_provider, item.access_name) == key), None)
            if current == comment:
                raise HTTPException(status_code=409, detail="This access comment is unchanged")
            comments = {
                (item.access_provider, item.access_name): item
                for item in active.access_comments
            }
            if comment is None:
                comments.pop(key, None)
            else:
                comments[key] = GoldenAccessComment(provider, access_name, comment)
            version = create_golden_version(
                source,
                set(active.assignments),
                "manual",
                versions,
                parent_version_id=active.id,
                comment=active.comment,
                golden_authentication_policy=active.golden_authentication_policy,
                schema_version=active.schema_version,
                expected_access_definitions=active.expected_access_definitions,
                expected_access_relations=active.expected_access_relations,
                functional_access_models=active.functional_access_models,
                access_comments=sorted(comments.values(), key=lambda item: (item.access_provider, item.access_name)),
            )
            with repo.transaction():
                copy_assignment_annotations(repo, active, version, principal.subject)
                source.active_version_id = version.id
                repo.upsert("golden_sources", source)
                repo.upsert("golden_source_versions", version)
                record_audit(repo, request, "golden_source.access_comment_changed", "golden_source_version", version.id, {"source_id": source.id, "version": version.version, "access_provider": provider, "access_name": access_name})
            return {"version": version.version, "version_id": version.id, "access_provider": provider, "access_name": access_name, "comment": comment}

    @app.get("/api/golden-sources/{name}/functional-model")
    def golden_functional_model(name: str, request: Request):
        """Read the immutable functional definitions for one Golden version."""
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        from access_review_engine.golden_functional import functional_access_rows

        with Repository(db_path) as repo:
            _, _, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            return {
                "version": active.version,
                "schema_version": active.schema_version,
                "items": functional_access_rows(repo, active),
                "capabilities": [
                    asdict(item)
                    for item in repo.list_capabilities()
                    if item.active
                ],
            }

    @app.post("/api/golden-sources/{name}/functional-model")
    def golden_functional_model_update(
        name: str, request: Request, payload: dict[str, Any] = Body(...)
    ):
        """Create a new immutable Golden V2 version with a functional Access definition."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        from access_review_engine.golden_functional import prepare_functional_model_update

        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            try:
                definitions, relations, models, comments, version_comment = (
                    prepare_functional_model_update(repo, active, payload)
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if (
                active.schema_version >= 2
                and definitions == active.expected_access_definitions
                and relations == active.expected_access_relations
                and models == active.functional_access_models
                and comments == active.access_comments
                and version_comment == active.comment
            ):
                raise HTTPException(status_code=409, detail="The functional model is unchanged")
            version = create_golden_version(
                source,
                active.assignments,
                "manual",
                versions,
                parent_version_id=active.id,
                comment=version_comment,
                golden_authentication_policy=active.golden_authentication_policy,
                schema_version=2,
                expected_access_definitions=definitions,
                expected_access_relations=relations,
                functional_access_models=models,
                access_comments=comments,
            )
            with repo.transaction():
                copy_assignment_annotations(repo, active, version, principal.subject)
                source.active_version_id = version.id
                repo.upsert("golden_sources", source)
                repo.upsert("golden_source_versions", version)
                record_audit(
                    repo,
                    request,
                    "golden_source.functional_model_changed",
                    "golden_source_version",
                    version.id,
                    {"source_id": source.id, "version": version.version},
                )
            return {
                "version": version.version,
                "version_id": version.id,
                "schema_version": version.schema_version,
                "access_provider": payload.get("access_provider"),
                "access_name": payload.get("access_name"),
            }
    @app.post("/api/golden-sources/{name}/assignments")
    def golden_edit_assignments(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Add, remove or replace expected assignments, as a new immutable version."""
        from access_review_engine.domain import GoldenSourceAssignment

        _require(current_user(request), ("ADMIN", "OPERATOR"))

        def entry(row: Any) -> GoldenSourceAssignment:
            if not isinstance(row, dict):
                raise HTTPException(status_code=400, detail="Each expected access must be an object")
            missing = [key for key in ("access_provider", "access_name", "identity_provider", "identity_identifier") if not str(row.get(key, "")).strip()]
            if missing:
                raise HTTPException(status_code=400, detail="Expected access requires " + ", ".join(missing))
            return GoldenSourceAssignment(
                access_provider=str(row["access_provider"]).strip(),
                access_name=str(row["access_name"]).strip(),
                identity_provider=str(row["identity_provider"]).strip(),
                identity_identifier=str(row["identity_identifier"]).strip(),
                access_native_id=str(row.get("access_native_id") or "") or None,
                access_permission=str(row.get("access_permission") or "") or None,
                identity_native_id=str(row.get("identity_native_id") or "") or None,
            )

        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            replace = payload.get("replace")
            if replace is not None:
                assignments = {entry(row) for row in replace}
                origin, comment = "csv", str(payload.get("comment") or "Replaced from the WebUI")
            else:
                assignments = set(active.assignments) if active else set()
                assignments |= {entry(row) for row in payload.get("add", [])}
                assignments -= {entry(row) for row in payload.get("remove", [])}
                origin, comment = "manual", str(payload.get("comment") or "Edited in the WebUI")
            if active is not None and assignments == set(active.assignments):
                raise HTTPException(status_code=409, detail="This change leaves the Golden Source unchanged")
            try:
                version = create_golden_version(source, assignments, origin, versions, parent_version_id=active.id if active else None, comment=comment, golden_authentication_policy=active.golden_authentication_policy if active else None)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            copy_assignment_annotations(repo, active, version)
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "golden_source.version_edited", "golden_source_version", version.id, {"source_id": source.id, "version": version.version, "assignments": len(version.assignments)})
            return {"version": version.version, "version_id": version.id, "assignments": len(version.assignments)}

    @app.post("/api/golden-sources/{name}/version-comment")
    def golden_version_comment(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        comment = payload.get("comment")
        if comment is not None and not isinstance(comment, str):
            raise HTTPException(status_code=400, detail="Golden version comment must be text")
        comment = (comment or "").strip()
        if len(comment) > 4000:
            raise HTTPException(status_code=400, detail="Golden version comment is too long")
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            if comment == (active.comment or ""):
                raise HTTPException(status_code=409, detail="This Golden version comment is unchanged")
            version = create_golden_version(
                source,
                set(active.assignments),
                "manual",
                versions,
                parent_version_id=active.id,
                comment=comment or None,
                golden_authentication_policy=active.golden_authentication_policy,
            )
            with repo.transaction():
                copy_assignment_annotations(repo, active, version, principal.subject)
                source.active_version_id = version.id
                repo.upsert("golden_sources", source)
                repo.upsert("golden_source_versions", version)
                record_audit(repo, request, "golden_source.version_comment_changed", "golden_source_version", version.id, {"source_id": source.id, "version": version.version})
            return {"version": version.version, "version_id": version.id, "comment": version.comment}

    @app.post("/api/golden-sources/{name}/assignment-comment")
    def golden_assignment_comment(name: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Version one expected-assignment comment without mutating historical evidence."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        from access_review_engine.domain import GoldenSourceAssignment

        try:
            requested = GoldenSourceAssignment(
                access_provider=str(payload.get("access_provider") or "").strip(),
                access_name=str(payload.get("access_name") or "").strip(),
                identity_provider=str(payload.get("identity_provider") or "").strip(),
                identity_identifier=str(payload.get("identity_identifier") or "").strip(),
                access_native_id=str(payload.get("access_native_id") or "") or None,
                access_permission=str(payload.get("access_permission") or "") or None,
                identity_native_id=str(payload.get("identity_native_id") or "") or None,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid expected assignment") from exc
        if not all(requested.key()):
            raise HTTPException(status_code=400, detail="Expected assignment reference is required")
        try:
            comment = normalize_assignment_comment(payload.get("comment"))
            version_comment = normalize_assignment_comment(payload.get("version_comment"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            source, versions, active = _golden_context(repo, name)
            if active is None:
                raise HTTPException(status_code=409, detail="Golden Source has no version yet")
            stable = [item for item in active.assignments if requested.stable_key() and item.stable_key() == requested.stable_key()]
            if requested.stable_key() is not None:
                matches = stable
            else:
                matches = [item for item in active.assignments if item.key() == requested.key() and item.stable_key() is None]
            if len(matches) != 1:
                raise HTTPException(status_code=404, detail="Expected assignment not found or ambiguous")
            current = matches[0]
            old = annotation_for_assignment(repo, active.id, current)
            if (old or {}).get("comment") == comment:
                raise HTTPException(status_code=409, detail="This comment is unchanged")
            version = create_golden_version(
                source,
                set(active.assignments),
                "manual",
                versions,
                parent_version_id=active.id,
                comment=version_comment or "Expected assignment comment updated",
                golden_authentication_policy=active.golden_authentication_policy,
            )
            try:
                with repo.transaction():
                    copy_assignment_annotations(repo, active, version)
                    annotation = set_assignment_annotation(repo, version, current, comment, principal.subject)
                    source.active_version_id = version.id
                    repo.upsert("golden_sources", source)
                    repo.upsert("golden_source_versions", version)
                    record_audit(repo, request, "golden_source.assignment_comment_changed", "golden_source_version", version.id, {"source_id": source.id, "version": version.version})
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            return {"version": version.version, "version_id": version.id, "annotation": annotation}

    @app.get("/api/golden-sources/{name}/export")
    def export_baseline(name: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            source = repo.find_by_name("golden_sources", name)
            if not source:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            golden = hydrate_golden_source(source)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == golden.id]
            if not versions:
                raise HTTPException(status_code=409, detail="Golden Source has no version")
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=["access_provider", "access_name", "identity_provider", "identity_identifier", "permission"])
            writer.writeheader()
            for item in versions[-1].assignments:
                writer.writerow({"access_provider": item.access_provider, "access_name": item.access_name, "identity_provider": item.identity_provider, "identity_identifier": item.identity_identifier, "permission": item.access_permission or ""})
            return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename={name}-baseline.csv"})


    @app.get("/api/reports/{campaign_id}/results")
    def campaign_report_results(campaign_id: str, request: Request, search: str | None = None, classification: str | None = None, decision: str | None = None, provider: str | None = None, owner: str | None = None, limit: int = 25, offset: int = 0, sort: str | None = None, order: str | None = None):
        """The report, readable in the WebUI: same rows and same counts as the exported file."""
        from access_review_engine.web_read_models import sorted_rows

        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            _require_campaign_access(principal, campaign, repo)
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            snapshot = _snapshot(repo, campaign.snapshot_id)
            identity_names = identity_names_from_snapshot(snapshot)
        rows = build_report_rows(items, decisions, identity_names)
        summary = report_summary(rows)
        facets = {
            "classification": sorted({str(row["classification"]) for row in rows if row["classification"]}),
            "decision": sorted({str(row["decision"]) for row in rows if row["decision"]}),
            "provider": sorted({str(row["provider"]) for row in rows if row["provider"]}),
            "owner": sorted({str(row["owner"]) for row in rows if row["owner"]}),
        }
        selected = {"classification": classification, "decision": decision, "provider": provider, "owner": owner}
        for field, value in selected.items():
            if value:
                rows = [row for row in rows if str(row.get(field)) == value]
        if search:
            needle = search.casefold()
            rows = [row for row in rows if needle in " ".join(str(value) for value in row.values()).casefold()]
        from access_review_engine.web_read_models import apply_field_filters

        rows = apply_field_filters(rows, column_filters(request))
        rows = sorted_rows(rows, sort or "source_group", order or "asc")
        bounded, start = max(1, min(limit, 500)), max(0, offset)
        return {
            "campaign": {"id": campaign.id, "name": campaign.name, "status": campaign.status, "due_at": campaign.due_at, "opened_at": campaign.opened_at, "closed_at": campaign.closed_at, "snapshot_id": campaign.snapshot_id, "golden_source_version_id": campaign.golden_source_version_id},
            "summary": summary,
            "facets": facets,
            "items": rows[start : start + bounded],
            "total": len(rows),
            "limit": bounded,
            "offset": start,
            "sort": sort or "",
            "order": (order or "asc").lower(),
        }

    @app.get("/api/reports/{campaign_id}/{format}")
    def campaign_report(campaign_id: str, format: str, request: Request, inline: bool = False):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        if format not in {"html", "csv", "json", "pdf"}:
            raise HTTPException(status_code=404, detail="Report format not available")
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            _require_campaign_access(principal, campaign, repo)
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            golden = _golden_version(repo, campaign.golden_source_version_id)
            snapshot = _snapshot(repo, campaign.snapshot_id)
            identity_names = identity_names_from_snapshot(snapshot)
            with tempfile.TemporaryDirectory(prefix="eare-report-") as directory:
                if format == "pdf":
                    content = render_pdf_report(campaign, build_report_rows(items, decisions, identity_names), golden)
                else:
                    write_reports(directory, campaign, items, decisions, golden, snapshot.authentication_posture, identity_names)
                    filename = {"html": "campaign-report.html", "csv": "campaign-results.csv", "json": "campaign-results.json"}[format]
                    content = (Path(directory) / filename).read_bytes()
            filename = {"html": "campaign-report.html", "csv": "campaign-results.csv", "json": "campaign-results.json", "pdf": "campaign-report.pdf"}[format]
            media = {"html": "text/html", "csv": "text/csv", "json": "application/json", "pdf": "application/pdf"}[format]
            safe_campaign_id = "".join(character if character.isalnum() or character in "-_" else "_" for character in campaign_id)
            disposition = "inline" if format == "html" and inline else "attachment"
            return StreamingResponse(iter([content]), media_type=media, headers={"Content-Disposition": f"{disposition}; filename={safe_campaign_id}-{filename}"})

    @app.get("/api/remediation-actions/export")
    def remediation_export(
        request: Request,
        status: str | None = None,
        provider: str | None = None,
        action: str | None = None,
        campaign: str | None = None,
    ):
        """Export the operational queue without implying that EARE executed any action."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR", "BUSINESS_ADMIN", "REMEDIATION_MANAGER"))
        if campaign and principal.role in {"ADMIN", "OPERATOR"}:
            _require_campaign_id_access(principal, campaign)
        filters = {"action": action} if action else None
        page_result = scoped_page(
            principal,
            "remediation_actions",
            500,
            0,
            None,
            status,
            provider,
            campaign,
            None,
            None,
            None,
            filters,
        )
        output = io.StringIO()
        fields = [
            "action", "access_provider", "identity_display_name", "identity_provider", "identity_identifier",
            "access_display_name", "access_name", "application", "target", "permission", "comment",
            "decided_by", "campaign_name", "campaign_id", "status",
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in page_result["items"]:
            context = row.get("business_context")
            application = ""
            if isinstance(context, dict):
                fields_context = context.get("fields")
                if isinstance(fields_context, dict):
                    application_value = fields_context.get("application")
                    if isinstance(application_value, dict):
                        application = application_value.get("value") or application_value.get("source") or ""
            writer.writerow({
                **row,
                "application": application,
                "target": json.dumps(row.get("target"), ensure_ascii=False, sort_keys=True) if row.get("target") else "",
                "permission": row.get("technical_permission") or row.get("permission") or "",
            })
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=remediation-plan.csv"},
        )

    @app.patch("/api/remediation-actions/{action_id}/status")
    def remediation_status(action_id: str, request: Request, payload: dict[str, Any] = Body(...)):
        """Record operational follow-up; this never executes a provider change."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR", "REMEDIATION_MANAGER"))
        status = str(payload.get("status") or "").strip().lower()
        if status not in {"pending", "exported", "completed", "not_completed"}:
            raise HTTPException(status_code=400, detail="Unsupported remediation status")
        comment = str(payload.get("comment") or "").strip()
        if len(comment) > 4000:
            raise HTTPException(status_code=400, detail="Status comment is limited to 4000 characters")
        if status == "not_completed" and not comment:
            raise HTTPException(status_code=400, detail="A comment is required when the remediation is not completed")
        with Repository(db_path) as repo:
            action = repo.get_payload("remediation_actions", action_id)
            if action is None:
                raise HTTPException(status_code=404, detail="Remediation action not found")
            provider = str(action.get("access_provider") or "")
            if not principal.can_access(provider):
                raise HTTPException(status_code=403, detail="Source is not authorized")
            action["status"] = status
            details = action.get("details") if isinstance(action.get("details"), dict) else {}
            details.update({"status_comment": comment, "status_updated_by": principal.username, "status_updated_at": now_utc()})
            action["details"] = details
            repo.upsert("remediation_actions", action)
            record_audit(repo, request, "remediation.status_changed", "remediation_action", action_id, {"status": status, "provider": provider})
            return action

    @app.get("/api/dashboard")
    def dashboard(request: Request):
        """What deserves attention today, and what to do about it."""
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        today = time.strftime("%Y-%m-%d")
        allowed_domains = None if principal.role == "ADMIN" or "*" in principal.scopes else set(principal.scopes)
        with Repository(db_path) as repo:
            allowed_campaigns = _authorized_campaign_ids(principal, repo)
            campaigns = [row for row in repo.list_payloads("campaigns") if str(row.get("id")) in allowed_campaigns]
            items = [row for row in repo.list_payloads("review_items") if str(row.get("campaign_id")) in allowed_campaigns]
            decided = {str(row.get("review_item_id")) for row in repo.list_payloads("decisions")}
            actions = [row for row in repo.list_payloads("remediation_actions") if allowed_domains is None or str(row.get("access_provider") or "") in allowed_domains]
            snapshots = repo.list_payloads("snapshots")
            sources = repo.list_payloads("golden_sources")
            versions = repo.list_payloads("golden_source_versions")
            connectors = repo.list_payloads("providers")
        if allowed_domains is not None:
            snapshots = [row for row in snapshots if any(str(provider.get("name") or "") in allowed_domains for provider in row.get("providers", []))]
        snapshot = snapshots[-1] if snapshots else None
        comparison = list(snapshot.get("comparison_states", [])) if snapshot else []
        if allowed_domains is not None:
            comparison = [row for row in comparison if str(row.get("access_provider") or "") in allowed_domains and str(row.get("identity_provider") or "") in allowed_domains]
        with Repository(db_path) as repo:
            accesses = [row for row in repo.list_payloads("accesses") if allowed_domains is None or str(row.get("provider") or "") in allowed_domains]
            assignments = [row for row in repo.list_payloads("access_assignments") if allowed_domains is None or (str(row.get("provider") or "") in allowed_domains and str(row.get("identity_provider") or "") in allowed_domains)]
            identity_names, access_names = __import__("access_review_engine.web_read_models", fromlist=["_display_names"])._display_names(repo)
        # What this person is personally on the hook for: their reviews and the rights they own.
        me = principal.username.casefold()
        my_items = [row for row in items if str((row.get("reviewer") or {}).get("identity", "")).casefold() == me]
        holders: dict[tuple[str, str], int] = {}
        for row in assignments:
            key = (str(row.get("provider")), str(row.get("access_name")))
            holders[key] = holders.get(key, 0) + 1
        owned = []
        for row in accesses:
            owner = row.get("access_owner") or {}
            if str(owner.get("identity", "")).casefold() != me:
                continue
            target = row.get("target") or {}
            service = (target.get("service") or {}) if isinstance(target, dict) else {}
            key = (str(row.get("provider")), str(row.get("name")))
            owned.append({
                "access_name": row.get("name"),
                "access_display_name": access_names.get(key) or row.get("display_name") or row.get("name"),
                "description": row.get("description"),
                "provider": row.get("provider"),
                "application": service.get("display_name") or service.get("identifier"),
                "holders": holders.get(key, 0),
            })
        owned.sort(key=lambda row: (str(row["application"] or "~"), str(row["access_display_name"]).casefold()))
        pending_actions = [row for row in actions if row.get("status") != "exported"]
        open_campaigns = [row for row in campaigns if row.get("status") == "open"]
        providers = projected_rows(db_path, "providers", limit=100, offset=0, allowed_providers=allowed_domains)["items"]
        attention: list[dict[str, Any]] = []

        def note(tone: str, title: str, detail: str, link: str) -> None:
            attention.append({"tone": tone, "title": title, "detail": detail, "link": link})

        for row in providers:
            if row.get("health") == "failed":
                note("red", f"Collection failed on {row.get('name')}", "The last synchronization did not complete.", "/sources")
            elif row.get("health") == "never_synced":
                note("amber", f"{row.get('name')} has never been collected", "EARE knows nothing about this source yet.", "/sources")
        if not connectors:
            note("blue", "No source yet", "Connect the first directory or application EARE should audit.", "/sources")
        elif not snapshot:
            note("blue", "Nothing collected yet", "Synchronize a source to see identities and accesses.", "/sources")

        active_versions = {str(row.get("active_version_id")) for row in sources}
        active = [row for row in versions if str(row.get("id")) in active_versions]
        newest_expected = max((str(row.get("created_at", "")) for row in active), default="")
        if not sources:
            note("blue", "No expected state yet", "Declare what is expected, so deviations can be reported.", "/golden")
        elif snapshot and newest_expected and str(snapshot.get("created_at", "")) > newest_expected:
            note("amber", "The systems changed since the expected state was set", "Compare the collected state with the Golden Source.", "/golden")

        for row in open_campaigns:
            scoped = [item for item in items if item.get("campaign_id") == row.get("id")]
            waiting = [item for item in scoped if str(item.get("id")) not in decided]
            due = str(row.get("due_at") or "")
            if waiting and due and due < today:
                note("red", f"{row.get('name')} is overdue", f"{len(waiting)} review(s) still waiting, due {due}.", f"/campaigns/{row.get('id')}")
            elif waiting:
                note("amber", f"{row.get('name')} is in progress", f"{len(waiting)} review(s) still waiting.", f"/campaigns/{row.get('id')}")
            else:
                note("blue", f"{row.get('name')} can be closed", "Every review has been decided.", f"/campaigns/{row.get('id')}")
        promoted = {str(row.get("source_campaign_id")) for row in versions if row.get("source_campaign_id")}
        for row in campaigns:
            if row.get("status") == "closed" and str(row.get("id")) not in promoted:
                note("blue", f"{row.get('name')} is closed but not promoted", "Its decisions have not been carried into the expected state.", f"/campaigns/{row.get('id')}")
        if pending_actions:
            note("amber", f"{len(pending_actions)} remediation action(s) to carry out", "Decisions are waiting to be applied in the systems.", "/actions")
        if not campaigns and snapshot:
            note("blue", "No campaign yet", "A campaign asks the owners to confirm who should keep their access.", "/campaigns/new")

        return {
            "role": principal.role,
            "metrics": {
                "campaigns": len(open_campaigns),
                "pending_reviews": sum(1 for item in items if str(item.get("id")) not in decided and item.get("campaign_id") in {str(row.get("id")) for row in open_campaigns}),
                "remediation_actions": len(pending_actions),
                "findings": sum(1 for row in comparison if row.get("findings")),
            },
            "collected_at": snapshot.get("created_at") if snapshot else None,
            "collected_from": [provider.get("name") for provider in (snapshot or {}).get("providers", []) if allowed_domains is None or provider.get("name") in allowed_domains],
            "expected_state": {"name": sources[0].get("name"), "version": max((int(row.get("version", 0)) for row in active), default=0), "assignments": max((len(row.get("assignments", [])) for row in active), default=0)} if sources else None,
            "mine": {
                "reviews": {
                    "total": len(my_items),
                    "pending": sum(1 for row in my_items if str(row.get("id")) not in decided),
                    "campaigns": sorted({str(row.get("campaign_id")) for row in my_items if str(row.get("id")) not in decided}),
                },
                "owned_accesses": owned[:12],
                "owned_total": len(owned),
                "applications": sorted({str(row["application"]) for row in owned if row["application"]}),
            },
            "campaigns": [
                {"id": row.get("id"), "name": row.get("name"), "status": row.get("status"), "due_at": row.get("due_at"), "review_items": len([item for item in items if item.get("campaign_id") == row.get("id")]), "pending": len([item for item in items if item.get("campaign_id") == row.get("id") and str(item.get("id")) not in decided])}
                for row in open_campaigns[:4]
            ],
            "sources": [{"name": row.get("name"), "health": row.get("health"), "last_sync": row.get("last_sync"), "identity_count": row.get("identity_count"), "access_count": row.get("access_count")} for row in providers],
            "attention": attention[:8],
        }


    def _snapshot(repo: Repository, snapshot_id: str | None = None):
        snapshots = repo.list_payloads("snapshots")
        payload = next((row for row in snapshots if row.get("id") == snapshot_id), None) if snapshot_id else (snapshots[-1] if snapshots else None)
        if payload is None:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        return hydrate_snapshot(payload)

    def _golden_version(repo: Repository, version_id: str | None):
        if not version_id:
            return None
        payload = next((row for row in repo.list_payloads("golden_source_versions") if row.get("id") == version_id), None)
        if payload is None:
            raise HTTPException(status_code=404, detail="Golden Source version not found")
        return hydrate_golden_version(payload)

    def _campaign_payload(payload: dict[str, Any], *, draft_id: str | None = None, pilot: str | None = None):
        from access_review_engine.domain import Campaign, OwnerRef
        def owner(value: Any):
            if value is None:
                return None
            if not isinstance(value, dict) or not value.get("provider") or not value.get("identity"):
                raise HTTPException(status_code=400, detail="Reviewer references require provider and identity")
            return OwnerRef(provider=str(value["provider"]), identity=str(value["identity"]))
        allowed = {key: payload[key] for key in ("name", "snapshot_id", "display_name", "description", "golden_source_version_id", "scope", "allow_unresolved_reviewers", "due_at") if key in payload}
        allowed["name"] = str(allowed.get("name") or "").strip()
        if not allowed["name"] or not isinstance(allowed.get("snapshot_id"), str) or not allowed["snapshot_id"].strip():
            raise HTTPException(status_code=400, detail="Campaign name and snapshot_id are required")
        allowed["snapshot_id"] = allowed["snapshot_id"].strip()
        try:
            allowed["scope"] = normalize_campaign_scope(allowed.get("scope") or {"type": "all"})
        except CampaignScopeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        allowed["default_reviewer"] = owner(payload.get("default_reviewer"))
        allowed["manager"] = owner(payload.get("manager"))
        pilot_username = str(payload.get("pilot") or pilot or "").strip().lower()
        pilot_user = _stored_user(pilot_username) if pilot_username else None
        if pilot_user is None or pilot_user.get("role") not in {"ADMIN", "OPERATOR"} or not pilot_user.get("enabled", True):
            raise HTTPException(status_code=400, detail="Campaign pilot must be an enabled ADMIN or OPERATOR account")
        allowed["pilot"] = pilot_username
        if draft_id:
            allowed["id"] = draft_id
        return Campaign(**allowed)

    def _prepare_campaign(repo: Repository, campaign):
        snapshot = _snapshot(repo, campaign.snapshot_id)
        golden = _golden_version(repo, campaign.golden_source_version_id)
        return prepare_campaign_review(campaign, snapshot, golden, snapshot_collection_scope(repo, snapshot))

    def _campaign_required_providers(campaign, repo: Repository, preparation=None) -> set[str]:
        review_items = [
            row for row in repo.list_payloads("review_items")
            if str(row.get("campaign_id")) == str(campaign.id)
        ]
        if campaign.status in {"open", "closed", "cancelled"} and review_items:
            # Historical review rows are immutable campaign evidence. Do not require the
            # Golden Source to remain recalculable. If the Snapshot still exists, its provider
            # coverage also remains part of an `all` campaign's authorization boundary.
            try:
                snapshot = _snapshot(repo, campaign.snapshot_id)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                snapshot = None
            return campaign_required_providers(
                campaign.scope,
                review_items=review_items,
                snapshot_providers=[provider.name for provider in snapshot.providers] if snapshot else (),
            )
        if campaign.status in {"open", "closed"}:
            # A materialized campaign with no reviews can still expose its explicit scope;
            # for `all`, Snapshot coverage prevents an empty provider set from authorizing it.
            try:
                snapshot = _snapshot(repo, campaign.snapshot_id)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                snapshot = None
            return campaign_required_providers(
                campaign.scope,
                snapshot_providers=[provider.name for provider in snapshot.providers] if snapshot else (),
            )
        preparation = preparation or _prepare_campaign(repo, campaign)
        return campaign_required_providers(
            campaign.scope,
            preparation.comparison_states,
            snapshot_providers=[provider.name for provider in preparation.snapshot.providers],
        )

    def _require_campaign_access(principal: WebPrincipal, campaign, repo: Repository, preparation=None):
        if principal.role == "ADMIN":
            return preparation
        if principal.role != "OPERATOR":
            raise HTTPException(status_code=403, detail="This role cannot manage campaigns")
        if "*" in principal.scopes:
            return preparation
        try:
            required = _campaign_required_providers(campaign, repo, preparation)
        except (ValueError, KeyError, TypeError, HTTPException) as exc:
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if not can_access_campaign(principal.role, principal.scopes, required):
            raise HTTPException(status_code=403, detail="Campaign includes providers outside your authorized domains")
        return preparation

    def _authorized_campaign_ids(principal: WebPrincipal, repo: Repository) -> set[str]:
        campaigns = repo.list_payloads("campaigns")
        if principal.role == "ADMIN" or (principal.role == "OPERATOR" and "*" in principal.scopes):
            return {str(row.get("id")) for row in campaigns}
        if principal.role != "OPERATOR":
            raise HTTPException(status_code=403, detail="This role cannot access campaigns")
        allowed: set[str] = set()
        for raw in campaigns:
            try:
                campaign = hydrate_campaign(raw)
                required = _campaign_required_providers(campaign, repo)
            except (ValueError, KeyError, TypeError, HTTPException):
                continue
            if can_access_campaign(principal.role, principal.scopes, required):
                allowed.add(str(campaign.id))
        return allowed

    def _require_campaign_id_access(principal: WebPrincipal, campaign_id: str):
        if principal.role not in {"ADMIN", "OPERATOR"}:
            raise HTTPException(status_code=403, detail="This role cannot access campaigns")
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            _require_campaign_access(principal, campaign, repo)
        return campaign

    @app.get("/api/campaign-scope-accesses")
    def campaign_scope_accesses(request: Request, snapshot_id: str, golden_source_version_id: str | None = None):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            snapshot = _snapshot(repo, snapshot_id)
            golden = _golden_version(repo, golden_source_version_id)
            try:
                rows = compare_snapshot(snapshot, golden, snapshot_collection_scope(repo, snapshot))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            references = {(access.provider, access.name) for access in snapshot.accesses}
            references.update((str(row.get("access_provider")), str(row.get("access_name"))) for row in rows)
            if golden:
                references.update((assignment.access_provider, assignment.access_name) for assignment in golden.assignments)
            allowed = None if principal.role == "ADMIN" or "*" in principal.scopes else set(principal.scopes)
            catalog = {(str(row.get("provider")), str(row.get("name"))): row for row in repo.list_payloads("accesses")}
            snapshot_catalog = {(access.provider, access.name): access for access in snapshot.accesses}
            items = []
            for provider, name in sorted(references):
                if not provider or not name or (allowed is not None and provider not in allowed):
                    continue
                access = snapshot_catalog.get((provider, name))
                saved = catalog.get((provider, name), {})
                context = access_context_for_payload(repo, asdict(access)) if access else access_context_for_payload(repo, saved)
                fields = context.get("fields", {}) if isinstance(context, dict) else {}
                application = (fields.get("application") or {}).get("source") or (fields.get("application") or {}).get("manual") if isinstance(fields, dict) else None
                items.append({
                    "provider": provider,
                    "name": name,
                    "display_name": (access.display_name if access else None) or saved.get("display_name") or name,
                    "application": application.get("value") if isinstance(application, dict) else None,
                })
            return {"items": items, "total": len(items)}

    @app.post("/api/campaigns/preview")
    def campaign_preview(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        campaign = _campaign_payload(payload, pilot=principal.username)
        with Repository(db_path) as repo:
            snapshot = _snapshot(repo, campaign.snapshot_id)
            golden = _golden_version(repo, campaign.golden_source_version_id)
            try:
                preparation = prepare_campaign_review(campaign, snapshot, golden, snapshot_collection_scope(repo, snapshot))
                _require_campaign_access(principal, campaign, repo, preparation)
                return preview_campaign_review(campaign, snapshot, golden, preparation=preparation)
            except HTTPException:
                raise
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/campaigns")
    def campaign_create(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        campaign = _campaign_payload(payload, pilot=principal.username)
        with Repository(db_path) as repo:
            snapshot = _snapshot(repo, campaign.snapshot_id)
            golden = _golden_version(repo, campaign.golden_source_version_id)
            try:
                preparation = prepare_campaign_review(campaign, snapshot, golden, snapshot_collection_scope(repo, snapshot))
                _require_campaign_access(principal, campaign, repo, preparation)
            except HTTPException:
                raise
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            repo.upsert("campaigns", campaign)
            record_audit(repo, request, "campaign.created", "campaign", campaign.id, {"snapshot_id": campaign.snapshot_id})
        return asdict(campaign)

    @app.put("/api/campaigns/{campaign_id}")
    def campaign_update(campaign_id: str, request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            current = hydrate_campaign(raw)
            if current.status != "draft":
                raise HTTPException(status_code=409, detail="Only draft campaigns can be edited")
            merged = asdict(current)
            merged.update(payload)
            try:
                campaign = _campaign_payload(merged, draft_id=campaign_id, pilot=principal.username)
                campaign.created_at = current.created_at
                campaign.status = current.status
                snapshot = _snapshot(repo, campaign.snapshot_id)
                golden = _golden_version(repo, campaign.golden_source_version_id)
                preparation = prepare_campaign_review(campaign, snapshot, golden, snapshot_collection_scope(repo, snapshot))
                _require_campaign_access(principal, campaign, repo, preparation)
            except HTTPException:
                raise
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            repo.upsert("campaigns", campaign)
            record_audit(repo, request, "campaign.updated", "campaign", campaign.id, {"snapshot_id": campaign.snapshot_id})
            return asdict(campaign)

    @app.post("/api/campaigns/{campaign_id}/open")
    def campaign_open(campaign_id: str, request: Request, payload: dict[str, Any] | None = Body(default=None)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            if not campaign.pilot:
                campaign.pilot = principal.username
            pilot_user = _stored_user(campaign.pilot)
            if pilot_user is None or pilot_user.get("role") not in {"ADMIN", "OPERATOR"} or not pilot_user.get("enabled", True):
                raise HTTPException(status_code=409, detail="Campaign pilot must be an enabled ADMIN or OPERATOR account")
            if payload and "allow_unresolved_reviewers" in payload:
                campaign.allow_unresolved_reviewers = bool(payload["allow_unresolved_reviewers"])
            snapshot = _snapshot(repo, campaign.snapshot_id)
            try:
                preparation = _prepare_campaign(repo, campaign)
                _require_campaign_access(principal, campaign, repo, preparation)
                # A bypass must still leave every review actionable. Items whose
                # business/access owner cannot be resolved are assigned to the
                # campaign pilot, who can review them from My Reviews. The
                # missing owner remains visible and should be corrected in the
                # Golden Source afterwards.
                fallback_reviewer = None
                if campaign.allow_unresolved_reviewers:
                    fallback_reviewer = campaign.manager or OwnerRef(LOCAL_SOURCE, campaign.pilot)
                opened, items = open_campaign(campaign, preparation.snapshot, fallback_reviewer)
            except HTTPException:
                raise
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            observed_accesses = {
                (access.provider, access.name): access
                for access in snapshot.accesses
            }
            reviewed_refs = {(item.access_provider, item.access_name) for item in items}
            catalog_accesses = {}
            for row in repo.list_payloads("accesses"):
                reference = (str(row.get("provider")), str(row.get("name")))
                if reference in reviewed_refs:
                    catalog_accesses[reference] = hydrate_access(row)
            contexts_to_capture = [
                observed_accesses.get(reference) or catalog_accesses.get(reference)
                for reference in sorted(reviewed_refs)
            ]
            contexts_to_capture = [access for access in contexts_to_capture if access is not None]
            with repo.transaction():
                repo.upsert("campaigns", opened)
                for item in items:
                    repo.upsert("review_items", item)
                capture_campaign_access_contexts(repo, opened.id, contexts_to_capture)
                record_audit(repo, request, "campaign.opened", "campaign", opened.id, {"review_items": len(items)})
            return {"campaign": asdict(opened), "items": len(items)}

    @app.post("/api/campaigns/{campaign_id}/close")
    def campaign_close(campaign_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            _require_campaign_access(principal, campaign, repo)
            if campaign.status != "open":
                raise HTTPException(status_code=409, detail="Only open campaigns can be closed")
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            try:
                closed = close_campaign(campaign, items, decisions)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            repo.upsert("campaigns", closed)
            # Closing is what turns decisions into work for the people who operate the systems.
            actions = remediation_from_decisions(items, decisions)
            for action in actions:
                repo.insert_append_only("remediation_actions", action)
            record_audit(repo, request, "campaign.closed", "campaign", closed.id, {"review_items": len(items), "remediation_actions": len(actions)})
            return {**asdict(closed), "remediation_actions": len(actions)}

    @app.post("/api/campaigns/{campaign_id}/cancel")
    def campaign_cancel(campaign_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            _require_campaign_access(principal, campaign, repo)
            if campaign.status != "draft":
                raise HTTPException(status_code=409, detail="Only draft campaigns can be cancelled")
            campaign.status = "cancelled"
            repo.upsert("campaigns", campaign)
            record_audit(repo, request, "campaign.cancelled", "campaign", campaign.id)
            return asdict(campaign)

    @app.post("/api/campaigns/{campaign_id}/promote")
    def campaign_promote(campaign_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            raw = repo.get_payload("campaigns", campaign_id)
            if raw is None:
                raise HTTPException(status_code=404, detail="Campaign not found")
            campaign = hydrate_campaign(raw)
            _require_campaign_access(principal, campaign, repo)
            if campaign.status != "closed":
                raise HTTPException(status_code=409, detail="Only closed campaigns can be promoted")
            source_payloads = repo.list_payloads("golden_sources")
            if not source_payloads:
                raise HTTPException(status_code=409, detail="A Golden Source is required")
            version_payloads = repo.list_payloads("golden_source_versions")
            selected_version = next((row for row in version_payloads if row.get("id") == campaign.golden_source_version_id), None)
            if selected_version is None:
                raise HTTPException(status_code=409, detail="Campaign has no unambiguous Golden Source reference.")
            source_payload = next(
                (row for row in source_payloads if row.get("id") == selected_version.get("golden_source_id")),
                None,
            )
            if source_payload is None:
                raise HTTPException(status_code=409, detail="Campaign Golden Source reference is invalid.")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in version_payloads if row.get("golden_source_id") == source.id]
            previous = max(versions, key=lambda item: item.version) if versions else None
            items = [hydrate_review_item(row) for row in repo.list_payloads("review_items") if row.get("campaign_id") == campaign_id]
            decisions = [hydrate_decision(row) for row in repo.list_payloads("decisions") if row.get("review_item_id") in {item.id for item in items}]
            try:
                version = promote_campaign(
                    source,
                    campaign,
                    items,
                    decisions,
                    previous,
                    mode="replace_scope",
                    observed_snapshot=_snapshot(repo, campaign.snapshot_id),
                )
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            copy_assignment_annotations(repo, previous, version)
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            record_audit(repo, request, "campaign.promoted", "campaign", campaign.id, {"version_id": version.id, "golden_source_id": source.id})
            return {"source": asdict(source), "version": asdict(version)}

    @app.get("/api/campaigns/{campaign_id}")
    def campaign_detail(campaign_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        _require_campaign_id_access(principal, campaign_id)
        # Aggregates and reviewer progress must cover the whole campaign. The generic page helper is
        # intentionally capped for table endpoints, so using it here silently truncated large reviews.
        result = projected_rows(db_path, "campaigns", limit=1_000_000_000, offset=0)
        campaign = next((item for item in result["items"] if item.get("id") == campaign_id), None)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        reviews = projected_rows(
            db_path,
            "review_items",
            limit=1_000_000_000,
            offset=0,
            campaign=campaign_id,
        )["items"]
        findings = [finding for item in reviews for finding in item.get("findings", [])]
        actions = projected_rows(
            db_path,
            "remediation_actions",
            limit=1_000_000_000,
            offset=0,
            campaign=campaign_id,
        )["items"]
        return {
            "campaign": campaign,
            "reviews": reviews,
            "findings": sorted(set(findings)),
            "remediation_actions": actions,
            "remediation_summary": {
                "total": len(actions),
                "pending": sum(1 for action in actions if action.get("status") == "pending"),
                "exported": sum(1 for action in actions if action.get("status") == "exported"),
            },
        }

    @app.get("/api/audit-events")
    def audit_events(request: Request, limit: int = 100, offset: int = 0):
        _require(current_user(request), ("ADMIN",))
        bounded_limit = max(1, min(limit, 500))
        bounded_offset = max(0, offset)
        with Repository(db_path) as repo:
            events = repo.list_payloads("audit_events")
        return {"items": events[bounded_offset : bounded_offset + bounded_limit], "total": len(events), "limit": bounded_limit, "offset": bounded_offset}

    def _golden_application_usage(repo: Repository, application_name: str) -> list[dict[str, Any]]:
        def key(value: Any) -> str:
            return str(value or "").strip().casefold()

        wanted = key(application_name)
        accesses = {str(row.get("id")): row for row in repo.list_payloads("accesses")}
        enrichments = {str(row.get("access_id")): row for row in repo.list_payloads("access_enrichments")}
        sources = {str(row.get("id")): row for row in repo.list_payloads("golden_sources")}
        usages: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for version in repo.list_payloads("golden_source_versions"):
            access_keys = {(str(item.get("access_provider")), str(item.get("access_name"))) for item in version.get("assignments", [])}
            source = sources.get(str(version.get("golden_source_id")), {})
            source_name = str(source.get("display_name") or source.get("name") or version.get("golden_source_id") or "Golden Source")
            for provider, access_name in access_keys:
                access = next((row for row in accesses.values() if str(row.get("provider")) == provider and str(row.get("name")) == access_name), None)
                if not access:
                    continue
                enrichment = enrichments.get(str(access.get("id"))) or {}
                context = access_context_for_payload(repo, access).get("fields", {})
                candidates = [enrichment.get("application")]
                source_application = context.get("application", {}).get("source") if isinstance(context.get("application"), dict) else None
                manual_application = context.get("application", {}).get("manual") if isinstance(context.get("application"), dict) else None
                candidates.extend([
                    source_application.get("value") if isinstance(source_application, dict) else None,
                    manual_application.get("value") if isinstance(manual_application, dict) else None,
                ])
                if not any(key(candidate) == wanted for candidate in candidates):
                    continue
                usage_key = (str(version.get("id")), f"{provider}/{access_name}")
                if usage_key in seen:
                    continue
                seen.add(usage_key)
                usages.append({"source": source_name, "version": version.get("version"), "access": f"{provider}/{access_name}"})
        return usages

    @app.get("/api/golden-applications")
    def golden_applications_list(request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            items = []
            for item in repo.list_payloads("golden_applications"):
                usage = _golden_application_usage(repo, str(item.get("name") or ""))
                items.append({**item, "usage_count": len(usage), "usage": usage})
        return {"applications": sorted(items, key=lambda item: str(item.get("name") or "").casefold())}

    @app.put("/api/golden-applications/{application_id}")
    def golden_application_update(application_id: str, request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN",))
        comment = str(payload.get("comment") or "").strip()
        if len(comment) > 4000:
            raise HTTPException(status_code=400, detail="Application comment is limited to 4000 characters")
        with Repository(db_path) as repo:
            record = repo.get_payload("golden_applications", application_id)
            if record is None:
                raise HTTPException(status_code=404, detail="Application not found")
            record = {**record, "comment": comment, "active": bool(payload.get("active", record.get("active", True)))}
            repo.upsert("golden_applications", record)
            record_audit(repo, request, "golden_application.updated", "golden_application", application_id, {"name": record.get("name"), "active": record.get("active")})
            return record

    @app.delete("/api/golden-applications/{application_id}")
    def golden_application_delete(application_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN",))
        with Repository(db_path) as repo:
            record = repo.get_payload("golden_applications", application_id)
            if record is None:
                raise HTTPException(status_code=404, detail="Application not found")
            usage = _golden_application_usage(repo, str(record.get("name") or ""))
            if usage:
                raise HTTPException(status_code=409, detail={"message": "Application is used by Golden Source versions and cannot be deleted", "usage": usage})
            repo.delete_ids("golden_applications", {application_id})
            record_audit(repo, request, "golden_application.deleted", "golden_application", application_id, {"name": record.get("name")})
            return {"deleted": True, "id": application_id}

    @app.post("/api/golden-applications")
    def golden_application_create(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        name = str(payload.get("name") or "").strip()
        comment = str(payload.get("comment") or "").strip()
        if not name or len(name) > 200:
            raise HTTPException(status_code=400, detail="Application name is required and limited to 200 characters")
        if len(comment) > 4000:
            raise HTTPException(status_code=400, detail="Application comment is limited to 4000 characters")
        def key(value: str) -> str:
            return "".join(char for char in unicodedata.normalize("NFKD", value).casefold() if char.isalnum())
        candidate = key(name)
        with Repository(db_path) as repo:
            existing = repo.list_payloads("golden_applications")
            exact = next((item for item in existing if key(str(item.get("name") or "")) == candidate), None)
            if exact:
                raise HTTPException(status_code=409, detail="An application with this name already exists")
            similar = [
                {"name": item.get("name"), "comment": item.get("comment"), "score": round(difflib.SequenceMatcher(None, candidate, key(str(item.get("name") or ""))).ratio(), 2)}
                for item in existing
                if candidate and (candidate in key(str(item.get("name") or "")) or key(str(item.get("name") or "")) in candidate or difflib.SequenceMatcher(None, candidate, key(str(item.get("name") or ""))).ratio() >= 0.62)
            ]
            similar.sort(key=lambda item: item["score"], reverse=True)
            if similar and not bool(payload.get("confirm")):
                return {"created": False, "requires_confirmation": True, "similar": similar[:5]}
            identifier = "app_" + hashlib.sha256((candidate or name).encode("utf-8")).hexdigest()[:24]
            record = {"id": identifier, "name": name, "comment": comment, "created_by": principal.subject, "active": True}
            repo.upsert("golden_applications", record)
            record_audit(repo, request, "golden_application.created", "golden_application", identifier, {"name": name})
            return {"created": True, "application": record}

    @app.get("/api/capabilities")
    def capabilities_list(request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            return {"capabilities": [asdict(item) for item in repo.list_capabilities()]}

    @app.post("/api/system/capabilities")
    def capabilities_save(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN",))
        capability_id = payload.get("id")
        label = payload.get("label")
        description = payload.get("description")
        active = payload.get("active", True)
        if (
            not isinstance(capability_id, str)
            or not capability_id
            or len(capability_id) > 64
            or not capability_id[0].islower()
            or not all(char.islower() or char.isdigit() or char in "_-" for char in capability_id)
        ):
            raise HTTPException(status_code=400, detail="Capability ID must be a stable lowercase identifier")
        if not isinstance(label, str) or not label.strip() or len(label) > 120:
            raise HTTPException(status_code=400, detail="Capability label is required and limited to 120 characters")
        if not isinstance(description, str) or not description.strip() or len(description) > 1000:
            raise HTTPException(status_code=400, detail="Capability description is required and limited to 1000 characters")
        if not isinstance(active, bool):
            raise HTTPException(status_code=400, detail="Capability active must be a boolean")
        with Repository(db_path) as repo:
            existing = next((item for item in repo.list_capabilities() if item.id == capability_id), None)
            if existing is not None and bool(payload.get("system", existing.system)) != existing.system:
                raise HTTPException(status_code=409, detail="Capability type cannot be changed")
            try:
                capability = Capability(
                    id=capability_id,
                    label=label.strip(),
                    description=description.strip(),
                    active=active,
                    system=existing.system if existing else False,
                )
                repo.save_capability(capability)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400 if existing is None else 409, detail=str(exc)
                ) from exc
            record_audit(repo, request, "capability.updated" if existing else "capability.created", "capability", capability.id)
            return {"capability": asdict(capability)}

    @app.get("/api/system/permission-capability-mappings")
    def permission_capability_mappings_list(request: Request):
        _require(current_user(request), ("ADMIN",))
        with Repository(db_path) as repo:
            return {"mappings": [asdict(item) for item in repo.list_permission_capability_mappings()]}

    @app.post("/api/system/permission-capability-mappings")
    def permission_capability_mapping_save(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        provider = payload.get("provider")
        permission = payload.get("permission_identifier")
        capability_ids = payload.get("capability_ids")
        if not isinstance(provider, str) or not provider.strip():
            raise HTTPException(status_code=400, detail="Provider is required")
        if not isinstance(permission, str) or not permission.strip():
            raise HTTPException(status_code=400, detail="Native permission identifier is required")
        if not isinstance(capability_ids, list) or not capability_ids or any(not isinstance(item, str) for item in capability_ids):
            raise HTTPException(status_code=400, detail="Select one or more capability IDs")
        try:
            mapping = PermissionCapabilityMapping(
                provider=provider.strip(),
                permission_identifier=permission.strip(),
                capability_ids=tuple(sorted(set(capability_ids))),
                provenance=Provenance.MAPPED,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        with Repository(db_path) as repo:
            try:
                repo.save_permission_capability_mapping(mapping)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            record_audit(repo, request, "permission_capability_mapping.updated", "permission_capability_mapping", mapping.provider + ":" + mapping.permission_identifier)
            return {"mapping": asdict(mapping)}
    tables = {"providers": "providers", "imports": "imports", "identities": "identities", "accesses": "accesses", "assignments": "access_assignments", "golden-sources": "golden_sources", "golden-source-versions": "golden_source_versions", "snapshots": "snapshots", "campaigns": "campaigns", "review-items": "review_items", "decisions": "decisions", "remediation-actions": "remediation_actions"}
    for path, table in tables.items():
        def route(request: Request, limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None, provider: str | None = None, campaign: str | None = None, action: str | None = None, sort: str | None = None, order: str | None = None, classification: str | None = None, _table: str = table):
            principal = _require(current_user(request))
            require_table_access(principal, _table)
            filters = column_filters(request)
            if action and _table == "remediation_actions":
                filters["action"] = action
            return scoped_page(principal, _table, limit, offset, search, status, provider, campaign, sort, order, classification, filters)
        app.get(f"/api/{path}")(route)

    @app.get("/api/findings")
    def findings(request: Request, limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None, provider: str | None = None, campaign: str | None = None, sort: str | None = None, order: str | None = None):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        if campaign:
            _require_campaign_id_access(principal, campaign)
        snapshot = latest_snapshot(db_path) or {}
        rows = list(snapshot.get("comparison_states", []))
        if principal.role == "OPERATOR" and "*" not in principal.scopes:
            rows = [row for row in rows if str(row.get("access_provider") or "") in principal.scopes and str(row.get("identity_provider") or "") in principal.scopes]
        if campaign:
            with Repository(db_path) as repo:
                campaign_keys = {
                    (
                        item.get("access_provider"),
                        item.get("access_name"),
                        item.get("identity_provider"),
                        item.get("identity_identifier"),
                    )
                    for item in repo.list_payloads("review_items")
                    if item.get("campaign_id") == campaign
                }
                rows = [
                    row for row in rows
                    if (
                        row.get("access_provider"),
                        row.get("access_name"),
                        row.get("identity_provider"),
                        row.get("identity_identifier"),
                    ) in campaign_keys
                ]
        with Repository(db_path) as repo:
            tracking = {
                str(item.get("finding_key")): item
                for item in repo.list_payloads("finding_tracking")
                if not campaign or str(item.get("campaign_id") or "") == campaign
            }
        for row in rows:
            row["finding_tracking"] = tracking.get(_finding_tracking_key(campaign, row), {})
        if status:
            rows = [row for row in rows if row.get("classification") == status]
        if provider:
            rows = [row for row in rows if row.get("access_provider") == provider]
        if search:
            needle = search.casefold()
            rows = [row for row in rows if needle in json.dumps(row, sort_keys=True).casefold()]
        from access_review_engine.web_read_models import apply_field_filters, sorted_rows

        rows = apply_field_filters(rows, column_filters(request))
        rows = sorted_rows(rows, sort or "source_group", order or "asc")
        return {"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset, "sort": sort or "", "order": (order or "asc").lower()}

    @app.patch("/api/findings/tracking")
    def finding_tracking_save(request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        campaign_id = str(payload.get("campaign_id") or "").strip() or None
        row = {key: payload.get(key) for key in ("access_provider", "access_name", "identity_provider", "identity_identifier", "classification")}
        provider = str(row.get("access_provider") or "")
        if not provider or not str(row.get("access_name") or "") or not str(row.get("identity_identifier") or ""):
            raise HTTPException(status_code=400, detail="Finding identity, access and source are required")
        if not principal.can_access(provider):
            raise HTTPException(status_code=403, detail="Source is not authorized")
        if campaign_id:
            _require_campaign_id_access(principal, campaign_id)
        ticket = str(payload.get("ticket") or "").strip()
        comment = str(payload.get("comment") or "").strip()
        if len(ticket) > 300 or len(comment) > 4000:
            raise HTTPException(status_code=400, detail="Ticket or comment is too long")
        finding_key = _finding_tracking_key(campaign_id, row)
        record = {
            "id": finding_key,
            "finding_key": finding_key,
            "campaign_id": campaign_id,
            **row,
            "ticket": ticket,
            "comment": comment,
            "updated_by": principal.username,
            "updated_at": now_utc(),
        }
        with Repository(db_path) as repo:
            repo.upsert("finding_tracking", record)
            record_audit(repo, request, "finding.tracking_updated", "finding", finding_key, {"ticket": bool(ticket), "campaign_id": campaign_id})
        return record

    def _snapshot_covering(provider: str | None) -> dict[str, Any]:
        """The most recent collection that covers this source.

        A collection holds one source, so the latest one overall would hide every
        identity and access belonging to the others.
        """
        with Repository(db_path) as repo:
            snapshots = repo.list_payloads("snapshots")
        if provider:
            for row in reversed(snapshots):
                if any(str(item.get("name")) == provider for item in row.get("providers", [])):
                    return row
        return snapshots[-1] if snapshots else {}

    def _identity_owner(identity_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Find an identity in any collection, and return it with the collection covering it."""
        with Repository(db_path) as repo:
            stored = repo.list_payloads("identities")
        found = next((row for row in stored if str(row.get("id")) == identity_id), None) or next((row for row in stored if str(row.get("identifier")) == identity_id), None)
        if found is None:
            raise HTTPException(status_code=404, detail="Identity not found")
        snapshot = _snapshot_covering(str(found.get("provider")))
        inside = next((row for row in snapshot.get("identities", []) if row.get("id") == found.get("id")), None) or found
        return inside, snapshot

    @app.get("/api/identities/{identity_id}/accesses")
    def identity_accesses(identity_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        identity, snapshot = _identity_owner(identity_id)
        if principal.role != "ADMIN" and not principal.can_access(str(identity.get("provider") or "")):
            raise HTTPException(status_code=403, detail="Scope is not authorized")
        assignments = [row for row in snapshot.get("access_assignments", []) if row.get("identity_provider") == identity.get("provider") and row.get("identity_identifier") == identity.get("identifier")]
        hydrated = hydrate_snapshot(snapshot)
        access_by_key = {(access.provider, access.name): access for access in hydrated.accesses}
        group_names = {
            str(group.identifier or group.native_id or group.id): str(group.display_name or group.identifier)
            for group in hydrated.identities
            if str(group.type).casefold() == "group"
        }

        def access_display(provider: str, name: str) -> str:
            access = access_by_key.get((provider, name))
            display = access.display_name if access else None
            if display and display != name:
                return display
            parts = name.split(":")
            return group_names.get(parts[1], name) if len(parts) >= 2 and parts[0].casefold() == "group" else name

        for assignment in assignments:
            assignment["access_display_name"] = access_display(str(assignment.get("provider") or ""), str(assignment.get("access_name") or ""))
        evaluation = calculate_effective_accesses(hydrated.access_assignments, hydrated.access_relations, hydrated.accesses)
        effective = [
            asdict(item)
            for item in evaluation.effective_accesses
            if item.identity_provider == identity.get("provider")
            and item.identity_identifier == identity.get("identifier")
            and not item.direct
        ]
        for item in effective:
            item["access_display_name"] = access_display(str(item.get("access_provider") or ""), str(item.get("access_name") or ""))
        return {"identity": identity, "accesses": assignments, "effective_accesses": effective, "paths": [path for item in effective for path in item.get("paths", [])]}

    @app.get("/api/accesses/{provider}/{access_name}/holders")
    def access_holders(provider: str, access_name: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        snapshot = _snapshot_covering(provider)
        rows = [row for row in snapshot.get("access_assignments", []) if row.get("provider") == provider and row.get("access_name") == access_name]
        hydrated = hydrate_snapshot(snapshot)
        evaluation = calculate_effective_accesses(hydrated.access_assignments, hydrated.access_relations, hydrated.accesses)
        effective = [
            asdict(item)
            for item in evaluation.effective_accesses
            if item.access_provider == provider
            and item.access_name == access_name
            and not item.direct
        ]
        return {"access": {"provider": provider, "name": access_name}, "holders": rows, "effective_holders": effective, "paths": [path for item in effective for path in item.get("paths", [])]}

    @app.get("/api/accesses/{access_id}/enrichment")
    def get_access_enrichment(access_id: str, request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            access = repo.get_payload("accesses", access_id)
            if access is None:
                raise HTTPException(status_code=404, detail="Access not found")
            provider = str(access.get("provider") or "")
            if principal.role != "ADMIN" and (not provider or not principal.can_access(provider)):
                raise HTTPException(status_code=403, detail="Scope is not authorized")
            return {"access_id": access_id, "enrichment": access_enrichment(repo, access_id), "business_context": access_context_for_payload(repo, access)}

    @app.put("/api/accesses/{access_id}/enrichment")
    def put_access_enrichment(access_id: str, request: Request, payload: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            access = repo.get_payload("accesses", access_id)
            if access is None:
                raise HTTPException(status_code=404, detail="Access not found")
            provider = str(access.get("provider") or "")
            if principal.role != "ADMIN" and (not provider or not principal.can_access(provider)):
                raise HTTPException(status_code=403, detail="Scope is not authorized")
            try:
                enrichment = save_access_enrichment(repo, access_id, payload, principal.subject)
            except ValueError as exc:
                status = 404 if str(exc) == "Access not found" else 400
                raise HTTPException(status_code=status, detail=str(exc)) from exc
            record_audit(repo, request, "access.enrichment_changed", "access", access_id, {"fields": sorted(key for key, value in payload.items() if value not in (None, ""))})
            return {"access_id": access_id, "enrichment": enrichment, "business_context": access_context_for_payload(repo, access)}

    @app.post("/api/sources/{provider}/sync", status_code=202)
    def sync(provider: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        def operation(job_id: str) -> dict[str, Any]:
            config = _load_web_connector(provider)
            secrets_config = secret_environment(config)
            if secrets_config.get("password_file"):
                config.setdefault("credentials", {})["password_file"] = secrets_config["password_file"]
            artifact = Path(db_path).with_name(f".eare-{provider}-{job_id}.zip")
            try:
                update_progress(db_path, job_id, "Collecting read-only source data")
                result = run_exporter(config, artifact)
                if result.returncode:
                    raise RunnerError(result.stderr.strip() or "Collector failed")
                update_progress(db_path, job_id, "Importing and creating snapshot")
                with Repository(db_path) as repo:
                    snapshot = import_file_to_repository(repo, artifact, provider_name=provider, source_config=config)
                    record_audit(repo, request, "source.sync_completed", "snapshot", snapshot.id, {"provider": provider})
                return {"snapshot_id": snapshot.id, "provider": provider}
            finally:
                artifact.unlink(missing_ok=True)
        return create_job(db_path, "sync", operation, context={"provider": provider})

    @app.post("/api/sources/{provider}/preview", status_code=202)
    def source_preview(provider: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        def operation(job_id: str) -> dict[str, Any]:
            artifact = Path(db_path).with_name(f".eare-preview-{provider}-{job_id}.zip")
            try:
                update_progress(db_path, job_id, "Collecting read-only source data")
                config = _load_web_connector(provider)
                secrets_config = secret_environment(config)
                if secrets_config.get("password_file"):
                    config.setdefault("credentials", {})["password_file"] = secrets_config["password_file"]
                result = run_exporter(config, artifact)
                if result.returncode:
                    raise RunnerError(result.stderr.strip() or "Collector failed")
                update_progress(db_path, job_id, "Analysing collected data")
                preview = preview_import(db_path, artifact, provider=provider, source_config=config).as_dict()
                with Repository(db_path) as repo:
                    record_audit(repo, request, "source.preview_completed", "provider", provider)
                return preview
            finally:
                artifact.unlink(missing_ok=True)
        return create_job(db_path, "preview", operation, context={"provider": provider})

    @app.post("/api/sources/{provider}/sync/preview")
    def sync_preview(provider: str, request: Request, input_path: str, classification_rules: str | None = None):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        source_config = None
        config_path = connector_path(provider, connector_directory)
        if config_path.is_file():
            source_config = _load_web_connector(provider)
        return preview_import(db_path, input_path, provider=provider, classification_rules=classification_rules, source_config=source_config).as_dict()

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        try:
            return get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc

    @app.get("/api/jobs/{job_id}/events")
    def job_events(job_id: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        try:
            get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc
        body = "".join(f"event: {event['event']}\ndata: {json.dumps(event)}\n\n" for event in get_events(db_path, job_id))
        return StreamingResponse(iter([body]), media_type="text/event-stream")

    @app.post("/api/review-items/{review_item_id}/decision")
    def decision(review_item_id: str, request: Request, body: dict[str, Any] = Body(...)):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR", "GROUP_OWNER"))
        with Repository(db_path) as repo:
            item_payload = repo.get_payload("review_items", review_item_id)
            if item_payload is None:
                raise HTTPException(status_code=404, detail="Review item not found")
            item = hydrate_review_item(item_payload)
            campaign_payload = repo.get_payload("campaigns", item_payload.get("campaign_id"))
            if campaign_payload is None:
                raise HTTPException(status_code=409, detail="Review item campaign is missing")
            campaign = hydrate_campaign(campaign_payload)
            if principal.role in {"ADMIN", "OPERATOR"}:
                _require_campaign_access(principal, campaign, repo)
            if campaign.status != "open":
                raise HTTPException(status_code=409, detail="Decisions are only allowed for open campaigns")
            if principal.role == "GROUP_OWNER" and (item.reviewer is None or item.reviewer.identity != principal.username):
                raise HTTPException(status_code=403, detail="Review item is not assigned to this user")
            value = body.get("value")
            comment = body.get("comment")
            if not isinstance(value, str) or (comment is not None and not isinstance(comment, str)):
                raise HTTPException(status_code=400, detail="A decision value and optional comment are required")
            try:
                result = create_decision(item, value, comment, principal.subject)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            repo.insert_append_only("decisions", result)
            record_audit(repo, request, "review.decision_recorded", "review_item", item.id, {"decision": result.value})
        return asdict(result)

    def _api_page(limit: int, offset: int) -> tuple[int, int]:
        return max(1, min(limit, 500)), max(0, offset)

    def _api_require_campaign_role(principal: WebPrincipal) -> None:
        if principal.role not in {"ADMIN", "OPERATOR"}:
            raise HTTPException(status_code=403, detail="This role cannot access campaigns")

    def _api_golden_context(repo: Repository, source_id: str):
        payload = repo.get_payload("golden_sources", source_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Golden Source not found")
        source = hydrate_golden_source(payload)
        versions = [
            hydrate_golden_version(row)
            for row in repo.list_payloads("golden_source_versions")
            if str(row.get("golden_source_id")) == source_id
        ]
        active = next((item for item in versions if item.id == source.active_version_id), None)
        return source, versions, active

    def _api_require_golden_access(principal: WebPrincipal, versions) -> None:
        if principal.role not in {"ADMIN", "OPERATOR"}:
            raise HTTPException(status_code=403, detail="This role cannot access Golden Sources")
        providers = {
            provider
            for version in versions
            for assignment in version.assignments
            for provider in (assignment.access_provider, assignment.identity_provider)
            if provider
        }
        if principal.role != "ADMIN" and not can_access_campaign(principal.role, principal.scopes, providers):
            raise HTTPException(status_code=403, detail="Golden Source includes providers outside your authorized domains")

    @app.get("/api/v1/me", tags=["External User API"])
    def external_me(principal: WebPrincipal = Depends(current_api_user)):
        return {
            "id": principal.subject,
            "username": principal.username,
            "display_name": principal.display_name,
            "role": principal.role,
            "authorized_domains": sorted(principal.scopes),
        }

    @app.get("/api/v1/golden-sources", tags=["External User API"])
    def external_golden_sources(principal: WebPrincipal = Depends(current_api_user), limit: int = 100, offset: int = 0, search: str | None = None):
        if principal.role not in {"ADMIN", "OPERATOR"}:
            raise HTTPException(status_code=403, detail="This role cannot access Golden Sources")
        bounded, start = _api_page(limit, offset)
        with Repository(db_path) as repo:
            versions = repo.list_payloads("golden_source_versions")
            items = []
            for payload in repo.list_payloads("golden_sources"):
                source_versions = [hydrate_golden_version(row) for row in versions if str(row.get("golden_source_id")) == str(payload.get("id"))]
                try:
                    _api_require_golden_access(principal, source_versions)
                except HTTPException as exc:
                    if exc.status_code == 403:
                        continue
                    raise
                active = next((row for row in source_versions if row.id == payload.get("active_version_id")), None)
                items.append({
                    "id": payload.get("id"),
                    "name": payload.get("name"),
                    "display_name": payload.get("display_name"),
                    "active_version": ({"id": active.id, "version": active.version, "comment": active.comment, "created_at": active.created_at, "assignment_count": len(active.assignments)} if active else None),
                })
        if search:
            needle = search.casefold()
            items = [row for row in items if needle in f"{row.get('name', '')} {row.get('display_name', '')}".casefold()]
        items.sort(key=lambda row: str(row.get("name") or "").casefold())
        return {"items": items[start:start + bounded], "total": len(items), "limit": bounded, "offset": start}

    @app.get("/api/v1/golden-sources/{source_id}", tags=["External User API"])
    def external_golden_source(source_id: str, principal: WebPrincipal = Depends(current_api_user)):
        with Repository(db_path) as repo:
            source, versions, active = _api_golden_context(repo, source_id)
            _api_require_golden_access(principal, versions)
            active_view = None
            if active is not None:
                active_view = {
                    "id": active.id, "version": active.version, "created_at": active.created_at,
                    "source_type": active.source_type, "comment": active.comment,
                    "assignment_count": len(active.assignments),
                }
            return {"source": asdict(source), "active_version": active_view}

    @app.get("/api/v1/golden-sources/{source_id}/versions", tags=["External User API"])
    def external_golden_versions(source_id: str, principal: WebPrincipal = Depends(current_api_user), limit: int = 100, offset: int = 0):
        bounded, start = _api_page(limit, offset)
        with Repository(db_path) as repo:
            _, versions, _ = _api_golden_context(repo, source_id)
            _api_require_golden_access(principal, versions)
            versions.sort(key=lambda item: item.version, reverse=True)
            rows = [{"id": item.id, "version": item.version, "created_at": item.created_at, "source_type": item.source_type, "comment": item.comment, "assignment_count": len(item.assignments)} for item in versions]
        return {"items": rows[start:start + bounded], "total": len(rows), "limit": bounded, "offset": start}

    @app.get("/api/v1/golden-sources/{source_id}/versions/{version_id}", tags=["External User API"])
    def external_golden_version(source_id: str, version_id: str, principal: WebPrincipal = Depends(current_api_user), limit: int = 100, offset: int = 0):
        bounded, start = _api_page(limit, offset)
        with Repository(db_path) as repo:
            _, versions, _ = _api_golden_context(repo, source_id)
            _api_require_golden_access(principal, versions)
            version = next((item for item in versions if item.id == version_id), None)
            if version is None:
                raise HTTPException(status_code=404, detail="Golden Source version not found")
            assignments = []
            for assignment in sorted(version.assignments, key=lambda item: item.key()):
                row = asdict(assignment)
                annotation = annotation_for_assignment(repo, version.id, assignment)
                row["comment"] = annotation.get("comment") if annotation else None
                assignments.append(row)
            return {
                "version": {"id": version.id, "version": version.version, "created_at": version.created_at, "source_type": version.source_type, "comment": version.comment},
                "assignments": assignments[start:start + bounded],
                "total_assignments": len(assignments), "limit": bounded, "offset": start,
            }

    @app.get("/api/v1/campaigns", tags=["External User API"])
    def external_campaigns(principal: WebPrincipal = Depends(current_api_user), limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None):
        _api_require_campaign_role(principal)
        bounded, start = _api_page(limit, offset)
        with Repository(db_path) as repo:
            allowed = _authorized_campaign_ids(principal, repo)
        page_result = projected_rows(
            db_path, "campaigns", limit=bounded, offset=start,
            allowed_campaign_ids=allowed, search=search, status=status,
        )
        return page_result

    def _external_campaign_view(principal: WebPrincipal, campaign_id: str) -> dict[str, Any]:
        _api_require_campaign_role(principal)
        _require_campaign_id_access(principal, campaign_id)
        page_result = projected_rows(db_path, "campaigns", limit=1, offset=0, filters={"id": campaign_id})
        view = next((row for row in page_result["items"] if row.get("id") == campaign_id), None)
        if view is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        return view

    @app.get("/api/v1/campaigns/{campaign_id}", tags=["External User API"])
    def external_campaign(campaign_id: str, principal: WebPrincipal = Depends(current_api_user)):
        campaign_view = _external_campaign_view(principal, campaign_id)
        return {"campaign": campaign_view}

    @app.get("/api/v1/campaigns/{campaign_id}/summary", tags=["External User API"])
    def external_campaign_summary(campaign_id: str, principal: WebPrincipal = Depends(current_api_user)):
        campaign_view = _external_campaign_view(principal, campaign_id)
        reviews = projected_rows(db_path, "review_items", limit=1, offset=0, campaign=campaign_id)
        return {
            "campaign_id": campaign_id,
            "summary": reviews.get("summary", review_summary([])),
            "reviewer_resolution": campaign_view.get("reviewer_resolution", {"resolved": 0, "unresolved": 0}),
            "campaign": {key: campaign_view.get(key) for key in ("name", "status", "due_at", "opened_at", "closed_at")},
        }

    @app.get("/api/v1/campaigns/{campaign_id}/review-items", tags=["External User API"])
    def external_campaign_review_items(campaign_id: str, principal: WebPrincipal = Depends(current_api_user), limit: int = 100, offset: int = 0):
        if principal.role == "BUSINESS_ADMIN":
            raise HTTPException(status_code=403, detail="This role cannot access campaign reviews")
        if principal.role == "OPERATOR":
            _require_campaign_id_access(principal, campaign_id)
        elif principal.role == "GROUP_OWNER":
            with Repository(db_path) as repo:
                if not any(
                    str(row.get("campaign_id")) == campaign_id
                    and str((row.get("reviewer") or {}).get("identity", "")).casefold() == principal.username.casefold()
                    for row in repo.list_payloads("review_items")
                ):
                    raise HTTPException(status_code=404, detail="Review items not found")
        elif principal.role != "ADMIN":
            raise HTTPException(status_code=403, detail="This role cannot access campaign reviews")
        bounded, start = _api_page(limit, offset)
        result = projected_rows(
            db_path, "review_items", limit=bounded, offset=start, campaign=campaign_id,
            reviewer_username=principal.username if principal.role == "GROUP_OWNER" else None,
        )
        return result

    @app.get("/api/v1/review-items/{review_item_id}", tags=["External User API"])
    def external_review_item(review_item_id: str, principal: WebPrincipal = Depends(current_api_user)):
        if principal.role == "BUSINESS_ADMIN":
            raise HTTPException(status_code=403, detail="This role cannot access review items")
        with Repository(db_path) as repo:
            payload = repo.get_payload("review_items", review_item_id)
            if payload is None:
                raise HTTPException(status_code=404, detail="Review item not found")
            if principal.role == "GROUP_OWNER":
                reviewer = (payload.get("reviewer") or {}).get("identity")
                if str(reviewer or "").casefold() != principal.username.casefold():
                    raise HTTPException(status_code=403, detail="Review item is not assigned to this user")
            elif principal.role == "OPERATOR":
                campaign_payload = repo.get_payload("campaigns", str(payload.get("campaign_id") or ""))
                if campaign_payload is None:
                    raise HTTPException(status_code=409, detail="Review item campaign is missing")
                _require_campaign_access(principal, hydrate_campaign(campaign_payload), repo)
            elif principal.role != "ADMIN":
                raise HTTPException(status_code=403, detail="This role cannot access review items")
            latest = _latest_decisions(repo.list_payloads("decisions"))
            view = review_item_view(repo, payload, latest_decisions=latest, names=_display_names(repo))
            _add_review_provenance(repo, [view])
            return view

    @app.get("/openapi.json", include_in_schema=False)
    def public_openapi():
        schema = dict(app.openapi())
        schema["paths"] = {
            path: {method: operation for method, operation in methods.items() if method == "get"}
            for path, methods in schema.get("paths", {}).items()
            if path.startswith("/api/v1/")
        }
        components = dict(schema.get("components", {}))
        schemas = dict(components.get("schemas", {}))
        referenced: set[str] = set()

        def collect_references(value: Any) -> None:
            if isinstance(value, dict):
                reference = value.get("$ref")
                if isinstance(reference, str) and reference.startswith("#/components/schemas/"):
                    referenced.add(reference.rsplit("/", 1)[-1])
                for child in value.values():
                    collect_references(child)
            elif isinstance(value, list):
                for child in value:
                    collect_references(child)

        collect_references(schema["paths"])
        while True:
            previous = len(referenced)
            for name in tuple(referenced):
                collect_references(schemas.get(name, {}))
            if len(referenced) == previous:
                break
        components["schemas"] = {name: schemas[name] for name in referenced if name in schemas}
        schema["components"] = components
        schema["tags"] = [{"name": "External User API", "description": "Read-only user API authenticated with an EARE API key."}]
        return schema

    @app.get("/swagger", include_in_schema=False, response_class=HTMLResponse)
    def swagger():
        return get_swagger_ui_html(openapi_url="/openapi.json", title="EARE External User API")

    return app
