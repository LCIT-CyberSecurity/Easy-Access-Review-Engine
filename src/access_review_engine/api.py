from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

try:
    from fastapi import Body, FastAPI, HTTPException, Request, Response
    from fastapi.responses import StreamingResponse
except ModuleNotFoundError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment]
    Body = Request = Response = HTTPException = StreamingResponse = None  # type: ignore[assignment,misc]

from access_review_engine.application import import_file_to_repository
from access_review_engine.collector_runner import RunnerError, run_exporter
from access_review_engine.config_loader import load_connector, secret_environment
from access_review_engine.services import create_decision, create_golden_source, golden_diff, golden_version_from_snapshot, promote_snapshot
from access_review_engine.storage import Repository, hydrate_golden_source, hydrate_golden_version, hydrate_review_item, hydrate_snapshot
from access_review_engine.web_jobs import create_job, get_events, get_job, update_progress
from access_review_engine.web_read_models import projected_rows
from access_review_engine.web_use_cases import latest_snapshot, list_payloads, preview_import
from access_review_engine.system_admin import authenticate_user, ensure_bootstrap_user, init_system, list_idps, list_users, upsert_idp, upsert_user


SESSION_COOKIE = "eare_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
ROLES = ("ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN")


@dataclass(frozen=True)
class WebPrincipal:
    subject: str
    role: str
    scopes: frozenset[str]
    username: str = ""
    display_name: str = ""

    def can_access(self, scope: str | None) -> bool:
        return self.role == "ADMIN" or not scope or "*" in self.scopes or scope in self.scopes


def _encode_session(principal: dict[str, Any], secret: bytes) -> str:
    payload = {"sub": principal["subject"], "username": principal["username"], "display_name": principal["display_name"], "role": principal["role"], "scopes": principal["scopes"], "exp": int(time.time()) + SESSION_TTL_SECONDS}
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
        return WebPrincipal(str(payload["sub"]), str(payload["role"]), frozenset(str(item) for item in payload.get("scopes", [])), str(payload.get("username", "")), str(payload.get("display_name", "")))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _require(user: WebPrincipal | None, roles: tuple[str, ...] = (), scope: str | None = None) -> WebPrincipal:
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if roles and user.role not in roles and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Insufficient role")
    if not user.can_access(scope):
        raise HTTPException(status_code=403, detail="Scope is not authorized")
    return user


def create_app(db_path: str | None = None):
    if FastAPI is None:
        raise RuntimeError("Install the 'app' extra to use the REST API")
    db_path = db_path or os.environ.get("EARE_DB_PATH", "access-review.db")
    app = FastAPI(title="Easy Access Review Engine", version="0.3.0")
    system_conn = sqlite3.connect(db_path, check_same_thread=False)
    system_conn.row_factory = sqlite3.Row
    init_system(system_conn)
    ensure_bootstrap_user(system_conn)
    session_secret = os.environ.get("EARE_SESSION_SECRET", "").encode() or secrets.token_bytes(32)

    def current_user(request: Request) -> WebPrincipal | None:
        return _decode_session(request.cookies.get(SESSION_COOKIE), session_secret)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    def page(table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None):
        return projected_rows(db_path, table, limit=max(1, min(limit, 500)), offset=max(0, offset), search=search, status=status, provider=provider)

    def scoped_page(principal: WebPrincipal, table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None):
        result = page(table, limit, offset, search, status, provider)
        if principal.role == "GROUP_OWNER":
            result["items"] = [item for item in result["items"] if (item.get("reviewer") or {}).get("identity") == principal.username]
            result["total"] = len(result["items"])
        return result

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
        principal = authenticate_user(system_conn, username, password)
        if principal is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        response.set_cookie(SESSION_COOKIE, _encode_session(principal, session_secret), httponly=True, secure=os.environ.get("EARE_COOKIE_SECURE") == "1", samesite="strict", max_age=SESSION_TTL_SECONDS, path="/")
        return {"subject": principal["subject"], "username": principal["username"], "display_name": principal["display_name"], "role": principal["role"], "scopes": principal["scopes"]}

    @app.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/auth/session")
    def session(request: Request):
        return asdict(_require(current_user(request)))

    @app.get("/api/me")
    def me(request: Request):
        return asdict(_require(current_user(request)))

    @app.get("/api/system")
    def system_overview(request: Request):
        _require(current_user(request), ("ADMIN",))
        return {"users": list_users(system_conn), "identity_providers": list_idps(system_conn), "roles": sorted(ROLES)}

    @app.post("/api/system/users")
    def system_user_create(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        try:
            return upsert_user(system_conn, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/identity-providers")
    def system_idp_create(request: Request, payload: dict[str, Any] = Body(...)):
        _require(current_user(request), ("ADMIN",))
        try:
            return upsert_idp(system_conn, payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/golden-sources/baseline")
    def create_baseline(request: Request, payload: dict[str, Any] | None = Body(default=None)):
        _require(current_user(request), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            snapshots = repo.list_payloads("snapshots")
            if not snapshots:
                raise HTTPException(status_code=409, detail="No snapshot is available to create a baseline")
            snapshot = hydrate_snapshot(snapshots[-1])
            requested = payload or {}
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
            source.active_version_id = version.id
            repo.upsert("golden_sources", source)
            repo.upsert("golden_source_versions", version)
            return {"source": asdict(source), "version": asdict(version), "snapshot_id": snapshot.id}

    @app.get("/api/golden-sources/{name}/compare")
    def compare_baseline(name: str, request: Request):
        _require(current_user(request))
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
            current = golden_version_from_snapshot(source, snapshot, versions)
            return {"name": name, "active_version": max(versions, key=lambda item: item.version).version, "observed_snapshot_id": snapshot.id, "changes": golden_diff(versions[-1], current)}

    @app.get("/api/golden-sources/{name}/export")
    def export_baseline(name: str, request: Request):
        _require(current_user(request))
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

    @app.get("/api/dashboard")
    def dashboard(request: Request):
        principal = _require(current_user(request), ("ADMIN", "OPERATOR"))
        campaigns = page("campaigns", 500, 0, None, None, None)["items"]
        items = page("review_items", 500, 0, None, None, None)["items"]
        actions = page("remediation_actions", 500, 0, None, None, None)["items"]
        pending = [item for item in items if not item.get("decision")]
        return {"role": principal.role, "metrics": {"campaigns": len(campaigns), "pending_reviews": len(pending), "remediation_actions": len(actions), "findings": sum(bool(item.get("findings")) for item in items)}, "latest_snapshot": latest_snapshot(db_path), "campaigns": campaigns[:3], "attention": []}

    @app.get("/api/campaigns/{campaign_id}")
    def campaign_detail(campaign_id: str, request: Request):
        _require(current_user(request))
        result = page("campaigns", 500, 0, None, None, None)
        campaign = next((item for item in result["items"] if item.get("id") == campaign_id), None)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        reviews = [item for item in page("review_items", 500, 0, None, None, None)["items"] if item.get("campaign_id") == campaign_id]
        findings = [finding for item in reviews for finding in item.get("findings", [])]
        return {"campaign": campaign, "reviews": reviews, "findings": sorted(set(findings))}

    tables = {"providers": "providers", "imports": "imports", "identities": "identities", "accesses": "accesses", "assignments": "access_assignments", "golden-sources": "golden_sources", "golden-source-versions": "golden_source_versions", "snapshots": "snapshots", "campaigns": "campaigns", "review-items": "review_items", "decisions": "decisions", "remediation-actions": "remediation_actions"}
    for path, table in tables.items():
        def route(request: Request, limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None, provider: str | None = None, _table: str = table):
            principal = _require(current_user(request))
            require_table_access(principal, _table)
            return scoped_page(principal, _table, limit, offset, search, status, provider)
        app.get(f"/api/{path}")(route)

    @app.get("/api/findings")
    def findings(request: Request, limit: int = 100, offset: int = 0, status: str | None = None):
        _require(current_user(request))
        snapshot = latest_snapshot(db_path)
        rows = snapshot.get("comparison_states", []) if snapshot else []
        if status:
            rows = [row for row in rows if row.get("classification") == status]
        return {"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset}

    @app.get("/api/identities/{identity_id}/accesses")
    def identity_accesses(identity_id: str, request: Request):
        _require(current_user(request))
        snapshot = latest_snapshot(db_path) or {}
        identities = {f"{item.get('provider')}:{item.get('identifier')}": item for item in snapshot.get("identities", [])}
        identity = next((item for item in snapshot.get("identities", []) if item.get("id") == identity_id), None)
        if identity is None:
            identity = next((item for item in snapshot.get("identities", []) if item.get("identifier") == identity_id), None)
        if identity is None:
            raise HTTPException(status_code=404, detail="Identity not found")
        rows = [row for row in snapshot.get("access_assignments", []) if row.get("identity_provider") == identity.get("provider") and row.get("identity_identifier") == identity.get("identifier")]
        return {"identity": identity, "accesses": rows, "paths": []}

    @app.get("/api/accesses/{provider}/{access_name}/holders")
    def access_holders(provider: str, access_name: str, request: Request):
        _require(current_user(request))
        snapshot = latest_snapshot(db_path) or {}
        rows = [row for row in snapshot.get("access_assignments", []) if row.get("provider") == provider and row.get("access_name") == access_name]
        return {"access": {"provider": provider, "name": access_name}, "holders": rows, "paths": []}

    @app.post("/api/sources/{provider}/sync", status_code=202)
    def sync(provider: str, request: Request):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        def operation(job_id: str) -> dict[str, Any]:
            config = load_connector(provider)
            secrets_config = secret_environment(config)
            if secrets_config.get("password_file"):
                config.setdefault("credentials", {})["password_file"] = secrets_config["password_file"]
            artifact = Path(db_path).with_name(f".eare-{provider}-{job_id}.zip")
            update_progress(db_path, job_id, "Collecting read-only source data")
            result = run_exporter(config, artifact)
            if result.returncode:
                raise RunnerError(result.stderr.strip() or "Collector failed")
            update_progress(db_path, job_id, "Importing and creating snapshot")
            with Repository(db_path) as repo:
                snapshot = import_file_to_repository(repo, artifact, provider_name=provider)
            artifact.unlink(missing_ok=True)
            return {"snapshot_id": snapshot.id, "provider": provider}
        return create_job(db_path, "sync", operation)

    @app.post("/api/sources/{provider}/sync/preview")
    def sync_preview(provider: str, request: Request, input_path: str, classification_rules: str | None = None):
        _require(current_user(request), ("ADMIN", "OPERATOR"), provider)
        return preview_import(db_path, input_path, provider=provider, classification_rules=classification_rules).as_dict()

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str, request: Request):
        _require(current_user(request))
        try:
            return get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc

    @app.get("/api/jobs/{job_id}/events")
    def job_events(job_id: str, request: Request):
        _require(current_user(request))
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
        return asdict(result)

    return app
