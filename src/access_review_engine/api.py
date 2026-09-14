from __future__ import annotations

from dataclasses import asdict, dataclass
import csv
import io
import json
import sqlite3
from pathlib import Path
from typing import Any

try:
    from fastapi import Body, FastAPI, Header, HTTPException
    from fastapi.responses import StreamingResponse
except ModuleNotFoundError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment]
    Body = Header = HTTPException = StreamingResponse = None  # type: ignore[assignment,misc]

from access_review_engine.application import import_file_to_repository
from access_review_engine.collector_runner import RunnerError, run_exporter
from access_review_engine.config_loader import load_connector, secret_environment
from access_review_engine.services import create_decision, create_golden_source, golden_diff, promote_snapshot
from access_review_engine.storage import Repository, hydrate_golden_source, hydrate_golden_version, hydrate_review_item, hydrate_snapshot
from access_review_engine.web_jobs import create_job, get_events, get_job, update_progress
from access_review_engine.web_use_cases import latest_snapshot, list_payloads, preview_import
from access_review_engine.system_admin import init_system, list_idps, list_users, run_openldap_tests, upsert_idp, upsert_user


@dataclass(frozen=True)
class WebPrincipal:
    subject: str
    role: str
    scopes: frozenset[str]

    def can_access(self, scope: str | None) -> bool:
        return self.role == "ADMIN" or not scope or "*" in self.scopes or scope in self.scopes


def _principal(role: str | None, scopes: str | None) -> WebPrincipal:
    normalized = (role or "ADMIN").upper()
    if normalized not in {"ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN"}:
        raise HTTPException(status_code=403, detail="Unsupported role")
    return WebPrincipal("header-user", normalized, frozenset(filter(None, (scopes or "*").split(","))))


def _require(user: WebPrincipal, roles: tuple[str, ...] = (), scope: str | None = None) -> None:
    if roles and user.role not in roles and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Insufficient role")
    if not user.can_access(scope):
        raise HTTPException(status_code=403, detail="Scope is not authorized")


def create_app(db_path: str = "access-review.db"):
    if FastAPI is None:
        raise RuntimeError("Install the 'app' extra to use the REST API")
    app = FastAPI(title="Easy Access Review Engine", version="0.2.0")
    system_conn = sqlite3.connect(db_path, check_same_thread=False)
    system_conn.row_factory = sqlite3.Row
    init_system(system_conn)

    def user(role: str | None, scopes: str | None) -> WebPrincipal:
        return _principal(role, scopes)

    def page(table: str, limit: int, offset: int, search: str | None, status: str | None, provider: str | None):
        return list_payloads(db_path, table, limit=max(1, min(limit, 500)), offset=max(0, offset), search=search, status=status, provider=provider)

    @app.get("/api/system")
    def system_overview(x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN",))
        return {"users": list_users(system_conn), "identity_providers": list_idps(system_conn), "roles": sorted({"ADMIN", "OPERATOR", "GROUP_OWNER", "BUSINESS_ADMIN"})}

    @app.post("/api/system/users")
    def system_user_create(payload: dict[str, Any] = Body(...), x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN",))
        try: return upsert_user(system_conn, payload)
        except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/identity-providers")
    def system_idp_create(payload: dict[str, Any] = Body(...), x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN",))
        try: return upsert_idp(system_conn, payload)
        except ValueError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/system/tests/openldap")
    def system_openldap_test(x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN",))
        return run_openldap_tests(str(Path(__file__).resolve().parents[2]))

    @app.post("/api/golden-sources/baseline")
    def create_baseline(payload: dict[str, Any] | None = Body(default=None), x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN", "OPERATOR"))
        with Repository(db_path) as repo:
            snapshots = repo.list_payloads("snapshots")
            if not snapshots:
                raise HTTPException(status_code=409, detail="No snapshot is available to create a baseline")
            snapshot = hydrate_snapshot(snapshots[-1])
            requested = payload or {}
            name = str(requested.get("name") or "crashtests-crm").strip()
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
    def compare_baseline(name: str, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes))
        with Repository(db_path) as repo:
            source_payload = repo.find_by_name("golden_sources", name)
            if not source_payload:
                raise HTTPException(status_code=404, detail="Golden Source not found")
            source = hydrate_golden_source(source_payload)
            versions = [hydrate_golden_version(row) for row in repo.list_payloads("golden_source_versions") if row.get("golden_source_id") == source.id]
            snapshots = repo.list_payloads("snapshots")
            if not versions or not snapshots:
                raise HTTPException(status_code=409, detail="Baseline and snapshot are required for comparison")
            current = promote_snapshot(source, hydrate_snapshot(snapshots[-1]), versions)
            return {"name": name, "current_version": current.version, "changes": golden_diff(versions[-1], current)}

    @app.get("/api/golden-sources/{name}/export")
    def export_baseline(name: str, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes))
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

    @app.get("/api/me")
    def me(x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        return asdict(user(x_eare_role, x_eare_scopes))

    @app.get("/api/dashboard")
    def dashboard(x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        current = user(x_eare_role, x_eare_scopes)
        _require(current)
        campaigns = page("campaigns", 500, 0, None, None, None)["items"]
        items = page("review_items", 500, 0, None, None, None)["items"]
        actions = page("remediation_actions", 500, 0, None, None, None)["items"]
        return {"role": current.role, "metrics": {"campaigns": len(campaigns), "pending_reviews": len(items), "remediation_actions": len(actions), "anomalies": sum(bool(item.get("findings")) for item in items)}, "latest_snapshot": latest_snapshot(db_path)}

    tables = {"providers": "providers", "imports": "imports", "identities": "identities", "accesses": "accesses", "assignments": "access_assignments", "golden-sources": "golden_sources", "golden-source-versions": "golden_source_versions", "snapshots": "snapshots", "campaigns": "campaigns", "review-items": "review_items", "decisions": "decisions", "remediation": "remediation_actions"}
    for path, table in tables.items():
        def route(limit: int = 100, offset: int = 0, search: str | None = None, status: str | None = None, provider: str | None = None, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None), _table: str = table):
            _require(user(x_eare_role, x_eare_scopes))
            return page(_table, limit, offset, search, status, provider)
        app.get(f"/api/{path}")(route)
        app.get(f"/{path}")(route)

    @app.get("/api/findings")
    def findings(limit: int = 100, offset: int = 0, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes))
        snapshot = latest_snapshot(db_path)
        rows = snapshot.get("comparison_states", []) if snapshot else []
        return {"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset}

    @app.post("/api/sources/{provider}/sync", status_code=202)
    def sync(provider: str, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN", "OPERATOR"), provider)
        def operation(job_id: str) -> dict[str, Any]:
            config = load_connector(provider)
            secrets = secret_environment(config)
            if secrets.get("password_file"):
                config.setdefault("credentials", {})["password_file"] = secrets["password_file"]
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
    def sync_preview(provider: str, input_path: str, classification_rules: str | None = None, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN", "OPERATOR"), provider)
        return preview_import(db_path, input_path, provider=provider, classification_rules=classification_rules).as_dict()

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes))
        try:
            return get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc

    @app.get("/api/jobs/{job_id}/events")
    def job_events(job_id: str, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes))
        try:
            get_job(db_path, job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc
        body = "".join(f"event: {event['event']}\ndata: {json.dumps(event)}\n\n" for event in get_events(db_path, job_id))
        return StreamingResponse(iter([body]), media_type="text/event-stream")

    @app.post("/api/review-items/{review_item_id}/decision")
    def decision(review_item_id: str, value: str, comment: str | None = None, x_eare_role: str | None = Header(default=None), x_eare_scopes: str | None = Header(default=None)):
        _require(user(x_eare_role, x_eare_scopes), ("ADMIN", "OPERATOR", "GROUP_OWNER"))
        with Repository(db_path) as repo:
            payload = repo.get_payload("review_items", review_item_id)
            if payload is None:
                raise HTTPException(status_code=404, detail="Review item not found")
            result = create_decision(hydrate_review_item(payload), value, comment, "header-user")
            repo.insert_append_only("decisions", result)
        return asdict(result)

    return app
