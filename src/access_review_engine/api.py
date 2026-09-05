from __future__ import annotations

try:
    from fastapi import FastAPI, Query
except ModuleNotFoundError:  # pragma: no cover - optional runtime dependency
    FastAPI = None  # type: ignore[assignment]
    Query = None  # type: ignore[assignment]

from access_review_engine.storage import Repository


def create_app(db_path: str = "access-review.db"):
    if FastAPI is None:
        raise RuntimeError("Install the 'app' extra to use the REST API")
    app = FastAPI(title="Easy Access Review Engine")

    def page(table: str, limit: int, offset: int) -> dict[str, object]:
        rows = Repository(db_path).list_payloads(table)
        return {"items": rows[offset : offset + limit], "total": len(rows), "limit": limit, "offset": offset}

    @app.get("/providers")
    def providers(limit: int = 100, offset: int = 0):
        return page("providers", limit, offset)

    @app.get("/imports")
    def imports(limit: int = 100, offset: int = 0):
        return page("imports", limit, offset)

    @app.get("/identities")
    def identities(limit: int = 100, offset: int = 0):
        return page("identities", limit, offset)

    @app.get("/accesses")
    def accesses(limit: int = 100, offset: int = 0):
        return page("accesses", limit, offset)

    @app.get("/assignments")
    def assignments(limit: int = 100, offset: int = 0):
        return page("access_assignments", limit, offset)

    @app.get("/findings")
    def findings(limit: int = 100, offset: int = 0):
        rows = Repository(db_path).list_payloads("snapshots")
        states = rows[-1]["comparison_states"] if rows else []
        return {"items": states[offset : offset + limit], "total": len(states)}

    @app.get("/golden-sources")
    def golden_sources(limit: int = 100, offset: int = 0):
        return page("golden_sources", limit, offset)

    @app.get("/golden-source-versions")
    def golden_source_versions(limit: int = 100, offset: int = 0):
        return page("golden_source_versions", limit, offset)

    @app.get("/snapshots")
    def snapshots(limit: int = 100, offset: int = 0):
        return page("snapshots", limit, offset)

    @app.get("/campaigns")
    def campaigns(limit: int = 100, offset: int = 0):
        return page("campaigns", limit, offset)

    @app.get("/review-items")
    def review_items(limit: int = 100, offset: int = 0):
        return page("review_items", limit, offset)

    @app.get("/decisions")
    def decisions(limit: int = 100, offset: int = 0):
        return page("decisions", limit, offset)

    @app.get("/remediation")
    def remediation(limit: int = 100, offset: int = 0):
        return page("remediation_actions", limit, offset)

    return app
