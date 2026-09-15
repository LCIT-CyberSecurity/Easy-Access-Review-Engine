from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from access_review_engine.api import create_app


class SpaFallbackMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, index_path: Path):
        super().__init__(app)
        self.index_path = index_path

    async def dispatch(self, request: Request, call_next):
        accepts_html = "text/html" in request.headers.get("accept", "")
        if request.method == "GET" and accepts_html and not request.url.path.startswith(("/api/", "/assets/")):
            return FileResponse(self.index_path, headers={"Cache-Control": "no-cache"})
        return await call_next(request)


def build_app(db_path: str, dist_path: str = "web/dist"):
    app = create_app(db_path)
    dist = Path(dist_path).resolve()
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
    app.add_middleware(SpaFallbackMiddleware, index_path=dist / "index.html")
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the EARE API and WebUI")
    parser.add_argument("--db", default="access-review.db")
    parser.add_argument("--dist", default="web/dist")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(build_app(args.db, args.dist), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
