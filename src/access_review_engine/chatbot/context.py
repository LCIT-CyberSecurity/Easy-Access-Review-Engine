from __future__ import annotations

import re
from dataclasses import dataclass

_ROUTE_OBJECT = re.compile(r"^/(campaigns|reviews)/([A-Za-z0-9._:-]+)$")
_KNOWN_ROUTES = {
    "/", "/dashboard", "/campaigns", "/reviews", "/golden", "/sources", "/reports", "/actions"
}


def resolve_ui_context(route: str, explicit_object_id: str | None = None) -> UIHints:
    """Normalize a bounded UI hint; never treat it as authorization."""
    clean = route.split("?", 1)[0] if isinstance(route, str) else "/"
    safe_explicit = (
        explicit_object_id
        if isinstance(explicit_object_id, str)
        and re.fullmatch(r"[A-Za-z0-9._:-]+", explicit_object_id)
        else None
    )
    if clean in _KNOWN_ROUTES:
        object_id = (
            safe_explicit
            if safe_explicit and clean in {"/campaigns", "/reviews"}
            else None
        )
        return UIHints(clean, object_id)
    match = _ROUTE_OBJECT.fullmatch(clean)
    if match:
        return UIHints(f"/{match.group(1)}", match.group(2))
    return UIHints("/", None)


@dataclass(frozen=True)
class AuthorizationContext:
    """Server-derived identity; client supplied role/scope values are never accepted."""

    subject: str
    username: str
    role: str
    scopes: frozenset[str]

    def can_access_provider(self, provider: str) -> bool:
        return self.role == "ADMIN" or "*" in self.scopes or provider in self.scopes


@dataclass(frozen=True)
class UIHints:
    route: str = "/"
    object_id: str | None = None
