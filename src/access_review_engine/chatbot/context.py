from __future__ import annotations

from dataclasses import dataclass


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
