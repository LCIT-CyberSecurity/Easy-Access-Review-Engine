from __future__ import annotations

import re

_SECRET = re.compile(
    r"Bearer\s+[A-Za-z0-9._~+/=-]+|-----BEGIN\s+(?:RSA|EC|OPENSSH|PRIVATE)\s+KEY-----|"
    r"(?:api[_ -]?key|client[_ -]?secret|password|token)\s*[:=]\s*[^\s,;]+",
    re.IGNORECASE,
)


def redact_secrets(value: str) -> tuple[str, bool]:
    return _SECRET.sub("[REDACTED]", value), bool(_SECRET.search(value))
