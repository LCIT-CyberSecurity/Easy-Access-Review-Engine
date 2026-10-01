from __future__ import annotations

from typing import Protocol


class SafetyProvider(Protocol):
    def check_input(self, question: str) -> tuple[str, str, bool]: ...
    def check_output(self, answer: str) -> str: ...
