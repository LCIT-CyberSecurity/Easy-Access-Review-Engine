from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.prompts import SYSTEM_PROMPT
from access_review_engine.chatbot.providers.base import (
    LLMProvider,
    ProviderCapabilities,
    ProviderResult,
    ToolCall,
)


class ProviderError(RuntimeError):
    """Safe application error; raw provider responses never leave this module."""


def _extract_output_text(body: dict[str, Any]) -> str:
    fragments: list[str] = []
    output = body.get("output")
    if not isinstance(output, list):
        return ""
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and part.get("type") == "output_text":
                text = part.get("text")
                if isinstance(text, str):
                    fragments.append(text)
    return "".join(fragments)


class OpenAIProvider(LLMProvider):
    capabilities = ProviderCapabilities(True, True, False)

    def __init__(self, config: ChatbotConfig) -> None:
        self.config = config

    def validate_configuration(self) -> None:
        if not self.config.api_key or not self.config.model:
            raise ProviderError("Chatbot provider is not configured")

    def healthcheck(self) -> bool:
        try:
            self.validate_configuration()
            return True
        except ProviderError:
            return False

    def classify(self, question: str, route: str) -> str:
        # Scope classification intentionally happens locally before any EARE data access.
        from access_review_engine.chatbot.scope import classify

        return classify(question)

    def generate(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ProviderResult:
        self.validate_configuration()
        payload = {
            "model": self.config.model,
            "store": False,
            "max_output_tokens": self.config.max_output_tokens,
            "input": [{"role": "system", "content": SYSTEM_PROMPT}, *messages],
            # Only caller-supplied custom EARE functions are sent. No OpenAI built-ins.
            "tools": tools,
        }
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - fixed official OpenAI HTTPS endpoint
                request, timeout=self.config.timeout_seconds
            ) as response:
                body = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            raise ProviderError("Chatbot provider temporarily unavailable") from exc
        text = _extract_output_text(body)
        calls: list[ToolCall] = []
        output_items: list[dict[str, Any]] = []
        raw_output = body.get("output", [])
        if not isinstance(raw_output, list):
            raise ProviderError("Chatbot returned invalid output")
        for item in raw_output:
            if not isinstance(item, dict):
                raise ProviderError("Chatbot returned invalid output")
            output_items.append(item)
            if item.get("type") != "function_call":
                continue
            try:
                arguments = json.loads(item.get("arguments", "{}"))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ProviderError("Chatbot returned invalid tool arguments") from exc
            if not isinstance(arguments, dict):
                raise ProviderError("Chatbot returned invalid tool arguments")
            calls.append(
                ToolCall(str(item.get("call_id", "")), str(item.get("name", "")), arguments)
            )
        usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
        return ProviderResult(
            text=text,
            tool_calls=tuple(calls),
            usage={
                key: int(value)
                for key, value in usage.items()
                if key in {"input_tokens", "output_tokens"}
            },
            output_items=tuple(output_items),
        )
