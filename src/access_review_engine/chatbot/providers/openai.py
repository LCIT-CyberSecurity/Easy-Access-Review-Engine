from __future__ import annotations

import json
import urllib.error
import urllib.request
from copy import deepcopy
from typing import Any

from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.prompts import SYSTEM_PROMPT
from access_review_engine.chatbot.providers.base import (
    LLMProvider,
    ProviderCapabilities,
    ProviderHealth,
    ProviderResult,
    ToolCall,
)


class ProviderError(RuntimeError):
    """Safe application error; raw provider responses never leave this module."""

    def __init__(self, message: str, category: str = "provider_error") -> None:
        super().__init__(message)
        self.category = category


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


def _nullable(schema: dict[str, Any]) -> None:
    raw_type = schema.get("type")
    if isinstance(raw_type, str):
        schema["type"] = [raw_type, "null"]
    elif isinstance(raw_type, list) and "null" not in raw_type:
        schema["type"] = [*raw_type, "null"]
    raw_enum = schema.get("enum")
    if isinstance(raw_enum, list) and None not in raw_enum:
        schema["enum"] = [*raw_enum, None]


def _strict_object_schema(schema: dict[str, Any]) -> None:
    raw_type = schema.get("type")
    is_object = raw_type == "object" or (
        isinstance(raw_type, list) and "object" in raw_type
    )
    if is_object:
        properties = schema.get("properties")
        if isinstance(properties, dict):
            originally_required = set(schema.get("required", []))
            for name, value in properties.items():
                if isinstance(value, dict):
                    if name not in originally_required:
                        _nullable(value)
                    _strict_object_schema(value)
            schema["required"] = list(properties)
            schema["additionalProperties"] = False
    items = schema.get("items")
    if isinstance(items, dict):
        _strict_object_schema(items)


def _openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Adapt optional EARE schemas to OpenAI strict-mode nullable required fields."""
    result = deepcopy(tools)
    for tool in result:
        if tool.get("strict") is not True:
            continue
        parameters = tool.get("parameters")
        if isinstance(parameters, dict):
            _strict_object_schema(parameters)
    return result


class OpenAIProvider(LLMProvider):
    capabilities = ProviderCapabilities(True, True, False)

    def __init__(self, config: ChatbotConfig) -> None:
        self.config = config

    def validate_configuration(self) -> None:
        if not self.config.api_key or not self.config.model:
            raise ProviderError(
                "Chatbot provider is not configured", category="authentication_error"
            )

    def healthcheck(self) -> ProviderHealth:
        try:
            result = self._request(
                [{"role": "user", "content": "Reply with OK."}],
                [],
                max_output_tokens=16,
                include_system_prompt=False,
            )
            if not result.text.strip():
                return ProviderHealth(False, "invalid_response")
            return ProviderHealth(True, "ok")
        except ProviderError as exc:
            return ProviderHealth(False, exc.category)

    def classify(self, question: str, route: str) -> str:
        # Scope classification intentionally happens locally before any EARE data access.
        from access_review_engine.chatbot.scope import classify

        return classify(question)

    def generate(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ProviderResult:
        return self._request(messages, tools, max_output_tokens=self.config.max_output_tokens)

    def _request(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_output_tokens: int,
        include_system_prompt: bool = True,
    ) -> ProviderResult:
        self.validate_configuration()
        payload = {
            "model": self.config.model,
            "store": False,
            "max_output_tokens": max_output_tokens,
            "input": (
                [{"role": "system", "content": SYSTEM_PROMPT}, *messages]
                if include_system_prompt
                else messages
            ),
            # Only caller-supplied custom EARE functions are sent. No OpenAI built-ins.
            "tools": _openai_tools(tools),
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
                try:
                    body = json.load(response)
                except (TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise ProviderError(
                        "Chatbot provider returned an invalid response",
                        category="invalid_response",
                    ) from exc
        except urllib.error.HTTPError as exc:
            category = {
                401: "authentication_error",
                403: "permission_denied",
                429: "rate_limited",
            }.get(exc.code, "provider_error")
            raise ProviderError("Chatbot provider request failed", category=category) from exc
        except TimeoutError as exc:
            raise ProviderError("Chatbot provider timed out", category="timeout") from exc
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            raise ProviderError("Chatbot provider network error", category="network_error") from exc
        if not isinstance(body, dict):
            raise ProviderError(
                "Chatbot provider returned an invalid response", category="invalid_response"
            )
        text = _extract_output_text(body)
        calls: list[ToolCall] = []
        output_items: list[dict[str, Any]] = []
        raw_output = body.get("output", [])
        if not isinstance(raw_output, list):
            raise ProviderError("Chatbot returned invalid output", category="invalid_response")
        for item in raw_output:
            if not isinstance(item, dict):
                raise ProviderError("Chatbot returned invalid output", category="invalid_response")
            output_items.append(item)
            if item.get("type") != "function_call":
                continue
            try:
                arguments = json.loads(item.get("arguments", "{}"))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ProviderError(
                    "Chatbot returned invalid tool arguments",
                    category="invalid_tool_response",
                ) from exc
            if not isinstance(arguments, dict):
                raise ProviderError(
                    "Chatbot returned invalid tool arguments",
                    category="invalid_tool_response",
                )
            calls.append(
                ToolCall(str(item.get("call_id", "")), str(item.get("name", "")), arguments)
            )
        raw_usage = body.get("usage")
        usage: dict[str, Any] = raw_usage if isinstance(raw_usage, dict) else {}
        try:
            safe_usage = {
                key: int(value)
                for key, value in usage.items()
                if key in {"input_tokens", "output_tokens"}
            }
        except (TypeError, ValueError) as exc:
            raise ProviderError(
                "Chatbot provider returned invalid usage", category="invalid_response"
            ) from exc
        return ProviderResult(
            text=text,
            tool_calls=tuple(calls),
            usage=safe_usage,
            output_items=tuple(output_items),
        )
