from __future__ import annotations

import io
import json
import urllib.error

import pytest
from access_review_engine.chatbot.config import ChatbotConfig
from access_review_engine.chatbot.providers.openai import (
    OpenAIProvider,
    ProviderError,
    _openai_tools,
)


def _provider() -> OpenAIProvider:
    return OpenAIProvider(ChatbotConfig(enabled=True, api_key="test-key", model="test-model"))


@pytest.mark.parametrize(
    ("status", "category"),
    [
        (401, "authentication_error"),
        (403, "permission_denied"),
        (429, "rate_limited"),
        (500, "provider_error"),
    ],
)
def test_openai_provider_categorizes_http_errors(monkeypatch, status, category):
    def fail(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            status,
            "provider failure",
            {},
            io.BytesIO(b'{"error":"redacted"}'),
        )

    monkeypatch.setattr("urllib.request.urlopen", fail)
    with pytest.raises(ProviderError) as caught:
        _provider().generate([], [])
    assert caught.value.category == category
    assert "test-key" not in str(caught.value)


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (TimeoutError(), "timeout"),
        (urllib.error.URLError("dns"), "network_error"),
    ],
)
def test_openai_provider_categorizes_transport_errors(monkeypatch, error, category):
    def fail(request, timeout):
        raise error

    monkeypatch.setattr("urllib.request.urlopen", fail)
    with pytest.raises(ProviderError) as caught:
        _provider().generate([], [])
    assert caught.value.category == category


def test_openai_provider_rejects_invalid_json(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"not-json"

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: Response())
    with pytest.raises(ProviderError) as caught:
        _provider().generate([], [])
    assert caught.value.category == "invalid_response"


def test_openai_provider_rejects_invalid_tool_arguments(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return (
                b'{"output":[{"type":"function_call","call_id":"c",'
                b'"name":"x","arguments":"not-json"}]}'
            )

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: Response())
    with pytest.raises(ProviderError) as caught:
        _provider().generate([], [])
    assert caught.value.category == "invalid_tool_response"


def test_provider_healthcheck_is_real_small_and_bounded(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(
                {
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "output_text", "text": "OK"}],
                        }
                    ]
                }
            ).encode()

    def succeed(request, timeout):
        captured["payload"] = json.loads(request.data)
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", succeed)
    health = _provider().healthcheck()
    assert health.ok is True
    assert health.category == "ok"
    assert captured["payload"]["max_output_tokens"] == 16
    assert captured["payload"]["store"] is False
    assert captured["payload"]["input"] == [{"role": "user", "content": "Reply with OK."}]


def test_openai_strict_adapter_requires_nullable_optional_fields_without_mutation():
    tool = {
        "type": "function",
        "name": "search",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    }
    adapted = _openai_tools([tool])[0]
    assert adapted["parameters"]["required"] == ["query", "limit"]
    assert adapted["parameters"]["properties"]["limit"]["type"] == ["integer", "null"]
    assert tool["parameters"]["required"] == ["query"]
