"""Authentication posture normalization and expected/observed assessment."""
from __future__ import annotations

from typing import Any

from access_review_engine.domain import AuthenticationPosture, AuthenticationStatus


def compare_authentication_posture(
    expected: AuthenticationPosture | None,
    observed: AuthenticationPosture | None,
) -> list[dict[str, Any]]:
    if expected is None:
        return []
    rows: list[dict[str, Any]] = []
    for control_name, expected_control in expected.controls.items():
        observed_control = (observed.controls.get(control_name) if observed else None) or {}
        fields = _expected_fields(expected_control)
        if not fields:
            fields = [(control_name, expected_control.get("expected", expected_control.get("value")), expected_control)]
        status = str(observed_control.get("status", AuthenticationStatus.NOT_COLLECTED))
        for field_name, expected_value, constraint in fields:
            observed_value = observed_control.get(field_name)
            if field_name == control_name and observed_value is None:
                observed_value = observed_control.get("observed", observed_control.get("value"))
            if observed_value is None and status != str(AuthenticationStatus.COLLECTED):
                observed_value = status
            assessment = _assessment(constraint, observed_control, status, expected_value, observed_value)
            rows.append({"control": field_name if field_name != control_name else control_name, "expected": expected_value, "observed": observed_value, "assessment": assessment})
    return rows


def _expected_fields(control: dict[str, Any]) -> list[tuple[str, Any, dict[str, Any]]]:
    fields = []
    for name, value in control.items():
        if name in {"status", "expected", "observed", "value", "operator"}:
            continue
        if isinstance(value, dict) and ("value" in value or "expected" in value or "operator" in value):
            fields.append((name, value.get("expected", value.get("value")), value))
        else:
            fields.append((name, value, {"operator": "eq"}))
    return fields


def _assessment(expected: dict[str, Any], observed: dict[str, Any], status: str, expected_value: Any, observed_value: Any) -> str:
    if status in {AuthenticationStatus.NOT_CONFIGURED, AuthenticationStatus.NOT_SUPPORTED}:
        return "unknown"
    if status in {AuthenticationStatus.NOT_COLLECTED, AuthenticationStatus.UNKNOWN} or not observed:
        return "not_collected"
    if status == AuthenticationStatus.ERROR:
        return "unknown"
    if expected_value is None or observed_value is None:
        return "unknown"
    operator = expected.get("operator", "eq")
    try:
        if operator == "gte":
            return "compliant" if observed_value >= expected_value else "deviation"
        if operator == "lte":
            return "compliant" if observed_value <= expected_value else "deviation"
        return "compliant" if observed_value == expected_value else "deviation"
    except TypeError:
        return "unknown"
