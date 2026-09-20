"""Bounded, read-only inspection of configured AD and OpenLDAP sources."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from access_review_engine.collector_runner import exporter_root
from access_review_engine.connector_capabilities import connector_capabilities
from access_review_engine.config_loader import secret_environment
from access_review_engine.source_mapping import (
    canonical_attribute_name,
    default_attribute_candidates,
    is_safe_attribute,
    required_mapping_attributes,
)


MAX_PAGE_SIZE = 100
MAX_OFFSET = 500
MAX_OUTPUT_BYTES = 2_000_000
MAX_VALUE_LENGTH = 500
DISCOVERY_SAMPLE_SIZE = 50
_SENSITIVE_PARTS = (
    "password",
    "unicodepwd",
    "supplementalcredentials",
    "authpassword",
    "token",
    "secret",
    "privatekey",
    "apikey",
    "credential",
)

Runner = Callable[[list[str], dict[str, str], int], subprocess.CompletedProcess[str]]


class SourceInspectorError(RuntimeError):
    """The read-only inspector could not safely complete its bounded query."""


def source_object_kinds(config: dict[str, Any]) -> list[dict[str, str]]:
    _kind(config)
    return [
        {"kind": "user", "display_name": "Users / identities"},
        {"kind": "group", "display_name": "Groups / access objects"},
    ]


def search_source_objects(
    config: dict[str, Any],
    object_kind: str,
    search: str = "",
    limit: int = 25,
    offset: int = 0,
    runner: Runner | None = None,
) -> dict[str, Any]:
    object_kind = _object_kind(object_kind)
    bounded_limit = max(1, min(int(limit), MAX_PAGE_SIZE))
    bounded_offset = max(0, min(int(offset), MAX_OFFSET))
    rows = _query(
        config,
        object_kind,
        search=search,
        limit=bounded_offset + bounded_limit + 1,
        runner=runner,
    )
    page = rows[bounded_offset : bounded_offset + bounded_limit]
    return {
        "items": [_summary(row, object_kind) for row in page],
        "limit": bounded_limit,
        "offset": bounded_offset,
        "has_more": len(rows) > bounded_offset + bounded_limit,
    }


def get_source_object(
    config: dict[str, Any],
    object_kind: str,
    identifier: str,
    runner: Runner | None = None,
) -> dict[str, Any]:
    object_kind = _object_kind(object_kind)
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 1000:
        raise SourceInspectorError("A valid source object identifier is required")
    rows = _query(config, object_kind, identifier=identifier.strip(), limit=2, runner=runner)
    if not rows:
        raise SourceInspectorError("Source object not found")
    row = rows[0]
    summary = _summary(row, object_kind)
    return {
        **summary,
        "attributes": _safe_attributes(row.get("attributes", {})),
    }


def discover_source_attributes(
    config: dict[str, Any],
    object_kind: str = "group",
    runner: Runner | None = None,
) -> dict[str, dict[str, object]]:
    object_kind = _object_kind(object_kind)
    if not connector_capabilities(_kind(config)).safe_attribute_sampling:
        raise SourceInspectorError("Connector does not support safe attribute sampling")
    rows = _query(
        config,
        object_kind,
        limit=DISCOVERY_SAMPLE_SIZE,
        discover=True,
        runner=runner,
    )
    population = max(1, len(rows))
    connector_type = _kind(config)
    display_names = {
        name.casefold(): name for name in default_attribute_candidates(connector_type)
    }
    for name in required_mapping_attributes(config, connector_type):
        display_names[name.casefold()] = name
    values: dict[str, list[str]] = {key: [] for key in display_names}
    populated_objects: dict[str, set[int]] = {key: set() for key in display_names}
    for index, row in enumerate(rows):
        attributes = _safe_attributes(row.get("attributes", {}))
        for name, raw_values in attributes.items():
            key = name.casefold()
            display_names[key] = name
            clean_values = [value for value in raw_values if value]
            if not clean_values:
                continue
            populated_objects.setdefault(key, set()).add(index)
            samples = values.setdefault(key, [])
            for value in clean_values:
                if value not in samples and len(samples) < 3:
                    samples.append(value)
    result = {}
    for key, name in sorted(display_names.items(), key=lambda item: item[1].casefold()):
        count = len(populated_objects.get(key, set()))
        result[name] = {
            "coverage": round(count / population * 100),
            "populated": count,
            "sampled": len(rows),
            "samples": values.get(key, []),
            "mappable": is_safe_attribute(connector_type, name),
        }
    return result


def _query(
    config: dict[str, Any],
    object_kind: str,
    *,
    search: str = "",
    identifier: str | None = None,
    limit: int,
    discover: bool = False,
    runner: Runner | None,
) -> list[dict[str, Any]]:
    if len(search) > 200:
        raise SourceInspectorError("Source search is too long")
    kind = _kind(config)
    if kind == "active_directory":
        return _query_ad(config, object_kind, search, identifier, limit, discover, runner)
    return _query_openldap(config, object_kind, search, identifier, limit, discover, runner)


def _query_ad(
    config: dict[str, Any],
    object_kind: str,
    search: str,
    identifier: str | None,
    limit: int,
    discover: bool,
    runner: Runner | None,
) -> list[dict[str, Any]]:
    connection = _mapping(config.get("connection"), "connection")
    collection = _mapping(config.get("collection", {}), "collection")
    attributes = set(default_attribute_candidates("active_directory"))
    attributes.update(required_mapping_attributes(config, "active_directory"))
    command = [
        "pwsh",
        str(exporter_root() / "exporters/active-directory/inspect-active-directory.ps1"),
        "-Server",
        str(connection.get("server", "")),
        "-Kind",
        object_kind,
        "-Limit",
        str(min(limit, MAX_OFFSET + MAX_PAGE_SIZE + 1)),
        "-Attributes",
        ",".join(sorted(attributes, key=str.casefold)),
    ]
    if search:
        command.extend(["-Search", search])
    if identifier:
        command.extend(["-Identifier", identifier])
    if discover:
        command.append("-Discover")
    result = (runner or _run)(command, os.environ.copy(), _timeout(collection))
    return _json_rows(result)


def _query_openldap(
    config: dict[str, Any],
    object_kind: str,
    search: str,
    identifier: str | None,
    limit: int,
    discover: bool,
    runner: Runner | None,
) -> list[dict[str, Any]]:
    connection = _mapping(config.get("connection"), "connection")
    collection = _mapping(config.get("collection", {}), "collection")
    uri = str(connection.get("uri", ""))
    base_dn = str(connection.get("base_dn", ""))
    classes = (
        "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))"
        if object_kind == "user"
        else "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"
    )
    ldap_filter = classes
    scope = "sub"
    if identifier:
        if identifier.startswith("dn:"):
            requested_dn = identifier[3:].strip()
            normalized_dn = requested_dn.casefold().replace(" ", "")
            normalized_base = base_dn.casefold().replace(" ", "")
            if normalized_dn != normalized_base and not normalized_dn.endswith("," + normalized_base):
                raise SourceInspectorError("Source object is outside the configured base DN")
            base_dn = requested_dn
            scope = "base"
            ldap_filter = "(objectClass=*)"
        else:
            ldap_filter = f"(&{classes}(entryUUID={_escape_filter(identifier)}))"
    elif search:
        needle = _escape_filter(search)
        ldap_filter = f"(&{classes}(|(cn=*{needle}*)(uid=*{needle}*)(mail=*{needle}*)))"
    attributes = {"entryUUID", "cn", "uid", "description", "owner", "dn"}
    attributes.update(default_attribute_candidates("openldap"))
    attributes.update(required_mapping_attributes(config, "openldap"))
    # Discovery samples only safe known/configured business attributes. Requesting "*"
    # would download secrets, binary values and potentially huge operational attributes.
    selected = sorted(attributes, key=str.casefold)
    command = [
        "ldapsearch",
        "-LLL",
        "-x",
        "-H",
        uri,
        "-b",
        base_dn,
        "-s",
        scope,
        "-z",
        str(min(limit, MAX_OFFSET + MAX_PAGE_SIZE + 1)),
        "-o",
        f"nettimeout={max(1, min(int(collection.get('connection_timeout', 10)), 60))}",
        "-l",
        str(max(1, min(int(collection.get("search_timeout", 30)), 120))),
    ]
    if str(connection.get("start_tls", "")).lower() in {"1", "true", "yes", "on"}:
        command.append("-ZZ")
    bind_dn = str(connection.get("bind_dn", "")).strip()
    if bind_dn:
        command.extend(["-D", bind_dn])
    command.extend([ldap_filter, *selected])
    result = _run_openldap(config, command, _timeout(collection), runner)
    entries = _parse_ldif(result.stdout)
    return [_ldap_row(entry, object_kind) for entry in entries]


def _run_openldap(
    config: dict[str, Any],
    command: list[str],
    timeout: int,
    runner: Runner | None,
) -> subprocess.CompletedProcess[str]:
    try:
        secrets = secret_environment(config)
    except ValueError as exc:
        raise SourceInspectorError("Source credentials are not configured") from exc
    connection = _mapping(config.get("connection"), "connection")
    bind_dn = str(connection.get("bind_dn", "")).strip()
    if bind_dn and not secrets.get("password") and not secrets.get("password_file"):
        raise SourceInspectorError("Source credentials are not configured")
    if runner is not None:
        return _checked_result(runner(command, os.environ.copy(), timeout))
    with tempfile.TemporaryDirectory(prefix="eare-source-inspector-") as directory:
        actual = list(command)
        password_file = secrets.get("password_file")
        if secrets.get("password"):
            path = Path(directory) / "bind"
            path.touch(mode=0o600)
            path.write_text(secrets["password"], encoding="utf-8")
            password_file = str(path)
        if password_file:
            filter_index = next((index for index, value in enumerate(actual) if value.startswith("(")), len(actual))
            actual[filter_index:filter_index] = ["-y", password_file]
        env = os.environ.copy()
        env["LDAPTLS_REQCERT"] = "demand"
        env["LDAPTLS_REQSAN"] = "demand"
        return _run(actual, env, timeout)


def _run(command: list[str], env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(  # noqa: S603 - executable and arguments are fixed/validated
            command,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SourceInspectorError(f"Required source runtime is not installed: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceInspectorError("Source inspection timed out") from exc
    return _checked_result(result)


def _checked_result(result: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    if result.returncode not in (0, 4):
        raise SourceInspectorError("The source refused the read-only inspection request")
    if len(result.stdout.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise SourceInspectorError("Source inspection response exceeded the safe size limit")
    return result


def _json_rows(result: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    checked = _checked_result(result)
    try:
        payload = json.loads(checked.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise SourceInspectorError("Source inspector returned invalid data") from exc
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        raise SourceInspectorError("Source inspector returned invalid data")
    return [row for row in payload if isinstance(row, dict)]


def _summary(row: dict[str, Any], object_kind: str) -> dict[str, Any]:
    attributes = _safe_attributes(row.get("attributes", {}))
    identifier = str(row.get("identifier") or _first(attributes, "entryUUID") or "")
    if not identifier:
        dn = _first(attributes, "dn")
        identifier = f"dn:{dn}" if dn else ""
    return {
        "kind": object_kind,
        "identifier": identifier,
        "display_name": str(
            row.get("display_name")
            or _first(attributes, "displayName")
            or _first(attributes, "cn")
            or _first(attributes, "uid")
            or identifier
        ),
        "technical_identifier": row.get("technical_identifier") or identifier,
    }


def _ldap_row(entry: dict[str, list[str]], object_kind: str) -> dict[str, Any]:
    dn = _first(entry, "dn")
    identifier = _first(entry, "entryUUID") or (f"dn:{dn}" if dn else "")
    return {
        "kind": object_kind,
        "identifier": identifier,
        "display_name": _first(entry, "cn") or _first(entry, "uid") or identifier,
        "technical_identifier": _first(entry, "entryUUID") or dn,
        "attributes": entry,
    }


def _parse_ldif(text: str) -> list[dict[str, list[str]]]:
    entries: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    unfolded: list[str] = []
    for line in text.splitlines():
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    for line in unfolded:
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        if value.startswith(":"):
            continue
        current.setdefault(name.split(";", 1)[0].strip(), []).append(value.strip())
    if current:
        entries.append(current)
    return entries


def _safe_attributes(value: object) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, list[str]] = {}
    for raw_name, raw_values in value.items():
        name = str(raw_name)
        canonical = canonical_attribute_name(name)
        if any(part in canonical for part in _SENSITIVE_PARTS):
            continue
        values = raw_values if isinstance(raw_values, list) else [raw_values]
        cleaned = []
        for item in values[:20]:
            if not isinstance(item, (str, int, float, bool)):
                continue
            text = str(item)
            cleaned.append(text[:MAX_VALUE_LENGTH] + ("…" if len(text) > MAX_VALUE_LENGTH else ""))
        if cleaned:
            result[name] = cleaned
    return result


def _escape_filter(value: str) -> str:
    replacements = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}
    return "".join(replacements.get(character, character) for character in value)


def _first(attributes: dict[str, list[str]], name: str) -> str | None:
    for key, values in attributes.items():
        if key.casefold() == name.casefold() and values:
            return values[0]
    return None


def _mapping(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SourceInspectorError(f"Invalid source {name}")
    return value


def _kind(config: dict[str, Any]) -> str:
    kind = str(config.get("type", ""))
    if not connector_capabilities(kind).source_browser:
        raise SourceInspectorError("This connector does not support Source Browser")
    return kind


def _object_kind(value: str) -> str:
    if value not in {"user", "group"}:
        raise SourceInspectorError("Source object kind must be user or group")
    return value


def _timeout(collection: dict[str, Any]) -> int:
    raw = collection.get("command_timeout", collection.get("timeout", 30))
    try:
        return max(1, min(int(raw), 120))
    except (TypeError, ValueError):
        return 30
