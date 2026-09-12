from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import yaml

class ConfigError(ValueError):
    pass

SUPPORTED_TYPES = {"active_directory", "openldap"}

def connector_path(name: str, directory: str | Path = "config/connectors") -> Path:
    if not name or Path(name).name != name or name in {".", ".."}:
        raise ConfigError("Invalid connector name")
    return Path(directory) / f"{name}.yaml"

def validate_connector(data: Any, expected_name: str | None = None) -> None:
    if not isinstance(data, dict):
        raise ConfigError("Connector configuration must be a YAML mapping")
    provider, kind = data.get("provider"), data.get("type")
    if not isinstance(provider, str) or not provider.strip():
        raise ConfigError("Connector configuration requires provider")
    if expected_name and provider != expected_name:
        raise ConfigError("Provider name does not match connector filename")
    if kind not in SUPPORTED_TYPES:
        raise ConfigError(f"Unsupported connector type: {kind or 'missing'}")
    connection = data.get("connection")
    if not isinstance(connection, dict):
        raise ConfigError("Connector configuration requires connection settings")
    required = ("server",) if kind == "active_directory" else ("uri", "base_dn")
    missing = [key for key in required if not connection.get(key)]
    if missing:
        raise ConfigError("Missing connection settings: " + ", ".join(missing))

def load_connector(name: str, config: str | Path | None = None) -> dict[str, Any]:
    path = Path(config) if config else connector_path(name)
    if not path.is_file():
        raise ConfigError(f"Connector configuration not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Cannot read connector configuration: {path}") from exc
    validate_connector(data, name)
    data["_path"] = str(path)
    return data

def secret_environment(data: dict[str, Any]) -> dict[str, str]:
    credentials = data.get("credentials", {})
    if not isinstance(credentials, dict):
        raise ConfigError("credentials must be a YAML mapping")
    result: dict[str, str] = {}
    for key, target in (("username_env", "username"), ("password_env", "password"), ("password_file_env", "password_file")):
        variable = credentials.get(key)
        if variable:
            if not isinstance(variable, str) or variable not in os.environ:
                raise ConfigError(f"Required secret environment variable is not set: {variable}")
            result[target] = os.environ[variable]
    return result

def template(provider: str, kind: str) -> dict[str, Any]:
    if kind == "active_directory":
        return {"provider": provider, "type": kind, "connection": {"server": ""}, "collection": {"timeout": 300, "allow_partial": False}}
    if kind == "openldap":
        return {"provider": provider, "type": kind, "connection": {"uri": "ldaps://", "base_dn": "", "bind_dn": ""}, "collection": {"search_scope": "sub", "page_size": 1000, "connection_timeout": 10, "search_timeout": 120, "command_timeout": 180, "allow_partial": False}}
    raise ConfigError(f"Unsupported connector type: {kind}")
