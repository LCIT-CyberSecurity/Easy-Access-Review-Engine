from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import yaml

from access_review_engine.source_mapping import validate_business_mapping

class ConfigError(ValueError):
    pass

SUPPORTED_TYPES = {"active_directory", "openldap", "google_workspace", "gcp_iam"}
SENSITIVE_KEY_PARTS = ("password", "secret", "token", "private_key")
ALLOWED_SECRET_REFERENCE_KEYS = {
    "username_env",
    "password_env",
    "password_file_env",
    "token_env",
    "token_file_env",
    "private_key_file_env",
}

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
    if kind == "active_directory":
        required = ("server",)
    elif kind == "openldap":
        required = ("uri", "base_dn")
    elif kind == "google_workspace":
        required = ("customer_id", "delegated_admin")
    else:
        required = ("scope",)
    missing = [key for key in required if not connection.get(key)]
    if missing:
        raise ConfigError("Missing connection settings: " + ", ".join(missing))
    if kind == "gcp_iam" and (not str(connection.get("scope", "")).startswith("projects/") or not str(connection.get("scope", "")).removeprefix("projects/")):
        raise ConfigError("GCP V1 supports only scope projects/<project>")
    collection = data.get("collection", {})
    if not isinstance(collection, dict):
        raise ConfigError("Connector collection settings must be a mapping")
    if "allow_anonymous" in collection and not isinstance(collection["allow_anonymous"], bool):
        raise ConfigError("collection.allow_anonymous must be a boolean")
    if "read_only_account" in collection and not isinstance(collection["read_only_account"], bool):
        raise ConfigError("collection.read_only_account must be a boolean")
    if kind in {"active_directory", "openldap"}:
        try:
            data["business_mapping"] = validate_business_mapping(kind, data.get("business_mapping"))
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
    elif data.get("business_mapping") not in (None, {}):
        raise ConfigError(f"Connector type {kind} does not support business_mapping")
    validate_no_plaintext_secrets(data)

def validate_no_plaintext_secrets(data: Any, path: str = "") -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            lowered = key_text.lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS) and lowered not in ALLOWED_SECRET_REFERENCE_KEYS:
                raise ConfigError(f"Plaintext secret key is not allowed in connector YAML: {child_path}")
            validate_no_plaintext_secrets(value, child_path)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            validate_no_plaintext_secrets(value, f"{path}[{index}]")

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
        return {"provider": provider, "type": kind, "connection": {"server": ""}, "collection": {"timeout": 300, "allow_partial": False, "read_only_account": False}, "business_mapping": validate_business_mapping(kind, None)}
    if kind == "openldap":
        return {"provider": provider, "type": kind, "connection": {"uri": "ldaps://", "base_dn": "", "bind_dn": ""}, "collection": {"search_scope": "sub", "page_size": 1000, "connection_timeout": 10, "search_timeout": 120, "command_timeout": 180, "allow_partial": False, "allow_anonymous": False, "read_only_account": False}, "business_mapping": validate_business_mapping(kind, None)}
    if kind == "google_workspace":
        return {"provider": provider, "type": kind, "connection": {"customer_id": "my_customer", "delegated_admin": ""}, "credentials": {"service_account_file_env": "EARE_WORKSPACE_CREDENTIALS_FILE"}, "collection": {"users": True, "groups": True, "memberships": True, "admin_roles": True, "admin_role_assignments": True, "page_size": 200, "allow_partial": False, "read_only_account": True}}
    if kind == "gcp_iam":
        return {"provider": provider, "type": kind, "connection": {"scope": "projects/"}, "credentials": {"application_default": True}, "collection": {"iam_allow_policies": True, "service_accounts": True, "allow_partial": False, "read_only_account": True}}
    raise ConfigError(f"Unsupported connector type: {kind}")
