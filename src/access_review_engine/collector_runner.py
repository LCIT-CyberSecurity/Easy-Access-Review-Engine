from __future__ import annotations
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
import yaml
from .config_loader import secret_environment
from .source_mapping import required_mapping_attributes

@dataclass
class RunnerResult:
    command: list[str]
    output: Path
    returncode: int
    stdout: str
    stderr: str

class RunnerError(RuntimeError):
    pass

def exporter_root() -> Path:
    package_root = Path(__file__).resolve().parents[2]
    if (package_root / "exporters").is_dir():
        return package_root
    cwd = Path.cwd()
    if (cwd / "exporters").is_dir():
        return cwd
    return package_root

def build_command(config: dict[str, object], output: Path, root: str | Path | None = None) -> tuple[list[str], dict[str, str]]:
    kind = str(config["type"])
    connection = config["connection"]
    collection = config.get("collection", {})
    if not isinstance(connection, dict) or not isinstance(collection, dict):
        raise ValueError("Invalid connector settings")
    base = Path(root).resolve() if root is not None else exporter_root()
    if kind == "active_directory":
        command = ["pwsh", str(base / "exporters/active-directory/export-active-directory.ps1"), "-ProviderName", str(config["provider"]), "-Output", str(output), "-Server", str(connection["server"]), "-OperationTimeoutSeconds", str(collection.get("timeout", 300))]
        extra_attributes = required_mapping_attributes(config, kind)
        if extra_attributes:
            command.extend(["-AdditionalGroupProperties", ",".join(extra_attributes)])
        if collection.get("allow_partial"): command.append("-AllowPartial")
        if config.get("_check_only"): command.append("-CheckOnly")
        return command, os.environ.copy()
    if kind == "openldap":
        env = os.environ.copy()
        env.update({"LDAP_URI": str(connection["uri"]), "BASE_DN": str(connection["base_dn"]), "PROVIDER_NAME": str(config["provider"])})
        if connection.get("bind_dn"): env["BIND_DN"] = str(connection["bind_dn"])
        names = {"search_scope": "SEARCH_SCOPE", "page_size": "PAGE_SIZE", "connection_timeout": "CONNECTION_TIMEOUT_SECONDS", "search_timeout": "SEARCH_TIMEOUT_SECONDS", "command_timeout": "COMMAND_TIMEOUT_SECONDS", "filter": "LDAP_FILTER"}
        for key, variable in names.items():
            if key in collection: env[variable] = str(collection[key])
        extra_attributes = required_mapping_attributes(config, kind)
        if extra_attributes:
            env["EXTRA_GROUP_ATTRIBUTES"] = ",".join(extra_attributes)
        if collection.get("allow_partial"): env["ALLOW_PARTIAL"] = "1"
        if collection.get("allow_anonymous") is True: env["ALLOW_ANONYMOUS"] = "1"
        if config.get("_check_only"): env["CHECK_ONLY"] = "1"
        return ["bash", str(base / "exporters/openldap/export-openldap.sh"), str(output)], env
    if kind in {"google_workspace", "gcp_iam"}:
        return [sys.executable, "-m", f"access_review_engine.collectors.{kind}", "--config", str(config.get("_path", "")), "--output", str(output)], os.environ.copy()
    raise ValueError(f"Unsupported connector type: {kind}")

def run_exporter(config: dict[str, object], output: str | Path, root: str | Path | None = None, timeout: int | None = None) -> RunnerResult:
    path = Path(output).resolve()
    temporary_config: Path | None = None
    effective_config = config
    if str(config.get("type")) in {"google_workspace", "gcp_iam"} and not config.get("_path"):
        handle = tempfile.NamedTemporaryFile(prefix="eare-google-check-", suffix=".yaml", mode="w", encoding="utf-8", delete=False)
        temporary_config = Path(handle.name)
        try:
            yaml.safe_dump({key: value for key, value in config.items() if key != "_path"}, handle, sort_keys=False)
        finally:
            handle.close()
        effective_config = dict(config)
        effective_config["_path"] = str(temporary_config)
    command, env = build_command(effective_config, path, root)
    secrets = secret_environment(config)
    if secrets.get("password"):
        env["LDAP_PASSWORD"] = secrets["password"]
    if secrets.get("password_file"):
        env["LDAP_PASSWORD_FILE"] = secrets["password_file"]
    collection = config.get("collection", {})
    default_timeout = collection.get("command_timeout", collection.get("timeout", 300)) if isinstance(collection, dict) else 300
    try:
        completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout or int(default_timeout), check=False)
    except FileNotFoundError as exc:
        raise RunnerError(f"Required collector runtime is not installed: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RunnerError(f"Collector timed out after {timeout or int(default_timeout)} seconds") from exc
    finally:
        if temporary_config is not None:
            temporary_config.unlink(missing_ok=True)
    return RunnerResult(command, path, completed.returncode, completed.stdout, completed.stderr)
