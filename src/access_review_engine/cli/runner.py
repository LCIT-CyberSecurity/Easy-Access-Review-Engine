from __future__ import annotations
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from .config_loader import secret_environment

@dataclass
class RunnerResult:
    command: list[str]
    output: Path
    returncode: int
    stdout: str
    stderr: str

class RunnerError(RuntimeError):
    pass

def build_command(config: dict[str, object], output: Path, root: str | Path = ".") -> tuple[list[str], dict[str, str]]:
    kind = str(config["type"])
    connection = config["connection"]
    collection = config.get("collection", {})
    if not isinstance(connection, dict) or not isinstance(collection, dict):
        raise ValueError("Invalid connector settings")
    base = Path(root).resolve()
    if kind == "active_directory":
        command = ["pwsh", str(base / "exporters/active-directory/export-active-directory.ps1"), "-ProviderName", str(config["provider"]), "-Output", str(output), "-Server", str(connection["server"]), "-OperationTimeoutSeconds", str(collection.get("timeout", 300))]
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
        if collection.get("allow_partial"): env["ALLOW_PARTIAL"] = "1"
        if config.get("_check_only"): env["CHECK_ONLY"] = "1"
        return ["bash", str(base / "exporters/openldap/export-openldap.sh"), str(output)], env
    raise ValueError(f"Unsupported connector type: {kind}")

def run_exporter(config: dict[str, object], output: str | Path, root: str | Path = ".", timeout: int | None = None) -> RunnerResult:
    path = Path(output).resolve()
    command, env = build_command(config, path, root)
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
    return RunnerResult(command, path, completed.returncode, completed.stdout, completed.stderr)
