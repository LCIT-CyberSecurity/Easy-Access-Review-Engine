"""LDAP directory lookup and authentication for EARE application users.

This module is about how people sign in to EARE, not about the directories EARE audits.
It shells out to ``ldapsearch``, like the collectors do, so the project keeps no LDAP
dependency. Passwords are passed through a private file, never on the command line.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_LOGIN_ATTRIBUTE = "uid"
DEFAULT_TIMEOUT_SECONDS = 10
SEARCH_ATTRIBUTES = ("dn", "cn", "displayName", "mail")
MAX_RESULTS = 50
LDAP_ATTRIBUTE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(?:;[A-Za-z][A-Za-z0-9-]*(?:=[A-Za-z0-9-]+)?)?$")


class DirectoryError(RuntimeError):
    """A directory operation failed for a reason the administrator can act on."""


def escape_filter(value: str) -> str:
    """Escape a value for an LDAP filter (RFC 4515)."""
    replacements = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00", "/": r"\2f"}
    return "".join(replacements.get(character, character) for character in value)


def _start_tls(settings: dict[str, Any]) -> bool:
    return str(settings.get("start_tls", "")).strip().lower() in {"1", "true", "yes", "on"}


def settings_of(config: dict[str, Any]) -> dict[str, Any]:
    settings = config.get("settings")
    return dict(settings) if isinstance(settings, dict) else {}


def validate_directory(config: dict[str, Any]) -> None:
    """Reject a directory configuration EARE could not authenticate against."""
    if str(config.get("kind", "")).upper() != "LDAP":
        raise DirectoryError("Only LDAP directories can authenticate EARE users today")
    if not str(config.get("endpoint", "")).strip():
        raise DirectoryError("The directory requires an LDAP URI, for example ldaps://ldap.example.org")
    settings = settings_of(config)
    login_attribute = str(settings.get("login_attribute") or DEFAULT_LOGIN_ATTRIBUTE).strip()
    if not LDAP_ATTRIBUTE.fullmatch(login_attribute):
        raise DirectoryError("login_attribute must be a valid LDAP attribute description")
    user_filter = str(settings.get("user_filter") or "(objectClass=person)").strip()
    if not user_filter or "\x00" in user_filter or not user_filter.startswith("(") or not user_filter.endswith(")"):
        raise DirectoryError("user_filter must be a parenthesized LDAP filter")
    depth = 0
    escaped = False
    for character in user_filter:
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise DirectoryError("user_filter has unbalanced parentheses")
    if depth != 0 or escaped:
        raise DirectoryError("user_filter has unbalanced parentheses")
    if not str(settings.get("base_dn", "")).strip():
        raise DirectoryError("The directory requires a base DN")
    # A bind carries the person's own password: refuse to send it over a plaintext connection.
    endpoint = str(config.get("endpoint", "")).strip().lower()
    if not endpoint.startswith(("ldaps://", "ldapi://")) and not _start_tls(settings):
        raise DirectoryError("Use ldaps:// or enable StartTLS: signing in over plain LDAP would send passwords in clear")
    bind_dn = str(settings.get("bind_dn", "")).strip()
    password_env = str(settings.get("bind_password_env", "")).strip()
    if bind_dn and not password_env:
        raise DirectoryError("A service account DN also requires the name of its password variable")
    if password_env and password_env not in os.environ:
        raise DirectoryError(f"The password variable is not set on the server: {password_env}")


def _timeout(settings: dict[str, Any]) -> int:
    try:
        return max(1, min(int(settings.get("timeout", DEFAULT_TIMEOUT_SECONDS)), 60))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS


def _run(arguments: list[str], password: str | None, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run ldapsearch, passing any password through a private file."""
    with tempfile.TemporaryDirectory(prefix="eare-directory-") as directory:
        command = list(arguments)
        if password is not None:
            secret = Path(directory) / "bind"
            secret.touch(mode=0o600)
            secret.write_text(password, encoding="utf-8")
            command += ["-y", str(secret)]
        else:
            command += ["-x"]
        try:
            return subprocess.run(  # noqa: S603 - fixed executable, no shell
                command,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
            )
        except FileNotFoundError as exc:
            raise DirectoryError("ldapsearch is not available on the server") from exc
        except subprocess.TimeoutExpired as exc:
            raise DirectoryError("The directory did not answer in time") from exc


def _base_command(config: dict[str, Any], settings: dict[str, Any], timeout: int) -> list[str]:
    command = [
        "ldapsearch",
        "-LLL",
        "-H",
        str(config["endpoint"]),
        "-o",
        f"nettimeout={timeout}",
        "-l",
        str(timeout),
    ]
    if _start_tls(settings):
        command.append("-ZZ")
    return command


def _service_credentials(settings: dict[str, Any]) -> tuple[list[str], str | None]:
    bind_dn = str(settings.get("bind_dn", "")).strip()
    password_env = str(settings.get("bind_password_env", "")).strip()
    if not bind_dn:
        return [], None
    password = os.environ.get(password_env)
    if password is None:
        raise DirectoryError(f"The password variable is not set on the server: {password_env}")
    return ["-D", bind_dn], password


def parse_ldif(text: str) -> list[dict[str, str]]:
    """Parse ldapsearch -LLL output into one flat mapping per entry."""
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    unfolded: list[str] = []
    for line in text.splitlines():
        if line.startswith(" ") and unfolded:
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
        name, _, raw = line.partition(":")
        value = raw
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", "replace")
            except ValueError:
                value = ""
        current.setdefault(name.strip(), value.strip())
    if current:
        entries.append(current)
    return entries


def _account(entry: dict[str, str], login_attribute: str) -> dict[str, str]:
    return {
        "dn": entry.get("dn", ""),
        "login": entry.get(login_attribute, ""),
        "display_name": entry.get("displayName") or entry.get("cn") or entry.get(login_attribute, ""),
        "email": entry.get("mail", ""),
    }


def _search(
    config: dict[str, Any],
    ldap_filter: str,
    limit: int,
    runner: Any = None,
) -> list[dict[str, str]]:
    validate_directory(config)
    settings = settings_of(config)
    timeout = _timeout(settings)
    login_attribute = str(settings.get("login_attribute") or DEFAULT_LOGIN_ATTRIBUTE)
    credentials, password = _service_credentials(settings)
    command = _base_command(config, settings, timeout) + credentials + [
        "-b",
        str(settings["base_dn"]),
        "-s",
        "sub",
        "-z",
        str(limit),
        ldap_filter,
        login_attribute,
        "cn",
        "displayName",
        "mail",
    ]
    result = (runner or _run)(command, password, timeout)
    # Exit code 4 means the size limit trimmed the answer, which is expected while searching.
    if result.returncode not in (0, 4):
        raise DirectoryError(_failure_message(result.stderr))
    accounts = [_account(entry, login_attribute) for entry in parse_ldif(result.stdout)]
    return [account for account in accounts if account["login"]][:limit]


def _failure_message(stderr: str) -> str:
    text = " ".join(stderr.split())
    lowered = text.lower()
    if "invalid credentials" in lowered:
        return "The directory rejected the service account credentials"
    if "can't contact ldap server" in lowered or "connect error" in lowered:
        return "EARE cannot reach the directory at this address"
    if "no such object" in lowered:
        return "The base DN does not exist on this directory"
    return text[:200] or "The directory refused the request"


def search_accounts(
    config: dict[str, Any],
    search: str = "",
    limit: int = 25,
    runner: Any = None,
) -> list[dict[str, str]]:
    """List directory accounts an administrator can import as EARE users."""
    settings = settings_of(config)
    login_attribute = str(settings.get("login_attribute") or DEFAULT_LOGIN_ATTRIBUTE)
    scope = str(settings.get("user_filter") or "(objectClass=person)")
    needle = escape_filter(search.strip())
    ldap_filter = (
        f"(&{scope}(|({login_attribute}=*{needle}*)(cn=*{needle}*)(mail=*{needle}*)))"
        if needle
        else f"(&{scope}({login_attribute}=*))"
    )
    return _search(config, ldap_filter, max(1, min(limit, MAX_RESULTS)), runner)


def find_account(config: dict[str, Any], login: str, runner: Any = None) -> dict[str, str] | None:
    """Resolve one directory account by its login attribute."""
    settings = settings_of(config)
    login_attribute = str(settings.get("login_attribute") or DEFAULT_LOGIN_ATTRIBUTE)
    scope = str(settings.get("user_filter") or "(objectClass=person)")
    ldap_filter = f"(&{scope}({login_attribute}={escape_filter(login)}))"
    matches = _search(config, ldap_filter, 2, runner)
    # An ambiguous login must never authenticate: EARE cannot tell which person signed in.
    return matches[0] if len(matches) == 1 else None


def authenticate(
    config: dict[str, Any],
    login: str,
    password: str,
    *,
    distinguished_name: str | None = None,
    runner: Any = None,
) -> dict[str, str] | None:
    """Verify a password by binding to the directory as that account."""
    if not password:
        return None
    account = (
        {"dn": distinguished_name, "login": login, "display_name": login, "email": ""}
        if distinguished_name
        else find_account(config, login, runner)
    )
    if account is None or not account.get("dn"):
        return None
    settings = settings_of(config)
    timeout = _timeout(settings)
    command = _base_command(config, settings, timeout) + [
        "-D",
        str(account["dn"]),
        "-b",
        str(account["dn"]),
        "-s",
        "base",
        "(objectClass=*)",
        "1.1",
    ]
    result = (runner or _run)(command, password, timeout)
    if result.returncode != 0:
        return None
    return dict(account)


def test_directory(config: dict[str, Any], runner: Any = None) -> dict[str, Any]:
    """Check the configuration end to end and report what the service account can see."""
    accounts = search_accounts(config, "", 5, runner)
    return {
        "status": "healthy",
        "name": config.get("name", ""),
        "accounts_visible": len(accounts),
        "message": f"Connected. {len(accounts)} account(s) visible with this configuration.",
    }
