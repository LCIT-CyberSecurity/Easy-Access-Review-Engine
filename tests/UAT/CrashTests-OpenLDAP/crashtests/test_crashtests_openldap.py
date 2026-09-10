from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
CONTAINER = "eare-crashtests-openldap"


def test_ct_openldap_001_targets_current_debian_stable() -> None:
    doc = (ROOT / "CRASHTESTS-OPENLDAP.md").read_text(encoding="utf-8")

    assert 'Debian 13.6 "trixie"' in doc
    assert "debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132" in doc


def test_ct_openldap_002_real_slapd_container_is_reachable() -> None:
    available, reason = _docker_container_ready()
    if not available:
        pytest.skip(f"CrashTests-OpenLDAP real lab unavailable: {reason}")

    result = _docker_exec(["slapd", "-VV"])
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "slapd-version.txt").write_text(result.stdout + result.stderr, encoding="utf-8")

    assert result.returncode == 0
    assert "slapd" in (result.stdout + result.stderr).lower()


def test_ct_openldap_003_root_dse_can_be_collected() -> None:
    available, reason = _docker_container_ready()
    if not available:
        pytest.skip(f"CrashTests-OpenLDAP real lab unavailable: {reason}")

    result = _docker_exec(["ldapsearch", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "", "-s", "base", "+", "*"])
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "ldapsearch-rootdse.ldif").write_text(result.stdout + result.stderr, encoding="utf-8")

    assert result.returncode == 0
    assert "dn:" in result.stdout


def _docker_container_ready() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "Docker CLI is not installed"
    version = subprocess.run(["docker", "version"], text=True, capture_output=True, check=False)
    if version.returncode != 0:
        return False, "Docker Engine is not reachable"
    inspect = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", CONTAINER],
        text=True,
        capture_output=True,
        check=False,
    )
    if inspect.returncode != 0 or inspect.stdout.strip() != "running":
        return False, "container is not running; run tests/UAT/CrashTests-OpenLDAP/run.sh"
    return True, ""


def _docker_exec(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", "exec", CONTAINER, *args], text=True, capture_output=True, check=False)
