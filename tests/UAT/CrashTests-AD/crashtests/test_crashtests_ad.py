from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"


def test_ct_ad_001_targets_windows_server_2025_functional_level() -> None:
    doc = (ROOT / "CRASHTESTS-AD.md").read_text(encoding="utf-8")

    assert "Windows Server 2025" in doc
    assert "functional level: Windows Server 2025" in doc


def test_ct_ad_002_real_ad_environment_contract_is_available() -> None:
    available, reason = _ad_environment_ready()
    if not available:
        pytest.skip(f"CrashTests-AD real lab unavailable: {reason}")

    payload = {
        "host_configured": bool(os.environ.get("EARE_AD_UAT_HOST")),
        "domain_configured": bool(os.environ.get("EARE_AD_UAT_DOMAIN")),
        "pwsh": shutil.which("pwsh"),
    }
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "ad-environment.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    assert payload["host_configured"]
    assert payload["domain_configured"]


def test_ct_ad_003_powershell_can_run_ad_probe_script() -> None:
    available, reason = _ad_environment_ready()
    if not available:
        pytest.skip(f"CrashTests-AD real lab unavailable: {reason}")

    result = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        text=True,
        capture_output=True,
        check=False,
    )
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "pwsh-version.txt").write_text(result.stdout + result.stderr, encoding="utf-8")

    assert result.returncode == 0
    assert result.stdout.strip()


def _ad_environment_ready() -> tuple[bool, str]:
    if shutil.which("pwsh") is None:
        return False, "pwsh is not installed"
    if not os.environ.get("EARE_AD_UAT_HOST"):
        return False, "EARE_AD_UAT_HOST is not set"
    if not os.environ.get("EARE_AD_UAT_DOMAIN"):
        return False, "EARE_AD_UAT_DOMAIN is not set"
    return True, ""

def test_ct_ad_004_uat_powershell_exporter_uses_existing_ad_archive_format() -> None:
    script = ROOT / "powershell" / "Export-CrashTestsAD.ps1"
    text = script.read_text(encoding="utf-8")

    assert "exporters/active-directory/export-active-directory.ps1" in text
    assert "Invoke-ActiveDirectoryExport" in text
    assert "ad-export.zip" in text
    assert "Credential" not in text
    assert "Password" not in text
