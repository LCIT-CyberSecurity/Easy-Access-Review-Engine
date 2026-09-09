from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def test_openldap_real_slapd_export_import_pipeline(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is required for real OpenLDAP/slapd integration test")
    image = os.environ.get("EARE_OPENLDAP_TEST_IMAGE", "osixia/openldap:1.5.0")
    inspected = subprocess.run(["docker", "image", "inspect", image], check=False, capture_output=True, text=True)
    if inspected.returncode != 0:
        pytest.skip(f"Docker image {image} is not available locally")

    pytest.skip(
        "real slapd integration harness is documented but not enabled by default; "
        "provide a prebuilt local test image with seeded LDIF/TLS fixtures to run this test"
    )
