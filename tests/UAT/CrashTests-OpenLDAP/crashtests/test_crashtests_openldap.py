from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from access_review_engine.application import import_file_to_repository
from access_review_engine.services import create_golden_source, promote_snapshot
from access_review_engine.storage import Repository

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
CONTAINER = "eare-crashtests-openldap"


def test_ct_openldap_001_targets_current_debian_stable() -> None:
    doc = (ROOT / "CRASHTESTS-OPENLDAP.md").read_text(encoding="utf-8")

    assert 'Debian 13.6 "trixie"' in doc
    assert (
        "debian:13-slim@sha256:"
        "d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132" in doc
    )


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

    result = _docker_exec(
        ["ldapsearch", "-Y", "EXTERNAL", "-H", "ldapi:///", "-b", "", "-s", "base", "+", "*"]
    )
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "ldapsearch-rootdse.ldif").write_text(
        result.stdout + result.stderr, encoding="utf-8"
    )

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
        return False, (
            "container is not running; run tests/UAT/CrashTests-OpenLDAP/Run_CrashTests-OpenLDAP.sh"
        )
    return True, ""


def _docker_exec(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", CONTAINER, *args], text=True, capture_output=True, check=False
    )


def test_ct_openldap_004_real_export_import_preserves_eare_model(tmp_path: Path) -> None:
    available, reason = _docker_container_ready()
    if not available:
        pytest.skip(f"CrashTests-OpenLDAP real lab unavailable: {reason}")

    exporter = ROOT.parents[2] / "exporters" / "openldap" / "export-openldap.sh"
    container_exporter = "/opt/crashtests-openldap/export-openldap.sh"
    archive_in_container = "/opt/crashtests-openldap/export.zip"
    copy_script = subprocess.run(
        ["docker", "cp", str(exporter), f"{CONTAINER}:{container_exporter}"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert copy_script.returncode == 0, copy_script.stderr

    collect = subprocess.run(
        [
            "docker", "exec",
            "--env", "LDAP_URI=ldap://127.0.0.1",
            "--env", "BASE_DN=dc=example,dc=com",
            "--env", "PROVIDER_NAME=crashtests-openldap",
            "--env", "ALLOW_ANONYMOUS=1",
            CONTAINER, "bash", container_exporter, archive_in_container,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert collect.returncode == 0, collect.stderr

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    archive = ARTIFACTS / "export.zip"
    copied_archive = subprocess.run(
        ["docker", "cp", f"{CONTAINER}:{archive_in_container}", str(archive)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert copied_archive.returncode == 0, copied_archive.stderr

    repo = Repository(tmp_path / "crashtests-openldap.db")
    try:
        snapshot = import_file_to_repository(repo, archive)
        import_record = repo.list_payloads("imports")[0]
        identities = repo.list_payloads_by_provider("identities", "crashtests-openldap")
        accesses = repo.list_payloads_by_provider("accesses", "crashtests-openldap")
        assignments = repo.list_payloads_by_provider("access_assignments", "crashtests-openldap")

        assert import_record["completeness"] == "full"
        assert snapshot.providers[0].name == "crashtests-openldap"
        user_rows = [item for item in identities if item["type"] == "user_account"]
        assert {item["metadata"]["uid"] for item in user_rows} == {"alice", "jdoe"}
        assert len([item for item in identities if item["type"] == "group"]) == 3
        assert len(accesses) == 3
        assert len(assignments) == 3
        assert {item["identity_identifier"] for item in snapshot.comparison_states} == {
            item["identifier"] for item in user_rows
        }
        assert all(
            "unknown_identity" not in item["findings"]
            for item in snapshot.comparison_states
        )

        raw_assignments = [item["origin"]["raw"] for item in assignments]
        imported_membership_attributes = {
            key
            for raw in raw_assignments
            for key in ("member", "uniquemember", "memberUid")
            if key in raw
        }
        assert imported_membership_attributes == {
            "member", "uniquemember", "memberUid"
        }
        unique_member = next(raw for raw in raw_assignments if "uniquemember" in raw)
        assert unique_member["unique_member_uid"] == "'0101'B"
        assert unique_member["member_dn"] == "cn=Doe\\, John,ou=People,dc=example,dc=com"

        golden = promote_snapshot(create_golden_source("crashtests-openldap-baseline"), snapshot)
        reviewed = import_file_to_repository(repo, archive, golden_version=golden)
        assert {item["classification"] for item in reviewed.comparison_states} == {
            "expected_and_observed"
        }
        assert len(repo.list_payloads_by_provider("access_assignments", "crashtests-openldap")) == 3

        (ARTIFACTS / "snapshot.json").write_text(
            json.dumps(
                {
                    "provider": snapshot.providers[0].name,
                    "completeness": import_record["completeness"],
                    "identity_count": len(identities),
                    "access_count": len(accesses),
                    "assignment_count": len(assignments),
                    "reimport_classifications": sorted(
                        item["classification"] for item in reviewed.comparison_states
                    ),
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
    finally:
        repo.close()
