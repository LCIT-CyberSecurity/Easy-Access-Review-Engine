import os
from pathlib import Path

import pytest

from access_review_engine.collectors.gcp_iam import collect as collect_gcp
from access_review_engine.collectors.google_workspace import collect as collect_workspace

if hasattr(pytest, "mark"):
    pytestmark = pytest.mark.live_google

def test_live_google_read_only_contract(tmp_path: Path):
    credential_path = os.environ.get("EARE_WORKSPACE_CREDENTIALS_FILE") or os.environ.get(
        "GOOGLE_APPLICATION_CREDENTIALS"
    )
    customer_id = os.environ.get("EARE_WORKSPACE_CUSTOMER_ID")
    delegated_admin = os.environ.get("EARE_WORKSPACE_DELEGATED_ADMIN")
    gcp_scope = os.environ.get("EARE_GCP_SCOPE")
    if not all((credential_path, customer_id, delegated_admin, gcp_scope)) or not Path(
        credential_path or ""
    ).is_file():
        pytest.skip(
            "GOOGLE LIVE requires credentials, EARE_WORKSPACE_CUSTOMER_ID, "
            "EARE_WORKSPACE_DELEGATED_ADMIN and EARE_GCP_SCOPE"
        )
    workspace_manifest = collect_workspace(
        {
            "provider": "live-workspace",
            "connection": {"customer_id": customer_id, "delegated_admin": delegated_admin},
            "credentials": {"service_account_file_env": "EARE_WORKSPACE_CREDENTIALS_FILE"}
            if os.environ.get("EARE_WORKSPACE_CREDENTIALS_FILE")
            else {"service_account_file_env": "GOOGLE_APPLICATION_CREDENTIALS"},
            "collection": {
                "users": True,
                "groups": True,
                "memberships": False,
                "admin_roles": True,
                "admin_role_assignments": False,
            },
            "_check_only": True,
        },
        tmp_path / "workspace-live.zip",
    )
    gcp_manifest = collect_gcp(
        {
            "provider": "live-gcp",
            "connection": {"scope": gcp_scope},
            "credentials": {
                "service_account_file_env": "EARE_WORKSPACE_CREDENTIALS_FILE"
            }
            if os.environ.get("EARE_WORKSPACE_CREDENTIALS_FILE")
            else {},
            "collection": {"iam_allow_policies": True, "service_accounts": True},
            "_check_only": True,
        },
        tmp_path / "gcp-live.zip",
    )
    assert workspace_manifest["check_only"] is True
    assert gcp_manifest["check_only"] is True
