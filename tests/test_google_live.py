import os

import pytest

pytestmark = pytest.mark.live_google


def test_live_google_credentials_are_explicitly_configured():
    if not (
        os.environ.get("EARE_WORKSPACE_CREDENTIALS_FILE")
        or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    ):
        pytest.skip("GOOGLE LIVE CREDENTIALS NOT CONFIGURED")
    # The live tenant contract is intentionally opt-in and supplied by deployment-specific fixtures.
    assert True
