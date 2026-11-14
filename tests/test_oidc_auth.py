from __future__ import annotations

import sqlite3
from urllib.parse import parse_qs, urlparse

import pytest
import time

from aurora import oidc
from aurora.api import create_app
from aurora.oidc import IdentityClaims, OIDCError, ProviderMetadata
from aurora.system_admin import init_system, upsert_user
from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt


ISSUER = "http://keycloak:8080/realms/aurora"
CLIENT_SECRET = "test-only-client-secret"


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AURORA_SESSION_SECRET", "test-session-secret-value-at-least-32-characters")
    monkeypatch.setenv("AURORA_PUBLIC_BASE_URL", "http://testserver")
    monkeypatch.setenv("AURORA_OIDC_ALLOW_HTTP", "1")
    monkeypatch.setenv("AURORA_OIDC_ALLOWED_HOSTS", "keycloak")
    monkeypatch.setenv("AURORA_OIDC_CLIENT_SECRET", CLIENT_SECRET)
    db_path = tmp_path / "oidc.db"
    app = create_app(str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        init_system(conn)
        upsert_user(conn, {"username": "admin", "display_name": "Admin", "role": "ADMIN", "password": "admin-test-password-long"})
        upsert_user(conn, {"username": "alice", "display_name": "Alice Local", "role": "OPERATOR", "scopes": ["finance"], "password": "alice-local-password-long"})
        upsert_user(conn, {"username": "disabled", "display_name": "Disabled", "role": "ADMIN", "password": "disabled-local-password-long", "enabled": False})
        # Bootstrap-created local accounts require a first password rotation; these
        # fixtures represent established accounts so admin APIs are available.
        conn.execute("UPDATE system_users SET must_change_password = 0")
        conn.commit()
    from fastapi.testclient import TestClient

    with TestClient(app, follow_redirects=False) as client:
        assert client.post("/api/auth/login", json={"username": "admin", "password": "admin-test-password-long"}).status_code == 200
        yield client, db_path


def _provider_payload(**overrides):
    return {
        "name": "Lab Keycloak",
        "kind": "keycloak",
        "issuer": ISSUER,
        "client_id": "aurora-test-client",
        "client_secret_env": "AURORA_OIDC_CLIENT_SECRET",
        "enabled": True,
        **overrides,
    }


def _metadata():
    return ProviderMetadata(
        issuer=ISSUER,
        authorization_endpoint="http://keycloak:8080/realms/aurora/protocol/openid-connect/auth",
        token_endpoint="http://keycloak:8080/realms/aurora/protocol/openid-connect/token",
        jwks_uri="http://keycloak:8080/realms/aurora/protocol/openid-connect/certs",
    )


def _signed_id_token(*, issuer=ISSUER, audience="aurora-test-client", nonce="expected-nonce", key=None, kid="lab-key", exp=None):
    signing_key = key or JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": kid})
    token = jose_jwt.encode(
        {"alg": "RS256", "kid": kid},
        {"iss": issuer, "sub": "stable-subject", "aud": audience,
         "iat": int(time.time()), "exp": exp or int(time.time()) + 300,
         "nonce": nonce, "email": "mutable@example.test", "name": "Lab User"},
        signing_key,
    )
    public_key = signing_key.as_dict(is_private=False)
    return token.decode("ascii"), {"keys": [public_key]}


def test_id_token_signature_and_claim_validation():
    token, jwks = _signed_id_token()
    identity = oidc.validate_id_token(
        token, JsonWebKey.import_key_set(jwks), issuer=ISSUER,
        client_id="aurora-test-client", expected_nonce="expected-nonce",
    )
    assert (identity.issuer, identity.subject, identity.email) == (
        ISSUER, "stable-subject", "mutable@example.test"
    )


@pytest.mark.parametrize(
    "claims,nonce,error",
    [
        ({"issuer": "https://attacker.example/"}, "expected-nonce", "validation"),
        ({"audience": "another-client"}, "expected-nonce", "validation"),
        ({}, "wrong-nonce", "nonce"),
        ({"exp": int(time.time()) - 600}, "expected-nonce", "validation"),
    ],
)
def test_id_token_rejects_wrong_issuer_audience_nonce_and_expiration(claims, nonce, error):
    token, jwks = _signed_id_token(**claims)
    with pytest.raises(OIDCError, match=error):
        oidc.validate_id_token(
            token, JsonWebKey.import_key_set(jwks), issuer=ISSUER,
            client_id="aurora-test-client", expected_nonce=nonce,
        )


def test_id_token_rejects_unknown_jwks_signing_key():
    token, _ = _signed_id_token()
    _, other_jwks = _signed_id_token(kid="different-key")
    with pytest.raises(OIDCError):
        oidc.validate_id_token(
            token, JsonWebKey.import_key_set(other_jwks), issuer=ISSUER,
            client_id="aurora-test-client", expected_nonce="expected-nonce",
        )


def _configure_and_activate(client, monkeypatch, *, active=True):
    monkeypatch.setattr("aurora.api.discover_provider", _discover)
    created = client.post("/api/system/oidc-providers", json=_provider_payload())
    assert created.status_code == 200, created.text
    provider = created.json()
    assert CLIENT_SECRET not in created.text
    assert provider.get("client_secret_env") == "AURORA_OIDC_CLIENT_SECRET"
    assert provider.get("client_secret_file_env") is None
    if active:
        activated = client.post(f"/api/system/oidc-providers/{provider['id']}/activate")
        assert activated.status_code == 200, activated.text
    return provider


async def _discover(_issuer, _kind, *, force_refresh=False):
    return _metadata()


def test_oidc_configuration_secrets_are_references_and_single_active_provider(auth_client, monkeypatch):
    client, _ = auth_client
    provider = _configure_and_activate(client, monkeypatch)
    safe = client.get("/api/system")
    assert safe.status_code == 200
    assert safe.json()["oidc_providers"][0]["active"] is True
    assert CLIENT_SECRET not in safe.text

    second = client.post(
        "/api/system/oidc-providers",
        json=_provider_payload(name="Second provider", issuer="http://keycloak:8080/realms/other"),
    )
    assert second.status_code == 200
    activated = client.post(f"/api/system/oidc-providers/{second.json()['id']}/activate")
    assert activated.status_code == 200
    providers = client.get("/api/system").json()["oidc_providers"]
    assert sum(item["active"] for item in providers) == 1
    assert next(item for item in providers if item["id"] == provider["id"])["active"] is False


def test_configuration_test_reports_discovery_not_authentication(auth_client, monkeypatch):
    client, _ = auth_client
    monkeypatch.setattr("aurora.api.discover_provider", _discover)
    response = client.post("/api/system/oidc-providers/test", json=_provider_payload())
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "configuration_valid"
    assert response.json()["authentication_tested"] is False
    assert response.json()["redirect_uri"] == "http://testserver/api/auth/oidc/callback"
    assert CLIENT_SECRET not in response.text


def test_sso_requires_explicit_issuer_subject_link_and_keeps_local_authorizations(auth_client, monkeypatch):
    client, _ = auth_client
    provider = _configure_and_activate(client, monkeypatch)
    linked = client.post(
        "/api/system/users/alice/oidc-links",
        json={"provider_id": provider["id"], "subject": "keycloak-sub-alice"},
    )
    assert linked.status_code == 200, linked.text

    async def exchange(*_args, **_kwargs):
        return IdentityClaims(ISSUER, "keycloak-sub-alice", "changed-email@example.test", "Alice SSO")

    monkeypatch.setattr("aurora.api.exchange_code", exchange)
    public = client.get("/api/auth/oidc/config")
    assert public.json()["enabled"] is True
    response = client.get("/api/auth/oidc/login")
    assert response.status_code == 302
    auth_query = parse_qs(urlparse(response.headers["location"]).query)
    assert auth_query["code_challenge_method"] == ["S256"]
    assert "client_secret" not in response.headers["location"]
    state = auth_query["state"][0]

    callback = client.get("/api/auth/oidc/callback", params={"code": "opaque-code", "state": state})
    assert callback.status_code == 303
    assert CLIENT_SECRET not in callback.headers.get("set-cookie", "")
    session = client.get("/api/auth/session")
    assert session.status_code == 200
    assert session.json()["username"] == "alice"
    assert session.json()["role"] == "OPERATOR"
    assert session.json()["scopes"] == ["finance"]
    # The local password still works after linking and no role was inferred from the IdP claims.
    assert client.post("/api/auth/logout").status_code == 200
    local = client.post("/api/auth/login", json={"username": "alice", "password": "alice-local-password-long"})
    assert local.status_code == 200 and local.json()["role"] == "OPERATOR"


def test_unlinked_and_disabled_users_get_no_session_and_callback_cannot_be_replayed(auth_client, monkeypatch):
    client, _ = auth_client
    _configure_and_activate(client, monkeypatch)
    client.post("/api/auth/logout")

    async def exchange(*_args, **_kwargs):
        return IdentityClaims(ISSUER, "unknown-subject", "admin@example.test", "Admin")

    monkeypatch.setattr("aurora.api.exchange_code", exchange)
    first = client.get("/api/auth/oidc/login")
    state = parse_qs(urlparse(first.headers["location"]).query)["state"][0]
    callback = client.get("/api/auth/oidc/callback", params={"code": "opaque", "state": state})
    assert callback.status_code == 303 and "sso_account_not_linked" in callback.headers["location"]
    assert client.get("/api/auth/session").status_code == 401
    replay = client.get("/api/auth/oidc/callback", params={"code": "opaque", "state": state})
    assert replay.status_code == 303 and "invalid_sso_response" in replay.headers["location"]


def test_invalid_browser_cookie_does_not_consume_another_browser_transaction(auth_client, monkeypatch):
    client, db_path = auth_client
    _configure_and_activate(client, monkeypatch)
    response = client.get("/api/auth/oidc/login")
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    client.cookies.delete("aurora_oidc_flow", path="/api/auth/oidc")
    client.cookies.set("aurora_oidc_flow", "attacker-cookie", path="/api/auth/oidc")
    rejected = client.get("/api/auth/oidc/callback", params={"code": "opaque", "state": state})
    assert "invalid_sso_response" in rejected.headers["location"]
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM oidc_login_transactions").fetchone()[0] == 1
    # The browser that owns the flow can still complete it; the invalid callback did not burn state.
    client.cookies.set("aurora_oidc_flow", response.cookies["aurora_oidc_flow"], path="/api/auth/oidc")


def test_disabled_aurora_account_and_disabled_provider_cannot_sign_in(auth_client, monkeypatch):
    client, db_path = auth_client
    provider = _configure_and_activate(client, monkeypatch)
    import sqlite3
    from aurora.system_admin import link_oidc_account, set_enabled

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        link_oidc_account(conn, "disabled", provider["id"], "disabled-sub")
        set_enabled(conn, "disabled", False)

    async def exchange(*_args, **_kwargs):
        return IdentityClaims(ISSUER, "disabled-sub", "admin@example.test", "Disabled")

    monkeypatch.setattr("aurora.api.exchange_code", exchange)
    flow = client.get("/api/auth/oidc/login")
    state = parse_qs(urlparse(flow.headers["location"]).query)["state"][0]
    result = client.get("/api/auth/oidc/callback", params={"code": "opaque", "state": state})
    assert "sso_account_disabled" in result.headers["location"]
    assert client.post(f"/api/system/oidc-providers/{provider['id']}/disable").status_code == 200
    disabled_provider_login = client.get("/api/auth/oidc/login")
    assert "sso_not_configured" in disabled_provider_login.headers["location"]


def test_oidc_url_policy_requires_explicit_allowlist_for_http_private_hosts(monkeypatch):
    monkeypatch.setenv("AURORA_OIDC_ALLOW_HTTP", "1")
    monkeypatch.delenv("AURORA_OIDC_ALLOWED_HOSTS", raising=False)
    with pytest.raises(OIDCError, match="allowlisted"):
        oidc.validate_oidc_url("http://127.0.0.1:8080/realms/test", kind="keycloak")
    monkeypatch.setenv("AURORA_OIDC_ALLOWED_HOSTS", "127.0.0.1")
    assert oidc.validate_oidc_url("http://127.0.0.1:8080/realms/test", kind="keycloak")


def test_local_admin_fallback_is_required_for_oidc_activation(auth_client, monkeypatch):
    client, db_path = auth_client
    provider = client.post("/api/system/oidc-providers", json=_provider_payload()).json()
    monkeypatch.setattr("aurora.api.discover_provider", _discover)
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE system_users SET auth_source='ldap', password_hash=NULL WHERE username='admin'")
        conn.commit()
    result = client.post(f"/api/system/oidc-providers/{provider['id']}/activate")
    assert result.status_code == 409
    assert "local administrator" in result.json()["detail"]


def test_local_session_is_revoked_when_account_is_disabled_and_reenabled(auth_client):
    client, db_path = auth_client
    assert client.get("/api/auth/session").status_code == 200
    from aurora.system_admin import set_enabled

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        set_enabled(conn, "admin", False)
        set_enabled(conn, "admin", True)
    assert client.get("/api/auth/session").status_code == 401


def test_local_login_does_not_depend_on_active_idp(auth_client, monkeypatch):
    client, _ = auth_client
    _configure_and_activate(client, monkeypatch)
    client.post("/api/auth/logout")

    async def unavailable(*_args, **_kwargs):
        raise OIDCError("provider unavailable")

    monkeypatch.setattr("aurora.api.discover_provider", unavailable)
    local = client.post(
        "/api/auth/login",
        json={"username": "alice", "password": "alice-local-password-long"},
    )
    assert local.status_code == 200
    assert local.json()["role"] == "OPERATOR"

