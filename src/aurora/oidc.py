"""OIDC Authorization Code + PKCE support adapted from LCIT-Sign's Authlib flow.

This module deliberately handles authentication only. Account association and every Aurora
authorization decision remain in Aurora's local system database.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx
from authlib.common.security import generate_token
from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc7636 import create_s256_code_challenge

DISCOVERY_TTL_SECONDS = 300
HTTP_TIMEOUT_SECONDS = 10
SUPPORTED_ID_TOKEN_ALGORITHMS = {
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
}
_metadata_cache: dict[tuple[str, str], tuple[float, "ProviderMetadata"]] = {}


class OIDCError(RuntimeError):
    """Safe, user-actionable error with no token or secret contents."""


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()
    id_token_signing_alg_values_supported: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True)
class IdentityClaims:
    issuer: str
    subject: str
    email: str
    display_name: str


def normalize_issuer(kind: str, value: str) -> str:
    issuer = value.strip().rstrip("/")
    if kind == "google" and not issuer:
        issuer = "https://accounts.google.com"
    if kind == "entra" and issuer and "://" not in issuer:
        issuer = f"https://login.microsoftonline.com/{issuer}/v2.0"
    return issuer


def _explicit_hosts() -> set[str]:
    return {
        item.strip().lower().rstrip(".")
        for item in os.environ.get("AURORA_OIDC_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }


def _provider_hosts(kind: str, issuer_host: str) -> set[str]:
    if kind == "entra":
        return {"login.microsoftonline.com", "login.windows.net"}
    if kind == "google":
        return {"accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com"}
    return {issuer_host.lower().rstrip(".")}


def _is_allowed_host(host: str, kind: str, issuer_host: str) -> bool:
    normalized = host.lower().rstrip(".")
    return normalized in _provider_hosts(kind, issuer_host) | _explicit_hosts()


def validate_oidc_url(value: str, *, kind: str, issuer_host: str | None = None) -> str:
    """Validate an OIDC URL and reject private-address SSRF unless explicitly allowlisted.

    The explicit host allowlist is intended only for isolated Docker labs (for example the
    `keycloak` service name). HTTP is accepted only when that host is explicitly allowlisted
    and AURORA_OIDC_ALLOW_HTTP=1.
    """
    parsed = urlsplit(value)
    host = parsed.hostname
    if (
        parsed.scheme not in {"https", "http"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "\x00" in value
    ):
        raise OIDCError("OIDC URLs must be absolute HTTPS URLs without credentials or fragments")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise OIDCError("OIDC URL contains an invalid port") from exc
    if parsed.scheme != "https":
        if os.environ.get("AURORA_OIDC_ALLOW_HTTP") != "1" or host.lower() not in _explicit_hosts():
            raise OIDCError("OIDC requires HTTPS; HTTP is allowed only for explicitly allowlisted labs")
    expected_host = issuer_host or host
    if not _is_allowed_host(host, kind, expected_host):
        raise OIDCError("OIDC metadata endpoint is on an untrusted host")
    try:
        address = ipaddress.ip_address(host)
        addresses = [address]
    except ValueError:
        if host.lower() in _explicit_hosts():
            # An explicit per-deployment allowlist is needed for internal Keycloak service DNS.
            addresses = []
        else:
            try:
                addresses = [
                    ipaddress.ip_address(item[4][0])
                    for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
                ]
            except OSError as exc:
                raise OIDCError("OIDC host could not be resolved") from exc
    if host.lower() not in _explicit_hosts() and any(not address.is_global for address in addresses):
        raise OIDCError("OIDC URL resolves to a non-public address")
    return value


def validate_provider_config(provider: dict[str, object]) -> str:
    kind = str(provider.get("kind", "")).lower()
    if kind not in {"entra", "keycloak", "google", "generic"}:
        raise OIDCError("Choose Microsoft Entra ID, Keycloak, Google, or Generic OIDC")
    issuer = normalize_issuer(kind, str(provider.get("issuer", "")))
    if not issuer:
        raise OIDCError("Issuer URL is required")
    parsed = urlsplit(issuer)
    if parsed.query or parsed.fragment:
        raise OIDCError("Issuer URL cannot contain a query or fragment")
    validate_oidc_url(issuer, kind=kind)
    if not str(provider.get("name", "")).strip():
        raise OIDCError("Provider name is required")
    if not str(provider.get("client_id", "")).strip():
        raise OIDCError("Client ID is required")
    has_secret_ref = bool(str(provider.get("client_secret_env") or "").strip()) ^ bool(
        str(provider.get("client_secret_file_env") or "").strip()
    )
    if not has_secret_ref:
        raise OIDCError("Configure exactly one client secret environment or file reference")
    for key in ("client_secret_env", "client_secret_file_env"):
        reference = str(provider.get(key) or "").strip()
        if reference and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", reference):
            raise OIDCError("Secret references must be environment variable names")
    return issuer


async def discover_provider(
    issuer: str, kind: str, *, force_refresh: bool = False
) -> ProviderMetadata:
    key = (issuer, kind)
    cached = _metadata_cache.get(key)
    if cached and cached[0] > time.monotonic() and not force_refresh:
        return cached[1]
    validate_oidc_url(issuer, kind=kind)
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        raise OIDCError("OIDC discovery endpoint could not be reached") from exc
    if response.status_code != 200:
        raise OIDCError("OIDC discovery endpoint returned an error")
    try:
        data = response.json()
        discovered_issuer = str(data["issuer"]).rstrip("/")
        issuer_host = urlsplit(issuer).hostname or ""
        if discovered_issuer != issuer:
            raise OIDCError("Discovered issuer does not match the configured issuer")
        metadata = ProviderMetadata(
            issuer=discovered_issuer,
            authorization_endpoint=validate_oidc_url(
                str(data["authorization_endpoint"]), kind=kind, issuer_host=issuer_host
            ),
            token_endpoint=validate_oidc_url(
                str(data["token_endpoint"]), kind=kind, issuer_host=issuer_host
            ),
            jwks_uri=validate_oidc_url(
                str(data["jwks_uri"]), kind=kind, issuer_host=issuer_host
            ),
            token_endpoint_auth_methods_supported=tuple(data.get("token_endpoint_auth_methods_supported", [])),
            id_token_signing_alg_values_supported=tuple(data.get("id_token_signing_alg_values_supported", [])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, OIDCError):
            raise
        raise OIDCError("OIDC discovery document is missing required metadata") from exc
    if metadata.token_endpoint_auth_methods_supported and not {
        "client_secret_post", "client_secret_basic"
    }.intersection(metadata.token_endpoint_auth_methods_supported):
        raise OIDCError("OIDC provider does not support confidential-client authentication")
    if metadata.id_token_signing_alg_values_supported and not (
        set(metadata.id_token_signing_alg_values_supported) & SUPPORTED_ID_TOKEN_ALGORITHMS
    ):
        raise OIDCError("OIDC provider advertises no supported ID-token signing algorithm")
    _metadata_cache[key] = (time.monotonic() + DISCOVERY_TTL_SECONDS, metadata)
    return metadata


def build_authorization_request(
    metadata: ProviderMetadata, *, client_id: str, redirect_uri: str
) -> AuthorizationRequest:
    state = generate_token(32)
    nonce = generate_token(32)
    verifier = generate_token(64)
    query = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": create_s256_code_challenge(verifier),
        "code_challenge_method": "S256",
    })
    return AuthorizationRequest(
        url=f"{metadata.authorization_endpoint}?{query}",
        state=state,
        nonce=nonce,
        code_verifier=verifier,
    )


def resolve_client_secret(provider: dict[str, object]) -> str:
    env_name = str(provider.get("client_secret_env") or "").strip()
    file_env_name = str(provider.get("client_secret_file_env") or "").strip()
    if env_name:
        secret = os.environ.get(env_name)
        if secret:
            return secret
    elif file_env_name:
        path = os.environ.get(file_env_name)
        if path:
            try:
                with open(path, encoding="utf-8") as secret_file:
                    secret = secret_file.read().rstrip("\r\n")
            except OSError as exc:
                raise OIDCError("OIDC client secret file cannot be read") from exc
            if secret:
                return secret
    raise OIDCError("OIDC client secret reference is not available to the Aurora API")


async def exchange_code(
    metadata: ProviderMetadata,
    *,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
    expected_nonce: str,
) -> IdentityClaims:
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                metadata.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code_verifier": code_verifier,
                },
            )
            if response.status_code != 200:
                raise OIDCError("OIDC code exchange failed")
            token_data = response.json()
            token = token_data.get("id_token")
            if not isinstance(token, str) or not token:
                raise OIDCError("OIDC token response has no ID token")
            jwks_response = await client.get(metadata.jwks_uri)
            if jwks_response.status_code != 200:
                raise OIDCError("OIDC signing keys could not be retrieved")
            key_set = JsonWebKey.import_key_set(jwks_response.json())
    except httpx.HTTPError as exc:
        raise OIDCError("OIDC provider could not complete the login") from exc
    except (ValueError, TypeError) as exc:
        raise OIDCError("OIDC provider returned an invalid response") from exc

    return validate_id_token(
        token, key_set, issuer=metadata.issuer, client_id=client_id,
        expected_nonce=expected_nonce,
    )


def validate_id_token(
    token: str,
    key_set: dict[str, object],
    *,
    issuer: str,
    client_id: str,
    expected_nonce: str,
) -> IdentityClaims:
    """Verify the ID token signature and all Aurora-required OIDC claims."""
    try:
        header_segment = token.split(".", 1)[0]
        header = json.loads(base64.urlsafe_b64decode(header_segment + "=" * (-len(header_segment) % 4)))
        algorithm = str(header.get("alg", ""))
        if algorithm not in SUPPORTED_ID_TOKEN_ALGORITHMS:
            raise OIDCError("OIDC ID token uses an unsupported signing algorithm")
        claims = jose_jwt.decode(
            token,
            key_set,
            claims_options={
                "iss": {"essential": True, "values": [issuer]},
                "aud": {"essential": True, "values": [client_id]},
                "sub": {"essential": True},
                "exp": {"essential": True},
                "iat": {"essential": True},
            },
        )
        claims.validate(leeway=60)
    except OIDCError:
        raise
    except (JoseError, ValueError, TypeError, KeyError) as exc:
        raise OIDCError("OIDC ID token validation failed") from exc
    values = dict(claims)
    audiences = values.get("aud")
    if not isinstance(audiences, (str, list)) or client_id not in (
        audiences if isinstance(audiences, list) else [audiences]
    ):
        raise OIDCError("OIDC ID token audience does not match this client")
    authorized_party = values.get("azp")
    if (len(audiences) > 1 if isinstance(audiences, list) else False) and not authorized_party:
        raise OIDCError("OIDC ID token is missing authorized party")
    if authorized_party is not None and authorized_party != client_id:
        raise OIDCError("OIDC ID token authorized party does not match this client")
    if values.get("nonce") != expected_nonce:
        raise OIDCError("OIDC ID token nonce does not match the login transaction")
    subject = values.get("sub")
    issued_at = values.get("iat")
    expires_at = values.get("exp")
    if not isinstance(subject, str) or not subject.strip() or len(subject) > 255:
        raise OIDCError("OIDC ID token has an invalid subject")
    if not isinstance(issued_at, (int, float)) or issued_at > time.time() + 60:
        raise OIDCError("OIDC ID token issued-at time is invalid")
    if not isinstance(expires_at, (int, float)) or expires_at <= time.time() - 60:
        raise OIDCError("OIDC ID token is expired")
    if values.get("iss") != issuer:
        raise OIDCError("OIDC ID token issuer does not match the configured issuer")
    email = values.get("email") or values.get("preferred_username") or values.get("upn") or ""
    display_name = values.get("name") or " ".join(
        str(item) for item in (values.get("given_name"), values.get("family_name")) if item
    )
    return IdentityClaims(issuer, subject, str(email), str(display_name))


def hash_transaction_value(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
