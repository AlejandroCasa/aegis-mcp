"""TDD suite for the OAuth 2.1 Resource Server (MCP authorization spec)."""

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

from app.auth import (
    MAX_JWKS_BYTES,
    AuthError,
    AuthUnavailableError,
    JWKSCache,
    OAuthConfig,
    ResourceServer,
    TokenValidator,
    build_resource_server,
    metadata_url_for,
    parse_jwks,
    strip_credentials,
    validate_algorithms,
)
from app.config import Settings, settings
from app.jsonrpc import JsonRpcGateway
from app.main import app, firewall, jsonrpc_gateway, policy_engine, resource_server
from app.metrics import metrics_registry

client = TestClient(app)

ISSUER = "https://auth.example.com"
RESOURCE = "https://aegis.example.com/mcp"
JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
METADATA_URL = "https://aegis.example.com" + METADATA_PATH
UPSTREAM_URL = "http://git-mcp.internal:9000/mcp"
ALL_ALGS = ("RS256", "PS256", "ES256", "EdDSA")

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_KEY_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())
ED_KEY = ed25519.Ed25519PrivateKey.generate()


def _jwk(public_jwk: Any, kid: str) -> dict[str, Any]:
    return {**dict(public_jwk), "kid": kid, "use": "sig"}


RSA_JWK = _jwk(RSAAlgorithm.to_jwk(RSA_KEY.public_key(), as_dict=True), "rsa-1")
RSA_JWK_2 = _jwk(RSAAlgorithm.to_jwk(RSA_KEY_2.public_key(), as_dict=True), "rsa-2")
EC_JWK = _jwk(ECAlgorithm.to_jwk(EC_KEY.public_key(), as_dict=True), "ec-1")
ED_JWK = _jwk(OKPAlgorithm.to_jwk(ED_KEY.public_key(), as_dict=True), "ed-1")


def _claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "agent-alpha",
        "iat": now,
        "exp": now + 300,
        "scope": "mcp:tools mcp:resources",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _token(
    claims: dict[str, Any] | None = None,
    key: Any = RSA_KEY,
    alg: str = "RS256",
    kid: str | None = "rsa-1",
) -> str:
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims or _claims(), key, algorithm=alg, headers=headers)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _hs256_token(secret: bytes, kid: str = "rsa-1") -> str:
    """Forge an HS256 token keyed with the RSA public key (alg confusion)."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    payload = _b64(json.dumps(_claims()).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64(signature)}"


def _none_token() -> str:
    header = _b64(json.dumps({"alg": "none", "typ": "JWT", "kid": "rsa-1"}).encode())
    return f"{header}.{_b64(json.dumps(_claims()).encode())}."


class JwksServer:
    """Mock authorization-server JWKS endpoint with a mutable key set."""

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.status = 200
        self.body: bytes | None = None
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.body is not None:
            return httpx.Response(self.status, content=self.body)
        return httpx.Response(self.status, json={"keys": self.keys})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _config(**overrides: Any) -> OAuthConfig:
    params: dict[str, Any] = {
        "issuer": ISSUER,
        "resource": RESOURCE,
        "jwks_url": JWKS_URL,
        "algorithms": ALL_ALGS,
    }
    params.update(overrides)
    return OAuthConfig(**params)


def _cache(server: JwksServer, clock: Callable[[], float] | None = None) -> JWKSCache:
    return JWKSCache(
        JWKS_URL,
        ttl_seconds=300,
        client=server.client(),
        min_refresh_seconds=10,
        clock=clock or FakeClock(),
    )


def _validator(
    keys: list[dict[str, Any]] | None = None, **overrides: Any
) -> TokenValidator:
    server = JwksServer(keys if keys is not None else [RSA_JWK, EC_JWK, ED_JWK])
    return TokenValidator(_config(**overrides), _cache(server))


# ---------------------------------------------------------------------------
# Configuration hardening
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("algs", [["none"], ["HS256"], ["RS256", "HS512"], []])
def test_insecure_or_empty_algorithm_lists_are_rejected(algs: list[str]) -> None:
    """``none`` and HS* can never be configured (algorithm confusion)."""
    with pytest.raises(ValueError):
        validate_algorithms(algs)


def test_algorithm_list_is_deduplicated_in_order() -> None:
    assert validate_algorithms(["ES256", "RS256", "ES256"]) == ("ES256", "RS256")


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": ""},
        {"jwks_url": ""},
        {"jwks_url": "ftp://auth.example.com/jwks.json"},
        {"resource": ""},
        {"resource": "mcp"},
        {"resource": "http://aegis.example.com/mcp"},
        {"resource": "https://aegis.example.com/mcp#frag"},
        {"algorithms": ("HS256",)},
        {"leeway_seconds": -1},
        {"leeway_seconds": 3600},
    ],
)
def test_oauth_config_fails_closed(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _config(**overrides)


def test_http_resource_allowed_for_localhost_only() -> None:
    config = _config(resource="http://localhost:8000/mcp")
    assert config.metadata_url == (
        "http://localhost:8000/.well-known/oauth-protected-resource/mcp"
    )


def test_metadata_url_follows_rfc9728_path_insertion() -> None:
    assert metadata_url_for(RESOURCE) == METADATA_URL
    assert metadata_url_for("https://aegis.example.com/") == (
        "https://aegis.example.com/.well-known/oauth-protected-resource"
    )


def test_settings_build_oauth_config_and_resource_server() -> None:
    configured = Settings(
        auth_mode="oauth",
        oauth_issuer=ISSUER,
        oauth_audience=RESOURCE,
        oauth_jwks_url=JWKS_URL,
        oauth_scopes_supported=["mcp:tools"],
    )
    server = build_resource_server(configured.auth_mode, configured.oauth_config)
    assert server.enabled
    assert server.metadata()["scopes_supported"] == ["mcp:tools"]


def test_oauth_mode_with_incomplete_settings_fails_closed() -> None:
    incomplete = Settings(auth_mode="oauth")
    with pytest.raises(ValueError):
        build_resource_server(incomplete.auth_mode, incomplete.oauth_config)


def test_api_key_mode_is_the_default() -> None:
    default = Settings()
    assert default.auth_mode == "api_key"
    assert not build_resource_server(default.auth_mode, default.oauth_config).enabled


# ---------------------------------------------------------------------------
# JWKS parsing, caching, and rotation
# ---------------------------------------------------------------------------


def test_parse_jwks_drops_symmetric_and_encryption_keys() -> None:
    oct_key = {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}
    enc_key = {**RSA_JWK_2, "use": "enc"}
    keys = parse_jwks({"keys": [RSA_JWK, oct_key, enc_key, "junk"]})
    assert set(keys) == {"rsa-1"}


@pytest.mark.parametrize("document", [[], {"keys": "nope"}, {}])
def test_parse_jwks_requires_keys_array(document: Any) -> None:
    with pytest.raises(AuthUnavailableError):
        parse_jwks(document)


def test_jwks_is_cached_within_ttl() -> None:
    server = JwksServer([RSA_JWK])
    cache = _cache(server)
    for _ in range(5):
        assert cache.get_key("rsa-1")["kid"] == "rsa-1"
    assert server.calls == 1


def test_jwks_refetched_after_ttl_expiry() -> None:
    server = JwksServer([RSA_JWK])
    clock = FakeClock()
    cache = _cache(server, clock)
    cache.get_key("rsa-1")
    clock.now += 301
    cache.get_key("rsa-1")
    assert server.calls == 2


def test_unknown_kid_forces_refresh_for_key_rotation() -> None:
    server = JwksServer([RSA_JWK])
    clock = FakeClock()
    cache = _cache(server, clock)
    cache.get_key("rsa-1")
    server.keys = [RSA_JWK, RSA_JWK_2]
    clock.now += 11
    assert cache.get_key("rsa-2")["kid"] == "rsa-2"
    assert server.calls == 2


def test_unknown_kid_refresh_is_rate_limited() -> None:
    server = JwksServer([RSA_JWK])
    cache = _cache(server)
    cache.get_key("rsa-1")
    for _ in range(3):
        with pytest.raises(AuthError):
            cache.get_key("forged-kid")
    assert server.calls == 1


def test_kidless_token_needs_exactly_one_trusted_key() -> None:
    assert _cache(JwksServer([RSA_JWK])).get_key(None)["kid"] == "rsa-1"
    with pytest.raises(AuthError):
        _cache(JwksServer([RSA_JWK, EC_JWK])).get_key(None)


@pytest.mark.parametrize(
    ("status", "body"),
    [(500, None), (200, b"{not json"), (200, b"x" * (MAX_JWKS_BYTES + 1))],
)
def test_jwks_fetch_failures_without_cache_are_unavailable(
    status: int, body: bytes | None
) -> None:
    server = JwksServer([RSA_JWK])
    server.status, server.body = status, body
    with pytest.raises(AuthUnavailableError):
        _cache(server).get_key("rsa-1")


def test_rate_limited_retry_after_initial_failure_stays_unavailable() -> None:
    """An AS outage must surface as 503, never as a 401 invalid_token."""
    server = JwksServer([RSA_JWK])
    server.status = 500
    cache = _cache(server)
    for _ in range(3):
        with pytest.raises(AuthUnavailableError):
            cache.get_key("rsa-1")
    assert server.calls == 1


def test_jwks_transport_error_is_unavailable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    transport = httpx.MockTransport(boom)
    cache = JWKSCache(JWKS_URL, client=httpx.Client(transport=transport))
    with pytest.raises(AuthUnavailableError):
        cache.get_key("rsa-1")


def test_jwks_refresh_failure_keeps_last_known_keys() -> None:
    server = JwksServer([RSA_JWK])
    clock = FakeClock()
    cache = _cache(server, clock)
    cache.get_key("rsa-1")
    server.status = 503
    clock.now += 301
    assert cache.get_key("rsa-1")["kid"] == "rsa-1"
    assert server.calls == 2


def test_default_jwks_client_is_hardened() -> None:
    cache = JWKSCache(JWKS_URL)
    assert cache.client.follow_redirects is False
    cache.client.close()


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "alg", "kid"),
    [
        (RSA_KEY, "RS256", "rsa-1"),
        (RSA_KEY, "PS256", "rsa-1"),
        (EC_KEY, "ES256", "ec-1"),
        (ED_KEY, "EdDSA", "ed-1"),
    ],
)
def test_valid_asymmetric_tokens_are_accepted(key: Any, alg: str, kid: str) -> None:
    principal = _validator().validate(_token(key=key, alg=alg, kid=kid))
    assert principal.agent_id == "agent-alpha"
    assert principal.subject == "agent-alpha"
    assert principal.scopes == frozenset({"mcp:tools", "mcp:resources"})


def test_audience_list_containing_resource_is_accepted() -> None:
    token = _token(_claims(aud=["https://other.example.com", RESOURCE]))
    assert _validator().validate(token).agent_id == "agent-alpha"


@pytest.mark.parametrize(
    ("claims", "expected"),
    [
        ({"sub": None, "azp": "client-azp"}, "client-azp"),
        ({"sub": None, "client_id": "client-cid"}, "client-cid"),
        ({"sub": "", "azp": "client-azp"}, "client-azp"),
    ],
)
def test_agent_id_falls_back_to_azp_then_client_id(
    claims: dict[str, Any], expected: str
) -> None:
    principal = _validator().validate(_token(_claims(**claims)))
    assert principal.agent_id == expected
    assert principal.client_id == expected


def test_token_without_identity_claims_is_rejected() -> None:
    with pytest.raises(AuthError, match="identity"):
        _validator().validate(_token(_claims(sub=None)))


def test_scp_list_claim_is_supported() -> None:
    token = _token(_claims(scope=None, scp=["a", "b", 3]))
    assert _validator().validate(token).scopes == frozenset({"a", "b"})
    assert _validator().validate(_token(_claims(scope=None))).scopes == frozenset()


@pytest.mark.parametrize(
    ("claims", "message"),
    [
        ({"iss": "https://evil.example.com"}, "issuer"),
        ({"aud": "https://other-resource.example.com"}, "audience"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"nbf": int(time.time()) + 3600}, "not yet valid"),
        ({"exp": None}, "validation failed"),
        ({"aud": None}, "validation failed"),
        ({"iss": None}, "validation failed"),
    ],
)
def test_invalid_claims_are_rejected(claims: dict[str, Any], message: str) -> None:
    with pytest.raises(AuthError, match=message):
        _validator().validate(_token(_claims(**claims)))


def test_leeway_tolerates_small_clock_skew() -> None:
    token = _token(_claims(exp=int(time.time()) - 5))
    assert _validator().validate(token).agent_id == "agent-alpha"


def test_alg_none_is_rejected() -> None:
    with pytest.raises(AuthError, match="algorithm is not allowed"):
        _validator().validate(_none_token())


def test_hs256_key_confusion_with_rsa_public_key_is_rejected() -> None:
    pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(AuthError, match="algorithm is not allowed"):
        _validator().validate(_hs256_token(pem))


def test_algorithm_outside_configured_allow_list_is_rejected() -> None:
    validator = _validator(algorithms=("RS256",))
    with pytest.raises(AuthError, match="algorithm is not allowed"):
        validator.validate(_token(key=EC_KEY, alg="ES256", kid="ec-1"))


def test_token_alg_must_match_jwk_key_type() -> None:
    """An ES256 header pointing at an RSA JWK is refused before verification."""
    token = _token(key=EC_KEY, alg="ES256", kid="rsa-1")
    with pytest.raises(AuthError, match="does not match"):
        _validator().validate(token)


def test_token_alg_must_match_declared_jwk_alg() -> None:
    validator = _validator([{**RSA_JWK, "alg": "RS512"}])
    with pytest.raises(AuthError, match="does not match"):
        validator.validate(_token())


def test_signature_from_untrusted_key_is_rejected() -> None:
    token = _token(key=RSA_KEY_2, kid="rsa-1")
    with pytest.raises(AuthError, match="validation failed"):
        _validator().validate(token)


def test_unknown_kid_is_rejected() -> None:
    with pytest.raises(AuthError, match="not trusted"):
        _validator().validate(_token(kid="rsa-2"))


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a" * 9000])
def test_malformed_tokens_are_rejected(token: str) -> None:
    with pytest.raises(AuthError, match="Malformed"):
        _validator().validate(token)


def test_non_string_kid_is_rejected() -> None:
    header = _b64(json.dumps({"alg": "RS256", "kid": 7}).encode())
    with pytest.raises(AuthError, match="Malformed"):
        _validator().validate(f"{header}.e30.sig")


# ---------------------------------------------------------------------------
# ResourceServer facade
# ---------------------------------------------------------------------------


def test_disabled_resource_server_refuses_oauth_operations() -> None:
    server = ResourceServer()
    assert not server.enabled
    assert server.challenge() == "Bearer"
    assert not server.serves_metadata_path("/.well-known/oauth-protected-resource")
    with pytest.raises(RuntimeError):
        server.authenticate("Bearer x")
    with pytest.raises(RuntimeError):
        server.metadata()


def test_missing_and_malformed_authorization_headers() -> None:
    server = ResourceServer(_config(), _cache(JwksServer([RSA_JWK])))
    with pytest.raises(AuthError) as missing:
        server.authenticate(None)
    assert missing.value.error is None
    for header in ("Basic abc", "Bearer ", "Bearer"):
        with pytest.raises(AuthError) as malformed:
            server.authenticate(header)
        assert malformed.value.error == "invalid_request"
    assert server.authenticate(f"bearer {_token()}").agent_id == "agent-alpha"


def test_challenge_includes_resource_metadata_and_error() -> None:
    server = ResourceServer(_config(), _cache(JwksServer([RSA_JWK])))
    assert server.challenge() == f'Bearer resource_metadata="{METADATA_URL}"'
    challenge = server.challenge(AuthError('bad "token"'))
    assert 'error="invalid_token"' in challenge
    assert 'error_description="bad \\"token\\""' in challenge


def test_strip_credentials_removes_all_caller_credentials() -> None:
    headers = httpx.Headers(
        {
            "Authorization": "Bearer abc",
            "Proxy-Authorization": "Basic xyz",
            "Cookie": "session=1",
            "Accept": "application/json",
        }
    )
    strip_credentials(headers)
    assert dict(headers) == {"accept": "application/json"}


# ---------------------------------------------------------------------------
# HTTP integration (OAuth mode)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_state() -> Iterator[None]:
    """Reset ledger, metrics, settings, RBAC, upstreams, and auth mode."""
    original_client = jsonrpc_gateway.client
    firewall.reset()
    metrics_registry.reset()
    policy_engine.reset()
    settings.api_key = None
    settings.block_threshold_score = 70
    settings.enable_dlp_redaction = True
    resource_server.configure(None)
    jsonrpc_gateway.set_upstreams({})
    yield
    resource_server.configure(None)
    jsonrpc_gateway.client = original_client
    jsonrpc_gateway.set_upstreams({})
    policy_engine.reset()
    settings.api_key = None


@pytest.fixture
def jwks_server() -> JwksServer:
    """Enable OAuth mode against a mock JWKS endpoint."""
    server = JwksServer([RSA_JWK])
    resource_server.configure(
        _config(scopes_supported=("mcp:tools",)), _cache(server, time.monotonic)
    )
    return server


class UpstreamRecorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"ok": True}}
        )


def _wire_upstream() -> UpstreamRecorder:
    recorder = UpstreamRecorder()
    jsonrpc_gateway.set_upstreams({"git-mcp": UPSTREAM_URL})
    jsonrpc_gateway.client = httpx.Client(transport=httpx.MockTransport(recorder))
    return recorder


def _bearer(token: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token or _token()}"}


INSPECT = "/api/v1/mcp/inspect"
JSONRPC = "/api/v1/mcp/jsonrpc"
CALL = {"server_name": "git-mcp", "tool_name": "git_status", "arguments": {}}
RPC = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "git_status", "arguments": {}},
}


@pytest.mark.usefixtures("jwks_server")
@pytest.mark.parametrize(
    "path", ["/.well-known/oauth-protected-resource", METADATA_PATH]
)
def test_protected_resource_metadata_endpoint(path: str) -> None:
    res = client.get(path)
    assert res.status_code == 200
    assert res.json() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "resource_name": "Aegis-MCP",
        "scopes_supported": ["mcp:tools"],
    }


@pytest.mark.usefixtures("jwks_server")
def test_metadata_for_unknown_resource_path_is_404() -> None:
    res = client.get("/.well-known/oauth-protected-resource/other")
    assert res.status_code == 404


def test_metadata_is_404_in_api_key_mode() -> None:
    assert client.get("/.well-known/oauth-protected-resource").status_code == 404


@pytest.mark.usefixtures("jwks_server")
@pytest.mark.parametrize("path", [INSPECT, JSONRPC])
def test_missing_token_returns_401_with_resource_metadata_challenge(
    path: str,
) -> None:
    res = client.post(path, json=CALL)
    assert res.status_code == 401
    assert res.headers["WWW-Authenticate"] == (
        f'Bearer resource_metadata="{METADATA_URL}"'
    )


@pytest.mark.usefixtures("jwks_server")
@pytest.mark.parametrize(
    "token",
    [
        _token(_claims(aud="https://other.example.com")),
        _token(_claims(iss="https://evil.example.com")),
        _token(_claims(exp=int(time.time()) - 3600)),
        _none_token(),
    ],
)
def test_invalid_token_returns_401_invalid_token(token: str) -> None:
    res = client.post(INSPECT, json=CALL, headers=_bearer(token))
    assert res.status_code == 401
    challenge = res.headers["WWW-Authenticate"]
    assert challenge.startswith(f'Bearer resource_metadata="{METADATA_URL}"')
    assert 'error="invalid_token"' in challenge
    assert firewall.list_audit_entries() == []


@pytest.mark.usefixtures("jwks_server")
def test_audit_endpoints_require_bearer_token_in_oauth_mode() -> None:
    assert client.get("/api/v1/audit").status_code == 401
    assert client.get("/api/v1/audit/verify").status_code == 401
    assert client.get("/api/v1/audit/verify", headers=_bearer()).status_code == 200


@pytest.mark.usefixtures("jwks_server")
def test_inspect_derives_agent_id_from_token_not_body() -> None:
    res = client.post(
        INSPECT, json={**CALL, "agent_id": "spoofed-admin"}, headers=_bearer()
    )
    assert res.status_code == 200
    [entry] = firewall.list_audit_entries()
    assert entry.agent_id == "agent-alpha"


@pytest.mark.usefixtures("jwks_server")
def test_jsonrpc_ignores_self_declared_agent_header_and_strips_token() -> None:
    recorder = _wire_upstream()
    token = _token()
    res = client.post(
        JSONRPC,
        json=RPC,
        headers={
            **_bearer(token),
            "X-Aegis-Agent-Id": "spoofed-admin",
            "X-Aegis-MCP-Server": "git-mcp",
        },
    )
    assert res.json()["result"] == {"ok": True}
    [entry] = firewall.list_audit_entries()
    assert entry.agent_id == "agent-alpha"
    [forwarded] = recorder.requests
    assert "authorization" not in forwarded.headers
    assert token.encode() not in forwarded.content


def test_upstream_hop_strips_credentials_even_from_client_defaults() -> None:
    recorder = UpstreamRecorder()
    gateway = JsonRpcGateway(
        firewall=firewall,
        upstreams={"git-mcp": UPSTREAM_URL},
        client=httpx.Client(
            transport=httpx.MockTransport(recorder),
            headers={"Authorization": "Bearer leaked", "Cookie": "s=1"},
        ),
    )
    response = gateway.handle(
        json.dumps(RPC).encode(), {"agent_id": "a", "server_name": "git-mcp"}
    )
    assert response["result"] == {"ok": True}
    [forwarded] = recorder.requests
    assert "authorization" not in forwarded.headers
    assert "cookie" not in forwarded.headers


def test_jwks_outage_returns_503() -> None:
    server = JwksServer([RSA_JWK])
    server.status = 500
    resource_server.configure(_config(), _cache(server))
    res = client.post(INSPECT, json=CALL, headers=_bearer())
    assert res.status_code == 503


# ---------------------------------------------------------------------------
# api_key fallback (local development)
# ---------------------------------------------------------------------------


def test_api_key_mode_keeps_x_api_key_and_self_declared_identity() -> None:
    settings.api_key = "local-dev-key"
    assert client.post(INSPECT, json=CALL).status_code == 401
    assert client.post(INSPECT, json=CALL, headers=_bearer()).status_code == 401
    res = client.post(
        INSPECT,
        json={**CALL, "agent_id": "dev-agent"},
        headers={"X-API-Key": "local-dev-key"},
    )
    assert res.status_code == 200
    [entry] = firewall.list_audit_entries()
    assert entry.agent_id == "dev-agent"


def test_api_key_mode_without_key_stays_open_for_local_dev() -> None:
    assert client.post(INSPECT, json=CALL).status_code == 200
