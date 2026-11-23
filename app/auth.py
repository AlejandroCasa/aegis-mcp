"""OAuth 2.1 Resource Server for Aegis-MCP (MCP authorization specification).

Implements the resource-server half of the MCP authorization spec:

* Bearer JWT access-token validation (``iss``, ``aud``, ``exp``, ``nbf``)
  against the authorization server's JWKS, fetched over a hardened client and
  cached with TTL plus rate-limited forced refresh on unknown ``kid`` (key
  rotation).
* Only an explicit allow-list of asymmetric algorithms is accepted. ``none``
  and every ``HS*`` algorithm are rejected at configuration time and again at
  validation time, and each JWK's ``kty``/``crv`` must match the token's
  ``alg`` so a public key can never be reused as an HMAC secret
  (algorithm-confusion attacks).
* RFC 8707 audience binding: the token ``aud`` must contain this resource's
  canonical identifier.
* RFC 9728 Protected Resource Metadata and ``WWW-Authenticate`` challenges
  pointing clients at it.
* The caller identity (``agent_id``) is derived only from validated claims
  (``sub`` -> ``azp`` -> ``client_id``).
"""

import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt

logger = logging.getLogger("aegis_mcp.auth")

AuthMode = Literal["api_key", "oauth"]

# alg -> (required JWK kty, required JWK crv or None)
ALGORITHM_KEY_TYPES: dict[str, tuple[str, str | None]] = {
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "EdDSA": ("OKP", None),
}
ASYMMETRIC_ALGORITHMS = frozenset(ALGORITHM_KEY_TYPES)
ASYMMETRIC_KEY_TYPES = frozenset(kty for kty, _ in ALGORITHM_KEY_TYPES.values())

WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource"
MAX_TOKEN_LENGTH = 8192
MAX_JWKS_BYTES = 262_144
MAX_AGENT_ID_LENGTH = 256
AGENT_ID_CLAIMS = ("sub", "azp", "client_id")
REQUIRED_CLAIMS = ["exp", "iss", "aud"]
CREDENTIAL_HEADERS = ("authorization", "proxy-authorization", "cookie")


class AuthError(Exception):
    """An RFC 6750 bearer-token error rendered as ``401`` + ``WWW-Authenticate``.

    ``error`` is ``None`` when no credentials were presented (RFC 6750 §3.1:
    the challenge then carries no error code).
    """

    def __init__(self, description: str, error: str | None = "invalid_token") -> None:
        """Store the RFC 6750 error code and a non-sensitive description."""
        super().__init__(description)
        self.error = error
        self.description = description


class AuthUnavailableError(Exception):
    """The authorization server's JWKS could not be obtained (``503``)."""


@dataclass(frozen=True)
class Principal:
    """An authenticated caller derived exclusively from validated token claims."""

    agent_id: str
    subject: str | None
    client_id: str | None
    scopes: frozenset[str]
    claims: Mapping[str, Any] = field(repr=False)


def validate_algorithms(algorithms: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """Return the algorithm allow-list, rejecting ``none``, ``HS*``, and unknowns."""
    if not algorithms:
        raise ValueError("At least one asymmetric JWT algorithm must be allowed.")
    rejected = sorted(set(algorithms) - ASYMMETRIC_ALGORITHMS)
    if rejected:
        raise ValueError(
            f"Unsupported or insecure JWT algorithms {rejected}: only asymmetric "
            f"algorithms {sorted(ASYMMETRIC_ALGORITHMS)} are allowed."
        )
    return tuple(dict.fromkeys(algorithms))


def canonical_resource(resource: str) -> str:
    """Validate an RFC 8707 resource identifier (absolute https URI, no fragment)."""
    parts = urlsplit(resource)
    local = parts.hostname in ("localhost", "127.0.0.1")
    if (
        parts.scheme not in ("https", "http")
        or (parts.scheme == "http" and not local)
        or not parts.hostname
        or parts.fragment
    ):
        raise ValueError(
            "AEGIS_OAUTH_AUDIENCE must be an absolute https URI without a fragment "
            "(http is only allowed for localhost)."
        )
    return resource


def metadata_url_for(resource: str) -> str:
    """Build the RFC 9728 §3.1 metadata URL for a resource identifier."""
    parts = urlsplit(resource)
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, WELL_KNOWN_PATH + path, "", ""))


@dataclass(frozen=True)
class OAuthConfig:
    """Validated OAuth 2.1 resource-server configuration."""

    issuer: str
    resource: str
    jwks_url: str
    algorithms: tuple[str, ...] = ("RS256", "ES256")
    authorization_servers: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()
    leeway_seconds: int = 30
    jwks_cache_seconds: int = 300

    def __post_init__(self) -> None:
        """Fail closed on incomplete or insecure configuration."""
        if not self.issuer or not self.jwks_url:
            raise ValueError(
                "OAuth mode requires AEGIS_OAUTH_ISSUER and AEGIS_OAUTH_JWKS_URL."
            )
        canonical_resource(self.resource)
        object.__setattr__(self, "algorithms", validate_algorithms(self.algorithms))
        if urlsplit(self.jwks_url).scheme not in ("https", "http"):
            raise ValueError("AEGIS_OAUTH_JWKS_URL must be an http(s) URL.")
        if not 0 <= self.leeway_seconds <= 300:
            raise ValueError("AEGIS_OAUTH_LEEWAY_SECONDS must be within [0, 300].")

    @property
    def metadata_url(self) -> str:
        """Return the RFC 9728 metadata URL advertised in challenges."""
        return metadata_url_for(self.resource)


def _usable_jwk(jwk: Any) -> bool:
    """Accept only asymmetric signature keys (never ``oct``/HMAC secrets)."""
    if not isinstance(jwk, dict):
        return False
    return jwk.get("kty") in ASYMMETRIC_KEY_TYPES and jwk.get("use", "sig") == "sig"


def parse_jwks(document: Any) -> dict[str | None, dict[str, Any]]:
    """Index usable JWKs by ``kid`` (``None`` for a kid-less key)."""
    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list):
        raise AuthUnavailableError("JWKS document has no 'keys' array.")
    indexed: dict[str | None, dict[str, Any]] = {}
    for jwk in filter(_usable_jwk, keys):
        kid = jwk.get("kid")
        indexed[kid if isinstance(kid, str) else None] = jwk
    return indexed


def build_jwks_client() -> httpx.Client:
    """Build the hardened JWKS client (no redirects, no env proxies)."""
    return httpx.Client(
        timeout=5.0,
        follow_redirects=False,
        trust_env=False,
        headers={"Accept": "application/json"},
    )


class JWKSCache:
    """Thread-safe TTL cache of the authorization server's signing keys.

    An unknown ``kid`` triggers a forced refresh (key rotation), rate-limited
    by ``min_refresh_seconds`` so forged ``kid`` values cannot be used to
    hammer the authorization server.
    """

    def __init__(
        self,
        jwks_url: str,
        ttl_seconds: float = 300.0,
        client: httpx.Client | None = None,
        min_refresh_seconds: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Bind the JWKS URL, cache policy, HTTP client, and clock."""
        self.jwks_url = jwks_url
        self.ttl_seconds = ttl_seconds
        self.min_refresh_seconds = min_refresh_seconds
        self.client = client or build_jwks_client()
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str | None, dict[str, Any]] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self.fetch_count = 0

    def get_key(self, kid: str | None) -> dict[str, Any]:
        """Return the JWK for ``kid``, refreshing on expiry or rotation."""
        with self._lock:
            if self._is_expired():
                self._refresh()
            jwk = self._lookup(kid)
            if jwk is None and self._may_force_refresh():
                self._refresh()
                jwk = self._lookup(kid)
            never_loaded = self._fetched_at is None
        if never_loaded:
            raise AuthUnavailableError("JWKS has not been loaded yet.")
        if jwk is None:
            raise AuthError("Token signing key is not trusted.")
        return jwk

    def _lookup(self, kid: str | None) -> dict[str, Any] | None:
        """Find a key by kid; a kid-less token needs exactly one trusted key."""
        if kid is None and len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return self._keys.get(kid) if kid is not None else None

    def _is_expired(self) -> bool:
        """Return True when the cached key set is missing or past its TTL."""
        if self._fetched_at is None:
            return self._may_force_refresh()
        return self._clock() - self._fetched_at >= self.ttl_seconds

    def _may_force_refresh(self) -> bool:
        """Rate-limit network fetches to one per ``min_refresh_seconds``."""
        if self._attempted_at is None:
            return True
        return self._clock() - self._attempted_at >= self.min_refresh_seconds

    def _refresh(self) -> None:
        """Fetch the JWKS; keep the previous keys if the fetch fails."""
        self._attempted_at = self._clock()
        try:
            keys = parse_jwks(self._fetch())
        except AuthUnavailableError:
            logger.warning("JWKS refresh from %s failed.", self.jwks_url)
            if self._fetched_at is None:
                raise
            return
        self._keys = keys
        self._fetched_at = self._clock()

    def _fetch(self) -> Any:
        """Download and decode the size-capped JWKS document."""
        self.fetch_count += 1
        try:
            with self.client.stream("GET", self.jwks_url) as response:
                if response.status_code != httpx.codes.OK:
                    raise AuthUnavailableError("JWKS endpoint returned an error.")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_JWKS_BYTES:
                        raise AuthUnavailableError("JWKS document too large.")
            return json.loads(body)
        except (httpx.HTTPError, ValueError) as exc:
            raise AuthUnavailableError("JWKS endpoint is unreachable.") from exc


def _check_key_matches_alg(jwk: Mapping[str, Any], alg: str) -> None:
    """Bind the JWK type (and curve) to the token algorithm."""
    kty, crv = ALGORITHM_KEY_TYPES[alg]
    declared = jwk.get("alg")
    if (
        jwk.get("kty") != kty
        or (crv is not None and jwk.get("crv") != crv)
        or (declared is not None and declared != alg)
    ):
        raise AuthError("Token algorithm does not match the signing key.")


def _derive_agent_id(claims: Mapping[str, Any]) -> str:
    """Return the first non-empty identity claim (``sub``/``azp``/``client_id``)."""
    for claim in AGENT_ID_CLAIMS:
        value = claims.get(claim)
        if isinstance(value, str) and 0 < len(value) <= MAX_AGENT_ID_LENGTH:
            return value
    raise AuthError("Token carries no usable subject or client identity.")


def _scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    """Read granted scopes from ``scope`` (RFC 9068) or ``scp`` claims."""
    scope = claims.get("scope")
    if isinstance(scope, str):
        return frozenset(scope.split())
    scp = claims.get("scp")
    if isinstance(scp, list):
        return frozenset(s for s in scp if isinstance(s, str))
    return frozenset()


def _optional_str(claims: Mapping[str, Any], name: str) -> str | None:
    """Return a string claim or None."""
    value = claims.get(name)
    return value if isinstance(value, str) else None


class TokenValidator:
    """Validates bearer JWT access tokens for this protected resource."""

    def __init__(self, config: OAuthConfig, jwks: JWKSCache) -> None:
        """Bind validated configuration and the JWKS cache."""
        self.config = config
        self.jwks = jwks

    def validate(self, token: str) -> Principal:
        """Verify signature and claims; return the caller's Principal."""
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise AuthError("Malformed bearer token.")
        alg, kid = self._header(token)
        jwk = self.jwks.get_key(kid)
        _check_key_matches_alg(jwk, alg)
        claims = self._decode(token, jwk, alg)
        return Principal(
            agent_id=_derive_agent_id(claims),
            subject=_optional_str(claims, "sub"),
            client_id=_optional_str(claims, "client_id")
            or _optional_str(claims, "azp"),
            scopes=_scopes(claims),
            claims=claims,
        )

    def _header(self, token: str) -> tuple[str, str | None]:
        """Read and vet the unverified JOSE header (alg allow-list, kid)."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("Malformed bearer token.") from exc
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self.config.algorithms:
            raise AuthError("Token algorithm is not allowed.")
        kid = header.get("kid")
        if kid is not None and not isinstance(kid, str):
            raise AuthError("Malformed bearer token.")
        return alg, kid

    def _decode(self, token: str, jwk: dict[str, Any], alg: str) -> dict[str, Any]:
        """Verify the signature, issuer, RFC 8707 audience, and lifetime."""
        try:
            key = jwt.PyJWK(jwk, algorithm=alg).key
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=self.config.resource,
                issuer=self.config.issuer,
                leeway=self.config.leeway_seconds,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("Token has expired.") from exc
        except jwt.ImmatureSignatureError as exc:
            raise AuthError("Token is not yet valid.") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("Token audience does not match this resource.") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("Token issuer is not trusted.") from exc
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            raise AuthError("Token validation failed.") from exc
        return claims


def _quote(value: str) -> str:
    """Quote an auth-param value (RFC 9110 quoted-string)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


class ResourceServer:
    """Runtime OAuth resource-server facade (disabled in ``api_key`` mode)."""

    def __init__(
        self, config: OAuthConfig | None = None, jwks: JWKSCache | None = None
    ) -> None:
        """Enable OAuth mode when a configuration is supplied."""
        self.validator: TokenValidator | None = None
        self.configure(config, jwks)

    def configure(
        self, config: OAuthConfig | None, jwks: JWKSCache | None = None
    ) -> None:
        """Atomically (re)configure or disable OAuth mode."""
        if config is None:
            self.validator = None
            return
        cache = jwks or JWKSCache(
            config.jwks_url, ttl_seconds=float(config.jwks_cache_seconds)
        )
        self.validator = TokenValidator(config, cache)

    @property
    def enabled(self) -> bool:
        """Return True when OAuth bearer authentication is enforced."""
        return self.validator is not None

    def authenticate(self, authorization: str | None) -> Principal:
        """Validate an ``Authorization: Bearer`` header value."""
        if self.validator is None:
            raise RuntimeError("OAuth resource server is not enabled.")
        if not authorization:
            raise AuthError("Bearer token required.", error=None)
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise AuthError("Malformed Authorization header.", error="invalid_request")
        return self.validator.validate(token.strip())

    def challenge(self, error: AuthError | None = None) -> str:
        """Build the RFC 6750 / RFC 9728 ``WWW-Authenticate`` header value."""
        params: list[str] = []
        if self.validator is not None:
            url = self.validator.config.metadata_url
            params.append(f"resource_metadata={_quote(url)}")
        if error is not None and error.error is not None:
            params.append(f"error={_quote(error.error)}")
            params.append(f"error_description={_quote(error.description)}")
        return "Bearer " + ", ".join(params) if params else "Bearer"

    def metadata(self) -> dict[str, Any]:
        """Return the RFC 9728 Protected Resource Metadata document."""
        if self.validator is None:
            raise RuntimeError("OAuth resource server is not enabled.")
        config = self.validator.config
        document: dict[str, Any] = {
            "resource": config.resource,
            "authorization_servers": list(
                config.authorization_servers or (config.issuer,)
            ),
            "bearer_methods_supported": ["header"],
            "resource_name": "Aegis-MCP",
        }
        if config.scopes_supported:
            document["scopes_supported"] = list(config.scopes_supported)
        return document

    def serves_metadata_path(self, path: str) -> bool:
        """Match a request path against the RFC 9728 metadata location."""
        if self.validator is None:
            return False
        expected = urlsplit(self.validator.config.metadata_url).path
        return path.rstrip("/") in (expected, WELL_KNOWN_PATH)


def strip_credentials(headers: httpx.Headers) -> None:
    """Remove caller credentials before any upstream hop (no token passthrough)."""
    for name in CREDENTIAL_HEADERS:
        headers.pop(name, None)


def build_resource_server(
    auth_mode: AuthMode, config_factory: Callable[[], OAuthConfig]
) -> ResourceServer:
    """Create the resource server; OAuth mode fails closed on bad config."""
    if auth_mode == "oauth":
        return ResourceServer(config_factory())
    return ResourceServer()
