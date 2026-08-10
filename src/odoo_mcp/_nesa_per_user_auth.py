"""NESA per-user authentication for streamable-http transport.

The NESA Odoo bridge (``nesa_mcp_bridge``) emits two HTTP request headers
when it talks to the MCP-server:

* ``X-Odoo-User``    — Odoo login of the human acting via the agent.
* ``X-Odoo-Api-Key`` — Plain Odoo API key bound to that login (Fernet-
  decrypted on the bridge side, only transmitted in transit over TLS).

Phase A (pre-PR1-Patch-2) the fork honored neither header and operated
with a single service-account from ``ODOO_API_KEY``. This module wires
per-user behaviour into the fork without touching the public tool API:

1. An ASGI middleware (``NesaPerUserAuthMiddleware``) intercepts every
   request that enters the streamable-http app, extracts the two headers
   and pins them onto a request-scoped :class:`contextvars.ContextVar`.
2. :func:`get_per_user_client` looks at that context variable and returns
   a per-credential :class:`~odoo_mcp.odoo_client.OdooClient` (cached, with
   TTL); when no header is present, it returns ``None`` so explicitly
   lenient transports can use the env-based service-account client.

The cache lives in-process and is keyed by login plus a SHA-256 fingerprint
of the API key. Network authentication happens outside the cache lock, so a
slow Odoo login never serializes unrelated users. Stateful MCP session IDs
are bound to the same credential fingerprint to prevent cross-user session
reuse.

Strict mode:
    Network transports fail closed by default and reject requests that lack
    both headers with HTTP 401. ``ODOO_MCP_REQUIRE_PER_USER`` can explicitly
    override that posture; stdio remains service-account compatible.

Audit logging:
    Every successful per-user resolution emits a structured ``[per_user]
    acting-as`` log line. Operators can grep these to verify that
    multi-tenant calls map to the right Odoo user.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
import time
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Optional, Tuple

_logger = logging.getLogger(__name__)

_USER_HEADER = "x-odoo-user"
_KEY_HEADER = "x-odoo-api-key"
_SESSION_HEADER = "mcp-session-id"
_REQUIRE_ENV = "ODOO_MCP_REQUIRE_PER_USER"
_CACHE_TTL_ENV = "ODOO_MCP_PER_USER_CACHE_TTL"
_CACHE_TTL_DEFAULT_SECONDS = 600  # 10 minutes; rotation happens every 90 days
_CACHE_MAX_ENTRIES_ENV = "ODOO_MCP_PER_USER_CACHE_MAX"
_CACHE_MAX_ENTRIES_DEFAULT = 64
_SESSION_IDLE_TIMEOUT_ENV = "MCP_SESSION_IDLE_TIMEOUT"
_SESSION_IDLE_TIMEOUT_DEFAULT_SECONDS = 1800
_SESSION_MAX_ENTRIES_ENV = "ODOO_MCP_SESSION_BINDING_MAX"
_SESSION_MAX_ENTRIES_DEFAULT = 1024
_runtime_transport: Optional[str] = None

# Request-scoped (login, api_key). ``None`` when no header was present.
_current_user_context: ContextVar[Optional[Tuple[str, str]]] = ContextVar(
    "nesa_mcp_user_context", default=None,
)

# Cache: (login, SHA-256(api_key)) -> (client, expires_at). Raw keys are never
# retained as dictionary keys or emitted to logs. Guarded by ``_lock``.
CredentialIdentity = Tuple[str, bytes]
_lock = threading.Lock()
_client_cache: dict[CredentialIdentity, Tuple[Any, float]] = {}

# FastMCP keeps an AppContext (and therefore a lazy OdooClient) per stateful
# MCP session. Bind every server-issued session ID to the same credential
# identity for the configured idle lifetime. FastMCP's own session state is
# process-local and cleared on restart; successful DELETE removes both.
_session_lock = threading.Lock()
_session_bindings: dict[str, Tuple[CredentialIdentity, float]] = {}
_SERVICE_ACCOUNT_IDENTITY: CredentialIdentity = ("<service-account>", b"")


def _cache_ttl_seconds() -> int:
    raw = os.environ.get(_CACHE_TTL_ENV, "").strip()
    if not raw:
        return _CACHE_TTL_DEFAULT_SECONDS
    try:
        return max(60, int(raw))
    except ValueError:
        _logger.warning(
            "[per_user] invalid %s=%r, falling back to %ds",
            _CACHE_TTL_ENV, raw, _CACHE_TTL_DEFAULT_SECONDS,
        )
        return _CACHE_TTL_DEFAULT_SECONDS


def _cache_max_entries() -> int:
    raw = os.environ.get(_CACHE_MAX_ENTRIES_ENV, "").strip()
    if not raw:
        return _CACHE_MAX_ENTRIES_DEFAULT
    try:
        return max(8, int(raw))
    except ValueError:
        return _CACHE_MAX_ENTRIES_DEFAULT


def session_idle_timeout_seconds() -> float:
    """Shared idle timeout for FastMCP sessions and credential bindings."""
    raw = os.environ.get(_SESSION_IDLE_TIMEOUT_ENV, "").strip()
    if not raw:
        return float(_SESSION_IDLE_TIMEOUT_DEFAULT_SECONDS)
    try:
        return max(60.0, float(raw))
    except ValueError:
        _logger.warning(
            "[per_user] invalid %s=%r, falling back to %ds",
            _SESSION_IDLE_TIMEOUT_ENV,
            raw,
            _SESSION_IDLE_TIMEOUT_DEFAULT_SECONDS,
        )
        return float(_SESSION_IDLE_TIMEOUT_DEFAULT_SECONDS)


def _session_max_entries() -> int:
    raw = os.environ.get(_SESSION_MAX_ENTRIES_ENV, "").strip()
    if not raw:
        return _SESSION_MAX_ENTRIES_DEFAULT
    try:
        return max(16, int(raw))
    except ValueError:
        return _SESSION_MAX_ENTRIES_DEFAULT


def set_runtime_transport(transport: str) -> None:
    """Set the effective parsed CLI transport for fail-closed decisions."""
    global _runtime_transport
    _runtime_transport = transport.strip().lower()


def strict_mode_enabled() -> bool:
    transport = _runtime_transport or os.environ.get("MCP_TRANSPORT", "stdio")
    transport_default = transport.strip().lower() in {
        "streamable-http",
        "sse",
    }
    configured = os.environ.get(_REQUIRE_ENV)
    if configured is None:
        # Network transports default fail-closed. Stdio keeps upstream's
        # explicit env/service-account behavior unless the operator opts in.
        return transport_default
    normalized = configured.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    _logger.error(
        "[per_user] invalid %s=%r; using fail-closed transport default for %s",
        _REQUIRE_ENV,
        configured,
        transport,
    )
    return transport_default


def set_user_context(login: Optional[str], api_key: Optional[str]) -> Any:
    """Pin (login, api_key) onto the current request's contextvar.

    Returns the previous token so callers can restore it; the ASGI
    middleware uses that to keep request scopes from leaking into each
    other when uvicorn re-uses worker threads.
    """
    if login and api_key:
        token = _current_user_context.set((login, api_key))
    else:
        token = _current_user_context.set(None)
    return token


def reset_user_context(token: Any) -> None:
    """Restore the contextvar token issued by :func:`set_user_context`."""
    try:
        _current_user_context.reset(token)
    except (ValueError, LookupError):
        # token issued in a different context (e.g. background task) —
        # safe to ignore, the original context tear-down will handle it.
        pass


def current_user_context() -> Optional[Tuple[str, str]]:
    """Return ``(login, api_key)`` for the current request, or ``None``."""
    return _current_user_context.get()


def _credential_identity(login: str, api_key: str) -> CredentialIdentity:
    """Return a cache/session identity without retaining the raw API key."""
    return login, hashlib.sha256(api_key.encode("utf-8")).digest()


def _identities_match(
    first: CredentialIdentity, second: CredentialIdentity,
) -> bool:
    """Compare credential identities without timing-leaking key fingerprints."""
    return first[0] == second[0] and hmac.compare_digest(first[1], second[1])


def _build_per_user_client(login: str, api_key: str) -> Any:
    """Construct a per-user OdooClient using env-based connection params
    but with ``username=login`` + ``password=api_key`` overrides.

    Reuses :func:`odoo_mcp.odoo_client.load_config` so URL/DB/timeout/
    SSL-verify/transport defaults track the service-account
    configuration. Only the credentials swap.
    """
    # Local import: avoid circular dependency at module-load time and
    # keep unit tests of this module lightweight.
    from .odoo_client import OdooClient, load_config, normalize_transport, parse_bool

    config = load_config()
    timeout = int(os.environ.get("ODOO_TIMEOUT", "30"))
    verify_ssl = os.environ.get("ODOO_VERIFY_SSL", "1").lower() in {"1", "true", "yes"}
    transport = normalize_transport(
        os.environ.get("ODOO_TRANSPORT", config.get("transport", "xmlrpc"))
    )
    json2_database_header = parse_bool(
        os.environ.get(
            "ODOO_JSON2_DATABASE_HEADER",
            config.get("json2_database_header", "1"),
        )
    )
    lang = os.environ.get("ODOO_LOCALE", config.get("lang")) or None
    return OdooClient(
        url=config["url"],
        db=config["db"],
        username=login,
        password=api_key,
        timeout=timeout,
        verify_ssl=verify_ssl,
        transport=transport,
        api_key=api_key,
        json2_database_header=json2_database_header,
        lang=lang,
    )


def get_per_user_client() -> Optional[Any]:
    """Return a cached per-user OdooClient, or ``None`` if no header was set.

    Strict mode (``ODOO_MCP_REQUIRE_PER_USER=1``) raises ``PermissionError``
    when the contextvar is unset, signalling that the global env fallback
    must NOT be used. The middleware turns that into HTTP 401.
    """
    ctx = _current_user_context.get()
    if ctx is None:
        if strict_mode_enabled():
            raise PermissionError(
                "Strict per-user mode is enabled but request lacks "
                "X-Odoo-User / X-Odoo-Api-Key headers."
            )
        return None
    login, api_key = ctx
    identity = _credential_identity(login, api_key)
    now = time.monotonic()
    ttl = _cache_ttl_seconds()
    with _lock:
        cached = _client_cache.get(identity)
        if cached and cached[1] > now:
            return cached[0]
        for stale_identity, (_c, expires) in list(_client_cache.items()):
            if expires <= now:
                _client_cache.pop(stale_identity, None)

    # OdooClient authenticates during construction. Keep this network call
    # outside the global lock so one slow/broken Odoo login cannot block every
    # other user. A same-credential race is resolved by the second cache check.
    try:
        client = _build_per_user_client(login, api_key)
    except Exception:
        _logger.exception(
            "[per_user] failed to build per-user client for login=%s", login,
        )
        raise

    now = time.monotonic()
    with _lock:
        cached = _client_cache.get(identity)
        if cached and cached[1] > now:
            return cached[0]
        for stale_identity, (_c, expires) in list(_client_cache.items()):
            if expires <= now:
                _client_cache.pop(stale_identity, None)
        if len(_client_cache) >= _cache_max_entries():
            # Drop oldest entry by expires_at.
            oldest = min(_client_cache, key=lambda k: _client_cache[k][1])
            _client_cache.pop(oldest, None)
        _client_cache[identity] = (client, now + ttl)
    _logger.info(
        "[per_user] acting-as login=%s uid=%s ttl=%ds",
        login, getattr(client, "uid", "?"), ttl,
    )
    return client


def reset_for_tests() -> None:
    """Drop all cached clients and session bindings. Tests-only."""
    global _runtime_transport
    with _lock:
        _client_cache.clear()
    with _session_lock:
        _session_bindings.clear()
    _runtime_transport = None


class NesaPerUserAuthMiddleware:
    """ASGI middleware that pins per-request user context onto a ContextVar.

    Reads ``X-Odoo-User`` and ``X-Odoo-Api-Key`` from the incoming HTTP
    headers and stores them via :func:`set_user_context` for the lifetime
    of the request. On exit the previous token is restored so worker-
    thread reuse never leaks credentials across requests.

    Strict mode: if ``ODOO_MCP_REQUIRE_PER_USER=1`` and the headers are
    missing on a non-lifespan request, the middleware short-circuits with
    HTTP 401 before the request reaches FastMCP's session manager.

    Only the configured Streamable HTTP endpoint reaches authentication.
    Every other HTTP path returns a plain 404 first. This prevents clients
    from mistaking the per-user 401 challenge for OAuth support while also
    suppressing Starlette's automatic trailing-slash redirects.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        mcp_path: str,
    ) -> None:
        if not mcp_path.startswith("/"):
            raise ValueError("mcp_path must be an absolute HTTP path")
        self.app = app
        self.mcp_path = mcp_path

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            # lifespan, websocket — pass through untouched.
            await self.app(scope, receive, send)
            return

        if scope.get("path") != self.mcp_path:
            await self._send_error(send, 404, "Not Found.")
            return

        try:
            login, api_key = self._extract_headers(scope)
            session_id = self._extract_single_header(scope, _SESSION_HEADER)
        except ValueError:
            await self._send_error(send, 400, "Duplicate authentication header.")
            return

        if (login is None) != (api_key is None):
            await self._send_error(
                send,
                401,
                "X-Odoo-User and X-Odoo-Api-Key must be supplied together.",
                authenticate=True,
            )
            return

        if strict_mode_enabled() and not (login and api_key):
            await self._send_error(
                send, 401, "Per-user authentication required.", authenticate=True,
            )
            return

        identity = (
            _credential_identity(login, api_key)
            if login and api_key
            else _SERVICE_ACCOUNT_IDENTITY
        )
        if session_id and not self._session_matches(session_id, identity):
            await self._send_error(
                send, 403, "MCP session is not bound to these credentials.",
            )
            return

        token = set_user_context(login, api_key)
        response_status = 0

        async def send_with_session_binding(message: dict) -> None:
            nonlocal response_status
            if message.get("type") == "http.response.start":
                response_status = int(message.get("status", 0))
                response_session_id = self._single_header_value(
                    message.get("headers", []) or [], _SESSION_HEADER,
                )
                if response_session_id:
                    self._bind_session(response_session_id, identity)
            await send(message)

        try:
            await self.app(scope, receive, send_with_session_binding)
        finally:
            reset_user_context(token)
            if (
                scope.get("method", "").upper() == "DELETE"
                and 200 <= response_status < 300
                and session_id
            ):
                with _session_lock:
                    _session_bindings.pop(session_id, None)

    @staticmethod
    def _extract_headers(scope: dict) -> Tuple[Optional[str], Optional[str]]:
        """Return the two auth headers, rejecting ambiguous duplicates."""
        return (
            NesaPerUserAuthMiddleware._extract_single_header(scope, _USER_HEADER),
            NesaPerUserAuthMiddleware._extract_single_header(scope, _KEY_HEADER),
        )

    @staticmethod
    def _extract_single_header(scope: dict, wanted_name: str) -> Optional[str]:
        return NesaPerUserAuthMiddleware._single_header_value(
            scope.get("headers", []) or [], wanted_name,
        )

    @staticmethod
    def _single_header_value(
        headers: list[tuple[bytes, bytes]], wanted_name: str,
    ) -> Optional[str]:
        values = [
            raw_value.decode("latin-1").strip()
            for raw_name, raw_value in headers
            if raw_name.decode("latin-1").lower() == wanted_name
        ]
        if len(values) > 1:
            raise ValueError(f"Duplicate {wanted_name} header")
        if not values:
            return None
        return values[0] or None

    @staticmethod
    def _session_matches(
        session_id: str, identity: CredentialIdentity,
    ) -> bool:
        now = time.monotonic()
        with _session_lock:
            NesaPerUserAuthMiddleware._evict_expired_sessions(now)
            binding = _session_bindings.get(session_id)
            if binding is None or not _identities_match(binding[0], identity):
                return False
            _session_bindings[session_id] = (
                binding[0], now + session_idle_timeout_seconds(),
            )
            return True

    @staticmethod
    def _bind_session(
        session_id: str, identity: CredentialIdentity,
    ) -> None:
        now = time.monotonic()
        with _session_lock:
            NesaPerUserAuthMiddleware._evict_expired_sessions(now)
            binding = _session_bindings.get(session_id)
            if binding is not None and not _identities_match(binding[0], identity):
                raise PermissionError(
                    "Server attempted to reuse an MCP session across credentials"
                )
            if binding is None and len(_session_bindings) >= _session_max_entries():
                # Keep memory bounded without failing a response after FastMCP
                # already emitted its response-start. The least-recently-used
                # approximation has the earliest sliding expiry.
                oldest = min(
                    _session_bindings,
                    key=lambda key: _session_bindings[key][1],
                )
                _session_bindings.pop(oldest, None)
            _session_bindings[session_id] = (
                identity, now + session_idle_timeout_seconds(),
            )

    @staticmethod
    def _evict_expired_sessions(now: float) -> None:
        """Remove idle bindings while the caller holds ``_session_lock``."""
        for stale_id, (_identity, expires_at) in list(_session_bindings.items()):
            if expires_at <= now:
                _session_bindings.pop(stale_id, None)

    @staticmethod
    async def _send_error(
        send: Callable, status: int, body: str, *, authenticate: bool = False,
    ) -> None:
        headers = [(b"content-type", b"text/plain; charset=utf-8")]
        if authenticate:
            headers.append((b"www-authenticate", b'Bearer realm="nesa-mcp"'))
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        })
        await send({
            "type": "http.response.body",
            "body": body.encode("utf-8"),
        })


def describe_state() -> dict[str, Any]:
    """Expose non-secret per-user security state for runtime diagnostics."""
    with _lock:
        cached_client_count = len(_client_cache)
    with _session_lock:
        NesaPerUserAuthMiddleware._evict_expired_sessions(time.monotonic())
        session_binding_count = len(_session_bindings)
    return {
        "strict_mode": strict_mode_enabled(),
        "runtime_transport": (
            _runtime_transport or os.environ.get("MCP_TRANSPORT", "stdio")
        ).strip().lower(),
        "credential_cache_ttl_seconds": _cache_ttl_seconds(),
        "credential_cache_max_entries": _cache_max_entries(),
        "credential_cache_entry_count": cached_client_count,
        "session_idle_timeout_seconds": session_idle_timeout_seconds(),
        "session_binding_max_entries": _session_max_entries(),
        "session_binding_count": session_binding_count,
    }
