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
   a per-login :class:`~odoo_mcp.odoo_client.OdooClient` (cached, with
   TTL); when no header is present, it returns ``None`` so callers can
   fall back to the env-based service-account client.

The cache lives in-process. A coarse-grained lock guards concurrent
inserts so that two simultaneous tool calls from the same user re-use
the same OdooClient instead of triggering two parallel XML-RPC
``authenticate`` round-trips against Odoo.

Strict mode:
    Set ``ODOO_MCP_REQUIRE_PER_USER=1`` to reject any incoming request
    that lacks both headers with HTTP 401. Default is permissive (use
    env-fallback) for local diagnostics and the initial rollout.

Audit logging:
    Every successful per-user resolution emits a structured ``[per_user]
    acting-as`` log line. Operators can grep these to verify that
    multi-tenant calls map to the right Odoo user.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from contextvars import ContextVar
from typing import Any, Awaitable, Callable, Optional, Tuple

_logger = logging.getLogger(__name__)

_USER_HEADER = "x-odoo-user"
_KEY_HEADER = "x-odoo-api-key"
_REQUIRE_ENV = "ODOO_MCP_REQUIRE_PER_USER"
_CACHE_TTL_ENV = "ODOO_MCP_PER_USER_CACHE_TTL"
_CACHE_TTL_DEFAULT_SECONDS = 600  # 10 minutes; rotation happens every 90 days
_CACHE_MAX_ENTRIES_ENV = "ODOO_MCP_PER_USER_CACHE_MAX"
_CACHE_MAX_ENTRIES_DEFAULT = 64

# Request-scoped (login, api_key). ``None`` when no header was present.
_current_user_context: ContextVar[Optional[Tuple[str, str]]] = ContextVar(
    "nesa_mcp_user_context", default=None,
)

# Cache: login -> (client, expires_at). Guarded by ``_lock``.
_lock = threading.Lock()
_client_cache: dict[str, Tuple[Any, float]] = {}


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


def strict_mode_enabled() -> bool:
    return os.environ.get(_REQUIRE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


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
    now = time.time()
    ttl = _cache_ttl_seconds()
    with _lock:
        cached = _client_cache.get(login)
        if cached and cached[1] > now:
            return cached[0]
        # Evict expired and trim cache to max-entries.
        for stale_login, (_c, expires) in list(_client_cache.items()):
            if expires <= now:
                _client_cache.pop(stale_login, None)
        if len(_client_cache) >= _cache_max_entries():
            # Drop oldest entry by expires_at.
            oldest = min(_client_cache, key=lambda k: _client_cache[k][1])
            _client_cache.pop(oldest, None)
        try:
            client = _build_per_user_client(login, api_key)
        except Exception:
            _logger.exception(
                "[per_user] failed to build per-user client for login=%s", login,
            )
            raise
        _client_cache[login] = (client, now + ttl)
        _logger.info(
            "[per_user] acting-as login=%s uid=%s ttl=%ds",
            login, getattr(client, "uid", "?"), ttl,
        )
        return client


def reset_for_tests() -> None:
    """Drop all cached per-user clients. Tests-only."""
    with _lock:
        _client_cache.clear()


class NesaPerUserAuthMiddleware:
    """ASGI middleware that pins per-request user context onto a ContextVar.

    Reads ``X-Odoo-User`` and ``X-Odoo-Api-Key`` from the incoming HTTP
    headers and stores them via :func:`set_user_context` for the lifetime
    of the request. On exit the previous token is restored so worker-
    thread reuse never leaks credentials across requests.

    Strict mode: if ``ODOO_MCP_REQUIRE_PER_USER=1`` and the headers are
    missing on a non-lifespan request, the middleware short-circuits with
    HTTP 401 before the request reaches FastMCP's session manager.
    """

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            # lifespan, websocket — pass through untouched.
            await self.app(scope, receive, send)
            return

        login, api_key = self._extract_headers(scope)

        if strict_mode_enabled() and not (login and api_key):
            await self._send_401(send, "Per-user authentication required.")
            return

        token = set_user_context(login, api_key)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_user_context(token)

    @staticmethod
    def _extract_headers(scope: dict) -> Tuple[Optional[str], Optional[str]]:
        """ASGI header values are lowercase-bytes tuples per spec."""
        login: Optional[str] = None
        api_key: Optional[str] = None
        for raw_name, raw_value in scope.get("headers", []) or []:
            try:
                name = raw_name.decode("latin-1").lower()
                value = raw_value.decode("latin-1")
            except Exception:
                continue
            if name == _USER_HEADER and value.strip():
                login = value.strip()
            elif name == _KEY_HEADER and value.strip():
                api_key = value.strip()
        return login, api_key

    @staticmethod
    async def _send_401(send: Callable, body: str) -> None:
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"www-authenticate", b'Bearer realm="nesa-mcp"'),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": body.encode("utf-8"),
        })
