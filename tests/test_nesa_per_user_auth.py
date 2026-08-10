"""Tests for the NESA per-user authentication middleware + cache (Patch 2).

Covers:
- ASGI middleware extracts X-Odoo-User / X-Odoo-Api-Key headers from scope.
- ContextVar is set during the inner call and reset on exit.
- Non-MCP paths return a direct 404 before authentication.
- Strict mode (ODOO_MCP_REQUIRE_PER_USER=1) short-circuits with HTTP 401
  when headers are missing and lets the request through when present.
- Lifespan / websocket scopes pass through untouched.
- ``get_per_user_client`` returns ``None`` when no context, raises
  PermissionError in strict mode, and caches per-credential clients within TTL.
- ``get_odoo_client`` integration: per-user wins when context is set,
  env-fallback wins only when credentials are absent.
- Stateful MCP sessions cannot be reused with another credential fingerprint.
"""
from __future__ import annotations

import asyncio
import importlib
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Clear NESA env vars + reset module state before each test."""
    for var in (
        "ODOO_MCP_REQUIRE_PER_USER",
        "ODOO_MCP_PER_USER_CACHE_TTL",
        "ODOO_MCP_PER_USER_CACHE_MAX",
        "ODOO_MCP_SESSION_BINDING_MAX",
        "MCP_SESSION_IDLE_TIMEOUT",
        "MCP_TRANSPORT",
    ):
        monkeypatch.delenv(var, raising=False)
    import odoo_mcp._nesa_per_user_auth as mod

    importlib.reload(mod)
    mod.reset_for_tests()
    yield
    mod.reset_for_tests()


@pytest.fixture
def per_user_module():
    import odoo_mcp._nesa_per_user_auth as mod

    return mod


def _scope(
    headers: list[tuple[bytes, bytes]] | None = None,
    scope_type: str = "http",
    path: str = "/mcp",
) -> dict:
    return {
        "type": scope_type,
        "method": "POST",
        "path": path,
        "headers": headers or [],
    }


def _drive(app, scope, messages_out: list | None = None) -> list:
    """Run an ASGI app via asyncio and return the captured ``send`` messages."""
    if messages_out is None:
        messages_out = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages_out.append(message)

    asyncio.run(app(scope, receive, send))
    return messages_out


def test_middleware_extracts_headers_and_sets_context(per_user_module):
    captured: dict[str, Any] = {}

    async def inner(scope, receive, send):
        captured["ctx"] = per_user_module.current_user_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    scope = _scope([
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"secret-key"),
    ])
    _drive(mw, scope)

    assert captured["ctx"] == ("alice", "secret-key")
    # Outside the request the contextvar must be reset back to None.
    assert per_user_module.current_user_context() is None


def test_middleware_lenient_passes_through_when_headers_missing(per_user_module):
    captured: dict[str, Any] = {}

    async def inner(scope, receive, send):
        captured["ctx"] = per_user_module.current_user_context()
        captured["reached"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    _drive(mw, _scope([]))
    assert captured.get("reached") is True
    assert captured["ctx"] is None


def test_middleware_strict_mode_blocks_missing_headers(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)

    async def inner(scope, receive, send):
        raise AssertionError("inner must not be called in strict mode without headers")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    sent = _drive(mw, _scope([]))

    start = next(m for m in sent if m["type"] == "http.response.start")
    body = next(m for m in sent if m["type"] == "http.response.body")
    assert start["status"] == 401
    headers = dict(start["headers"])
    assert headers.get(b"www-authenticate", b"").startswith(b"Bearer")
    assert b"required" in body["body"].lower()


@pytest.mark.parametrize(
    "path",
    [
        "/mcp/",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth/authorize",
        "/oauth/token",
        "/register",
        "/not-an-mcp-route",
    ],
)
def test_middleware_rejects_non_mcp_paths_before_auth(
    per_user_module, monkeypatch, path,
):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    async def inner(scope, receive, send):
        raise AssertionError("non-MCP paths must never reach authentication or routing")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    sent = _drive(mw, _scope([], path=path))

    start = next(m for m in sent if m["type"] == "http.response.start")
    body = next(m for m in sent if m["type"] == "http.response.body")
    headers = dict(start["headers"])
    assert start["status"] == 404
    assert headers.get(b"location") is None
    assert headers.get(b"www-authenticate") is None
    assert body["body"] == b"Not Found."


def test_middleware_uses_configured_mcp_path(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    async def inner(scope, receive, send):
        raise AssertionError("strict auth must run for the configured MCP path")

    mw = per_user_module.NesaPerUserAuthMiddleware(
        inner,
        mcp_path="/custom-mcp",
    )
    sent = _drive(mw, _scope([], path="/custom-mcp"))

    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 401
    assert dict(start["headers"])[b"www-authenticate"].startswith(b"Bearer")


def test_middleware_requires_absolute_mcp_path(per_user_module):
    with pytest.raises(ValueError, match="absolute HTTP path"):
        per_user_module.NesaPerUserAuthMiddleware(
            lambda scope, receive, send: None,
            mcp_path="relative",
        )


def test_network_transport_defaults_to_fail_closed(per_user_module, monkeypatch):
    monkeypatch.delenv("ODOO_MCP_REQUIRE_PER_USER", raising=False)
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    importlib.reload(per_user_module)

    assert per_user_module.strict_mode_enabled() is True
    with pytest.raises(PermissionError):
        per_user_module.get_per_user_client()


@pytest.mark.parametrize("configured", ["", "maybe", "TRUE-ish"])
def test_malformed_strict_mode_env_uses_network_fail_closed_default(
    per_user_module, monkeypatch, caplog, configured,
):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", configured)

    with caplog.at_level("ERROR"):
        assert per_user_module.strict_mode_enabled() is True

    assert "invalid ODOO_MCP_REQUIRE_PER_USER" in caplog.text


def test_explicit_false_strict_mode_override_stays_supported(
    per_user_module, monkeypatch,
):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "false")

    assert per_user_module.strict_mode_enabled() is False


def test_describe_state_prefers_parsed_runtime_transport(
    per_user_module, monkeypatch,
):
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    per_user_module.set_runtime_transport("streamable-http")

    state = per_user_module.describe_state()

    assert state["runtime_transport"] == "streamable-http"
    assert state["strict_mode"] is True


def test_middleware_strict_mode_allows_headers_present(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)

    captured: dict[str, Any] = {}

    async def inner(scope, receive, send):
        captured["ctx"] = per_user_module.current_user_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    _drive(mw, _scope([
        (b"x-odoo-user", b"bob"),
        (b"x-odoo-api-key", b"k2"),
    ]))
    assert captured["ctx"] == ("bob", "k2")


def test_middleware_rejects_partial_headers_even_when_lenient(per_user_module):
    async def inner(scope, receive, send):
        raise AssertionError("partial credentials must never reach the app")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    sent = _drive(mw, _scope([(b"x-odoo-user", b"bob")]))
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 401


def test_middleware_rejects_duplicate_auth_headers(per_user_module):
    async def inner(scope, receive, send):
        raise AssertionError("ambiguous credentials must never reach the app")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    sent = _drive(mw, _scope([
        (b"x-odoo-user", b"bob"),
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"k2"),
    ]))
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 400


def test_middleware_rejects_duplicate_session_headers(per_user_module):
    async def inner(scope, receive, send):
        raise AssertionError("ambiguous session must never reach the app")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    sent = _drive(mw, _scope([
        (b"x-odoo-user", b"bob"),
        (b"x-odoo-api-key", b"k2"),
        (b"mcp-session-id", b"one"),
        (b"mcp-session-id", b"two"),
    ]))
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 400


def test_middleware_passes_lifespan_scope_untouched(per_user_module):
    reached: dict[str, bool] = {"ok": False}

    async def inner(scope, receive, send):
        reached["ok"] = scope.get("type") == "lifespan"

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(_):
        pass

    asyncio.run(mw({"type": "lifespan"}, receive, send))
    assert reached["ok"] is True


def test_get_per_user_client_returns_none_when_no_context(per_user_module):
    assert per_user_module.get_per_user_client() is None


def test_get_per_user_client_strict_mode_raises(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)
    with pytest.raises(PermissionError):
        per_user_module.get_per_user_client()


def test_get_per_user_client_caches_within_ttl(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_PER_USER_CACHE_TTL", "60")
    importlib.reload(per_user_module)
    per_user_module.reset_for_tests()

    fake_clients: list[Any] = []

    def fake_build(login, key):
        instance = MagicMock(name=f"OdooClient({login})", uid=42 + len(fake_clients))
        fake_clients.append(instance)
        return instance

    with patch.object(per_user_module, "_build_per_user_client", side_effect=fake_build):
        token = per_user_module.set_user_context("alice", "k1")
        try:
            c1 = per_user_module.get_per_user_client()
            c2 = per_user_module.get_per_user_client()
        finally:
            per_user_module.reset_user_context(token)

    assert c1 is c2
    assert len(fake_clients) == 1


def test_get_per_user_client_refreshes_after_ttl(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_PER_USER_CACHE_TTL", "60")
    importlib.reload(per_user_module)
    per_user_module.reset_for_tests()

    fake_clients: list[Any] = []

    def fake_build(login, key):
        instance = MagicMock(name=f"OdooClient({login})", uid=42 + len(fake_clients))
        fake_clients.append(instance)
        return instance

    with patch.object(per_user_module, "_build_per_user_client", side_effect=fake_build):
        token = per_user_module.set_user_context("alice", "k1")
        try:
            per_user_module.get_per_user_client()
            # Simulate TTL expiry by editing the cache entry's expiry time.
            with per_user_module._lock:
                identity = per_user_module._credential_identity("alice", "k1")
                client, _expires = per_user_module._client_cache[identity]
                per_user_module._client_cache[identity] = (
                    client, time.monotonic() - 1,
                )
            per_user_module.get_per_user_client()
        finally:
            per_user_module.reset_user_context(token)

    assert len(fake_clients) == 2


def test_cache_eviction_when_max_entries_exceeded(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_PER_USER_CACHE_MAX", "8")
    importlib.reload(per_user_module)
    per_user_module.reset_for_tests()

    def fake_build(login, key):
        return MagicMock(name=f"OdooClient({login})", uid=hash(login) & 0xFFFF)

    with patch.object(per_user_module, "_build_per_user_client", side_effect=fake_build):
        for i in range(10):
            token = per_user_module.set_user_context(f"user{i}", "k")
            try:
                per_user_module.get_per_user_client()
            finally:
                per_user_module.reset_user_context(token)

    with per_user_module._lock:
        assert len(per_user_module._client_cache) <= 8


def test_same_login_with_different_key_never_reuses_client(per_user_module):
    fake_clients: list[Any] = []

    def fake_build(login, key):
        instance = MagicMock(name=f"OdooClient({login},{len(fake_clients)})")
        fake_clients.append(instance)
        return instance

    with patch.object(per_user_module, "_build_per_user_client", side_effect=fake_build):
        first_token = per_user_module.set_user_context("alice", "valid-key")
        try:
            first = per_user_module.get_per_user_client()
        finally:
            per_user_module.reset_user_context(first_token)

        second_token = per_user_module.set_user_context("alice", "wrong-key")
        try:
            second = per_user_module.get_per_user_client()
        finally:
            per_user_module.reset_user_context(second_token)

    assert first is not second
    assert len(fake_clients) == 2


def test_client_build_does_not_hold_global_cache_lock(per_user_module):
    lock_was_free: list[bool] = []

    def fake_build(login, key):
        acquired = per_user_module._lock.acquire(blocking=False)
        lock_was_free.append(acquired)
        if acquired:
            per_user_module._lock.release()
        return MagicMock(uid=42)

    with patch.object(per_user_module, "_build_per_user_client", side_effect=fake_build):
        token = per_user_module.set_user_context("alice", "k1")
        try:
            per_user_module.get_per_user_client()
        finally:
            per_user_module.reset_user_context(token)

    assert lock_was_free == [True]


def test_get_odoo_client_prefers_per_user_when_context_set(per_user_module):
    """get_odoo_client() short-circuits to per-user when ContextVar is set."""
    import odoo_mcp.odoo_client as oc

    fake_client = MagicMock(name="PerUserClient")

    with patch.object(per_user_module, "get_per_user_client", return_value=fake_client):
        result = oc.get_odoo_client()
    assert result is fake_client


def test_get_odoo_client_falls_back_to_env_when_no_context(per_user_module, monkeypatch):
    """get_odoo_client() builds env-based OdooClient when no context."""
    import odoo_mcp.odoo_client as oc

    env_client = MagicMock(name="EnvClient")
    monkeypatch.setenv("ODOO_URL", "http://example.com")
    monkeypatch.setenv("ODOO_DB", "db")
    monkeypatch.setenv("ODOO_USERNAME", "service")
    monkeypatch.setenv("ODOO_PASSWORD", "svc-key")

    with patch.object(per_user_module, "get_per_user_client", return_value=None), \
         patch.object(oc, "OdooClient", return_value=env_client) as ctor:
        result = oc.get_odoo_client()
    assert result is env_client
    kwargs = ctor.call_args.kwargs
    assert kwargs["username"] == "service"
    assert kwargs["password"] == "svc-key"


def test_service_client_factory_ignores_request_credentials(
    per_user_module, monkeypatch,
):
    import odoo_mcp.odoo_client as oc

    monkeypatch.setenv("ODOO_URL", "http://example.com")
    monkeypatch.setenv("ODOO_DB", "db")
    monkeypatch.setenv("ODOO_USERNAME", "service")
    monkeypatch.setenv("ODOO_PASSWORD", "svc-key")
    service_client = MagicMock(name="ServiceClient")

    token = per_user_module.set_user_context("alice", "alice-key")
    try:
        with patch.object(oc, "OdooClient", return_value=service_client) as ctor:
            result = oc.get_service_odoo_client()
    finally:
        per_user_module.reset_user_context(token)

    assert result is service_client
    assert ctor.call_args.kwargs["username"] == "service"
    assert ctor.call_args.kwargs["password"] == "svc-key"


def test_get_odoo_client_propagates_strict_mode_permissionerror(per_user_module, monkeypatch):
    """When strict mode is on and headers missing, the error bubbles up."""
    import odoo_mcp.odoo_client as oc

    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)

    with pytest.raises(PermissionError):
        oc.get_odoo_client()


@pytest.mark.parametrize("failure", [ValueError("bad key"), ConnectionError("down")])
def test_get_odoo_client_never_falls_back_after_per_user_failure(
    per_user_module, monkeypatch, failure,
):
    import odoo_mcp.odoo_client as oc

    monkeypatch.setenv("ODOO_URL", "http://example.com")
    monkeypatch.setenv("ODOO_DB", "db")
    monkeypatch.setenv("ODOO_USERNAME", "service")
    monkeypatch.setenv("ODOO_PASSWORD", "svc-key")

    with patch.object(
        per_user_module, "get_per_user_client", side_effect=failure,
    ), patch.object(oc, "OdooClient") as env_ctor:
        with pytest.raises(type(failure), match=str(failure)):
            oc.get_odoo_client()
    env_ctor.assert_not_called()


def test_mcp_session_is_bound_to_credential_fingerprint(per_user_module):
    reached = 0

    async def inner(scope, receive, send):
        nonlocal reached
        reached += 1
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"mcp-session-id", b"session-1")],
        })
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    first_headers = [
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"key-a"),
    ]
    _drive(mw, _scope(first_headers))

    same_headers = first_headers + [(b"mcp-session-id", b"session-1")]
    same_sent = _drive(mw, _scope(same_headers))
    assert next(
        m for m in same_sent if m["type"] == "http.response.start"
    )["status"] == 200

    other_headers = [
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"key-b"),
        (b"mcp-session-id", b"session-1"),
    ]
    other_sent = _drive(mw, _scope(other_headers))
    assert next(
        m for m in other_sent if m["type"] == "http.response.start"
    )["status"] == 403
    assert reached == 2


def test_unknown_mcp_session_is_rejected(per_user_module):
    async def inner(scope, receive, send):
        raise AssertionError("unbound session must never reach the app")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    sent = _drive(mw, _scope([
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"key-a"),
        (b"mcp-session-id", b"unknown"),
    ]))
    assert next(
        m for m in sent if m["type"] == "http.response.start"
    )["status"] == 403


def test_service_session_cannot_be_reused_with_user_credentials(per_user_module):
    async def inner(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"mcp-session-id", b"service-session")],
        })
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    _drive(mw, _scope([]))

    sent = _drive(mw, _scope([
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"key-a"),
        (b"mcp-session-id", b"service-session"),
    ]))
    assert next(
        m for m in sent if m["type"] == "http.response.start"
    )["status"] == 403


def test_successful_delete_removes_session_binding(per_user_module):
    async def inner(scope, receive, send):
        response_headers = []
        if scope.get("method") == "POST":
            response_headers = [(b"mcp-session-id", b"delete-me")]
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": response_headers,
        })
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    auth_headers = [
        (b"x-odoo-user", b"alice"),
        (b"x-odoo-api-key", b"key-a"),
    ]
    _drive(mw, _scope(auth_headers))
    assert "delete-me" in per_user_module._session_bindings

    delete_scope = _scope(auth_headers + [(b"mcp-session-id", b"delete-me")])
    delete_scope["method"] = "DELETE"
    _drive(mw, delete_scope)

    assert "delete-me" not in per_user_module._session_bindings


def test_session_bindings_are_bounded(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_SESSION_BINDING_MAX", "16")
    identity = per_user_module._credential_identity("alice", "key-a")

    for index in range(17):
        per_user_module.NesaPerUserAuthMiddleware._bind_session(
            f"session-{index}", identity,
        )

    assert len(per_user_module._session_bindings) == 16
    assert "session-0" not in per_user_module._session_bindings


def test_expired_session_binding_is_removed(per_user_module):
    identity = per_user_module._credential_identity("alice", "key-a")
    per_user_module._session_bindings["expired"] = (identity, time.monotonic() - 1)

    assert per_user_module.NesaPerUserAuthMiddleware._session_matches(
        "expired", identity,
    ) is False
    assert "expired" not in per_user_module._session_bindings


def test_describe_state_reports_non_secret_security_posture(
    per_user_module, monkeypatch,
):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    state = per_user_module.describe_state()

    assert state["strict_mode"] is True
    assert state["credential_cache_entry_count"] == 0
    assert state["session_binding_count"] == 0
    assert "api_key" not in str(state).lower()
