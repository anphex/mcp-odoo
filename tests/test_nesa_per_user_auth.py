"""Tests for the NESA per-user authentication middleware + cache (Patch 2).

Covers:
- ASGI middleware extracts X-Odoo-User / X-Odoo-Api-Key headers from scope.
- ContextVar is set during the inner call and reset on exit.
- Strict mode (ODOO_MCP_REQUIRE_PER_USER=1) short-circuits with HTTP 401
  when headers are missing and lets the request through when present.
- Lifespan / websocket scopes pass through untouched.
- ``get_per_user_client`` returns ``None`` when no context, raises
  PermissionError in strict mode, and caches per-login clients within TTL.
- ``get_odoo_client`` integration: per-user wins when context is set,
  env-fallback wins otherwise.
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


def _scope(headers: list[tuple[bytes, bytes]] | None = None, scope_type: str = "http") -> dict:
    return {
        "type": scope_type,
        "method": "POST",
        "path": "/mcp",
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

    mw = per_user_module.NesaPerUserAuthMiddleware(inner)
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

    mw = per_user_module.NesaPerUserAuthMiddleware(inner)
    _drive(mw, _scope([]))
    assert captured.get("reached") is True
    assert captured["ctx"] is None


def test_middleware_strict_mode_blocks_missing_headers(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)

    async def inner(scope, receive, send):
        raise AssertionError("inner must not be called in strict mode without headers")

    mw = per_user_module.NesaPerUserAuthMiddleware(inner)
    sent = _drive(mw, _scope([]))

    start = next(m for m in sent if m["type"] == "http.response.start")
    body = next(m for m in sent if m["type"] == "http.response.body")
    assert start["status"] == 401
    headers = dict(start["headers"])
    assert headers.get(b"www-authenticate", b"").startswith(b"Bearer")
    assert b"required" in body["body"].lower()


def test_middleware_strict_mode_allows_headers_present(per_user_module, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)

    captured: dict[str, Any] = {}

    async def inner(scope, receive, send):
        captured["ctx"] = per_user_module.current_user_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = per_user_module.NesaPerUserAuthMiddleware(inner)
    _drive(mw, _scope([
        (b"x-odoo-user", b"bob"),
        (b"x-odoo-api-key", b"k2"),
    ]))
    assert captured["ctx"] == ("bob", "k2")


def test_middleware_passes_lifespan_scope_untouched(per_user_module):
    reached: dict[str, bool] = {"ok": False}

    async def inner(scope, receive, send):
        reached["ok"] = scope.get("type") == "lifespan"

    mw = per_user_module.NesaPerUserAuthMiddleware(inner)

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
                client, _expires = per_user_module._client_cache["alice"]
                per_user_module._client_cache["alice"] = (client, time.time() - 1)
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


def test_get_odoo_client_propagates_strict_mode_permissionerror(per_user_module, monkeypatch):
    """When strict mode is on and headers missing, the error bubbles up."""
    import odoo_mcp.odoo_client as oc

    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    importlib.reload(per_user_module)

    with pytest.raises(PermissionError):
        oc.get_odoo_client()
