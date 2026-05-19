"""Tests for the NESA DB-driven allowlist (server-side).

Covers:
- ENV unset -> module reports disabled, empty set.
- Search-read rows with descriptions are cached as-is.
- Empty descriptions trigger a get_method_doc fallback per row.
- Fallback failures stay silent (allowlist entry kept, no description).
- Cache TTL prevents repeated XML-RPC traffic.
"""
from __future__ import annotations

import importlib
import time

import pytest


@pytest.fixture
def allowlist_module(monkeypatch):
    """Reload module per test so module-globals start clean."""
    import odoo_mcp._nesa_db_allowlist as mod

    importlib.reload(mod)
    mod.reset_for_tests()
    monkeypatch.setenv("ODOO_MCP_METHOD_ALLOWLIST_MODEL", "nesa.mcp.allowed_method")
    monkeypatch.setenv("ODOO_MCP_METHOD_ALLOWLIST_TTL", "60")
    # TTL is read at module import; refresh after monkeypatch.
    importlib.reload(mod)
    mod.reset_for_tests()
    return mod


class _FakeOdoo:
    """Records execute_method calls; returns scripted responses."""

    def __init__(self, search_read_rows, doc_map=None, doc_errors=None):
        self.search_read_rows = search_read_rows
        self.doc_map = doc_map or {}
        self.doc_errors = doc_errors or {}
        self.calls = []

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args, kwargs))
        if method == "search_read":
            return self.search_read_rows
        if method == "get_method_doc":
            target = f"{args[0]}.{args[1]}"
            if target in self.doc_errors:
                raise self.doc_errors[target]
            return self.doc_map.get(target, "")
        raise AssertionError(f"unexpected method {method}")


def _patch_client(monkeypatch, fake):
    """Force `_fetch_once` to use the supplied fake OdooClient."""
    import odoo_mcp.odoo_client as oc

    monkeypatch.setattr(oc, "get_odoo_client", lambda: fake)


def test_env_unset_disables_module(monkeypatch):
    import odoo_mcp._nesa_db_allowlist as mod

    importlib.reload(mod)
    mod.reset_for_tests()
    monkeypatch.delenv("ODOO_MCP_METHOD_ALLOWLIST_MODEL", raising=False)

    assert mod.methods() == frozenset()
    state = mod.describe_state()
    assert state["enabled"] is False
    assert state["cached_method_count"] == 0


def test_descriptions_used_when_present(monkeypatch, allowlist_module):
    fake = _FakeOdoo(
        search_read_rows=[
            {"method_path": "sale.order.action_confirm", "description": "Confirm a sale order."},
            {"method_path": "res.partner.message_post", "description": "Post a chatter message."},
        ],
    )
    _patch_client(monkeypatch, fake)

    methods = allowlist_module.methods()

    assert methods == frozenset({"sale.order.action_confirm", "res.partner.message_post"})
    assert allowlist_module.description("sale.order.action_confirm") == "Confirm a sale order."
    assert allowlist_module.description("res.partner.message_post") == "Post a chatter message."
    # No get_method_doc calls because descriptions were present.
    assert [c[1] for c in fake.calls] == ["search_read"]


def test_empty_description_triggers_docstring_fallback(monkeypatch, allowlist_module):
    fake = _FakeOdoo(
        search_read_rows=[
            {"method_path": "sale.order.action_confirm", "description": ""},
            {"method_path": "res.partner.message_post", "description": "   "},
        ],
        doc_map={
            "sale.order.action_confirm": "Confirm sale order (from docstring).",
            "res.partner.message_post": "Post chatter message (from docstring).",
        },
    )
    _patch_client(monkeypatch, fake)

    allowlist_module.methods()  # primes cache

    assert allowlist_module.description("sale.order.action_confirm") == "Confirm sale order (from docstring)."
    assert allowlist_module.description("res.partner.message_post") == "Post chatter message (from docstring)."
    # Both fallback rows triggered get_method_doc.
    doc_calls = [c for c in fake.calls if c[1] == "get_method_doc"]
    assert {(c[2][0], c[2][1]) for c in doc_calls} == {
        ("sale.order", "action_confirm"),
        ("res.partner", "message_post"),
    }


def test_docstring_fallback_failure_stays_silent(monkeypatch, allowlist_module):
    fake = _FakeOdoo(
        search_read_rows=[
            {"method_path": "sale.order.action_confirm", "description": ""},
        ],
        doc_errors={"sale.order.action_confirm": RuntimeError("xmlrpc down")},
    )
    _patch_client(monkeypatch, fake)

    methods = allowlist_module.methods()

    # Method still present, just no description.
    assert "sale.order.action_confirm" in methods
    assert allowlist_module.description("sale.order.action_confirm") is None


def test_path_without_dot_is_skipped_for_fallback(monkeypatch, allowlist_module):
    fake = _FakeOdoo(
        search_read_rows=[
            {"method_path": "malformed_no_dot", "description": ""},
        ],
    )
    _patch_client(monkeypatch, fake)

    methods = allowlist_module.methods()

    assert "malformed_no_dot" in methods
    # No get_method_doc call attempted.
    assert all(c[1] != "get_method_doc" for c in fake.calls)


def test_cache_avoids_repeated_xmlrpc(monkeypatch, allowlist_module):
    fake = _FakeOdoo(
        search_read_rows=[
            {"method_path": "sale.order.action_confirm", "description": "Confirm."},
        ],
    )
    _patch_client(monkeypatch, fake)

    allowlist_module.methods()
    allowlist_module.methods()  # within TTL

    search_calls = [c for c in fake.calls if c[1] == "search_read"]
    assert len(search_calls) == 1, "cache should suppress duplicate fetch within TTL"


def test_cache_refreshes_after_ttl_expiry(monkeypatch, allowlist_module):
    fake = _FakeOdoo(
        search_read_rows=[
            {"method_path": "sale.order.action_confirm", "description": "Confirm."},
        ],
    )
    _patch_client(monkeypatch, fake)

    allowlist_module.methods()

    # Simulate TTL expiry by rewinding the cache timestamp.
    monkeypatch.setattr(
        allowlist_module, "_cache_fetched_at",
        time.time() - allowlist_module._CACHE_TTL_SECONDS - 1,
    )

    allowlist_module.methods()

    search_calls = [c for c in fake.calls if c[1] == "search_read"]
    assert len(search_calls) == 2
