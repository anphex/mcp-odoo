"""NESA Patch 8: per-user invoice tools from the Odoo invoice gateway."""

import asyncio

import pytest

from odoo_mcp import _nesa_dynamic_tools as dyn
from odoo_mcp import _nesa_per_user_auth as per_user
from odoo_mcp import server

GATEWAY = "nesa.agent.invoice.mcp.gateway"


def _spec(name, read_only=True, schema=None):
    return {
        "name": name,
        "description": f"Beschreibung {name}",
        "input_schema": schema or {
            "type": "object",
            "properties": {"invoice_id": {"type": "integer"}},
            "required": ["invoice_id"],
        },
        "read_only": read_only,
    }


LISTING = {
    "success": True,
    "enabled": True,
    "tools": [
        _spec("invoice_context_read"),
        _spec("invoice_lines_apply", read_only=False),
        _spec("search_records"),  # collides with a static tool
        _spec("bad name!"),
        _spec("invoice_broken_schema", schema={"type": "array"}),
    ],
}


class FakeClient:
    def __init__(self, listing=None, answer=None, error=None):
        self.listing = LISTING if listing is None else listing
        self.answer = answer
        self.error = error
        self.calls = []
        self.timeout = 55

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args, kwargs))
        if self.error is not None:
            raise self.error
        if method == "mcp_list_tools":
            return self.listing
        return self.answer


@pytest.fixture(autouse=True)
def _reset_dynamic_tools():
    dyn.reset_for_tests()
    yield
    dyn.reset_for_tests()


@pytest.fixture
def as_user():
    tokens = []

    def _enter(login="buchhaltung@example.com", key="key-one"):
        tokens.append(per_user.set_user_context(login, key))

    yield _enter
    for token in reversed(tokens):
        per_user.reset_user_context(token)


@pytest.fixture
def clients(monkeypatch):
    state = {"list": FakeClient(), "call": FakeClient(), "built": 0, "listed": 0}

    def _list_client():
        state["listed"] += 1
        return state["list"]

    def _build(login, api_key):
        state["built"] += 1
        return state["call"]

    monkeypatch.setattr(per_user, "get_per_user_client", _list_client)
    monkeypatch.setattr(per_user, "_build_per_user_client", _build)
    return state


def _names():
    return {tool.name for tool in asyncio.run(server.mcp.list_tools())}


def test_without_user_context_nothing_is_added(clients):
    static = {tool.name for tool in server.mcp._tool_manager.list_tools()}
    assert _names() == static
    assert clients["listed"] == 0
    with pytest.raises(Exception, match="Unknown tool"):
        asyncio.run(server.mcp.call_tool("invoice_context_read", {"invoice_id": 1}))
    assert clients["built"] == 0


def test_listing_adds_valid_tools_and_skips_bad_specs(clients, as_user):
    as_user()
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    assert "invoice_context_read" in tools
    assert "invoice_lines_apply" in tools
    assert "bad name!" not in tools
    assert "invoice_broken_schema" not in tools
    # The static tool keeps its own definition.
    assert tools["search_records"].description != "Beschreibung search_records"
    assert tools["invoice_context_read"].annotations.readOnlyHint is True
    assert tools["invoice_lines_apply"].annotations.readOnlyHint is False
    assert tools["invoice_context_read"].outputSchema is None
    model, method, _args, _kwargs = clients["list"].calls[0]
    assert (model, method) == (GATEWAY, "mcp_list_tools")


def test_disabled_gateway_adds_nothing(clients, as_user):
    clients["list"] = FakeClient(
        listing={"success": True, "enabled": False, "tools": []},
    )
    as_user()
    assert "invoice_context_read" not in _names()


def test_listing_is_cached_per_user(clients, as_user):
    as_user()
    _names()
    _names()
    assert len(clients["list"].calls) == 1
    as_user("monteur@example.com", "key-two")
    _names()
    assert len(clients["list"].calls) == 2


def test_listing_failure_hides_tools_without_breaking_list(clients, as_user):
    clients["list"] = FakeClient(error=PermissionError("no access"))
    as_user()
    names = _names()
    assert "invoice_context_read" not in names
    assert "search_records" in names


def test_call_forwards_to_gateway_with_fresh_call_id(clients, as_user, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_INVOICE_TOOLS_TIMEOUT", "420")
    clients["call"] = FakeClient(answer={
        "success": True, "is_error": False, "content": "Positionen: 3",
        "session_id": 7, "run_id": 11, "workflow": "invoice_bza_680",
    })
    as_user()
    result = asyncio.run(server.mcp.call_tool(
        "invoice_context_read", {"invoice_id": 42, "workflow": "invoice_bza_680"},
    ))
    assert result.isError is False
    assert result.content[0].text == "Positionen: 3"
    meta = result.structuredContent["result"]
    assert meta["success"] is True and meta["run_id"] == 11
    assert clients["call"].timeout == 420
    model, method, args, kwargs = clients["call"].calls[0]
    assert (model, method, args) == (GATEWAY, "mcp_call_tool", ())
    assert kwargs["name"] == "invoice_context_read"
    assert kwargs["arguments"] == {"invoice_id": 42, "workflow": "invoice_bza_680"}
    assert len(kwargs["call_id"]) == 32
    asyncio.run(server.mcp.call_tool("invoice_context_read", {"invoice_id": 42}))
    second_id = clients["call"].calls[1][3]["call_id"]
    assert second_id != kwargs["call_id"]
    assert clients["built"] == 1


def test_gateway_refusal_is_an_error_result(clients, as_user):
    clients["call"] = FakeClient(answer={
        "success": False, "error": "Die Rechnung ist kein Entwurf.",
    })
    as_user()
    result = asyncio.run(server.mcp.call_tool("invoice_lines_apply", {"invoice_id": 1}))
    assert result.isError is True
    assert result.content[0].text == "Die Rechnung ist kein Entwurf."
    assert result.structuredContent["result"]["success"] is False


def test_tool_error_is_not_counted_as_success(clients, as_user):
    clients["call"] = FakeClient(answer={
        "success": True, "is_error": True, "content": "Artikel nicht gefunden.",
        "session_id": 7, "run_id": 11, "workflow": "invoice_bza_680",
    })
    as_user()
    result = asyncio.run(server.mcp.call_tool("invoice_context_read", {"invoice_id": 1}))
    assert result.isError is True
    assert result.content[0].text == "Artikel nicht gefunden."
    meta = result.structuredContent["result"]
    assert meta["success"] is False and meta["is_error"] is True
    success, _count, _size = server._result_summary(result)
    assert success is False


def test_lost_answer_is_not_retried(clients, as_user):
    clients["call"] = FakeClient(error=ConnectionError("reset by peer"))
    as_user()
    result = asyncio.run(server.mcp.call_tool("invoice_lines_apply", {"invoice_id": 1}))
    assert result.isError is True
    assert len(clients["call"].calls) == 1
    meta = result.structuredContent["result"]
    assert meta["outcome_unknown"] is True
    assert len(meta["call_id"]) == 32


def test_tool_not_listed_for_user_is_not_forwarded(clients, as_user):
    as_user()
    with pytest.raises(Exception, match="Unknown tool"):
        asyncio.run(server.mcp.call_tool("invoice_secret_tool", {"invoice_id": 1}))
    assert clients["built"] == 0


def test_static_tool_name_is_never_forwarded(clients, as_user, monkeypatch):
    as_user()
    forwarded = []
    monkeypatch.setattr(dyn, "call_dynamic_tool", lambda *a: forwarded.append(a))
    try:
        asyncio.run(server.mcp.call_tool("search_records", {"model": "res.partner"}))
    except Exception:  # noqa: BLE001 — only the routing matters here
        pass
    assert forwarded == []


def test_gateway_model_is_not_delegable():
    assert "nesa.agent.invoice.mcp.gateway." in server.NON_DELEGABLE_METHOD_PREFIXES


def test_log_summary_reads_call_tool_result():
    result = dyn._result("ok", {"success": False, "tool": "x"}, True)
    success, _count, size = server._result_summary(result)
    assert success is False
    assert size == 2
