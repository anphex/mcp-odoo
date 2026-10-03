"""Regressions for connection diagnosis and attachment results (Forstweg)."""
import asyncio
import importlib
import json
import logging
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import Image
from mcp.types import ImageContent, TextContent


def _request(auth, inner, headers=(), path="/mcp", method="POST"):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"PRIVATE-BODY"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "path": path, "method": method,
        "headers": list(headers), "query_string": b"PRIVATE-QUERY",
    }
    middleware = auth.NesaPerUserAuthMiddleware(inner, mcp_path="/mcp")
    asyncio.run(middleware(scope, receive, send))
    return next(m["status"] for m in messages if m["type"] == "http.response.start")


def _events(caplog):
    return [r.getMessage() for r in caplog.records if "[mcp_transport]" in r.getMessage()]


_HEADERS = [(b"x-odoo-user", b"PRIVATE-LOGIN"), (b"x-odoo-api-key", b"PRIVATE-KEY")]


@pytest.mark.parametrize("case,status,category", [
    ("route", 404, "route_not_found"),
    ("duplicate", 400, "duplicate_header"),
    ("incomplete", 401, "incomplete_credentials"),
    ("missing", 401, "credentials_required"),
    ("unknown", 404, "session_not_found"),
    ("mismatch", 403, "session_credentials_mismatch"),
    ("sdk", 400, "http_error"),
])
def test_http_diagnosis_has_only_category_and_status(case, status, category, caplog, monkeypatch):
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    headers, path = list(_HEADERS), "/mcp"
    if case == "route":
        path = "/PRIVATE-CAPABILITY"
    elif case == "duplicate":
        headers.append(_HEADERS[0])
    elif case == "incomplete":
        headers = headers[:1]
    elif case == "missing":
        headers = []
    elif case in {"unknown", "mismatch"}:
        headers.append((b"mcp-session-id", b"PRIVATE-SESSION"))
        if case == "mismatch":
            auth.NesaPerUserAuthMiddleware._bind_session(
                "PRIVATE-SESSION", auth._credential_identity("OTHER-LOGIN", "OTHER-KEY"),
            )

    async def inner(scope, receive, send):
        assert case == "sdk"
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b"PRIVATE-RESPONSE"})

    with caplog.at_level(logging.INFO, logger=auth._logger.name):
        assert _request(auth, inner, headers, path) == status
    assert _events(caplog) == [f"[mcp_transport] category={category} status={status}"]
    assert "PRIVATE" not in caplog.text
    assert auth.current_user_context() is None


def test_session_lifecycle_events_omit_identifiers(caplog, monkeypatch):
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"mcp-session-id", b"PRIVATE-SESSION")]})
        await send({"type": "http.response.body", "body": b"PRIVATE-RESPONSE"})

    with caplog.at_level(logging.INFO, logger=auth._logger.name):
        assert _request(auth, inner, _HEADERS) == 200
        assert _request(auth, inner, [*_HEADERS, (b"mcp-session-id", b"PRIVATE-SESSION")],
                        method="DELETE") == 200
        auth.NesaPerUserAuthMiddleware._bind_session("PRIVATE-EXPIRED", ("PRIVATE-LOGIN", b"x"))
        auth.NesaPerUserAuthMiddleware._evict_expired_sessions(float("inf"))
        auth.NesaPerUserAuthMiddleware._evict_expired_sessions(float("inf"))
    assert _events(caplog) == [
        "[mcp_transport] category=session_initialized status=200",
        "[mcp_transport] category=session_deleted status=200",
        "[mcp_transport] category=session_binding_expired status=0",
    ]
    assert "PRIVATE" not in caplog.text
    assert not auth._session_bindings


def test_transport_logger_failure_does_not_break_authentication(monkeypatch):
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    def fail(*args, **kwargs):
        raise RuntimeError("logging unavailable")

    async def inner(scope, receive, send):
        raise AssertionError("authentication must still reject the request")

    monkeypatch.setattr(auth._logger, "log", fail)
    assert _request(auth, inner) == 401


def test_binding_eviction_is_logged_without_session_values(caplog, monkeypatch):
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    monkeypatch.setattr(auth, "_session_max_entries", lambda: 1)
    with caplog.at_level(logging.INFO, logger=auth._logger.name):
        auth.NesaPerUserAuthMiddleware._bind_session("PRIVATE-OLD", ("PRIVATE-LOGIN", b"x"))
        auth.NesaPerUserAuthMiddleware._bind_session("PRIVATE-NEW", ("PRIVATE-LOGIN", b"x"))
    assert _events(caplog) == ["[mcp_transport] category=session_binding_evicted status=0"]
    assert "PRIVATE" not in caplog.text
    assert set(auth._session_bindings) == {"PRIVATE-NEW"}


def test_ordinary_success_has_no_new_transport_log(caplog):
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"PRIVATE-RESPONSE"})

    with caplog.at_level(logging.INFO, logger=auth._logger.name):
        assert _request(auth, inner, _HEADERS) == 200
    assert not _events(caplog)


@pytest.mark.parametrize("case", ["initialization_error", "existing_session", "delete_error"])
def test_failed_or_existing_sessions_do_not_get_false_lifecycle_events(case, caplog):
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    headers = list(_HEADERS)
    if case != "initialization_error":
        auth.NesaPerUserAuthMiddleware._bind_session(
            "PRIVATE-SESSION", auth._credential_identity("PRIVATE-LOGIN", "PRIVATE-KEY"),
        )
        headers.append((b"mcp-session-id", b"PRIVATE-SESSION"))
    status = 200 if case == "existing_session" else 400

    async def inner(scope, receive, send):
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"mcp-session-id", b"PRIVATE-SESSION")]})
        await send({"type": "http.response.body", "body": b"PRIVATE-RESPONSE"})

    with caplog.at_level(logging.INFO, logger=auth._logger.name):
        assert _request(auth, inner, headers, method="DELETE" if case == "delete_error" else "POST") == status
    assert _events(caplog) == ([] if status == 200 else ["[mcp_transport] category=http_error status=400"])
    assert "PRIVATE" not in caplog.text
    assert "PRIVATE-SESSION" in auth._session_bindings


@pytest.mark.parametrize("success,image,large_text", [
    (False, False, False), (True, True, False), (True, False, True),
])
def test_real_fastmcp_content_results_have_correct_status(success, image, large_text, monkeypatch, caplog):
    server = importlib.import_module("odoo_mcp.server")
    telemetry = importlib.import_module("odoo_mcp.telemetry")
    captured = []
    collector = SimpleNamespace(
        begin=lambda *args: {},
        finish=lambda *args: captured.append(args),
    )
    monkeypatch.setattr(telemetry, "get_telemetry", lambda: collector)
    probe = server.NesaFastMCP("attachment-probe")
    payload = {"success": success, "tool": "read_attachment"}
    if not success:
        payload.update(error_type="request", error="Cannot read attachment_id")
    if large_text:
        # Maximum text window with escaped unicode still has a bounded envelope.
        payload["text"] = "\uffff" * server.DOC_TEXT_WINDOW_MAX

    @probe.tool(structured_output=False)
    def read_attachment():
        return [Image(data=b"fake-image", format="png"), payload] if image else payload

    with caplog.at_level(logging.INFO, logger=server.logger.name):
        result = asyncio.run(probe.call_tool("read_attachment", {}))
    assert server._structured_of(result) == payload
    assert server._result_summary(result)[0] is success
    assert captured[0][2] is success
    assert captured[0][5] == payload
    call_line = next(r.getMessage() for r in caplog.records if "[mcp_call]" in r.getMessage())
    assert f"ok={str(success).lower()}" in call_line
    assert call_line.endswith("error=-" if success else "error=request")
    if image:
        assert any(isinstance(block, ImageContent) for block in result)


@pytest.mark.parametrize("text", [
    '{"success": true, "text": "a document, not the tool envelope"}',
    '{"success": "false", "tool": "read_attachment"}',
    "not JSON", "[" * 2000, "x" * (1024 * 1024 + 1),
])
def test_content_status_parser_is_bounded_and_ignores_document_content(text):
    server = importlib.import_module("odoo_mcp.server")
    assert server._structured_of([TextContent(type="text", text=text)]) is None


@pytest.mark.parametrize("metadata", [{}, {"attachment_id": {"type": "binary"}},
                                       {"attachment_id": {"type": "many2one", "relation": "res.partner"}}])
def test_attachment_schema_guard_does_not_read_missing_or_wrong_field(metadata):
    server = importlib.import_module("odoo_mcp.server")

    class Client:
        def get_model_fields(self, model):
            assert model == "nesa.tagesbericht.photo"
            return metadata

        def read_records(self, *args, **kwargs):
            raise AssertionError("unsupported attachment_id must never be read")

    client = Client()
    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=SimpleNamespace(odoo=client)))
    result = server.read_attachment(ctx, 1, model="nesa.tagesbericht.photo")
    assert result["success"] is False
    assert result["error_type"] == "request"
    assert result["retryable"] is False
    for hint in ("ir.attachment", "res_model", "res_id", "res_field"):
        assert hint in result["error"]


def test_attachment_schema_guard_preserves_supported_many2one_and_direct_ids():
    server = importlib.import_module("odoo_mcp.server")

    class Client:
        def get_model_fields(self, model):
            assert model == "documents.document"
            return {"attachment_id": {"type": "many2one", "relation": "ir.attachment"}}

        def read_records(self, model, record_ids, fields):
            assert (model, record_ids, fields) == ("documents.document", [1], ["attachment_id"])
            return [{"attachment_id": [42, "document.pdf"]}]

    assert server._resolve_attachment_id(Client(), "documents.document", 1) == 42
    assert server._resolve_attachment_id(object(), "ir.attachment", 42) == 42


@pytest.mark.parametrize("metadata", [None, {"error": "PRIVATE-SCHEMA-ERROR"}])
def test_attachment_schema_guard_fails_closed_without_metadata(metadata):
    server = importlib.import_module("odoo_mcp.server")

    class Client:
        def get_model_fields(self, model):
            return metadata

        def read_records(self, *args, **kwargs):
            raise AssertionError("metadata failure must not fall through to a guessed read")

    with pytest.raises(RuntimeError, match="Cannot inspect attachment_id metadata") as error:
        server._resolve_attachment_id(Client(), "documents.document", 1)
    assert "PRIVATE-SCHEMA-ERROR" not in str(error.value)


@pytest.mark.parametrize("cause,error_type,retryable", [
    ("[Errno 111] Connection refused PRIVATE-SCHEMA-ERROR", "transport", True),
    ("timed out PRIVATE-SCHEMA-ERROR", "transport", True),
    ("Access denied PRIVATE-SCHEMA-ERROR", "odoo_error", False),
])
def test_attachment_metadata_errors_keep_coarse_retry_classification(cause, error_type, retryable, caplog):
    server = importlib.import_module("odoo_mcp.server")

    class Client:
        def get_model_fields(self, model):
            return {"error": cause}

        def read_records(self, *args, **kwargs):
            raise AssertionError("failed metadata must not permit a guessed read")

    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=SimpleNamespace(odoo=Client())))
    result = server.read_attachment(ctx, 1, model="documents.document")
    assert result["error_type"] == error_type
    assert result["retryable"] is retryable
    assert "PRIVATE" not in result["error"]
    assert "PRIVATE" not in caplog.text


def test_attachment_schema_cache_is_scoped_per_user_and_allows_error_field(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    auth = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    stores = []
    original_store = server.process_cache_set

    def store(key, value):
        stores.append(key)
        original_store(key, value)

    monkeypatch.setattr(server, "process_cache_set", store)

    class Client:
        fields_calls = 0

        def get_model_fields(self, model):
            self.fields_calls += 1
            return {"attachment_id": {"type": "many2one", "relation": "ir.attachment"},
                    "error": {"type": "html"}}

        def read_records(self, *args, **kwargs):
            return [{"attachment_id": [42, "document.pdf"]}]

    client = Client()
    for user, key in (("alice", "key-a"), ("alice", "key-a"), ("bob", "key-b"), ("bob", "key-b")):
        token = auth.set_user_context(user, key)
        try:
            assert server._resolve_attachment_id(client, "documents.document", 1) == 42
        finally:
            auth.reset_user_context(token)
    assert client.fields_calls == 2
    assert len(stores) == 2  # Cache hits must not extend the schema TTL.
