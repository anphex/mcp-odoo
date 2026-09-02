import asyncio
import importlib
import json
from pathlib import Path

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent


def call_tool_json(server, name, arguments):
    content = asyncio.run(server.mcp.call_tool(name, arguments))
    if isinstance(content, tuple):
        content, structured = content
        if isinstance(structured, dict):
            return structured.get("result", structured)
    if content and isinstance(content[0], list):
        content = content[0]
    assert isinstance(content[0], TextContent)
    return json.loads(content[0].text)


class FakeRequest:
    def __init__(self, lifespan_context):
        self.lifespan_context = lifespan_context


class FakeCtx:
    def __init__(self, odoo):
        self.request_context = FakeRequest(FakeLife(_wrap_with_approval_store(odoo)))


class FakeLife:
    def __init__(self, odoo):
        self.odoo = odoo
        self.schema_cache = {}
        # NESA A1: mirrors AppContext.transient_cache used by the wizard
        # exemption in execute_method.
        self.transient_cache = {}


# ---------------------------------------------------------------------------
# NESA Patch 3 (2026-05-20): Approval-Tokens werden seit nesa_mcp_bridge
# 18.0.1.2.0 / server.py "Patch 3" in Odoo persistiert (Tabelle
# nesa.mcp.approval.token). Die alten Tests assertierten gegen
# AppContext.write_approvals (in-memory dict, jetzt entfernt). Hier wird
# ein FakeApprovalStore um den Test-OdooClient gewickelt, der die drei
# Helper-Methoden 1:1 mit der DB-Implementation simuliert. Tests bleiben
# damit semantisch dasselbe und greifen weiter den End-to-End-Flow ab
# (preview -> validate -> execute_approved -> revoke).
# ---------------------------------------------------------------------------

class _FakeApprovalStoreClient:
    """Wraps a test-OdooClient so that execute_method calls against
    'nesa.mcp.approval.token' hit an in-memory store with the same
    contract as the bridge-side helper methods."""

    def __init__(self, inner):
        self._inner = inner
        self.approval_store = {}

    def __getattr__(self, name):
        # Forward anything not explicitly overridden to the wrapped client.
        return getattr(self._inner, name)

    def get_model_fields(self, model):
        return self._inner.get_model_fields(model)

    @staticmethod
    def _canonical_hash(payload):
        import hashlib as _h
        import json as _j
        if not isinstance(payload, dict):
            return ""
        return _h.sha256(
            _j.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def execute_method(self, model, method, *args, **kwargs):
        if model == "nesa.mcp.approval.token":
            return self._dispatch_token(method, args)
        return self._inner.execute_method(model, method, *args, **kwargs)

    def _dispatch_token(self, method, args):
        import time as _t
        if method == "mcp_register_approval":
            token, model_name, operation, payload, _validated_at_iso = args
            existing = self.approval_store.get(token)
            payload_hash = self._canonical_hash(payload)
            if existing and existing["payload_hash"] != payload_hash:
                return {"success": False, "error": "token already exists with different payload"}
            self.approval_store[token] = {
                "model_name": model_name,
                "operation": operation,
                "payload": payload,
                "payload_hash": payload_hash,
                "validated_at": _t.time(),
                "expires_at": _t.time() + 600,
            }
            return {"success": True, "token": token, "expires_at_iso": "2030-01-01 00:00:00"}
        if method == "mcp_consume_approval":
            token, expected_hash = args
            record = self.approval_store.get(token)
            if not record:
                return {"success": False, "error": "approval token has not been validated in this server session or has expired; call validate_write first"}
            if _t.time() > record["expires_at"]:
                self.approval_store.pop(token, None)
                return {"success": False, "error": "approval token expired"}
            if expected_hash and record["payload_hash"] != expected_hash:
                return {"success": False, "error": "approval payload does not match the stored validation record"}
            return {
                "success": True,
                "payload": record["payload"],
                "validated_at_iso": "2030-01-01 00:00:00",
                "expires_at_iso": "2030-01-01 00:10:00",
            }
        if method == "mcp_revoke_approval":
            token, = args
            self.approval_store.pop(token, None)
            return {"success": True, "revoked": True}
        raise AssertionError(f"unexpected token-store method {method!r}")


def _wrap_with_approval_store(odoo):
    """Wrap a test OdooClient so token-store roundtrips work transparently.

    Idempotent: if already wrapped, return as-is.
    """
    if odoo is None or isinstance(odoo, _FakeApprovalStoreClient):
        return odoo
    return _FakeApprovalStoreClient(odoo)


def test_server_import_initializes_fastmcp_with_current_sdk_without_lifespan():
    server = importlib.import_module("odoo_mcp.server")

    assert isinstance(server.mcp, FastMCP)
    assert server.mcp.name == "Odoo MCP Server"
    assert server.mcp.instructions == "MCP Server for interacting with Odoo ERP systems"


def test_server_registers_expected_tools_and_resources_without_lifespan():
    server = importlib.import_module("odoo_mcp.server")

    tools = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    resources = {
        str(resource.uri) for resource in asyncio.run(server.mcp.list_resources())
    }
    templates = {
        str(template.uriTemplate)
        for template in asyncio.run(server.mcp.list_resource_templates())
    }

    expected_tools = {
        "execute_method",
        "list_models",
        "get_model_fields",
        "search_records",
        "read_record",
        "search_employee",
        "search_holidays",
        "diagnose_odoo_call",
        "diagnose_access",
        "inspect_model_relationships",
        "generate_json2_payload",
        "upgrade_risk_report",
        "fit_gap_report",
        "get_odoo_profile",
        "schema_catalog",
        "preview_write",
        "validate_write",
        "execute_approved_write",
        "scan_addons_source",
        "build_domain",
        "business_pack_report",
        "health_check",
        "aggregate_records",
        "chatter_post",
        # NESA backlog part B — document, report and pricing surface.
        "read_records",
        "get_document_text",
        "read_attachment",
        "create_attachment_download",
        "create_attachment_from_url",
        "create_attachment_upload",
        "render_report",
        "list_allowed_methods",
        "chatter_read",
        "get_record_url",
        "price_preview",
    }
    assert expected_tools <= tools
    assert len(tools) == 35
    assert "odoo://models" in resources
    assert {
        "odoo://model/{model_name}",
        "odoo://record/{model_name}/{record_id}",
        "odoo://search/{model_name}/{domain}",
    } <= templates

    prompts = {prompt.name for prompt in asyncio.run(server.mcp.list_prompts())}
    assert {
        "diagnose_failed_odoo_call",
        "fit_gap_workshop",
        "json2_migration_plan",
        "safe_write_review",
        "custom_module_audit",
    } <= prompts


def test_tools_expose_safety_annotations_and_output_schemas():
    server = importlib.import_module("odoo_mcp.server")

    tools = {
        tool.name: tool.model_dump() for tool in asyncio.run(server.mcp.list_tools())
    }

    assert tools["list_models"]["annotations"]["readOnlyHint"] is True
    assert tools["list_models"]["annotations"]["destructiveHint"] is False
    assert tools["diagnose_access"]["annotations"]["readOnlyHint"] is True
    assert tools["preview_write"]["annotations"]["destructiveHint"] is False
    assert tools["execute_approved_write"]["annotations"]["destructiveHint"] is True
    assert tools["execute_method"]["annotations"]["destructiveHint"] is True
    assert tools["get_odoo_profile"]["outputSchema"]["type"] == "object"


def test_resources_are_json_with_assistant_annotations():
    server = importlib.import_module("odoo_mcp.server")

    resources = {
        str(resource.uri): resource.model_dump()
        for resource in asyncio.run(server.mcp.list_resources())
    }
    templates = {
        str(template.uriTemplate): template.model_dump()
        for template in asyncio.run(server.mcp.list_resource_templates())
    }

    assert resources["odoo://models"]["mimeType"] == "application/json"
    assert resources["odoo://models"]["annotations"]["audience"] == ["assistant"]
    assert templates["odoo://model/{model_name}"]["mimeType"] == "application/json"


def test_domain_normalization_accepts_json_object_and_standard_domain_list():
    server = importlib.import_module("odoo_mcp.server")

    assert server.normalize_domain_input('[["name", "ilike", "ada"]]') == [
        ["name", "ilike", "ada"]
    ]
    assert server.normalize_domain_input(
        {"conditions": [{"field": "id", "operator": ">", "value": 0}]}
    ) == [["id", ">", 0]]
    assert server.normalize_domain_input(
        ["|", ["name", "=", "Ada"], ["id", ">", 0]]
    ) == [
        "|",
        ["name", "=", "Ada"],
        ["id", ">", 0],
    ]


def test_safety_helpers_reject_bad_model_names_and_bounds_limits():
    server = importlib.import_module("odoo_mcp.server")

    assert server.clamp_limit(999) == 100
    server.validate_model_name("res.partner")
    server.validate_method_name("search_read")

    try:
        server.validate_model_name("res.partner;DROP")
    except ValueError as exc:
        assert "Invalid model name" in str(exc)
    else:
        raise AssertionError("unsafe model name should be rejected")

    try:
        server.validate_method_name("search-read")
    except ValueError as exc:
        assert "Invalid method name" in str(exc)
    else:
        raise AssertionError("unsafe method name should be rejected")

    try:
        server.clamp_limit(0)
    except ValueError as exc:
        assert "limit" in str(exc)
    else:
        raise AssertionError("zero limit should be rejected")


def test_lifespan_is_lazy_and_preview_tools_call_tool_succeed_when_client_raises(
    monkeypatch,
):
    server = importlib.import_module("odoo_mcp.server")

    def fail_client():
        raise AssertionError("get_odoo_client should not be called for preview tools")

    monkeypatch.setattr(server, "get_odoo_client", fail_client)

    async def enter_lifespan():
        async with server.app_lifespan(server.mcp) as lifespan_context:
            return lifespan_context

    context = asyncio.run(enter_lifespan())
    assert context._odoo is None

    payload = call_tool_json(
        server,
        "generate_json2_payload",
        {
            "model": "res.partner",
            "method": "search_read",
            "args": [[["id", ">", 0]]],
            "kwargs": {"fields": ["name"], "limit": 1},
            "database": "demo-db",
        },
    )
    assert payload["success"] is True
    assert payload["metadata_used"]["client_instantiated"] is False
    assert payload["headers"]["X-Odoo-Database"] == "demo-db"

    diagnosis = call_tool_json(
        server,
        "diagnose_odoo_call",
        {"model": "res.partner", "method": "write", "args": [[7], {"name": "Ada"}]},
    )
    assert diagnosis["classification"]["safety"] == "destructive"

    upgrade = call_tool_json(
        server,
        "upgrade_risk_report",
        {
            "target_version": "20.0",
            "methods": [{"model": "res.partner", "method": "write"}],
        },
    )
    assert upgrade["transport"]["xmlrpc_jsonrpc_deprecation"] == "Odoo 20 fall 2026"

    fit_gap = call_tool_json(
        server,
        "fit_gap_report",
        {"requirements": ["Track contacts", "Complex custom workflow"]},
    )
    assert fit_gap["success"] is True
    assert fit_gap["summary"]["fit"] >= 1


def test_report_tools_do_not_execute_candidate_methods():
    server = importlib.import_module("odoo_mcp.server")

    class ExplodingClient:
        def execute_method(self, *args, **kwargs):
            raise AssertionError("diagnostic tools must not execute candidate methods")

        def get_model_fields(self, model):
            return {"partner_id": {"type": "many2one", "relation": "res.partner"}}

    assert server.diagnose_odoo_call("res.partner", "write")["success"] is True
    assert server.generate_json2_payload("res.partner", "write")["success"] is True
    assert (
        server.upgrade_risk_report(
            methods=[{"model": "res.partner", "method": "write"}]
        )["success"]
        is True
    )
    assert server.fit_gap_report(["Track contacts"])["success"] is True
    relationships = server.inspect_model_relationships(
        FakeCtx(ExplodingClient()),
        "res.partner",
        use_live_metadata=True,
    )
    assert relationships["success"] is True
    assert relationships["relationships"]["many2one"][0]["relation"] == "res.partner"


def test_inspect_model_relationships_uses_only_get_model_fields_for_live_metadata():
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class FakeClient:
        def get_model_fields(self, model):
            calls.append(("get_model_fields", model))
            return {"partner_id": {"type": "many2one", "relation": "res.partner"}}

        def execute_method(self, *args, **kwargs):
            calls.append(("execute_method", args, kwargs))
            raise AssertionError("execute_method must not be used")

    report = server.inspect_model_relationships(FakeCtx(FakeClient()), "res.partner")

    assert report["success"] is True
    assert calls == [("get_model_fields", "res.partner")]


def test_new_tools_return_stable_top_level_response_keys():
    server = importlib.import_module("odoo_mcp.server")

    payload = call_tool_json(
        server,
        "generate_json2_payload",
        {"model": "res.partner", "method": "search_read", "args": [[]]},
    )
    assert {
        "success",
        "tool",
        "model",
        "method",
        "endpoint",
        "headers",
        "body",
        "warnings",
        "transaction",
        "classification",
        "metadata_used",
    } <= payload.keys()

    diagnosis = call_tool_json(
        server,
        "diagnose_odoo_call",
        {"model": "res.partner", "method": "search_read", "args": [[]]},
    )
    assert {
        "success",
        "tool",
        "classification",
        "issues",
        "suggested_payload",
    } <= diagnosis.keys()

    access = server.diagnose_access(
        FakeCtx(AccessDiagnosticClient()),
        "res.partner",
        "read",
        expected_count=1,
    )
    assert {"success", "tool", "diagnosis", "access", "rules"} <= access.keys()

    upgrade = call_tool_json(server, "upgrade_risk_report", {"target_version": "20.0"})
    assert {"success", "tool", "summary", "risks", "transport"} <= upgrade.keys()

    fit_gap = call_tool_json(
        server, "fit_gap_report", {"requirements": ["Track contacts"]}
    )
    assert {"success", "tool", "summary", "items", "metadata_used"} <= fit_gap.keys()


def test_safe_write_preview_validate_and_execute_gates(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    preview = call_tool_json(
        server,
        "preview_write",
        {
            "model": "res.partner",
            "operation": "write",
            "record_ids": [7],
            "values": {"name": "Ada"},
        },
    )

    # NESA A2: preview_write is a dry run and must not hand out a token that
    # execute_approved_write would then reject.
    assert preview["success"] is True
    assert "approval" not in preview
    assert preview["approval_token_issued"] is False
    assert "validate_write" in preview["next_step"]
    assert preview["payload"]["record_ids"] == [7]

    class FakeClient:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            raise AssertionError("writes must stay disabled without env gate")

    validation = server.validate_write(
        FakeCtx(FakeClient()),
        "res.partner",
        "write",
        values={"name": "Ada"},
        record_ids=[7],
    )
    assert validation["success"] is True
    assert validation["approval"]["token"].startswith("odoo-write:")

    monkeypatch.delenv("ODOO_MCP_ENABLE_WRITES", raising=False)
    untokenized = dict(preview["payload"])
    preview_only_blocked = server.execute_approved_write(
        FakeCtx(FakeClient()), untokenized, confirm=True
    )
    assert preview_only_blocked["success"] is False
    assert "token" in preview_only_blocked["error"]

    ctx = FakeCtx(FakeClient())
    validation = server.validate_write(
        ctx,
        "res.partner",
        "write",
        values={"name": "Ada"},
        record_ids=[7],
    )
    assert validation["success"] is True
    assert validation["approval"]["token"].startswith("odoo-write:")

    blocked = server.execute_approved_write(ctx, validation["approval"], confirm=True)
    assert blocked["success"] is False
    assert "disabled" in blocked["error"]

    bad = dict(validation["approval"])
    bad["values"] = {"name": "Grace"}
    rejected = server.execute_approved_write(ctx, bad, confirm=True)
    assert rejected["success"] is False
    assert "token" in rejected["error"]


def test_execute_method_validates_model_and_method_before_client_call():
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            raise AssertionError("invalid input must fail before client call")

    result = server.execute_method(FakeCtx(FakeClient()), "res.partner", "bad-method")

    assert result["success"] is False
    assert "Invalid method name" in result["error"]


def test_execute_method_blocks_direct_writes_and_unknown_methods(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            raise AssertionError("blocked methods must fail before client call")

    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.delenv("ODOO_MCP_NATIVE_ACL_PARITY", raising=False)

    blocked_write = server.execute_method(
        FakeCtx(FakeClient()),
        "res.partner",
        "write",
        args=[[7], {"name": "Ada"}],
    )
    assert blocked_write["success"] is False
    assert "validate_write" in blocked_write["error"]
    assert blocked_write["transient_model"] is False

    blocked_unknown = server.execute_method(
        FakeCtx(FakeClient()),
        "sale.order",
        "action_confirm",
        args=[[7]],
    )
    assert blocked_unknown["success"] is False
    assert "blocked by default" in blocked_unknown["error"]
    assert blocked_unknown["classification"]["safety"] == "side_effect"


@pytest.mark.parametrize(
    "method",
    [
        "web_save",
        "name_create",
        "copy",
        "copy_data",
        "copy_multi",
        "create_multi",
        "load",
        "import_data",
        "update_field_translations",
        "web_override_translations",
    ],
)
def test_execute_method_blocks_write_equivalent_aliases_in_native_parity(
    monkeypatch, method,
):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *_args, **_kwargs):
            raise AssertionError("write aliases must fail before the Odoo call")

    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    result = server.execute_method(
        FakeCtx(FakeClient()), "res.partner", method, args=[]
    )

    assert result["success"] is False
    assert "write-equivalent aliases" in result["error"]


@pytest.mark.parametrize(
    ("model", "method"),
    [
        ("nesa.mcp.approval.token", "mcp_register_approval"),
        ("nesa.mcp.allowed_method", "create_allowlist_entry"),
        ("nesa.mcp.audit_log", "clear_log"),
        ("nesa.mcp.shadow.compare", "action_apply"),
        ("nesa.agent.definition", "action_activate"),
        ("nesa.agent.pending.action", "action_approve"),
    ],
)
def test_control_plane_hard_deny_is_not_configurable(
    monkeypatch, model, method,
):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *_args, **_kwargs):
            raise AssertionError("control-plane calls must fail before Odoo")

    monkeypatch.delenv("ODOO_MCP_DENIED_METHOD_PREFIXES", raising=False)
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    result = server.execute_method(
        FakeCtx(FakeClient()), model, method, args=[]
    )

    assert result["success"] is False
    assert "hard-deny" in result["error"]


def test_execute_method_can_opt_into_unknown_methods(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"ok": True}

    monkeypatch.setenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", "1")

    result = server.execute_method(
        FakeCtx(FakeClient()),
        "sale.order",
        "action_confirm",
        args=[[7]],
    )

    assert result["success"] is True
    assert calls == [(("sale.order", "action_confirm", [7]), {})]


def test_execute_method_native_acl_parity_requires_strict_per_user(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"ok": True}

    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "0")

    blocked = server.execute_method(
        FakeCtx(FakeClient()),
        "hr.leave",
        "action_approve",
        args=[[500]],
    )
    assert blocked["success"] is False
    assert calls == []

    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    def fail_if_allowlist_is_consulted(*_args, **_kwargs):
        raise AssertionError("native ACL parity must not consult a positive list")

    monkeypatch.setattr(
        server, "side_effect_method_allowed", fail_if_allowlist_is_consulted,
    )
    allowed = server.execute_method(
        FakeCtx(FakeClient()),
        "hr.leave",
        "action_approve",
        args=[[500]],
    )

    assert allowed["success"] is True
    assert calls == [(("hr.leave", "action_approve", [500]), {})]


def test_native_acl_parity_default_stdio_remains_disabled(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.delenv("ODOO_MCP_REQUIRE_PER_USER", raising=False)
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)

    assert server.native_acl_parity_requested() is True
    assert server.native_acl_parity_enabled() is False


def test_execute_method_native_acl_parity_preserves_odoo_denial(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class DeniedClient:
        def execute_method(self, *_args, **_kwargs):
            raise RuntimeError("AccessError: native Odoo record rule denied write")

    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    result = server.execute_method(
        FakeCtx(DeniedClient()),
        "hr.leave",
        "action_approve",
        args=[[500]],
    )

    assert result["success"] is False
    assert "AccessError" in result["error"]
    assert "record rule denied write" in result["error"]


def test_execute_method_audits_login_target_and_strips_suppression_context(
    monkeypatch, caplog,
):
    server = importlib.import_module("odoo_mcp.server")
    per_user = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    calls = []

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return True

    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    token = per_user.set_user_context("monteur@example.com", "secret-api-key")
    try:
        with caplog.at_level("INFO", logger="odoo_mcp.server"):
            result = server.execute_method(
                FakeCtx(FakeClient()),
                "hr.leave",
                "action_approve",
                args=[[500]],
                kwargs={
                    "context": {
                        "lang": "de_DE",
                        "tracking_disable": True,
                        "mail_notrack": True,
                        "mail_create_nolog": True,
                    }
                },
            )
    finally:
        per_user.reset_user_context(token)

    assert result["success"] is True
    assert calls[0][1] == {"context": {"lang": "de_DE"}}
    assert "Removed audit-suppression context keys" in result["warnings"][0]
    assert "login=monteur@example.com" in caplog.text
    assert "model=hr.leave" in caplog.text
    assert "method=action_approve" in caplog.text
    assert "secret-api-key" not in caplog.text


def test_execute_method_native_acl_parity_never_calls_private_methods(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *_args, **_kwargs):
            raise AssertionError("private methods must fail before Odoo call")

    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")

    result = server.execute_method(
        FakeCtx(FakeClient()),
        "hr.leave",
        "_action_validate",
        args=[[500]],
    )

    assert result["success"] is False
    assert "Private underscore methods" in result["error"]


@pytest.mark.parametrize(
    ("mode_env", "mode_value"),
    [
        ("ODOO_MCP_NATIVE_ACL_PARITY", "1"),
        ("ODOO_MCP_ALLOW_UNKNOWN_METHODS", "1"),
        ("ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "account.move.action_post"),
    ],
)
def test_execute_method_hard_deny_precedes_every_execution_mode(
    monkeypatch, mode_env, mode_value,
):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *_args, **_kwargs):
            raise AssertionError("hard-denied methods must fail before Odoo call")

    for env_name in (
        "ODOO_MCP_NATIVE_ACL_PARITY",
        "ODOO_MCP_ALLOW_UNKNOWN_METHODS",
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS",
    ):
        monkeypatch.delenv(env_name, raising=False)
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    monkeypatch.setenv("ODOO_MCP_DENIED_METHOD_PREFIXES", " account.move. , HR.PAYSLIP. ")
    monkeypatch.setenv(mode_env, mode_value)

    result = server.execute_method(
        FakeCtx(FakeClient()),
        "account.move",
        "action_post",
        args=[[42]],
    )

    assert result["success"] is False
    assert "hard-deny policy (account.move.)" in result["error"]


def test_execute_method_allows_exact_side_effect_allowlist(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return {"ok": True}

    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "sale.order.action_confirm"
    )

    allowed = server.execute_method(
        FakeCtx(FakeClient()),
        "sale.order",
        "action_confirm",
        args=[[7]],
    )
    blocked = server.execute_method(
        FakeCtx(FakeClient()),
        "res.partner",
        "message_post",
        args=[[7]],
    )

    assert allowed["success"] is True
    assert calls == [(("sale.order", "action_confirm", [7]), {})]
    assert blocked["success"] is False
    assert "Unreviewed side-effect" in blocked["error"]


def test_validate_write_only_registers_live_metadata_approvals(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *args, **kwargs):
            raise AssertionError("non-registered approvals must fail before execution")

    ctx = FakeCtx(FakeClient())
    shape_only = server.validate_write(
        ctx,
        "res.partner",
        "write",
        values={"name": "Ada"},
        record_ids=[7],
        use_live_metadata=False,
    )

    assert shape_only["success"] is True
    assert shape_only["approval_status"]["stored"] is False
    assert ctx.request_context.lifespan_context.odoo.approval_store == {}

    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    blocked = server.execute_approved_write(ctx, shape_only["approval"], confirm=True)
    assert blocked["success"] is False
    assert "validated" in blocked["error"]

    empty_metadata = server.validate_write(
        FakeCtx(FakeClient()),
        "res.partner",
        "write",
        values={"name": "Ada"},
        record_ids=[7],
        fields_metadata={},
        use_live_metadata=False,
    )
    assert empty_metadata["success"] is False
    assert empty_metadata["issues"][0]["code"] == "unknown_field"
    assert empty_metadata["approval"] is None


def test_validate_write_rejects_empty_live_metadata_for_unlink(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class EmptyMetadataClient:
        def get_model_fields(self, model):
            return {}

        def execute_method(self, *args, **kwargs):
            raise AssertionError("empty metadata must fail before execution")

    ctx = FakeCtx(EmptyMetadataClient())
    validation = server.validate_write(
        ctx,
        "res.partner",
        "unlink",
        record_ids=[7],
    )

    assert validation["success"] is False
    assert "metadata was empty" in validation["error"]
    assert validation["approval_status"]["stored"] is False
    assert ctx.request_context.lifespan_context.odoo.approval_store == {}

    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    preview = server.preview_write("res.partner", "unlink", record_ids=[7])
    blocked = server.execute_approved_write(ctx, preview["payload"], confirm=True)
    assert blocked["success"] is False
    assert "token" in blocked["error"]


def test_execute_approved_write_runs_only_after_all_gates(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return True

    calls = []
    ctx = FakeCtx(FakeClient())
    validation = server.validate_write(
        ctx,
        "res.partner",
        "write",
        values={"name": "Ada"},
        record_ids=[7],
        context={"lang": "en_US"},
    )

    assert validation["approval_status"]["stored"] is True
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, validation["approval"], confirm=True)

    assert result["success"] is True
    assert calls == [
        (
            ("res.partner", "write", [7], {"name": "Ada"}),
            {"context": {"lang": "en_US"}},
        )
    ]


def test_execute_approved_write_audits_and_strips_suppression_context(
    monkeypatch, caplog,
):
    server = importlib.import_module("odoo_mcp.server")
    per_user = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    calls = []

    class FakeClient:
        def get_model_fields(self, _model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return True

    ctx = FakeCtx(FakeClient())
    validation = server.validate_write(
        ctx,
        "res.partner",
        "write",
        values={"name": "Ada"},
        record_ids=[7],
        context={"lang": "de_DE", "tracking_disable": True},
    )
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    token = per_user.set_user_context("office@example.com", "another-secret")
    try:
        with caplog.at_level("INFO", logger="odoo_mcp.server"):
            result = server.execute_approved_write(
                ctx, validation["approval"], confirm=True
            )
    finally:
        per_user.reset_user_context(token)

    business_call = next(
        call for call in calls if call[0][:2] == ("res.partner", "write")
    )
    assert business_call[1] == {"context": {"lang": "de_DE"}}
    assert result["success"] is True
    assert result["warnings"]
    assert "login=office@example.com" in caplog.text
    assert "another-secret" not in caplog.text


def test_hard_deny_applies_to_every_approved_write_stage(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class FakeClient:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return True

    ctx = FakeCtx(FakeClient())
    monkeypatch.delenv("ODOO_MCP_DENIED_METHOD_PREFIXES", raising=False)
    validation = server.validate_write(
        ctx,
        "account.move",
        "write",
        values={"name": "blocked"},
        record_ids=[42],
    )
    assert validation["success"] is True
    assert validation["approval_status"]["stored"] is True

    monkeypatch.setenv("ODOO_MCP_DENIED_METHOD_PREFIXES", "account.move.")
    preview = server.preview_write(
        "account.move", "write", values={"name": "blocked"}, record_ids=[42],
    )
    revalidation = server.validate_write(
        ctx,
        "account.move",
        "write",
        values={"name": "blocked"},
        record_ids=[42],
    )
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    execution = server.execute_approved_write(
        ctx, validation["approval"], confirm=True,
    )

    for result in (preview, revalidation, execution):
        assert result["success"] is False
        assert "hard-deny policy (account.move.)" in result["error"]
    assert calls == []


def test_datev_export_method_uses_real_model_method_prefix(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def execute_method(self, *_args, **_kwargs):
            raise AssertionError("DATEV export must fail before Odoo call")

    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    monkeypatch.setenv(
        "ODOO_MCP_DENIED_METHOD_PREFIXES",
        "account.general.ledger.report.handler.l10n_de_datev",
    )

    result = server.execute_method(
        FakeCtx(FakeClient()),
        "account.general.ledger.report.handler",
        "l10n_de_datev_export_to_zip_and_attach",
        args=[{}],
    )

    assert result["success"] is False
    assert "hard-deny policy" in result["error"]


def test_schema_catalog_caches_and_business_pack_uses_live_metadata():
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def __init__(self):
            self.model_calls = 0

        def get_models(self):
            self.model_calls += 1
            return {
                "model_names": ["res.partner", "sale.order"],
                "models_details": {
                    "res.partner": {"name": "Contact"},
                    "sale.order": {"name": "Sales Order"},
                },
            }

        def get_model_fields(self, model):
            return {"name": {"type": "char"}}

        def get_installed_modules(self, limit=100):
            return [{"name": "sale"}, {"name": "crm"}]

    fake = FakeClient()
    ctx = FakeCtx(fake)
    first = server.schema_catalog(ctx, query="sale", include_fields=True)
    second = server.schema_catalog(ctx, query="sale", include_fields=True)
    pack = server.business_pack_report(ctx, "sales")

    assert first["success"] is True
    assert first["result"][0]["model"] == "sale.order"
    assert second["metadata_used"]["cache_hit"] is True
    assert fake.model_calls == 2
    assert pack["success"] is True
    assert "sale" in pack["installed_modules"]


def test_domain_builder_and_addon_scanner(tmp_path: Path, monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    domain = call_tool_json(
        server,
        "build_domain",
        {
            "conditions": [
                {"field": "name", "operator": "ilike", "value": "Ada"},
                {"field": "id", "operator": "in", "value": [1, 2]},
            ],
            "logical_operator": "or",
        },
    )
    assert domain["success"] is True
    assert domain["domain"][0] == "|"

    addon = tmp_path / "custom_sale"
    addon.mkdir()
    (addon / "__manifest__.py").write_text(
        "{'name': 'Custom Sale', 'depends': ['sale'], 'installable': True}",
        encoding="utf-8",
    )
    (addon / "models.py").write_text(
        "from odoo import api, fields, models\n"
        "class X(models.Model):\n"
        "    _name = 'x.demo'\n"
        "    amount = fields.Float(compute='_compute_amount')\n"
        "    total = fields.Float(compute='_compute_total')\n"
        "    def _compute_amount(self):\n"
        "        for record in self:\n"
        "            record.amount = record.qty * record.price\n"
        "    @api.depends('qty', 'price')\n"
        "    def _compute_total(self):\n"
        "        for record in self:\n"
        "            record.total = record.qty * record.price\n"
        "    def create(self, vals):\n"
        "        return {'id': 1}\n"
        "    def write(self, vals):\n"
        "        result = super().write(vals)\n"
        "        return result\n"
        "    def unlink(self):\n"
        "        super().unlink()\n"
        "        return True\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ODOO_ADDONS_PATHS", str(tmp_path))
    scan = call_tool_json(
        server,
        "scan_addons_source",
        {"addons_paths": [str(tmp_path)], "max_files": 20},
    )

    assert scan["success"] is True
    assert scan["summary"]["modules"] == 1
    codes = {item["code"] for item in scan["source_findings"]}
    assert "custom_method" in codes
    assert "computed_method_missing_depends" in codes
    assert "computed_depends_missing_fields" not in codes
    assert "crud_override_missing_super" in codes
    assert "crud_override_super_not_returned" in codes

    blocked_scan = call_tool_json(
        server,
        "scan_addons_source",
        {"addons_paths": [str(tmp_path.parent)], "max_files": 20},
    )
    assert blocked_scan["success"] is False
    assert "outside configured ODOO_ADDONS_PATHS" in blocked_scan["error"]


def test_profile_health_and_prompts_are_available():
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        url = "https://odoo.example.test"
        hostname = "odoo.example.test"
        db = "demo-db"
        username = "demo"
        transport = "xmlrpc"
        timeout = 3
        verify_ssl = True
        json2_database_header = True

        def get_server_version(self):
            return {"server_version": "19.0"}

        def get_user_context(self):
            return {"lang": "en_US"}

    profile = server.get_odoo_profile(
        FakeCtx(FakeClient()), include_modules=False, module_limit=10
    )
    assert profile["success"] is True
    assert profile["profile"]["server_version"]["server_version"] == "19.0"

    health = call_tool_json(server, "health_check", {})
    assert health["success"] is True
    assert health["server"]["tool_count"] == 35
    assert health["runtime"]["chatter_direct_enabled"] is False
    assert health["runtime"]["broad_unknown_method_mode"]["enabled"] is False

    prompt = asyncio.run(
        server.mcp.get_prompt(
            "safe_write_review",
            {"model": "res.partner", "operation": "write"},
        )
    )
    assert "execute_approved_write" in prompt.messages[0].content.text


class AccessDiagnosticClient:
    uid = 7

    def __init__(self, *, fail_acl=False, fail_rules=False, count=1):
        self.fail_acl = fail_acl
        self.fail_rules = fail_rules
        self.count = count

    def get_user_context(self):
        return {"lang": "en_US", "uid": 7}

    def execute_method(self, model, method, *args, **kwargs):
        if model == "ir.model" and method == "search_read":
            return [{"id": 11, "name": "Contact", "model": "res.partner"}]
        if model == "res.users" and method == "fields_get":
            return {
                "id": {"type": "integer"},
                "name": {"type": "char"},
                "groups_id": {"type": "many2many", "relation": "res.groups"},
                "company_id": {"type": "many2one", "relation": "res.company"},
                "company_ids": {"type": "many2many", "relation": "res.company"},
            }
        if model == "res.users" and method == "read":
            return [{"id": 7, "name": "Demo", "groups_id": [3, 9]}]
        if model == "ir.model.access" and method == "search_read":
            if self.fail_acl:
                raise ValueError("Access denied reading ir.model.access")
            return [
                {
                    "id": 21,
                    "name": "partner user",
                    "model_id": [11, "Contact"],
                    "group_id": [3, "Sales / User"],
                    "perm_read": True,
                    "perm_write": False,
                    "perm_create": False,
                    "perm_unlink": False,
                }
            ]
        if model == "ir.rule" and method == "search_read":
            if self.fail_rules:
                raise ValueError("Access denied reading ir.rule")
            return [
                {
                    "id": 31,
                    "name": "own contacts",
                    "model_id": [11, "Contact"],
                    "domain_force": "[('user_id', '=', user.id)]",
                    "groups": [3],
                    "active": True,
                    "perm_read": True,
                    "perm_write": True,
                    "perm_create": True,
                    "perm_unlink": True,
                }
            ]
        if model == "res.partner" and method == "search_count":
            return self.count
        raise AssertionError(f"unexpected call: {model}.{method}")


def test_diagnose_access_reports_acl_rules_and_count_mismatch():
    server = importlib.import_module("odoo_mcp.server")

    report = server.diagnose_access(
        FakeCtx(AccessDiagnosticClient(count=1)),
        "res.partner",
        "read",
        expected_count=2,
        verbose=True,
    )

    codes = {item["code"] for item in report["diagnosis"]["codes"]}
    assert report["success"] is True
    assert report["permission_field"] == "perm_read"
    assert report["actual_count"] == 1
    assert report["access"]["granting_count"] == 1
    assert report["rules"]["group_bound"][0]["name"] == "own contacts"
    assert "record_rule_filter_likely" in codes


def test_diagnose_access_default_omits_full_acl_and_rule_dumps():
    """NESA A9: the compact answer keeps counts, not every row."""
    server = importlib.import_module("odoo_mcp.server")

    report = server.diagnose_access(
        FakeCtx(AccessDiagnosticClient(count=1)),
        "res.partner",
        "read",
        expected_count=2,
    )

    assert report["access"]["rows"] is None
    assert report["access"]["row_count"] >= 1
    assert report["rules"]["group_bound"] is None
    assert report["rules"]["group_bound_count"] == 1
    assert report["rules"]["applicable_count"] >= 0


def test_diagnose_access_uses_odoo19_group_ids_field():
    server = importlib.import_module("odoo_mcp.server")

    class Odoo19AccessDiagnosticClient(AccessDiagnosticClient):
        def execute_method(self, model, method, *args, **kwargs):
            if model == "res.users" and method == "fields_get":
                return {
                    "id": {"type": "integer"},
                    "name": {"type": "char"},
                    "group_ids": {"type": "many2many", "relation": "res.groups"},
                    "all_group_ids": {"type": "many2many", "relation": "res.groups"},
                    "company_id": {"type": "many2one", "relation": "res.company"},
                    "company_ids": {"type": "many2many", "relation": "res.company"},
                }
            if model == "res.users" and method == "read":
                return [
                    {
                        "id": 7,
                        "name": "Demo",
                        "login": "demo",
                        "group_ids": [3],
                        "all_group_ids": [3, 9],
                    }
                ]
            if model == "res.groups" and method == "read":
                # NESA A9: decisive groups are resolved to readable names.
                return [{"id": 3, "display_name": "Sales / User"}]
            return super().execute_method(model, method, *args, **kwargs)

    report = server.diagnose_access(
        FakeCtx(Odoo19AccessDiagnosticClient(count=1)),
        "res.partner",
        "read",
        expected_count=1,
    )

    assert report["success"] is True
    assert report["metadata_errors"] == []
    # NESA A9: the compact default no longer dumps raw membership lists.
    assert report["verbose"] is False
    assert "direct_group_ids" not in report["current_user"]
    assert report["current_user"]["group_count"] == 2
    assert report["access"]["granting_count"] == 1

    verbose_report = server.diagnose_access(
        FakeCtx(Odoo19AccessDiagnosticClient(count=1)),
        "res.partner",
        "read",
        expected_count=1,
        verbose=True,
    )
    assert verbose_report["current_user"]["group_field"] == "group_ids"
    assert verbose_report["current_user"]["all_group_field"] == "all_group_ids"
    assert verbose_report["current_user"]["direct_group_ids"] == [3]
    assert verbose_report["current_user"]["all_group_ids"] == [3, 9]


def test_diagnose_access_reports_missing_permission_metadata():
    server = importlib.import_module("odoo_mcp.server")

    report = server.diagnose_access(
        FakeCtx(AccessDiagnosticClient(fail_acl=True)),
        "res.partner",
        "write",
        expected_count=1,
    )

    codes = {item["code"] for item in report["diagnosis"]["codes"]}
    assert report["success"] is True
    assert report["permission_field"] == "perm_write"
    assert report["metadata_errors"][0]["stage"] == "ir.model.access"
    assert "metadata_access_unavailable" in codes


def test_diagnose_access_survives_record_rule_read_failure():
    server = importlib.import_module("odoo_mcp.server")

    report = server.diagnose_access(
        FakeCtx(AccessDiagnosticClient(fail_rules=True)),
        "res.partner",
        "read",
        expected_count=1,
    )

    codes = {item["code"] for item in report["diagnosis"]["codes"]}
    assert report["success"] is True
    assert report["access"]["granting_count"] == 1
    assert report["metadata_errors"][0]["stage"] == "ir.rule"
    assert "metadata_access_unavailable" in codes


# ----- Smart field selection (Phase 1.1) -----


class _SmartFieldsClient:
    """Recording client used to verify smart-field plumbing."""

    def __init__(self, fields_meta=None, records=None):
        self.fields_meta = fields_meta or {
            "id": {"type": "integer"},
            "name": {"type": "char"},
            "code": {"type": "char"},
            "state": {"type": "selection"},
            "partner_id": {"type": "many2one"},
            "create_uid": {"type": "many2one"},
            "create_date": {"type": "datetime"},
            "message_ids": {"type": "one2many"},
            "avatar_128": {"type": "binary"},
        }
        self.records = records or [{"id": 1, "name": "Demo", "code": "D-1"}]
        self.search_read_calls = []
        self.read_calls = []
        self.fields_get_calls = 0

    def get_model_fields(self, model):
        self.fields_get_calls += 1
        return self.fields_meta

    def search_read(self, model_name, domain, fields=None, **kwargs):
        self.search_read_calls.append({"model": model_name, "fields": fields, **kwargs})
        return list(self.records)

    def read_records(self, model_name, ids, fields=None):
        self.read_calls.append({"model": model_name, "ids": ids, "fields": fields})
        return list(self.records)

    def execute_method(self, model, method, *args, **kwargs):
        # search_records asks for the real total (NESA A3); ir.model lookups
        # come from the transient check (NESA A1).
        if method == "search_count":
            return len(self.records)
        if model == "ir.model" and method == "search_read":
            return [{"id": 1, "transient": False}]
        raise AssertionError(f"unexpected call {model}.{method}")


def test_search_records_applies_smart_fields_when_caller_omits_fields():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()

    result = server.search_records(FakeCtx(client), "res.partner")

    assert result["success"] is True
    assert result["smart_fields_applied"] is True
    used = result["fields_used"]
    assert "name" in used and "id" in used
    assert "create_uid" not in used
    assert "message_ids" not in used
    assert "avatar_128" not in used
    assert client.search_read_calls[0]["fields"] == used


def test_search_records_star_fields_expand_without_binary_payloads():
    """NESA A10: fields=['*'] must not drag base64 blobs into the answer."""
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()

    result = server.search_records(FakeCtx(client), "res.partner", fields=["*"])

    assert result["success"] is True
    assert result["smart_fields_applied"] is False
    assert result["expanded_wildcard"] is True
    assert result["excluded_binary_fields"] == ["avatar_128"]
    assert "avatar_128" not in result["fields_used"]
    assert "name" in result["fields_used"]
    assert "avatar_128" not in client.search_read_calls[0]["fields"]


def test_search_records_reports_total_count_and_paging_hints():
    """NESA A3/A4: count is the page size, total_count is the truth."""
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient(
        records=[{"id": index, "name": f"P{index}"} for index in range(1, 6)]
    )

    result = server.search_records(FakeCtx(client), "res.partner", limit=5)

    assert result["count"] == 5
    assert result["total_count"] == 5
    assert result["has_more"] is False
    assert result["next_offset"] is None
    assert result["order_used"] == "id desc"
    assert result["order_defaulted"] is True
    assert client.search_read_calls[0]["order"] == "id desc"


def test_search_records_explicit_fields_pass_through():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()

    result = server.search_records(
        FakeCtx(client), "res.partner", fields=["name", "code"]
    )

    assert result["success"] is True
    assert result["smart_fields_applied"] is False
    assert result["fields_used"] == ["name", "code"]
    assert client.search_read_calls[0]["fields"] == ["name", "code"]
    # Explicit fields are validated against fields_get once per model
    # (lifespan cache) so a guessed name never reaches Odoo.
    assert client.fields_get_calls == 1


def test_search_records_rejects_unknown_explicit_fields_before_rpc():
    """A guessed field name must fail in the MCP, not as an Odoo ERROR."""
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient(
        fields_meta={
            "id": {"type": "integer"},
            "name": {"type": "char"},
            "date_end": {"type": "datetime"},
            "planned_date_begin": {"type": "datetime"},
        }
    )

    result = server.search_records(
        FakeCtx(client), "project.task", fields=["name", "planned_date_end"]
    )

    assert result["success"] is False
    assert client.search_read_calls == []  # never reached Odoo
    text = json.dumps(result)
    assert "planned_date_end" in text
    assert "planned_date_begin" in text  # close-match hint


def test_search_records_unknown_field_check_fails_open_without_metadata():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient(fields_meta={"error": "boom"})

    result = server.search_records(
        FakeCtx(client), "res.partner", fields=["name", "whatever"]
    )

    assert result["success"] is True
    assert client.search_read_calls[0]["fields"] == ["name", "whatever"]


def test_read_record_applies_smart_fields_and_uses_schema_cache():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()
    ctx = FakeCtx(client)

    first = server.read_record(ctx, "res.partner", 1)
    second = server.read_record(ctx, "res.partner", 1)

    assert first["success"] is True
    assert first["smart_fields_applied"] is True
    assert "create_date" not in first["fields_used"]
    # schema_cache should be reused — only one fields_get call.
    assert client.fields_get_calls == 1
    assert second["fields_used"] == first["fields_used"]


def test_max_smart_fields_env_caps_selection(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("ODOO_MCP_MAX_SMART_FIELDS", "3")
    client = _SmartFieldsClient()

    result = server.search_records(FakeCtx(client), "res.partner")
    assert len(result["fields_used"]) == 3
    assert result["fields_used"][0] == "id"


# ----- aggregate_records (Phase 1.2) -----


class _AggregateClient:
    def __init__(self, version="17.0+e", rows=None, fail_formatted=False):
        self.version = version
        self.rows = rows if rows is not None else []
        self.fail_formatted = fail_formatted
        self.calls: list[tuple[str, str, dict]] = []

    def get_server_version(self):
        return {"server_version": self.version}

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, kwargs))
        if method == "formatted_read_group" and self.fail_formatted:
            raise RuntimeError("formatted_read_group not available")
        return list(self.rows)


def test_aggregate_records_uses_read_group_on_legacy_odoo():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(
        version="17.0+e",
        rows=[{"state": "draft", "amount_total": 100.0}],
    )

    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["amount_total:sum"],
    )

    assert result["success"] is True
    assert result["method"] == "read_group"
    assert result["major_version"] == 17
    assert result["measures"] == ["amount_total:sum"]
    assert result["row_count"] == 1
    method, kwargs = client.calls[0][1], client.calls[0][2]
    assert method == "read_group"
    assert kwargs["fields"] == ["amount_total:sum"]
    assert kwargs["groupby"] == ["state"]


def test_aggregate_records_uses_formatted_read_group_on_odoo_19():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(
        version="19.0+e",
        rows=[{"state": "sale", "amount_total:sum": 5000.0}],
    )

    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["amount_total:sum"],
    )

    assert result["success"] is True
    assert result["method"] == "formatted_read_group"
    assert result["major_version"] == 19
    assert client.calls[0][1] == "formatted_read_group"
    assert client.calls[0][2]["aggregates"] == ["amount_total:sum"]


def test_aggregate_records_falls_back_when_formatted_read_group_unavailable():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(
        version="19.0",
        rows=[{"state": "draft"}],
        fail_formatted=True,
    )

    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["amount_total:sum"],
    )

    assert result["success"] is True
    assert result["method"] == "read_group"
    assert result["fallback_reason"]
    methods = [call[1] for call in client.calls]
    assert methods == ["formatted_read_group", "read_group"]


def test_aggregate_records_rejects_invalid_measure():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0")

    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["amount_total:bogus"],
    )

    assert result["success"] is False
    assert "bogus" in result["error"]


def test_aggregate_records_requires_group_by():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0")

    result = server.aggregate_records(
        FakeCtx(client), model="sale.order", group_by=[]
    )

    assert result["success"] is False
    assert "group_by" in result["error"]


def test_odoo_major_version_falls_back_to_base_module_latest_version():
    server = importlib.import_module("odoo_mcp.server")

    class StubClient:
        def __init__(self):
            self.execute_calls = []

        def get_server_version(self):
            return {"error": "Not Found"}

        def execute_method(self, model, method, *args, **kwargs):
            self.execute_calls.append((model, method))
            assert model == "ir.module.module"
            return [{"latest_version": "19.0.1.0.0"}]

    stub = StubClient()
    assert server.odoo_major_version(stub) == 19
    assert stub.execute_calls == [("ir.module.module", "search_read")]


def test_odoo_major_version_uses_server_version_metadata_when_present():
    server = importlib.import_module("odoo_mcp.server")

    class StubClient:
        def get_server_version(self):
            return {"server_version": "17.0+e"}

        def execute_method(self, *args, **kwargs):
            raise AssertionError("execute_method should not run when metadata is present")

    assert server.odoo_major_version(StubClient()) == 17


def test_parse_measure_spec_defaults_to_sum_and_validates_aggregator():
    server = importlib.import_module("odoo_mcp.server")

    assert server.parse_measure_spec("amount_total") == ("amount_total", "sum")
    assert server.parse_measure_spec("price:avg") == ("price", "avg")
    try:
        server.parse_measure_spec("name:concat")
    except ValueError as exc:
        assert "concat" in str(exc)
    else:  # pragma: no cover - assertion path
        raise AssertionError("expected ValueError for invalid aggregator")


# ----- chatter_post (Phase 1.3) -----


class _ChatterClient:
    def __init__(self, post_result=4242):
        self.post_result = post_result
        self.calls: list[tuple[str, str, tuple, dict]] = []

    def execute_method(self, model, method, *args, **kwargs):
        if model == "mail.message" and method == "search":
            # Baseline/follow-up lookups from _message_post_returning_id.
            # Keep them out of self.calls so message_post stays calls[0].
            return []
        self.calls.append((model, method, args, kwargs))
        return self.post_result


def test_chatter_post_default_returns_preview_without_executing(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()

    result = server.chatter_post(
        FakeCtx(client),
        model="res.partner",
        record_id=7,
        body="Hello there",
    )

    assert result["success"] is True
    assert result["mode"] == "preview"
    assert result["approval"]["token"].startswith("odoo-write:")
    assert client.calls == []


def test_chatter_post_execute_with_valid_approval_posts(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()
    ctx = FakeCtx(client)

    preview = server.chatter_post(
        ctx, model="res.partner", record_id=7, body="Hi"
    )
    approved = server.chatter_post(
        ctx,
        model="res.partner",
        record_id=7,
        body="Hi",
        approval=preview["approval"],
        confirm=True,
    )

    assert approved["success"] is True
    assert approved["mode"] == "execute"
    assert client.calls[0][0] == "res.partner"
    assert client.calls[0][1] == "message_post"
    assert client.calls[0][2] == ([7],)
    assert client.calls[0][3]["body"] == "Hi"
    assert client.calls[0][3]["message_type"] == "comment"


def test_chatter_post_rejects_token_mismatch(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()
    ctx = FakeCtx(client)

    preview = server.chatter_post(
        ctx, model="res.partner", record_id=7, body="Hi"
    )
    bad = server.chatter_post(
        ctx,
        model="res.partner",
        record_id=7,
        body="Different body",
        approval=preview["approval"],
        confirm=True,
    )

    assert bad["success"] is False
    assert "token" in bad["error"].lower()
    assert client.calls == []


def test_chatter_post_requires_confirm_in_gated_mode(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()
    ctx = FakeCtx(client)

    preview = server.chatter_post(
        ctx, model="res.partner", record_id=7, body="Hi"
    )
    no_confirm = server.chatter_post(
        ctx,
        model="res.partner",
        record_id=7,
        body="Hi",
        approval=preview["approval"],
        confirm=False,
    )

    assert no_confirm["success"] is False
    assert "confirm" in no_confirm["error"].lower()
    assert client.calls == []


def test_chatter_post_direct_mode_posts_immediately(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")
    client = _ChatterClient(post_result=999)

    result = server.chatter_post(
        FakeCtx(client),
        model="res.partner",
        record_id=7,
        body="urgent",
    )

    assert result["success"] is True
    assert result["mode"] == "direct"
    assert result["approval_required"] is False
    assert result["result"] == 999
    assert client.calls[0][1] == "message_post"


def test_chatter_post_direct_mode_resolves_id_when_marshal_fails(monkeypatch):
    """Odoo 18 message_post returns a recordset the RPC layer cannot marshal;
    the note is already committed when serialization fails. The tool must
    swallow exactly that fault and resolve the persisted id via the
    baseline + follow-up mail.message search (commit 250eace)."""
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")

    class _MarshalFaultClient(_ChatterClient):
        def execute_method(self, model, method, *args, **kwargs):
            if model == "mail.message" and method == "search":
                domain = args[0]
                is_followup = any(
                    isinstance(clause, (list, tuple)) and clause[0] == "id"
                    for clause in domain
                )
                return [321] if is_followup else [300]
            self.calls.append((model, method, args, kwargs))
            raise Exception("<Fault 1: cannot marshal objects>")

    client = _MarshalFaultClient()
    result = server.chatter_post(
        FakeCtx(client), model="res.partner", record_id=7, body="hi"
    )

    assert result["success"] is True
    assert result["result"] == 321
    assert client.calls[0][1] == "message_post"


def test_chatter_post_hard_deny_precedes_preview_and_direct_mode(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    client = _ChatterClient()
    monkeypatch.delenv("ODOO_MCP_DENIED_METHOD_PREFIXES", raising=False)
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")

    result = server.chatter_post(
        FakeCtx(client),
        model="nesa.mcp.audit_log",
        record_id=7,
        body="erase evidence",
    )

    assert result["success"] is False
    assert "hard-deny" in result["error"]
    assert client.calls == []


def test_chatter_post_audits_acting_login_without_api_key(monkeypatch, caplog):
    server = importlib.import_module("odoo_mcp.server")
    per_user = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    client = _ChatterClient()
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")
    token = per_user.set_user_context("office@example.com", "chatter-secret")
    try:
        with caplog.at_level("INFO", logger="odoo_mcp.server"):
            result = server.chatter_post(
                FakeCtx(client), model="res.partner", record_id=7, body="Hi"
            )
    finally:
        per_user.reset_user_context(token)

    assert result["success"] is True
    assert "login=office@example.com" in caplog.text
    assert "model=res.partner" in caplog.text
    assert "method=message_post" in caplog.text
    assert "chatter-secret" not in caplog.text


def test_chatter_post_validates_inputs(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()

    empty = server.chatter_post(
        FakeCtx(client), model="res.partner", record_id=7, body="   "
    )
    assert empty["success"] is False
    assert "body" in empty["error"]

    bad_type = server.chatter_post(
        FakeCtx(client),
        model="res.partner",
        record_id=7,
        body="hi",
        message_type="email",
    )
    assert bad_type["success"] is False
    assert "message_type" in bad_type["error"]

    assert client.calls == []


# ----- Edge cases (Group A) ------------------------------------------------


def test_resolve_read_fields_returns_none_when_metadata_unavailable():
    server = importlib.import_module("odoo_mcp.server")

    class FailingClient:
        def get_model_fields(self, model):
            return {"error": "Access denied"}

    app_context = FakeLife(FailingClient())
    resolved, notes = server.resolve_read_fields(
        app_context, app_context.odoo, "res.partner", None
    )
    # NESA A10: no metadata must NOT fall back to "all fields" — that is how a
    # single read of ir.attachment returns megabytes of base64.  Fall back to
    # the two fields every model has and say so.
    assert resolved == ["id", "display_name"]
    assert notes["fields_metadata_available"] is False
    assert "fell back" in notes["warning"]


def test_resolve_read_fields_treats_empty_metadata_as_no_smart():
    server = importlib.import_module("odoo_mcp.server")

    class EmptyClient:
        def get_model_fields(self, model):
            return {}

    app_context = FakeLife(EmptyClient())
    resolved, _notes = server.resolve_read_fields(
        app_context, app_context.odoo, "res.partner", None
    )
    assert resolved == ["id", "display_name"]


def test_resolve_read_fields_passes_explicit_fields_through():
    server = importlib.import_module("odoo_mcp.server")

    class CountingClient:
        calls = 0

        def get_model_fields(self, model):
            # One fields_get per model: served from the lifespan cache after.
            CountingClient.calls += 1
            return {"id": {"type": "integer"}, "name": {"type": "char"},
                    "email": {"type": "char"}}

    app_context = FakeLife(CountingClient())
    resolved, _notes = server.resolve_read_fields(
        app_context, app_context.odoo, "res.partner", ["name", "email"]
    )
    assert resolved == ["name", "email"]
    server.resolve_read_fields(
        app_context, app_context.odoo, "res.partner", ["email"]
    )
    assert CountingClient.calls == 1

    with pytest.raises(ValueError, match="Unknown field"):
        server.resolve_read_fields(
            app_context, app_context.odoo, "res.partner", ["name", "e_mail"]
        )


def test_aggregate_records_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0")

    result = server.aggregate_records(
        FakeCtx(client),
        model="not a model",
        group_by=["state"],
        measures=["amount_total:sum"],
    )
    assert result["success"] is False
    assert "model" in result["error"].lower()
    assert client.calls == []


def test_aggregate_records_rejects_negative_offset():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0")

    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["id:count"],
        offset=-1,
    )
    assert result["success"] is False
    assert "offset" in result["error"]
    assert client.calls == []


def test_aggregate_records_clamps_high_limits():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0", rows=[])

    server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["id:count"],
        limit=999,
    )
    assert client.calls[0][2]["limit"] == 100  # MAX_SEARCH_LIMIT


def test_aggregate_records_passes_lazy_and_order_through():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="18.0", rows=[])

    server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state", "partner_id"],
        measures=["amount_total:sum", "id:count_distinct"],
        lazy=True,
        order="amount_total:sum desc",
    )
    kwargs = client.calls[0][2]
    assert kwargs["lazy"] is True
    assert kwargs["orderby"] == "amount_total:sum desc"
    assert kwargs["groupby"] == ["state", "partner_id"]
    assert kwargs["fields"] == ["amount_total:sum", "id:count_distinct"]


def test_aggregate_records_accepts_all_supported_aggregators():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0", rows=[])

    measures = [
        "amount_total:sum",
        "amount_total:avg",
        "amount_total:min",
        "amount_total:max",
        "id:count",
        "partner_id:count_distinct",
        "tag_ids:array_agg",
        "is_company:bool_and",
        "is_company:bool_or",
    ]
    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=measures,
    )
    assert result["success"] is True
    assert result["measures"] == measures


def test_aggregate_records_accepts_domain_json_string():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0", rows=[])

    result = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["id:count"],
        domain='[["state", "=", "draft"]]',
    )
    assert result["success"] is True
    assert client.calls[0][2]["domain"] == [["state", "=", "draft"]]


def test_chatter_post_rejects_negative_record_id(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()

    result = server.chatter_post(
        FakeCtx(client), model="res.partner", record_id=0, body="hi"
    )
    assert result["success"] is False
    assert "record_id" in result["error"]
    assert client.calls == []


def test_chatter_post_rejects_invalid_model_name(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()

    result = server.chatter_post(
        FakeCtx(client), model="bad model", record_id=1, body="hi"
    )
    assert result["success"] is False
    assert client.calls == []


def test_chatter_post_passes_optional_kwargs_through(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")
    client = _ChatterClient(post_result=42)

    result = server.chatter_post(
        FakeCtx(client),
        model="crm.lead",
        record_id=12,
        body="Body",
        subtype_xmlid="mail.mt_note",
        partner_ids=[1, 2, 3],
        attachment_ids=[7, 8],
    )
    assert result["success"] is True
    kwargs = client.calls[0][3]
    assert kwargs["subtype_xmlid"] == "mail.mt_note"
    assert kwargs["partner_ids"] == [1, 2, 3]
    assert kwargs["attachment_ids"] == [7, 8]
    assert kwargs["body"] == "Body"


def test_chatter_post_token_is_deterministic_for_same_payload(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    client = _ChatterClient()
    ctx = FakeCtx(client)

    a = server.chatter_post(ctx, model="res.partner", record_id=1, body="x")
    b = server.chatter_post(ctx, model="res.partner", record_id=1, body="x")
    assert a["approval"]["token"] == b["approval"]["token"]


def test_chatter_post_propagates_execute_method_failure(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")

    class BoomClient:
        def execute_method(self, *args, **kwargs):
            raise RuntimeError("Odoo refused")

    result = server.chatter_post(
        FakeCtx(BoomClient()), model="res.partner", record_id=1, body="hi"
    )
    assert result["success"] is False
    assert "Odoo refused" in result["error"]


def test_max_smart_fields_invalid_env_falls_back_to_default(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("ODOO_MCP_MAX_SMART_FIELDS", "not-a-number")
    assert server.max_smart_fields() == server.DEFAULT_MAX_SMART_FIELDS

    monkeypatch.setenv("ODOO_MCP_MAX_SMART_FIELDS", "0")
    assert server.max_smart_fields() == 1  # clamped to >=1


# ----- Schema-shape regression (Group B) -----------------------------------


def test_mcp_surface_counts_reports_v030_totals():
    server = importlib.import_module("odoo_mcp.server")
    counts = server.mcp_surface_counts()
    assert counts["tool_count"] == 35
    assert counts["prompt_count"] == 5
    # 1 fixed resource + 3 templates = 4
    assert counts["resource_count"] == 4


def test_new_tools_expose_output_schema_and_annotations():
    import asyncio

    server = importlib.import_module("odoo_mcp.server")
    tools = {
        tool.name: tool.model_dump()
        for tool in asyncio.run(server.mcp.list_tools())
    }

    aggregate = tools["aggregate_records"]
    assert aggregate["annotations"]["readOnlyHint"] is True
    assert aggregate["annotations"]["destructiveHint"] is False
    assert aggregate["outputSchema"]["type"] == "object"

    chatter = tools["chatter_post"]
    assert chatter["annotations"]["readOnlyHint"] is False
    assert chatter["annotations"]["destructiveHint"] is True
    assert chatter["outputSchema"]["type"] == "object"


def test_search_records_and_read_record_response_carry_new_keys():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()

    search = server.search_records(FakeCtx(client), "res.partner", limit=1)
    for required in ("success", "count", "result", "smart_fields_applied", "fields_used"):
        assert required in search

    read = server.read_record(FakeCtx(client), "res.partner", 1)
    for required in ("success", "result", "smart_fields_applied", "fields_used"):
        assert required in read


def test_aggregate_records_response_shape_is_stable():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0", rows=[{"state": "draft"}])

    response = server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["id:count"],
    )
    expected_keys = {
        "success",
        "method",
        "major_version",
        "fallback_reason",
        "model",
        "group_by",
        "measures",
        "row_count",
        "rows",
    }
    assert expected_keys <= set(response)


def test_chatter_post_preview_response_shape_is_stable(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)

    response = server.chatter_post(
        FakeCtx(_ChatterClient()),
        model="res.partner",
        record_id=1,
        body="hi",
    )
    assert response["success"] is True
    assert response["mode"] == "preview"
    approval = response["approval"]
    for key in ("model", "method", "record_ids", "kwargs", "token"):
        assert key in approval
    assert approval["method"] == "message_post"


def test_runtime_security_report_surfaces_chatter_direct(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    report = server.runtime_security_report()
    assert "chatter_direct_enabled" in report
    assert report["chatter_direct_enabled"] is False

    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")
    assert server.runtime_security_report()["chatter_direct_enabled"] is True


def test_runtime_security_report_surfaces_per_user_auth_without_secrets(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    monkeypatch.setenv("ODOO_API_KEY", "must-not-appear")

    report = server.runtime_security_report()
    auth = report["nesa_per_user_auth"]

    assert auth["strict_mode"] is True
    assert auth["credential_cache_entry_count"] >= 0
    assert auth["session_binding_count"] >= 0
    assert "must-not-appear" not in str(report)


def test_runtime_security_report_surfaces_native_acl_parity(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "0")

    disabled = server.runtime_security_report()["native_acl_parity"]
    assert disabled == {
        "requested": True,
        "enabled": False,
        "requires_strict_per_user": True,
        "positive_authorizer": "exact_method_allowlist",
    }

    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    enabled = server.runtime_security_report()["native_acl_parity"]
    assert enabled["requested"] is True
    assert enabled["enabled"] is True
    assert enabled["positive_authorizer"] == (
        "odoo_acl_record_rules_and_business_validation"
    )


def test_runtime_security_report_surfaces_hard_deny_prefixes(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv(
        "ODOO_MCP_DENIED_METHOD_PREFIXES",
        "account.move., nesa.agent., HR.PAYSLIP.",
    )

    report = server.runtime_security_report()

    assert {
        "account.move.",
        "nesa.agent.",
        "hr.payslip.",
    }.issubset(report["denied_method_prefixes"])
    assert "nesa.mcp.approval.token." in report["denied_method_prefixes"]


def test_runtime_security_report_uses_runtime_transport_and_broad_authorizer(
    monkeypatch,
):
    server = importlib.import_module("odoo_mcp.server")
    per_user = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", "1")
    per_user.set_runtime_transport("streamable-http")

    report = server.runtime_security_report()

    assert report["transport"] == "streamable-http"
    assert report["native_acl_parity"]["positive_authorizer"] == (
        "broad_unreviewed_method_mode"
    )


def test_runtime_security_report_redacts_db_allowlist_error(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    allowlist = importlib.import_module("odoo_mcp._nesa_db_allowlist")
    monkeypatch.setattr(
        allowlist,
        "describe_state",
        lambda: {"enabled": True, "last_error": "https://user:key@private/db"},
    )

    report = server.runtime_security_report()

    assert report["nesa_db_allowlist"]["last_error"] == (
        "[redacted: refresh failed]"
    )
    assert "private" not in str(report)


# ----- AppContext / Resources / Pydantic helpers (low-line-count branches) ----


def test_app_context_caches_odoo_factory_result_lazily():
    server = importlib.import_module("odoo_mcp.server")
    calls = {"count": 0}

    class Sentinel:
        pass

    sentinel = Sentinel()

    def factory():
        calls["count"] += 1
        return sentinel

    ctx = server.AppContext(odoo_factory=factory)
    assert ctx._odoo is None
    a = ctx.odoo
    b = ctx.odoo
    assert a is b is sentinel
    assert calls["count"] == 1


def test_search_domain_to_domain_list_converts_conditions_to_tuples():
    server = importlib.import_module("odoo_mcp.server")
    sd = server.SearchDomain(
        conditions=[
            server.DomainCondition(field="name", operator="=", value="Ada"),
            server.DomainCondition(field="active", operator="=", value=True),
        ]
    )
    assert sd.to_domain_list() == [["name", "=", "Ada"], ["active", "=", True]]


def test_resource_get_models_returns_json_when_client_provides_models(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def get_models(self):
            return {"model_names": ["res.partner"], "models_details": {}}

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    payload = json.loads(server.get_models())
    assert payload["model_names"] == ["res.partner"]


def test_resource_get_model_info_returns_combined_payload(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def get_model_info(self, model):
            return {"id": 1, "model": model, "name": "Contact"}

        def get_model_fields(self, model):
            return {"name": {"type": "char"}}

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    info = json.loads(server.get_model_info("res.partner"))
    assert info["fields"] == {"name": {"type": "char"}}
    assert info["id"] == 1


def test_resource_get_model_info_returns_error_for_invalid_name(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        pass

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    info = json.loads(server.get_model_info("bad model"))
    assert "error" in info


def test_resource_get_record_returns_record_when_found(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def read_records(self, model, ids):
            return [{"id": 1, "name": "Ada"}]

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    payload = json.loads(server.get_record("res.partner", "1"))
    assert payload["name"] == "Ada"


def test_resource_get_record_returns_error_when_not_found(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def read_records(self, model, ids):
            return []

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    payload = json.loads(server.get_record("res.partner", "1"))
    assert "Record not found" in payload["error"]


def test_resource_get_record_rejects_invalid_id(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        pass

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    payload = json.loads(server.get_record("res.partner", "0"))
    assert "error" in payload


def test_resource_search_records_returns_results(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        def search_read(self, model, domain, limit=10):
            return [{"id": 1, "name": "Ada"}]

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    payload = json.loads(
        server.search_records_resource("res.partner", '[["name","=","Ada"]]')
    )
    assert payload[0]["name"] == "Ada"


def test_resource_search_records_returns_error_on_invalid_domain(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class FakeClient:
        pass

    monkeypatch.setattr(server, "get_odoo_client", lambda: FakeClient())
    payload = json.loads(server.search_records_resource("res.partner", '"oops"'))
    assert "error" in payload


# ----- parse_measure_spec error branches ---------------------------------


def test_parse_measure_spec_rejects_empty_string():
    server = importlib.import_module("odoo_mcp.server")
    try:
        server.parse_measure_spec("")
    except ValueError as exc:
        assert "non-empty" in str(exc)
    else:
        raise AssertionError("empty spec must raise")


def test_parse_measure_spec_rejects_blank_field_or_aggregator():
    server = importlib.import_module("odoo_mcp.server")
    try:
        server.parse_measure_spec(":sum")
    except ValueError as exc:
        assert "invalid measure spec" in str(exc)
    else:
        raise AssertionError("blank field must raise")
    try:
        server.parse_measure_spec("amount:")
    except ValueError as exc:
        assert "invalid measure spec" in str(exc)
    else:
        raise AssertionError("blank agg must raise")


# ----- odoo_major_version fallback paths ---------------------------------


def test_odoo_major_version_returns_none_when_module_search_returns_empty():
    server = importlib.import_module("odoo_mcp.server")

    class StubClient:
        def get_server_version(self):
            return {"server_version": "no-digits-here"}

        def execute_method(self, *args, **kwargs):
            return []

    assert server.odoo_major_version(StubClient()) is None


def test_odoo_major_version_returns_none_when_latest_version_lacks_digits():
    server = importlib.import_module("odoo_mcp.server")

    class StubClient:
        def get_server_version(self):
            return {}

        def execute_method(self, *args, **kwargs):
            return [{"latest_version": "alpha"}]

    assert server.odoo_major_version(StubClient()) is None


def test_odoo_major_version_returns_none_when_get_server_version_returns_non_dict():
    server = importlib.import_module("odoo_mcp.server")

    class StubClient:
        def get_server_version(self):
            return "string-not-dict"

        def execute_method(self, *args, **kwargs):
            raise RuntimeError("rpc")

    assert server.odoo_major_version(StubClient()) is None


# ----- normalize_domain_input edge cases ---------------------------------


def test_normalize_domain_input_accepts_search_domain_object():
    server = importlib.import_module("odoo_mcp.server")
    sd = server.SearchDomain(
        conditions=[
            server.DomainCondition(field="name", operator="=", value="Ada")
        ]
    )
    assert server.normalize_domain_input(sd) == [["name", "=", "Ada"]]


def test_normalize_domain_input_returns_empty_for_invalid_string():
    server = importlib.import_module("odoo_mcp.server")
    assert server.normalize_domain_input("def x():") == []


def test_normalize_domain_input_handles_python_literal_via_ast():
    server = importlib.import_module("odoo_mcp.server")
    # Python tuple literal that json can't parse but ast.literal_eval can
    assert server.normalize_domain_input("[('name', '=', 'Ada')]") == []


def test_normalize_domain_input_returns_empty_for_dict_without_conditions_list():
    server = importlib.import_module("odoo_mcp.server")
    assert server.normalize_domain_input({"foo": "bar"}) == []
    assert server.normalize_domain_input({"conditions": "not-a-list"}) == []


def test_normalize_domain_input_returns_empty_for_non_list_value():
    server = importlib.import_module("odoo_mcp.server")
    assert server.normalize_domain_input(42) == []


def test_normalize_domain_input_returns_empty_for_empty_list():
    server = importlib.import_module("odoo_mcp.server")
    assert server.normalize_domain_input([]) == []
    assert server.normalize_domain_input([[]]) == []


def test_normalize_domain_input_returns_empty_for_empty_string():
    server = importlib.import_module("odoo_mcp.server")
    assert server.normalize_domain_input("") == []


# ----- write approval helpers -------------------------------------------


def test_register_write_approval_returns_false_for_failed_report():
    server = importlib.import_module("odoo_mcp.server")
    ctx = server.AppContext()
    assert server.register_write_approval(ctx, {"success": False}) is False


def test_register_write_approval_returns_false_for_missing_token():
    server = importlib.import_module("odoo_mcp.server")
    ctx = server.AppContext()
    assert (
        server.register_write_approval(
            ctx,
            {
                "success": True,
                "approval": {"model": "res.partner", "operation": "write"},
            },
        )
        is False
    )


def test_require_validated_write_approval_returns_none_when_token_missing():
    """NESA Patch 3: token lookup now goes through app_context.odoo. Use the
    FakeCtx wrapper which routes 'nesa.mcp.approval.token' to an in-memory
    store; missing token -> require returns None."""
    server = importlib.import_module("odoo_mcp.server")

    class _DummyClient:
        def get_model_fields(self, model):
            return {}

        def execute_method(self, *args, **kwargs):
            raise AssertionError("non-token methods should not be called")

    ctx = FakeCtx(_DummyClient())
    rejection = server.require_validated_write_approval(
        ctx.request_context.lifespan_context, {"token": "ghost"}
    )
    assert rejection["ok"] is False
    # NESA A2: the reason is now explicit instead of one catch-all sentence.
    assert rejection["reason_code"] in {"token_unknown", "token_rejected"}


def test_require_validated_write_approval_reports_missing_token():
    """NESA A2: no token at all is its own, distinguishable reason."""
    server = importlib.import_module("odoo_mcp.server")

    class _DummyClient:
        def get_model_fields(self, model):
            return {}

        def execute_method(self, *args, **kwargs):
            raise AssertionError("token store must not be called without a token")

    ctx = FakeCtx(_DummyClient())
    rejection = server.require_validated_write_approval(
        ctx.request_context.lifespan_context, {}
    )
    assert rejection["ok"] is False
    assert rejection["reason_code"] == "token_missing"


def test_require_validated_write_approval_clears_expired_records():
    """NESA Patch 3: expired tokens are evicted by _mcp_consume_approval in
    the bridge model. Server-side, the require helper simply observes a
    failure-dict (success=False) and returns None — the bridge eviction is
    invisible to the server lifespan."""
    server = importlib.import_module("odoo_mcp.server")

    class _DummyClient:
        def get_model_fields(self, model):
            return {}

        def execute_method(self, *args, **kwargs):
            raise AssertionError("non-token methods should not be called")

    ctx = FakeCtx(_DummyClient())
    life = ctx.request_context.lifespan_context
    # Seed expired record directly in the wrapped client's in-memory store.
    life.odoo.approval_store["odoo-write:expired"] = {
        "model_name": "res.partner",
        "operation": "write",
        "payload": {},
        "payload_hash": "",
        "validated_at": 0,
        "expires_at": 0,  # already expired
    }
    rejection = server.require_validated_write_approval(
        life, {"token": "odoo-write:expired"}
    )
    assert rejection["ok"] is False
    assert rejection["reason_code"] == "token_expired"
    # Bridge-side eviction: store should drop the expired record after consume.
    assert "odoo-write:expired" not in life.odoo.approval_store


# ----- configured_addons_roots / restrict_addons_paths ------------------


def test_configured_addons_roots_skips_blank_entries(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    import os as _os

    monkeypatch.setenv(
        "ODOO_ADDONS_PATHS", f"{_os.pathsep}/tmp/x{_os.pathsep}{_os.pathsep}/tmp/y"
    )
    roots = server.configured_addons_roots()
    assert all(str(p).endswith(("x", "y")) for p in roots)
    assert len(roots) == 2


def test_restrict_addons_paths_returns_none_when_input_none():
    server = importlib.import_module("odoo_mcp.server")
    assert server.restrict_addons_paths(None) is None


def test_restrict_addons_paths_raises_when_no_root_configured(monkeypatch, tmp_path):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("ODOO_ADDONS_PATHS", raising=False)
    try:
        server.restrict_addons_paths([str(tmp_path)])
    except ValueError as exc:
        assert "ODOO_ADDONS_PATHS" in str(exc)
    else:
        raise AssertionError("missing roots must raise")


# ----- access_permission_field branches ---------------------------------


def test_access_permission_field_maps_each_operation():
    server = importlib.import_module("odoo_mcp.server")
    assert server.access_permission_field("create") == "perm_create"
    assert server.access_permission_field("write") == "perm_write"
    assert server.access_permission_field("unlink") == "perm_unlink"
    assert server.access_permission_field("delete") == "perm_unlink"
    assert server.access_permission_field("read") == "perm_read"
    assert server.access_permission_field("search") == "perm_read"
    assert server.access_permission_field("search_read") == "perm_read"


def test_access_permission_field_classifies_side_effect_methods_as_write():
    server = importlib.import_module("odoo_mcp.server")
    assert server.access_permission_field("action_confirm") == "perm_write"


def test_access_permission_field_defaults_to_read_for_get_helpers():
    server = importlib.import_module("odoo_mcp.server")
    # safety = read_only (because of get_ prefix), so falls to perm_read
    assert server.access_permission_field("get_thing") == "perm_read"


# ----- _safe_odoo_read --------------------------------------------------


def test_safe_odoo_read_returns_normalized_error_on_exception():
    server = importlib.import_module("odoo_mcp.server")

    def boom():
        raise RuntimeError("oh no")

    result, error = server._safe_odoo_read("stage", boom)
    assert result is None
    assert error["stage"] == "stage"


# ----- _m2o_id, _m2m_ids, _field_names, _available_user_read_fields ----


def test_m2o_id_handles_list_tuple_int_and_other():
    server = importlib.import_module("odoo_mcp.server")
    assert server._m2o_id([3, "Sales"]) == 3
    assert server._m2o_id((4, "X")) == 4
    assert server._m2o_id(7) == 7
    assert server._m2o_id("nope") is None
    assert server._m2o_id([]) is None
    assert server._m2o_id(()) is None


def test_m2m_ids_handles_lists_tuples_and_filters_unknown_entries():
    server = importlib.import_module("odoo_mcp.server")
    assert server._m2m_ids([1, 2, 3]) == {1, 2, 3}
    assert server._m2m_ids([(5, "label"), [9, "x"], "skip"]) == {5, 9}
    assert server._m2m_ids("not-a-list") == set()


def test_field_names_returns_empty_for_non_dict():
    server = importlib.import_module("odoo_mcp.server")
    assert server._field_names("not-a-dict") == set()
    assert server._field_names({"a": {}, "b": {}}) == {"a", "b"}


def test_available_user_read_fields_returns_base_when_metadata_missing():
    server = importlib.import_module("odoo_mcp.server")
    assert server._available_user_read_fields(set()) == [
        "id",
        "name",
        "login",
        "company_id",
        "company_ids",
    ]


def test_available_user_read_fields_includes_group_fields_when_present():
    server = importlib.import_module("odoo_mcp.server")
    # When the model exposes both groups_id and all_group_ids, we want both
    fields = server._available_user_read_fields({"id", "name", "groups_id", "all_group_ids"})
    assert "groups_id" in fields
    assert "all_group_ids" in fields


def test_group_field_names_returns_pair_or_none():
    server = importlib.import_module("odoo_mcp.server")
    direct, all_field = server._group_field_names({"groups_id": [1]})
    assert direct == "groups_id"
    assert all_field is None
    direct, all_field = server._group_field_names(
        {"group_ids": [], "all_group_ids": []}
    )
    assert direct == "group_ids"
    assert all_field == "all_group_ids"
    direct, all_field = server._group_field_names({})
    assert direct is None
    assert all_field is None


def test_acl_row_applies_returns_true_when_no_group_id():
    server = importlib.import_module("odoo_mcp.server")
    # _m2o_id returns None for None/strings/empty containers
    assert server._acl_row_applies({"group_id": None}, {1, 2}) is True
    assert server._acl_row_applies({}, {1, 2}) is True


def test_acl_row_applies_returns_false_when_user_group_unknown():
    server = importlib.import_module("odoo_mcp.server")
    assert server._acl_row_applies({"group_id": [3, "x"]}, None) is False
    assert server._acl_row_applies({"group_id": [3, "x"]}, {4}) is False


def test_rule_applies_returns_true_when_no_groups_or_user_match():
    server = importlib.import_module("odoo_mcp.server")
    assert server._rule_applies({"groups": []}, {1}) is True
    assert server._rule_applies({"groups": [3]}, None) is False
    assert server._rule_applies({"groups": [3]}, {3}) is True


def test_record_id_domain_filters_non_positive_ids():
    server = importlib.import_module("odoo_mcp.server")
    assert server._record_id_domain([1, 0, -2, 3]) == [["id", "in", [1, 3]]]
    assert server._record_id_domain([]) == []
    assert server._record_id_domain(None) == []


# ----- _access_diagnosis_codes branches ---------------------------------


def test_access_diagnosis_codes_reports_record_rule_filter_likely():
    server = importlib.import_module("odoo_mcp.server")
    codes = server._access_diagnosis_codes(
        metadata_errors=[],
        acl_rows=[{"perm_read": True}],
        granting_acl_rows=[{"perm_read": True}],
        active_rules=[{"x": 1}],
        applicable_rules=[{"x": 1}],
        actual_count=0,
        expected_count=2,
        record_ids=[],
    )
    code_names = {c["code"] for c in codes}
    assert "record_rule_filter_likely" in code_names


def test_access_diagnosis_codes_reports_domain_or_rule_filter_likely():
    server = importlib.import_module("odoo_mcp.server")
    codes = server._access_diagnosis_codes(
        metadata_errors=[],
        acl_rows=[],
        granting_acl_rows=[],
        active_rules=[],
        applicable_rules=[],
        actual_count=0,
        expected_count=2,
        record_ids=[],
    )
    code_names = {c["code"] for c in codes}
    assert "domain_or_rule_filter_likely" in code_names


def test_access_diagnosis_codes_reports_no_issue_detected_when_clean():
    server = importlib.import_module("odoo_mcp.server")
    codes = server._access_diagnosis_codes(
        metadata_errors=[],
        acl_rows=[{"perm_read": True}],
        granting_acl_rows=[{"perm_read": True}],
        active_rules=[],
        applicable_rules=[],
        actual_count=5,
        expected_count=5,
        record_ids=[],
    )
    code_names = {c["code"] for c in codes}
    assert "no_access_issue_detected" in code_names


def test_access_diagnosis_codes_reports_record_count_mismatch_via_record_ids():
    server = importlib.import_module("odoo_mcp.server")
    codes = server._access_diagnosis_codes(
        metadata_errors=[],
        acl_rows=[],
        granting_acl_rows=[],
        active_rules=[],
        applicable_rules=[],
        actual_count=1,
        expected_count=None,
        record_ids=[1, 2, 3],
    )
    code_names = {c["code"] for c in codes}
    assert "domain_or_rule_filter_likely" in code_names


# ----- diagnose_access boundary inputs ---------------------------------


def test_diagnose_access_rejects_negative_expected_count():
    server = importlib.import_module("odoo_mcp.server")

    class _C:
        pass

    result = server.diagnose_access(
        FakeCtx(_C()), "res.partner", "read", expected_count=-5
    )
    assert result["success"] is False
    assert "expected_count" in result["error"]


def test_diagnose_access_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")

    class _C:
        pass

    result = server.diagnose_access(FakeCtx(_C()), "bad model", "read")
    assert result["success"] is False


def test_diagnose_access_handles_user_context_raise():
    """Cover lines 998-999: error metadata when get_user_context() raises."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            raise RuntimeError("context blocked")

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {}
            if model == "res.users" and method == "read":
                return [{"id": 7}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return []
            if model == "res.partner" and method == "search_count":
                return 1
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read", expected_count=1
    )
    stages = {err["stage"] for err in report["metadata_errors"]}
    assert "res.users.context_get" in stages


def test_diagnose_access_handles_user_context_error_dict():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"error": "Access denied"}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {"id": {"type": "integer"}, "groups_id": {"type": "many2many"}}
            if model == "res.users" and method == "read":
                return [{"id": 7, "groups_id": [1]}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return []
            if model == "res.partner" and method == "search_count":
                return 0
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read", expected_count=1
    )
    assert report["success"] is True
    assert any(
        err["stage"] == "res.users.context_get" for err in report["metadata_errors"]
    )


def test_diagnose_access_skips_inactive_or_unrelated_permission_rules():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {}
            if model == "res.users" and method == "read":
                return [{"id": 7}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return [
                    {"id": 1, "name": "off", "active": False},  # inactive → skipped
                    {
                        "id": 2,
                        "name": "no-write-perm",
                        "active": True,
                        "perm_read": False,
                    },  # perm_read False → skipped
                ]
            if model == "res.partner" and method == "search_count":
                return 0
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read", expected_count=1, verbose=True
    )
    assert report["success"] is True
    assert report["rules"]["active"] == []


def test_diagnose_access_rules_branch_with_global_rule_no_groups():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {"groups_id": {"type": "many2many"}}
            if model == "res.users" and method == "read":
                return [{"id": 7, "groups_id": [3]}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return [
                    {
                        "id": 5,
                        "name": "global",
                        "active": True,
                        "groups": False,  # no groups → global rule
                        "perm_read": True,
                    }
                ]
            if model == "res.partner" and method == "search_count":
                return 5
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read", expected_count=5, verbose=True
    )
    assert report["success"] is True
    assert len(report["rules"]["global"]) == 1
    assert report["rules"]["group_bound"] == []


# ----- schema_catalog error branches -------------------------------------


def test_schema_catalog_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        pass

    result = server.schema_catalog(FakeCtx(_Client()), models=["bad model"])
    assert result["success"] is False


def test_schema_catalog_returns_error_when_get_models_fails():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_models(self):
            return {"error": "rpc fail"}

    result = server.schema_catalog(FakeCtx(_Client()))
    assert result["success"] is False
    assert "rpc" in result["error"]


def test_schema_catalog_filters_explicit_models_and_skips_field_errors():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_models(self):
            return {
                "model_names": ["res.partner", "res.users"],
                "models_details": {"res.partner": {"name": "Contact"}},
            }

        def get_model_fields(self, model):
            return {"error": "ACL"}

    result = server.schema_catalog(
        FakeCtx(_Client()), models=["res.partner"], include_fields=True
    )
    assert result["success"] is True
    assert result["result"][0]["model"] == "res.partner"
    assert result["result"][0]["fields"] == {}
    assert result["result"][0]["field_error"] == "ACL"


# ----- preview_write / validate_write / execute_approved_write extras ----


def test_preview_write_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")
    result = server.preview_write("bad model", "create", values={"x": 1})
    assert result["success"] is False
    assert "Invalid" in result["error"]


def test_validate_write_returns_error_when_live_metadata_call_fails():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"error": "no access"}

    result = server.validate_write(
        FakeCtx(_Client()), "res.partner", "write", values={"x": 1}, record_ids=[1]
    )
    assert result["success"] is False
    assert "no access" in result["error"]


def test_execute_approved_write_rejects_invalid_operation(monkeypatch):
    """Cover line 1563: ValueError raised for unsupported operation.

    Build a canonical payload with an invalid operation, register it
    server-side as a validated approval, then call execute_approved_write
    which must reject the operation despite token + confirm + env all passing.
    """
    server = importlib.import_module("odoo_mcp.server")
    import time as _time

    class _Client:
        def execute_method(self, *args, **kwargs):
            raise AssertionError("must reject before reaching the client")

    ctx = FakeCtx(_Client())
    canonical = {
        "model": "res.partner",
        "operation": "destroy",  # invalid
        "record_ids": [7],
        "values": {"name": "Ada"},
        "context": {},
    }
    token = server.build_approval_token(canonical)
    approval = {**canonical, "token": token}
    # Register as if validate_write had stored it — NESA Patch 3: dict lives
    # in the wrapped client's approval_store (mimics the DB-backed table).
    canonical_payload = server.write_approval_payload(approval)
    ctx.request_context.lifespan_context.odoo.approval_store[token] = {
        "model_name": canonical_payload["model"],
        "operation": canonical_payload["operation"],
        "payload": canonical_payload,
        "payload_hash": ctx.request_context.lifespan_context.odoo._canonical_hash(canonical_payload),
        "validated_at": _time.time(),
        "expires_at": _time.time() + 600,
    }
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, approval, confirm=True)
    assert result["success"] is False
    assert "operation must be one of" in result["error"]


def test_execute_approved_write_rejects_when_payload_does_not_match(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            return True

    ctx = FakeCtx(_Client())
    validation = server.validate_write(
        ctx, "res.partner", "write", values={"name": "Ada"}, record_ids=[7]
    )
    # Mutate stored validation record's payload but KEEP the original
    # payload_hash. This exercises the server-side defense-in-depth check:
    # consume passes (caller-supplied hash matches stored hash because both
    # were computed over the original payload), but the dict-equality
    # comparison in execute_approved_write detects the divergence and
    # produces the "stored validation record" error.
    record = list(ctx.request_context.lifespan_context.odoo.approval_store.values())[0]
    record["payload"]["values"] = {"name": "DIFFERENT"}
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, validation["approval"], confirm=True)
    assert result["success"] is False
    assert "stored validation record" in result["error"]


def test_execute_approved_write_requires_confirm_true(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            return True

    ctx = FakeCtx(_Client())
    validation = server.validate_write(
        ctx, "res.partner", "write", values={"name": "Ada"}, record_ids=[7]
    )
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, validation["approval"], confirm=False)
    assert result["success"] is False
    assert "confirm" in result["error"]


def test_execute_approved_write_runs_create_path(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class _Client:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return 7

    ctx = FakeCtx(_Client())
    validation = server.validate_write(
        ctx, "res.partner", "create", values={"name": "Ada"}
    )
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, validation["approval"], confirm=True)
    assert result["success"] is True
    assert calls[0][0] == ("res.partner", "create", {"name": "Ada"})


def test_execute_approved_write_runs_unlink_path(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    calls = []

    class _Client:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            calls.append((args, kwargs))
            return True

    ctx = FakeCtx(_Client())
    validation = server.validate_write(ctx, "res.partner", "unlink", record_ids=[7])
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, validation["approval"], confirm=True)
    assert result["success"] is True
    assert calls[0][0] == ("res.partner", "unlink", [7])


# ----- scan_addons_source / build_domain / business_pack tool wrappers --


def test_scan_addons_source_tool_rejects_invalid_max_file_bytes():
    server = importlib.import_module("odoo_mcp.server")
    result = server.scan_addons_source(max_file_bytes=0)
    assert result["success"] is False
    assert "max_file_bytes" in result["error"]


def test_build_domain_tool_returns_error_payload_on_unexpected_exception(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    def boom(*args, **kwargs):
        raise RuntimeError("oh no")

    monkeypatch.setattr(server, "build_domain_report", boom)
    result = server.build_domain([])
    assert result["success"] is False
    assert "oh no" in result["error"]


def test_business_pack_report_tool_returns_error_payload_on_exception(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_models(self):
            raise RuntimeError("rpc")

        def get_installed_modules(self, limit=200):
            return []

    result = server.business_pack_report(FakeCtx(_Client()), "sales")
    assert result["success"] is False
    assert "rpc" in result["error"]


def test_business_pack_report_skips_live_metadata_when_disabled():
    server = importlib.import_module("odoo_mcp.server")

    class _NopeClient:
        def get_models(self):  # pragma: no cover
            raise AssertionError("must not be called")

    result = server.business_pack_report(
        FakeCtx(_NopeClient()), "sales", use_live_metadata=False
    )
    assert result["success"] is True


def test_business_pack_report_skips_modules_when_get_models_returns_error():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_models(self):
            return {"error": "ACL"}

        def get_installed_modules(self, limit=200):
            return [{"name": "sale"}]

    result = server.business_pack_report(FakeCtx(_Client()), "sales")
    assert result["success"] is True


# ----- get_odoo_profile error path -------------------------------------


def test_get_odoo_profile_returns_error_when_module_limit_invalid():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        pass

    result = server.get_odoo_profile(FakeCtx(_Client()), module_limit=0)
    assert result["success"] is False
    assert "limit" in result["error"]


# ----- inspect_model_relationships error path --------------------------


def test_inspect_model_relationships_returns_error_when_live_metadata_fails():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            raise RuntimeError("rpc")

    report = server.inspect_model_relationships(
        FakeCtx(_Client()), "res.partner", use_live_metadata=True
    )
    assert report["success"] is False or report["metadata_used"]["error"]


def test_inspect_model_relationships_returns_error_payload_when_metadata_dict_has_error():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"error": "Access denied"}

    report = server.inspect_model_relationships(
        FakeCtx(_Client()), "res.partner", use_live_metadata=True
    )
    # The function returns a "no metadata" report with metadata_error set
    assert report["success"] is False
    assert "Access denied" in str(report["metadata_used"].get("error"))


def test_inspect_model_relationships_outer_exception_path():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            raise RuntimeError("rpc")

    # Using invalid model name forces validate_model_name to raise before
    # reaching get_model_fields, demonstrating the outer except path.
    report = server.inspect_model_relationships(
        FakeCtx(_Client()), "bad model", use_live_metadata=False
    )
    assert report["success"] is False
    assert "Invalid" in report["error"]


# ----- diagnose_odoo_call use_live_metadata flag ----------------------


def test_diagnose_odoo_call_includes_live_metadata_not_used_note():
    server = importlib.import_module("odoo_mcp.server")
    report = server.diagnose_odoo_call(
        "res.partner", "search_read", use_live_metadata=True
    )
    codes = {issue["code"] for issue in report["issues"]}
    assert "live_metadata_not_used" in codes


def test_upgrade_risk_report_includes_live_metadata_not_used_note():
    server = importlib.import_module("odoo_mcp.server")
    report = server.upgrade_risk_report(use_live_metadata=True, target_version="18.0")
    codes = {risk["code"] for risk in report["risks"]}
    assert "live_metadata_not_used" in codes


def test_fit_gap_report_includes_live_metadata_not_used_assumption():
    server = importlib.import_module("odoo_mcp.server")
    report = server.fit_gap_report(["Track contacts"], use_live_metadata=True)
    assert any(
        "fit_gap_report is input-driven" in str(item)
        for item in report["assumptions"]
    )


# ----- list_models / get_model_fields / search_records / read_record err paths -


def test_list_models_returns_error_when_get_models_fails():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_models(self):
            return {"error": "ACL"}

    result = server.list_models(FakeCtx(_Client()))
    assert result["success"] is False
    assert "ACL" in result["error"]


def test_list_models_filters_by_query_against_model_and_display_name():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_models(self):
            return {
                "model_names": ["res.partner", "res.users", "sale.order"],
                "models_details": {
                    "res.partner": {"name": "Contact"},
                    "res.users": {"name": "User"},
                    "sale.order": {"name": "Sales Order"},
                },
            }

    result = server.list_models(FakeCtx(_Client()), query="contact")
    names = [r["model"] for r in result["result"]]
    assert names == ["res.partner"]


def test_list_models_propagates_clamp_error():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        pass

    result = server.list_models(FakeCtx(_Client()), limit=0)
    assert result["success"] is False
    assert "limit" in result["error"]


def test_get_model_fields_tool_filters_by_field_names():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"name": {"type": "char"}, "ref": {"type": "char"}, "active": {"type": "boolean"}}

    result = server.get_model_fields(
        FakeCtx(_Client()), "res.partner", field_names=["name", "ref", "ghost"]
    )
    assert set(result["result"].keys()) == {"name", "ref"}


def test_get_model_fields_tool_returns_error_when_model_returns_error():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"error": "no access"}

    result = server.get_model_fields(FakeCtx(_Client()), "res.partner")
    assert result["success"] is False


def test_get_model_fields_tool_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        pass

    result = server.get_model_fields(FakeCtx(_Client()), "bad model")
    assert result["success"] is False


def test_search_records_rejects_negative_offset():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()
    result = server.search_records(FakeCtx(client), "res.partner", offset=-1)
    assert result["success"] is False
    assert "offset" in result["error"]


def test_search_records_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()
    result = server.search_records(FakeCtx(client), "bad model")
    assert result["success"] is False


def test_read_record_rejects_zero_id():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()
    result = server.read_record(FakeCtx(client), "res.partner", record_id=0)
    assert result["success"] is False
    assert "record_id" in result["error"]


def test_read_record_returns_error_when_no_record_found():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"id": {"type": "integer"}, "name": {"type": "char"}}

        def read_records(self, model, ids, fields=None):
            return []

    result = server.read_record(FakeCtx(_Client()), "res.partner", record_id=99)
    assert result["success"] is False
    assert "Record not found" in result["error"]


def test_read_record_rejects_invalid_model_name():
    server = importlib.import_module("odoo_mcp.server")
    client = _SmartFieldsClient()
    result = server.read_record(FakeCtx(client), "bad model", record_id=1)
    assert result["success"] is False


# ----- aggregate_records additional branches ---------------------------


def test_aggregate_records_no_measures_passes_empty_aggregates():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="19.0", rows=[])
    result = server.aggregate_records(
        FakeCtx(client), model="sale.order", group_by=["state"], measures=None
    )
    assert result["success"] is True
    assert result["measures"] == []


def test_aggregate_records_offset_propagates_for_legacy_path():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="17.0", rows=[])
    server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["id:count"],
        offset=5,
    )
    assert client.calls[0][2]["offset"] == 5


def test_aggregate_records_falls_back_propagates_offset_and_order():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="19.0", rows=[], fail_formatted=True)
    server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["id:count"],
        offset=3,
        limit=50,
        order="id:count desc",
    )
    fallback_kwargs = client.calls[1][2]
    assert fallback_kwargs["offset"] == 3
    assert fallback_kwargs["limit"] == 50
    assert fallback_kwargs["orderby"] == "id:count desc"


def test_aggregate_records_passes_offset_and_order_in_formatted_path():
    server = importlib.import_module("odoo_mcp.server")
    client = _AggregateClient(version="19.0", rows=[])
    server.aggregate_records(
        FakeCtx(client),
        model="sale.order",
        group_by=["state"],
        measures=["amount_total:sum"],
        offset=2,
        limit=20,
        order="amount_total:sum desc",
    )
    kwargs = client.calls[0][2]
    assert kwargs["offset"] == 2
    assert kwargs["limit"] == 20
    assert kwargs["order"] == "amount_total:sum desc"


# ----- chatter_post additional branches ---------------------------------


def test_chatter_post_returns_error_for_empty_body_validation_message(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    result = server.chatter_post(
        FakeCtx(_ChatterClient()),
        model="res.partner",
        record_id=1,
        body="",
    )
    assert result["success"] is False


# ----- search_employee / search_holidays branches -----------------------


def test_search_employee_returns_results_via_name_search():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def execute_method(self, model, method, *args, **kwargs):
            return [(7, "Ada Lovelace"), (8, "Grace Hopper")]

    result = server.search_employee(FakeCtx(_Client()), name="Ada")
    assert result.success is True
    assert result.result[0].name == "Ada Lovelace"


def test_search_employee_returns_error_on_failure():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def execute_method(self, *args, **kwargs):
            raise RuntimeError("rpc")

    result = server.search_employee(FakeCtx(_Client()), name="Ada")
    assert result.success is False
    assert "rpc" in result.error


def test_search_holidays_rejects_invalid_start_date():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        pass

    result = server.search_holidays(FakeCtx(_Client()), start_date="garbage", end_date="2024-01-01")
    assert result.success is False
    assert "start_date" in result.error


def test_search_holidays_rejects_invalid_end_date():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        pass

    result = server.search_holidays(
        FakeCtx(_Client()), start_date="2024-01-01", end_date="oops"
    )
    assert result.success is False
    assert "end_date" in result.error


def test_search_holidays_returns_results_with_employee_filter():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def search_read(self, model_name, domain, **kwargs):
            return [
                {
                    "display_name": "Holiday",
                    "start_datetime": "2024-01-01 00:00:00",
                    "stop_datetime": "2024-01-02 00:00:00",
                    "employee_id": [7, "Ada"],
                    "name": "Vacation",
                    "state": "validate",
                }
            ]

    result = server.search_holidays(
        FakeCtx(_Client()),
        start_date="2024-01-01",
        end_date="2024-01-31",
        employee_id=7,
    )
    assert result.success is True
    assert result.result[0].name == "Vacation"


def test_search_holidays_returns_error_on_search_failure():
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def search_read(self, *args, **kwargs):
            raise RuntimeError("rpc")

    result = server.search_holidays(
        FakeCtx(_Client()), start_date="2024-01-01", end_date="2024-01-31"
    )
    assert result.success is False
    assert "rpc" in result.error


# ----- prompt rendering -------------------------------------------------


def test_prompt_diagnose_failed_odoo_call_renders_arguments():
    server = importlib.import_module("odoo_mcp.server")
    text = server.prompt_diagnose_failed_odoo_call(
        "res.partner", "write", error="Access denied"
    )
    assert "res.partner" in text
    assert "write" in text
    assert "Access denied" in text


def test_prompt_diagnose_failed_odoo_call_uses_placeholder_when_no_error():
    server = importlib.import_module("odoo_mcp.server")
    text = server.prompt_diagnose_failed_odoo_call("res.partner", "write")
    assert "<not provided>" in text


def test_prompt_fit_gap_workshop_renders_requirement():
    server = importlib.import_module("odoo_mcp.server")
    text = server.prompt_fit_gap_workshop("Track expenses")
    assert "Track expenses" in text


def test_prompt_json2_migration_plan_renders_inputs():
    server = importlib.import_module("odoo_mcp.server")
    text = server.prompt_json2_migration_plan("sale.order", "action_confirm")
    assert "sale.order" in text
    assert "action_confirm" in text


def test_prompt_custom_module_audit_renders_addons_path():
    server = importlib.import_module("odoo_mcp.server")
    text = server.prompt_custom_module_audit("/srv/addons")
    assert "/srv/addons" in text


# ----- execute_method search-method domain normalization ---------------


def test_is_relative_to_returns_true_when_path_inside_root(tmp_path):
    server = importlib.import_module("odoo_mcp.server")
    sub = tmp_path / "sub"
    sub.mkdir()
    assert server._is_relative_to(sub, tmp_path) is True
    assert server._is_relative_to(tmp_path, sub) is False


def test_diagnose_access_reports_acl_denied_likely_when_no_granting_rows():
    """Cover the acl_denied_likely branch (lines 755-762, 756 in particular)."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {"groups_id": {"type": "many2many"}}
            if model == "res.users" and method == "read":
                return [{"id": 7, "groups_id": [99]}]  # not in ACL group
            if model == "ir.model.access":
                return [
                    {
                        "id": 1,
                        "name": "ACL row",
                        "model_id": [11, "C"],
                        "group_id": [3, "Sales"],
                        "perm_read": False,  # not granting read
                        "perm_write": False,
                        "perm_create": False,
                        "perm_unlink": False,
                    }
                ]
            if model == "ir.rule":
                return []
            if model == "res.partner" and method == "search_count":
                return 0
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read"
    )
    code_names = {c["code"] for c in report["diagnosis"]["codes"]}
    assert "acl_denied_likely" in code_names


def test_diagnose_access_reports_metadata_error_when_ir_model_search_fails():
    """Cover lines 971-972, 982 (ir.model error, model_id None branch)."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                raise RuntimeError("ACL on ir.model")
            if model == "res.users" and method == "fields_get":
                return {}
            if model == "res.users" and method == "read":
                return [{"id": 7}]
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read"
    )
    stages = {err["stage"] for err in report["metadata_errors"]}
    assert "ir.model" in stages


def test_diagnose_access_recovers_uid_from_user_context_when_client_lacks_attribute():
    """Cover line 1011: uid from user_context.get('uid')."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        # NOTE: no `uid` attribute → falls back to user_context["uid"]
        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {"groups_id": {"type": "many2many"}}
            if model == "res.users" and method == "read":
                return [{"id": 7, "groups_id": [3]}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return []
            if model == "res.partner" and method == "search_count":
                return 1
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read"
    )
    assert report["current_user"]["uid"] == 7


def test_diagnose_access_records_user_fields_and_read_errors():
    """Cover lines 1033, 1045 (errors on res.users.fields_get/read)."""
    server = importlib.import_module("odoo_mcp.server")

    state = {"fields_called": False}

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                if not state["fields_called"]:
                    state["fields_called"] = True
                    raise RuntimeError("fields_get blocked")
                return {}
            if model == "res.users" and method == "read":
                raise RuntimeError("read blocked")
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return []
            if model == "res.partner" and method == "search_count":
                return 0
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read"
    )
    stages = {err["stage"] for err in report["metadata_errors"]}
    assert "res.users.fields_get" in stages or "res.users.read" in stages


def test_diagnose_access_skips_non_dict_rule_entries():
    """Cover line 1122: skip non-dict rule entries."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {"groups_id": {"type": "many2many"}}
            if model == "res.users" and method == "read":
                return [{"id": 7, "groups_id": [3]}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                # Mix dict and non-dict entries to exercise the skip
                return [
                    "broken",
                    {"id": 1, "name": "valid", "active": True, "perm_read": True, "groups": False},
                ]
            if model == "res.partner" and method == "search_count":
                return 1
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read", verbose=True
    )
    assert len(report["rules"]["active"]) == 1


def test_diagnose_access_reports_search_count_error():
    """Cover line 1142: error on search_count metadata read."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        uid = 7

        def get_user_context(self):
            return {"lang": "en_US", "uid": 7}

        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 11, "name": "C", "model": "res.partner"}]
            if model == "res.users" and method == "fields_get":
                return {}
            if model == "res.users" and method == "read":
                return [{"id": 7}]
            if model == "ir.model.access":
                return []
            if model == "ir.rule":
                return []
            if model == "res.partner" and method == "search_count":
                raise RuntimeError("count blocked")
            raise AssertionError(f"unexpected: {model}.{method}")

    report = server.diagnose_access(
        FakeCtx(_Client()), "res.partner", "read", expected_count=5
    )
    stages = {err["stage"] for err in report["metadata_errors"]}
    assert "res.partner.search_count" in stages


def test_get_odoo_profile_with_include_modules_true_calls_get_profile():
    """Cover line 1284: include_modules=True path uses get_profile."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_profile(self, module_limit=100):
            return {
                "url": "u",
                "hostname": "h",
                "database": "db",
                "username": "user",
                "transport": "xmlrpc",
                "timeout": 3,
                "verify_ssl": True,
                "json2_database_header": True,
                "server_version": {},
                "user_context": {},
                "installed_modules": [{"name": "base"}],
                "installed_module_count": 1,
            }

    report = server.get_odoo_profile(
        FakeCtx(_Client()), include_modules=True, module_limit=10
    )
    assert report["success"] is True
    assert report["profile"]["installed_module_count"] == 1


def test_validate_write_outer_exception_returns_error_payload(monkeypatch):
    """Cover lines 1505-1506: outer except in validate_write."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            raise RuntimeError("boom")

    # Live metadata raises → outer except wraps the error
    result = server.validate_write(
        FakeCtx(_Client()), "res.partner", "write", values={"x": 1}, record_ids=[1]
    )
    assert result["success"] is False
    assert "boom" in result["error"]


def test_execute_approved_write_outer_exception_returns_error_payload(monkeypatch):
    """Cover lines 1585-1586: outer except in execute_approved_write."""
    server = importlib.import_module("odoo_mcp.server")

    class _Client:
        def get_model_fields(self, model):
            return {"name": {"type": "char", "readonly": False}}

        def execute_method(self, *args, **kwargs):
            raise RuntimeError("exec blew up")

    ctx = FakeCtx(_Client())
    validation = server.validate_write(
        ctx, "res.partner", "write", values={"name": "Ada"}, record_ids=[7]
    )
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    result = server.execute_approved_write(ctx, validation["approval"], confirm=True)
    assert result["success"] is False
    assert "exec blew up" in result["error"]


def test_execute_method_normalizes_domain_for_search_methods(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    monkeypatch.setenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", "0")
    captured = []

    class _Client:
        def execute_method(self, *args, **kwargs):
            captured.append((args, kwargs))
            return []

    # search is read-only; normalization runs because args[0] is a JSON string
    server.execute_method(
        FakeCtx(_Client()),
        "res.partner",
        "search_read",
        args=['[["name","=","Ada"]]'],
    )
    assert captured[0][0] == ("res.partner", "search_read", [["name", "=", "Ada"]])
