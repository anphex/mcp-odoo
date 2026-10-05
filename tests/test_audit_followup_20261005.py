"""Regression tests for the MCP usage-audit follow-up fixes (2026-10-05).

1. A write Odoo refuses with a business error releases its approval token.
2. validate_write reports an already consumed token as a refusal.
3. Transient wizards can be created through validate_write.
4. read_records accepts ``ids`` as an alias of ``record_ids``.
5. A model that is not installed is reported as ``unknown_model``.
"""

import asyncio
import hashlib
import importlib
import json
import xmlrpc.client

import pytest


def _hash(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class _Life:
    def __init__(self, odoo):
        self.odoo = odoo
        self.schema_cache = {}
        self.transient_cache = {}


class _Ctx:
    def __init__(self, odoo):
        self.request_context = type("_Req", (), {"lifespan_context": _Life(odoo)})()


class _Odoo:
    """Odoo double with the bridge's token-store semantics.

    ``write_outcomes`` is consumed per business call: an exception instance is
    raised, anything else is returned.  ``release_supported=False`` imitates a
    bridge that predates mcp_release_approval.
    """

    def __init__(self, write_outcomes=(), release_supported=True, fields=None):
        self.write_outcomes = list(write_outcomes)
        self.release_supported = release_supported
        self.tokens = {}
        self.calls = []
        self.fields = fields or {
            "name": {"type": "char", "readonly": False},
            "state": {"type": "selection", "readonly": True},
        }

    def get_model_fields(self, model):
        if model.endswith(".wizard"):
            return {
                "res_model": {"type": "char", "readonly": True},
                "task_id": {"type": "many2one", "readonly": True},
                "note": {"type": "text", "readonly": False},
            }
        return dict(self.fields)

    def read_records(self, model, ids, fields=None):
        self.calls.append((model, "read", tuple(ids)))
        return [{"id": record_id, "name": f"R{record_id}"} for record_id in ids]

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method))
        if model == "nesa.mcp.approval.token":
            return self._token(method, args)
        if model == "nesa.mcp.doc.helper" and method == "mcp_transient_write_profile":
            requested = args[0]
            return {
                "exists": True,
                "transient": requested.endswith(".wizard"),
                "overrides": [],
                "inverse_fields": [],
            }
        outcome = self.write_outcomes.pop(0) if self.write_outcomes else 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def _token(self, method, args):
        if method == "mcp_register_approval":
            token, _model, _operation, payload, _iso = args
            record = self.tokens.get(token)
            if record and record["consumed"]:
                return {
                    "success": False,
                    "error": (
                        "approval already consumed; rerun preview with a "
                        "changed payload or wait for cleanup"
                    ),
                }
            self.tokens[token] = {
                "payload": payload, "hash": _hash(payload), "consumed": False,
            }
            return {"success": True, "token": token}
        if method == "mcp_consume_approval":
            token, expected_hash = args
            record = self.tokens.get(token)
            if not record:
                return {"success": False, "error": "unknown approval token"}
            if record["consumed"]:
                return {
                    "success": False,
                    "error": "approval token already consumed (race-condition guard)",
                }
            if record["hash"] != expected_hash:
                return {"success": False, "error": "approval payload does not match"}
            record["consumed"] = True
            return {"success": True, "payload": record["payload"]}
        if method == "mcp_revoke_approval":
            return {"success": True, "revoked": True}
        if method == "mcp_release_approval":
            if not self.release_supported:
                raise xmlrpc.client.Fault(
                    "'nesa.mcp.approval.token' object has no attribute "
                    "'mcp_release_approval'",
                    "Traceback (most recent call last): ...",
                )
            token, expected_hash = args
            record = self.tokens.get(token)
            if not record or record["hash"] != expected_hash or not record["consumed"]:
                return {"success": False, "error": "not releasable"}
            record["consumed"] = False
            return {"success": True, "released": True}
        raise AssertionError(f"unexpected token-store method {method!r}")


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    return importlib.import_module("odoo_mcp.server")


def _user_error(text="Der Datensatz ist gesperrt."):
    return xmlrpc.client.Fault(f"warning -- UserError\n\n{text}", "")


def _approve(server, ctx, **kwargs):
    params = {"values": {"name": "Ada"}, "record_ids": [7]}
    params.update(kwargs)
    report = server.validate_write(ctx, "res.partner", "write", **params)
    assert report["success"] is True, report
    assert report["approval_status"]["stored"] is True
    return report["approval"]


def _release_calls(odoo):
    return [
        call for call in odoo.calls
        if call == ("nesa.mcp.approval.token", "mcp_release_approval")
    ]


# ----- 1. token release after a refused write -------------------------------


def test_business_error_releases_token_and_same_approval_runs_after_fix(server):
    odoo = _Odoo(write_outcomes=[_user_error(), True])
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)

    refused = server.execute_approved_write(ctx, approval, confirm=True)
    assert refused["success"] is False
    assert refused["reason_code"] == "odoo_rejected_write"
    assert refused["write_executed"] is False
    assert refused["approval_released"] is True
    assert "nothing was written" in refused["remedy"]
    assert "gesperrt" in refused["error"]

    retried = server.execute_approved_write(ctx, approval, confirm=True)
    assert retried["success"] is True

    third = server.execute_approved_write(ctx, approval, confirm=True)
    assert third["success"] is False
    assert third["reason_code"] == "token_already_consumed"


@pytest.mark.parametrize("fault_code", [
    "warning -- AccessError\n\nKein Zugriff",
    "warning -- MissingError\n\nDatensatz fehlt",
    "warning -- Warning\n\nWeiterleitung",
    "AccessDenied",
])
def test_every_pre_commit_fault_releases(server, fault_code):
    odoo = _Odoo(write_outcomes=[xmlrpc.client.Fault(fault_code, "")])
    ctx = _Ctx(odoo)
    result = server.execute_approved_write(ctx, _approve(server, ctx), confirm=True)
    assert result["approval_released"] is True
    assert len(_release_calls(odoo)) == 1


@pytest.mark.parametrize("exc", [
    xmlrpc.client.Fault(
        "KeyError: 'x'",
        "Traceback (most recent call last):\n  ...\nKeyError: 'x'",
    ),
    xmlrpc.client.Fault(1, "int fault code from /xmlrpc/ v1"),
    ConnectionError("connection reset by peer"),
    TimeoutError("timed out"),
    RuntimeError("warning -- UserError looks alike but is no Fault"),
])
def test_unproven_failures_keep_the_token_consumed(server, exc):
    odoo = _Odoo(write_outcomes=[exc])
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)

    result = server.execute_approved_write(ctx, approval, confirm=True)
    assert result["success"] is False
    assert "approval_released" not in result
    assert _release_calls(odoo) == []

    again = server.execute_approved_write(ctx, approval, confirm=True)
    assert again["reason_code"] == "token_already_consumed"


def test_bridge_without_release_method_keeps_old_behaviour(server):
    odoo = _Odoo(write_outcomes=[_user_error()], release_supported=False)
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)

    result = server.execute_approved_write(ctx, approval, confirm=True)
    assert result["approval_released"] is False
    assert result["write_executed"] is False
    assert "stays consumed" in result["remedy"]

    again = server.execute_approved_write(ctx, approval, confirm=True)
    assert again["reason_code"] == "token_already_consumed"


def test_odoo_rejected_before_commit_only_accepts_string_fault_codes(server):
    check = server.odoo_rejected_before_commit
    assert check(_user_error()) is True
    assert check(xmlrpc.client.Fault("AccessDenied", "")) is True
    assert check(xmlrpc.client.Fault("ValueError: x", "Traceback ...")) is False
    assert check(xmlrpc.client.Fault(2, "warning -- UserError")) is False
    assert check(ValueError("warning -- UserError")) is False


# ----- 2. validate_write and a consumed token -------------------------------


def test_validate_write_refuses_payload_whose_token_is_consumed(server):
    odoo = _Odoo(write_outcomes=[True])
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)
    assert server.execute_approved_write(ctx, approval, confirm=True)["success"]

    report = server.validate_write(
        ctx, "res.partner", "write", values={"name": "Ada"}, record_ids=[7],
    )
    assert report["success"] is False
    assert report["outcome"] == "rejected"
    assert report["reason_code"] == "token_already_consumed"
    assert report["error_type"] == "request"
    assert "approval" not in report
    assert report["approval_status"]["stored"] is False
    assert "Read the record back" in report["remedy"]


def test_validate_write_names_other_store_refusals(server):
    odoo = _Odoo()
    ctx = _Ctx(odoo)

    def refuse(method, args):
        return {"success": False, "error": "token collision (different user)"}

    odoo._token = refuse
    report = server.validate_write(
        ctx, "res.partner", "write", values={"name": "Ada"}, record_ids=[7],
    )
    # Unchanged contract for every other refusal: success with stored=False.
    assert report["success"] is True
    assert report["approval_status"]["stored"] is False
    assert report["approval_status"]["reason"] == "token collision (different user)"


# ----- 3. transient wizards -------------------------------------------------


def test_wizard_create_accepts_readonly_target_fields(server):
    odoo = _Odoo(write_outcomes=[42])
    ctx = _Ctx(odoo)
    report = server.validate_write(
        ctx, "x.wizard", "create",
        values={"res_model": "project.task", "note": "Hallo"},
    )
    assert report["success"] is True, report
    assert any(
        hint["field"] == "res_model" and "transient wizard" in hint["hint"]
        for hint in report["field_hints"]
    )
    result = server.execute_approved_write(ctx, report["approval"], confirm=True)
    assert result["success"] is True
    assert result["result"] == 42


def test_wizard_create_with_only_context_defaults(server):
    odoo = _Odoo(write_outcomes=[43])
    ctx = _Ctx(odoo)
    report = server.validate_write(
        ctx, "x.wizard", "create", values={},
        context={"default_task_id": 5, "active_id": 5},
    )
    assert report["success"] is True, report
    assert {"field": "task_id", "hint": "filled from context default_ key on wizard create."} in report["field_hints"]
    result = server.execute_approved_write(ctx, report["approval"], confirm=True)
    assert result["success"] is True


def test_wizard_create_default_for_unknown_field_stays_refused(server):
    ctx = _Ctx(_Odoo())
    report = server.validate_write(
        ctx, "x.wizard", "create", values={}, context={"default_nope": 1},
    )
    assert report["success"] is False
    assert report["reason_code"] == "missing_create_values"


def test_persistent_model_keeps_readonly_and_empty_create_refusals(server):
    ctx = _Ctx(_Odoo())
    readonly = server.validate_write(
        ctx, "res.partner", "create", values={"name": "Ada", "state": "x"},
    )
    assert readonly["success"] is False
    assert readonly["reason_code"] == "readonly_field"

    empty = server.validate_write(
        ctx, "res.partner", "create", values={}, context={"default_name": "Ada"},
    )
    assert empty["success"] is False
    assert empty["reason_code"] == "missing_create_values"


def test_wizard_write_keeps_readonly_refusal(server):
    ctx = _Ctx(_Odoo())
    report = server.validate_write(
        ctx, "x.wizard", "write", values={"res_model": "x"}, record_ids=[1],
    )
    assert report["success"] is False
    assert report["reason_code"] == "readonly_field"


def test_unavailable_transient_profile_counts_as_persistent(server):
    odoo = _Odoo()
    original = odoo.execute_method

    def no_helper(model, method, *args, **kwargs):
        if model == "nesa.mcp.doc.helper":
            raise ConnectionError("helper missing")
        return original(model, method, *args, **kwargs)

    odoo.execute_method = no_helper
    report = server.validate_write(
        _Ctx(odoo), "x.wizard", "create", values={"res_model": "x"},
    )
    assert report["success"] is False
    assert report["reason_code"] == "readonly_field"


def test_ordinary_create_skips_transient_lookup(server):
    odoo = _Odoo()
    report = server.validate_write(
        _Ctx(odoo), "res.partner", "create", values={"name": "Ada"},
    )
    assert report["success"] is True
    assert ("nesa.mcp.doc.helper", "mcp_transient_write_profile") not in odoo.calls


# ----- 4. read_records ids alias --------------------------------------------


def test_read_records_accepts_ids_alias(server):
    odoo = _Odoo()
    result = server.read_records(_Ctx(odoo), "res.partner", ids=[3, 4], fields=["name"])
    assert result["success"] is True
    assert result["requested_count"] == 2
    assert ("res.partner", "read", (3, 4)) in odoo.calls


def test_read_records_rejects_conflicting_ids(server):
    result = server.read_records(
        _Ctx(_Odoo()), "res.partner", record_ids=[1], ids=[2], fields=["name"],
    )
    assert result["success"] is False
    assert "record_ids" in result["error"]


def test_read_records_without_ids_names_record_ids(server):
    result = server.read_records(_Ctx(_Odoo()), "res.partner", fields=["name"])
    assert result["success"] is False
    assert "record_ids must contain at least one ID" in result["error"]


def test_read_records_schema_lists_alias(server):
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    schema = tools["read_records"].inputSchema
    assert "ids" in schema["properties"]
    assert "record_ids" in schema["properties"]
    assert schema.get("required") == ["model"]


# ----- 5. unknown model -----------------------------------------------------


def test_unknown_model_fault_is_a_request_error(server):
    fault = xmlrpc.client.Fault(
        "warning -- UserError\n\nObject fleet.vehicle doesn't exist", "",
    )
    response = server.error_response("read_record", fault)
    assert response["error_type"] == "request"
    assert response["reason_code"] == "unknown_model"
    assert response["retryable"] is False
    assert "list_models" in response["remedy"]


def test_other_odoo_faults_stay_odoo_errors(server):
    response = server.error_response("read_record", _user_error())
    assert response["error_type"] == "odoo_error"
    assert "reason_code" not in response
