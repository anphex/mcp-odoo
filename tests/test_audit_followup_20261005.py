"""Regression tests for the MCP usage-audit follow-up fixes (2026-10-05).

1. A write Odoo refuses with a business error releases its approval token,
   but only when the bridge's commit marker shows nothing was committed.
2. validate_write reports an already consumed token as a refusal.
3. Transient wizards can be created through validate_write.
4. read_records accepts ``ids`` as an alias of ``record_ids``.
5. A model that is not installed is reported as ``unknown_model``.

Faults use the integer codes of /xmlrpc/2 (odoo/addons/base/controllers/
rpc.py xmlrpc_handle_exception_int), the endpoint the client talks to.
"""

import asyncio
import hashlib
import http.client
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
    raised, a ``_Committed`` sets the commit marker and then raises its fault,
    anything else commits and is returned.  ``consume_ids=False`` imitates a
    bridge before 18.0.1.7.5 (no consume_id, no release);
    ``release_supported=False`` a release call that fails.
    """

    def __init__(
        self, write_outcomes=(), release_supported=True, fields=None,
        consume_ids=True,
    ):
        self.write_outcomes = list(write_outcomes)
        self.release_supported = release_supported
        self.consume_ids = consume_ids
        self.consume_counter = 0
        self.write_contexts = []
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
        return self._business(kwargs)

    def execute_method_once(self, model, method, *args, **kwargs):
        self.calls.append(("once", model, method))
        return self._business(kwargs)

    def _business(self, kwargs):
        context = dict(kwargs.get("context") or {})
        self.write_contexts.append(context)
        outcome = self.write_outcomes.pop(0) if self.write_outcomes else 1
        if isinstance(outcome, BaseException):
            raise outcome
        # Like the bridge's base hook: the marker commits with the write.
        consume_id = context.get("nesa_mcp_approval_consume_id")
        for record in self.tokens.values():
            if consume_id and record.get("consume_id") == consume_id:
                record["executed"] = True
        if isinstance(outcome, _Committed):
            raise outcome.fault
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
            reply = {"success": True, "payload": record["payload"]}
            if self.consume_ids:
                self.consume_counter += 1
                record["consume_id"] = f"{self.consume_counter:032x}"
                reply["consume_id"] = record["consume_id"]
            return reply
        if method == "mcp_revoke_approval":
            return {"success": True, "revoked": True}
        if method == "mcp_release_approval":
            if not self.release_supported:
                raise xmlrpc.client.Fault(1, "Traceback (most recent call last): ...")
            token, expected_hash, consume_id = args
            record = self.tokens.get(token)
            if (
                not record or record["hash"] != expected_hash
                or not record["consumed"]
                or record.get("consume_id") != consume_id
            ):
                return {"success": False, "error": "not releasable"}
            if record.get("executed"):
                return {
                    "success": False,
                    "error": "approved write was committed",
                    "write_committed": True,
                }
            record["consumed"] = False
            record["consume_id"] = None
            return {"success": True, "released": True}
        raise AssertionError(f"unexpected token-store method {method!r}")


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    return importlib.import_module("odoo_mcp.server")


class _Committed:
    """Write outcome: the transaction commits, then Odoo answers with a fault.

    Covers a post-commit callback raising UserError and a transport replay
    whose second attempt fails after the first one committed.
    """

    def __init__(self, fault):
        self.fault = fault


def _user_error(text="Der Datensatz ist gesperrt."):
    return xmlrpc.client.Fault(2, text)


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
    assert "consume_id" not in json.dumps(refused)

    retried = server.execute_approved_write(ctx, approval, confirm=True)
    assert retried["success"] is True

    third = server.execute_approved_write(ctx, approval, confirm=True)
    assert third["success"] is False
    assert third["reason_code"] == "token_already_consumed"


def test_approved_write_carries_consume_id_and_skips_transport_replay(server):
    odoo = _Odoo(write_outcomes=[True])
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx, context={
        "lang": "de_DE", "nesa_mcp_approval_consume_id": "forged",
    })

    assert server.execute_approved_write(ctx, approval, confirm=True)["success"]
    assert ("once", "res.partner", "write") in odoo.calls
    assert ("res.partner", "write") not in odoo.calls
    context = odoo.write_contexts[-1]
    assert context["lang"] == "de_DE"
    assert context["nesa_mcp_approval_consume_id"] == f"{1:032x}"


@pytest.mark.parametrize("fault", [
    xmlrpc.client.Fault(2, "Validierungsfehler"),
    xmlrpc.client.Fault(3, "Access Denied"),
    xmlrpc.client.Fault(4, "Kein Zugriff"),
])
def test_every_business_fault_code_releases(server, fault):
    odoo = _Odoo(write_outcomes=[fault])
    ctx = _Ctx(odoo)
    result = server.execute_approved_write(ctx, _approve(server, ctx), confirm=True)
    assert result["approval_released"] is True
    assert result["write_executed"] is False
    assert len(_release_calls(odoo)) == 1


@pytest.mark.parametrize("fault", [
    _user_error("Postcommit-Callback warf UserError"),
    xmlrpc.client.Fault(
        2,
        "The operation cannot be completed: duplicate key value violates "
        "unique constraint (second attempt after a lost answer)",
    ),
])
def test_business_fault_after_commit_keeps_token_consumed(server, fault):
    odoo = _Odoo(write_outcomes=[_Committed(fault)])
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)

    result = server.execute_approved_write(ctx, approval, confirm=True)
    assert result["success"] is False
    assert result["reason_code"] == "odoo_error_after_commit"
    assert result["write_executed"] is True
    assert result["approval_released"] is False
    assert "do not repeat" in result["remedy"]
    assert len(_release_calls(odoo)) == 1

    again = server.execute_approved_write(ctx, approval, confirm=True)
    assert again["reason_code"] == "token_already_consumed"


@pytest.mark.parametrize("exc", [
    xmlrpc.client.Fault(
        1, "Traceback (most recent call last):\n  ...\nKeyError: 'x'",
    ),
    xmlrpc.client.Fault("warning -- UserError\n\nlegacy /xmlrpc/ string code", ""),
    http.client.RemoteDisconnected("Remote end closed connection without response"),
    ConnectionResetError(104, "Connection reset by peer"),
    TimeoutError("timed out"),
    RuntimeError("Fault 2 looks alike but is no Fault"),
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


@pytest.mark.parametrize("exc", [
    http.client.RemoteDisconnected("Remote end closed connection without response"),
    ConnectionResetError(104, "Connection reset by peer"),
    TimeoutError("timed out"),
    xmlrpc.client.ProtocolError("odoo/xmlrpc/2/object", 502, "Bad Gateway", {}),
])
def test_lost_write_answer_is_an_unknown_outcome(server, exc):
    odoo = _Odoo(write_outcomes=[exc])
    ctx = _Ctx(odoo)
    result = server.execute_approved_write(ctx, _approve(server, ctx), confirm=True)
    assert result["outcome_unknown"] is True
    assert result["retryable"] is False
    assert "Read the affected record back" in result["remedy"]


def test_failed_release_reports_unknown_outcome(server):
    odoo = _Odoo(write_outcomes=[_user_error()], release_supported=False)
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)

    result = server.execute_approved_write(ctx, approval, confirm=True)
    assert result["reason_code"] == "odoo_write_outcome_unknown"
    assert result["approval_released"] is False
    assert "write_executed" not in result
    assert "stays consumed" in result["remedy"]

    again = server.execute_approved_write(ctx, approval, confirm=True)
    assert again["reason_code"] == "token_already_consumed"


def test_bridge_without_consume_id_keeps_old_behaviour(server):
    odoo = _Odoo(write_outcomes=[_user_error()], consume_ids=False)
    ctx = _Ctx(odoo)
    approval = _approve(server, ctx)

    result = server.execute_approved_write(ctx, approval, confirm=True)
    assert result["success"] is False
    assert "approval_released" not in result
    assert _release_calls(odoo) == []
    assert ("res.partner", "write") in odoo.calls
    assert "nesa_mcp_approval_consume_id" not in odoo.write_contexts[-1]

    again = server.execute_approved_write(ctx, approval, confirm=True)
    assert again["reason_code"] == "token_already_consumed"


def test_odoo_business_fault_matches_xmlrpc2_codes_only(server):
    check = server.odoo_business_fault
    assert check(xmlrpc.client.Fault(2, "UserError")) is True
    assert check(xmlrpc.client.Fault(3, "AccessDenied")) is True
    assert check(xmlrpc.client.Fault(4, "AccessError")) is True
    assert check(xmlrpc.client.Fault(1, "Traceback ...")) is False
    assert check(xmlrpc.client.Fault("warning -- UserError\n\nx", "")) is False
    assert check(ValueError("Fault 2")) is False


# ----- 1b. no transport replay for the approved write -----------------------


def _bare_client(odoo_client_module):
    client = odoo_client_module.OdooClient.__new__(odoo_client_module.OdooClient)
    client.transport = "xmlrpc"
    client.url = "http://odoo.invalid"
    client.db = "db"
    client.uid = 2
    client.password = "secret"
    client.timeout = 5
    client.verify_ssl = True
    client.lang = None
    return client


def _count_single_requests(monkeypatch, odoo_client_module):
    sent = []

    def lost_answer(self, host, handler, request_body, verbose=False):
        sent.append(handler)
        raise http.client.RemoteDisconnected(
            "Remote end closed connection without response",
        )

    monkeypatch.setattr(
        odoo_client_module.RedirectTransport, "single_request", lost_answer,
    )
    return sent


def test_execute_method_once_does_not_resend_after_lost_answer(monkeypatch):
    odoo_client = importlib.import_module("odoo_mcp.odoo_client")
    sent = _count_single_requests(monkeypatch, odoo_client)

    with pytest.raises(http.client.RemoteDisconnected):
        _bare_client(odoo_client).execute_method_once(
            "res.partner", "create", {"name": "Ada"},
        )
    assert sent == ["/xmlrpc/2/object"]


def test_default_transport_still_resends_once(monkeypatch):
    # Documents the stdlib behaviour execute_method_once switches off.
    odoo_client = importlib.import_module("odoo_mcp.odoo_client")
    sent = _count_single_requests(monkeypatch, odoo_client)
    transport = odoo_client.RedirectTransport(timeout=5, use_https=False)

    with pytest.raises(http.client.RemoteDisconnected):
        transport.request("odoo.invalid", "/xmlrpc/2/object", b"<x/>")
    assert len(sent) == 2


def _shared_proxy_client(odoo_client_module):
    client = _bare_client(odoo_client_module)
    client._models = xmlrpc.client.ServerProxy(
        f"{client.url}/xmlrpc/2/object",
        transport=odoo_client_module.RedirectTransport(timeout=5, use_https=False),
    )
    return client


@pytest.mark.parametrize("model, method, args", [
    ("sale.order", "action_confirm", [[5]]),
    ("res.partner", "message_post", [[7]]),
    ("nesa.mcp.doc.helper", "mcp_store_attachment", ["res.partner", 7]),
    ("res.partner", "create", [{"name": "Ada"}]),
])
def test_execute_method_sends_non_read_methods_once(monkeypatch, model, method, args):
    # Regression 2026-10-06: the stdlib transport replayed a committed
    # action_confirm/message_post after a lost answer.
    odoo_client = importlib.import_module("odoo_mcp.odoo_client")
    sent = _count_single_requests(monkeypatch, odoo_client)

    with pytest.raises(http.client.RemoteDisconnected):
        _shared_proxy_client(odoo_client).execute_method(model, method, *args)
    assert sent == ["/xmlrpc/2/object"]


def test_execute_method_read_keeps_transport_resend(monkeypatch):
    odoo_client = importlib.import_module("odoo_mcp.odoo_client")
    sent = _count_single_requests(monkeypatch, odoo_client)

    with pytest.raises(http.client.RemoteDisconnected):
        _shared_proxy_client(odoo_client).execute_method(
            "res.partner", "read", [7], fields=["name"],
        )
    assert len(sent) == 2


def test_single_attempt_call_keeps_arguments_and_lang(monkeypatch):
    odoo_client = importlib.import_module("odoo_mcp.odoo_client")
    bodies = []

    def answer(self, host, handler, request_body, verbose=False):
        bodies.append(xmlrpc.client.loads(request_body))
        return (True,)

    monkeypatch.setattr(odoo_client.RedirectTransport, "single_request", answer)
    client = _bare_client(odoo_client)
    client.lang = "de_DE"

    assert client.execute_method(
        "sale.order", "action_confirm", [5], context={"tz": "Europe/Berlin"},
    ) is True
    (params, method_name), = bodies
    assert method_name == "execute_kw"
    assert params == (
        "db", 2, "secret", "sale.order", "action_confirm", [[5]],
        {"context": {"tz": "Europe/Berlin", "lang": "de_DE"}},
    )


def test_server_uses_the_client_read_method_set(server):
    odoo_client = importlib.import_module("odoo_mcp.odoo_client")
    assert server.IDEMPOTENT_READ_METHODS is odoo_client.IDEMPOTENT_READ_METHODS


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
    fault = xmlrpc.client.Fault(2, "Object fleet.vehicle doesn't exist")
    response = server.error_response("read_record", fault)
    assert response["error_type"] == "request"
    assert response["reason_code"] == "unknown_model"
    assert response["retryable"] is False
    assert "list_models" in response["remedy"]


def test_other_odoo_faults_stay_odoo_errors(server):
    response = server.error_response("read_record", _user_error())
    assert response["error_type"] == "odoo_error"
    assert "reason_code" not in response
