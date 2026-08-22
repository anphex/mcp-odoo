"""Regression tests for the NESA Odoo-MCP improvement backlog (2026-08-22).

Each test names the backlog item it protects. They are deliberately written
against the behaviour an agent observes — the answer payload — not against
internal helpers, because every one of these items was a case where the tool
answered in a way that could be read as a fact about the business data
("no records", "no addons", "not validated") when it was really a fact about
the bridge.
"""

import importlib
import json

import pytest


class _Life:
    """Minimal stand-in for AppContext."""

    def __init__(self, odoo):
        self.odoo = odoo
        self.schema_cache = {}
        self.transient_cache = {}


class _Ctx:
    def __init__(self, odoo):
        self.request_context = type("_Req", (), {"lifespan_context": _Life(odoo)})()


@pytest.fixture
def server():
    return importlib.import_module("odoo_mcp.server")


# ----- A1: transient wizards are exempt from the write chain --------------


class _WizardClient:
    """Odoo double where ``x.wizard`` is transient and ``account.move`` is not.

    ``overrides`` names the models whose create/write are overridden — those
    are transient too, but writing them can reach persistent records, which is
    exactly the case the exemption must not cover.
    """

    def __init__(self, overrides=(), inverse_fields=()):
        self.calls = []
        self.overrides = dict(overrides)
        self.inverse_fields = dict(inverse_fields)

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method))
        if model == "nesa.mcp.doc.helper" and method == "mcp_transient_write_profile":
            requested = args[0]
            transient = requested.endswith(".wizard")
            overrides = list(self.overrides.get(requested, []))
            inverse_fields = list(self.inverse_fields.get(requested, []))
            clean = not inverse_fields
            return {
                "model": requested,
                "exists": True,
                "transient": transient,
                "inert_create": transient and clean and "create" not in overrides,
                "inert_write": transient and clean and "write" not in overrides,
                "overrides": overrides,
                "inverse_fields": inverse_fields,
            }
        if method in {"create", "write"}:
            return 42 if method == "create" else True
        raise AssertionError(f"unexpected call {model}.{method}")

    def read_records(self, model, ids, fields=None):
        return [{"id": ids[0]}]

    def get_model_fields(self, model):
        return {"id": {"type": "integer"}, "search_term": {"type": "char"}}


def test_a1_transient_create_and_write_run_without_approval(server):
    client = _WizardClient()

    created = server.execute_method(
        _Ctx(client), "nesa.shk.product.match.wizard", "create", args=[{}],
    )
    written = server.execute_method(
        _Ctx(client),
        "nesa.shk.product.match.wizard",
        "write",
        args=[[42], {"search_term": "Geberit"}],
    )

    assert created["success"] is True
    assert created["transient_model"] is True
    assert written["success"] is True


def test_a1_persistent_write_still_blocked(server):
    """Negative test: the guard must keep holding where it matters."""
    blocked = server.execute_method(
        _Ctx(_WizardClient()), "account.move", "write", args=[[7], {"ref": "x"}],
    )
    assert blocked["success"] is False
    assert blocked["transient_model"] is False
    assert "validate_write" in blocked["error"]


@pytest.mark.parametrize("method", ["unlink", "web_save", "copy", "load"])
def test_a1_transient_exemption_covers_only_create_and_write(server, method):
    blocked = server.execute_method(
        _Ctx(_WizardClient()), "nesa.shk.product.match.wizard", method, args=[[42]],
    )
    assert blocked["success"] is False
    assert blocked["transient_model"] is True
    assert "approved-write chain" in blocked["error"]


def test_a1_unknown_transient_state_is_treated_as_persistent(server):
    """A failed ir.model lookup must never widen the guard."""

    class _Blind:
        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                raise RuntimeError("metadata unavailable")
            raise AssertionError("must not reach the write")

    blocked = server.execute_method(
        _Ctx(_Blind()), "some.wizard", "write", args=[[1], {}],
    )
    assert blocked["success"] is False
    assert blocked["transient_model"] is False


def test_a1_transient_lookup_is_cached(server):
    client = _WizardClient()
    ctx = _Ctx(client)
    server.execute_method(ctx, "x.wizard", "create", args=[{}])
    server.execute_method(ctx, "x.wizard", "create", args=[{}])
    profile_calls = [
        call for call in client.calls if call[0] == "nesa.mcp.doc.helper"
    ]
    assert len(profile_calls) == 1


@pytest.mark.parametrize("method", ["create", "write"])
def test_a1_transient_model_with_overridden_write_stays_on_the_chain(server, method):
    """Negative test: transient is not the same as free of side effects.

    ``account.setup.bank.manual.config.create()`` creates a persistent
    ``res.bank``; ``account.financial.year.op.write()`` writes ``res.company``.
    Both are transient, so a blanket exemption would hand out token-free
    business writes.
    """
    client = _WizardClient(overrides={"account.setup.wizard": [method]})
    blocked = server.execute_method(
        _Ctx(client), "account.setup.wizard", method, args=[[1], {}],
    )
    assert blocked["success"] is False
    assert blocked["transient_model"] is True
    assert "not inert" in blocked["error"]
    assert method not in {call[1] for call in client.calls}


def test_a1_transient_model_with_inverse_field_stays_on_the_chain(server):
    """An ``inverse`` method runs on write and is arbitrary code."""
    client = _WizardClient(inverse_fields={"x.wizard": ["partner_ref"]})
    blocked = server.execute_method(
        _Ctx(client), "x.wizard", "write", args=[[1], {"partner_ref": "A"}],
    )
    assert blocked["success"] is False
    assert blocked["transient_model"] is True
    assert "partner_ref" in blocked["error"]


def test_a1_reviewed_override_can_be_allowlisted(server, monkeypatch):
    """The escape hatch is explicit and per model.method, never a class."""
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "account.setup.wizard.write",
    )
    client = _WizardClient(overrides={"account.setup.wizard": ["write"]})
    allowed = server.execute_method(
        _Ctx(client), "account.setup.wizard", "write", args=[[1], {}],
    )
    assert allowed["success"] is True


def test_a1_missing_bridge_profile_is_treated_as_persistent(server):
    """Without the Odoo-side helper the exemption must simply not apply."""

    class _NoHelper:
        def execute_method(self, model, method, *args, **kwargs):
            if model == "nesa.mcp.doc.helper":
                raise RuntimeError("model does not exist")
            raise AssertionError("must not reach the write")

    blocked = server.execute_method(
        _Ctx(_NoHelper()), "x.wizard", "write", args=[[1], {}],
    )
    assert blocked["success"] is False
    assert blocked["transient_model"] is False


@pytest.mark.parametrize(
    "method", ["update", "toggle_active", "action_archive", "action_unarchive"],
)
def test_a1_public_orm_mutator_aliases_stay_on_the_chain(server, method):
    """Negative test: ``update`` and the archive helpers are writes.

    They are public on ``BaseModel`` and therefore RPC-reachable, and each of
    them ends in ``write()`` — under native ACL parity they would otherwise be
    token-free writes on any persistent model.
    """
    blocked = server.execute_method(
        _Ctx(_WizardClient()), "res.partner", method, args=[[7], {"name": "x"}],
    )
    assert blocked["success"] is False
    assert "validate_write" in blocked["error"]


# ----- A3/A4: honest counts and a deterministic order ---------------------


class _PagingClient:
    def __init__(self, total=420, page=None):
        self.total = total
        self.page = page or [{"id": index} for index in range(10, 5, -1)]
        self.search_read_kwargs = None

    def get_model_fields(self, model):
        return {"id": {"type": "integer"}, "name": {"type": "char"}}

    def search_read(self, model_name, domain, fields=None, **kwargs):
        self.search_read_kwargs = kwargs
        return list(self.page)

    def execute_method(self, model, method, *args, **kwargs):
        if method == "search_count":
            return self.total
        raise AssertionError(f"unexpected call {model}.{method}")


def test_a3_count_is_page_size_and_total_count_is_the_truth(server):
    client = _PagingClient()
    result = server.search_records(
        _Ctx(client), "account.move", limit=5, fields=["id"],
    )
    assert result["count"] == 5
    assert result["total_count"] == 420
    assert result["has_more"] is True
    assert result["next_offset"] == 5


def test_a3_unknown_total_reports_unknown_not_no(server):
    """A failing search_count must not be rendered as "nothing more"."""

    class _NoCount(_PagingClient):
        def execute_method(self, model, method, *args, **kwargs):
            raise RuntimeError("count failed")

    result = server.search_records(
        _Ctx(_NoCount()), "account.move", limit=5, fields=["id"],
    )
    assert result["success"] is True
    assert result["total_count"] is None
    assert result["has_more"] is True
    assert "total_count_error" in result


def test_a4_default_order_is_total_and_echoed(server):
    client = _PagingClient()
    result = server.search_records(_Ctx(client), "account.move", fields=["id"])
    assert client.search_read_kwargs["order"] == "id desc"
    assert result["order_used"] == "id desc"
    assert result["order_defaulted"] is True


def test_a4_explicit_order_is_preserved(server):
    client = _PagingClient()
    result = server.search_records(
        _Ctx(client), "account.move", fields=["id"], order="name asc",
    )
    assert client.search_read_kwargs["order"] == "name asc"
    assert result["order_defaulted"] is False


# ----- A5: no silent empty scan ------------------------------------------


def test_a5_unconfigured_scan_fails_loudly(server, monkeypatch):
    monkeypatch.delenv("ODOO_ADDONS_PATHS", raising=False)
    result = server.scan_addons_source()
    assert result["success"] is False
    assert result["error_type"] == "not_configured"
    assert "NOT evidence" in result["error"]


def test_a5_unreadable_roots_fail_loudly(server, monkeypatch, tmp_path):
    missing = tmp_path / "does-not-exist"
    monkeypatch.setenv("ODOO_ADDONS_PATHS", str(missing))
    result = server.scan_addons_source()
    assert result["success"] is False
    assert result["error_type"] == "not_readable"


# ----- A6: transport errors are named, business errors are not retried ----


def test_a6_business_error_is_not_retryable(server):
    classification = server.classify_call_error(ValueError("Invalid field x"))
    assert classification["retryable"] is False


def test_a6_transport_error_is_retried_once(server):
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionResetError("connection reset by peer")
        return "ok"

    assert server.call_with_transport_retry(flaky, label="probe") == "ok"
    assert len(attempts) == 2


def test_a6_non_idempotent_call_is_never_retried(server):
    """Odoo commits before it answers, so a lost answer is not a failed call.

    Retrying ``action_post`` after a timeout could post the same invoice
    twice; the bridge has to say "unknown outcome" instead.
    """
    attempts = []

    def flaky():
        attempts.append(1)
        raise ConnectionResetError("connection reset by peer")

    with pytest.raises(server.UnknownOutcomeError):
        server.call_with_transport_retry(
            flaky, label="account.move.action_post", idempotent=False,
        )
    assert len(attempts) == 1


def test_a6_unknown_outcome_is_reported_as_such(server, monkeypatch):
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "account.move.action_post",
    )

    class _Lost:
        def execute_method(self, model, method, *args, **kwargs):
            if model == "nesa.mcp.doc.helper":
                raise AssertionError("no write profile needed for a read method")
            raise ConnectionResetError("connection reset by peer")

    result = server.execute_method(
        _Ctx(_Lost()), "account.move", "action_post", args=[[1]],
    )
    assert result["success"] is False
    assert result["outcome_unknown"] is True
    assert result["retryable"] is False
    assert "Read the affected record back" in result["remedy"]


def test_a6_traceback_never_reaches_the_answer(server):
    """The cause line is useful; Odoo's source paths are not the agent's business."""
    fault = RuntimeError(
        'Traceback (most recent call last):\\n  File "/opt/odoo/models.py", '
        'line 42, in write\\n    raise ValueError(...)\\nValueError: '
        "Invalid field account.move.no_such_field in leaf"
    )
    response = server.error_response("execute_method", fault)
    assert "no_such_field" in response["error"]
    assert "error_traceback_tail" not in response
    assert "/opt/odoo/models.py" not in json.dumps(response)
    assert len(response["error_ref"]) == 12


def test_a6_business_error_is_raised_immediately(server):
    attempts = []

    def broken():
        attempts.append(1)
        raise ValueError("Invalid field account.move.nope")

    with pytest.raises(ValueError):
        server.call_with_transport_retry(broken, label="probe")
    assert len(attempts) == 1


def test_a6_search_failure_is_not_reported_as_empty_result(server):
    class _Broken:
        def get_model_fields(self, model):
            return {"id": {"type": "integer"}}

        def search_read(self, *args, **kwargs):
            raise RuntimeError("Object no.such.model doesn't exist")

        def execute_method(self, *args, **kwargs):
            raise RuntimeError("unused")

    result = server.search_records(_Ctx(_Broken()), "no.such.model")
    assert result["success"] is False
    assert result["error_type"] == "odoo_error"


def test_a6_traceback_is_compacted_to_its_cause(server):
    fault = RuntimeError(
        "<Fault 1: 'Traceback (most recent call last):\\n"
        "  File \"/x/models.py\", line 1, in search_read\\n"
        "    raise ValueError(\"boom\")\\n"
        "ValueError: Invalid field account.move.nope in leaf x\\n'>"
    )
    message, tail = server.compact_error_message(fault)
    assert message == "ValueError: Invalid field account.move.nope in leaf x"
    assert tail


# ----- A8: wizard actions report what they produced ----------------------


def test_a8_act_window_on_self_gets_result_counts(server, monkeypatch):
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "x.wizard.action_search",
    )

    class _Wizard:
        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.model":
                return [{"id": 1, "transient": True}]
            if method == "action_search":
                return {
                    "type": "ir.actions.act_window",
                    "res_model": "x.wizard",
                    "res_id": 24,
                    "view_mode": "form",
                }
            raise AssertionError(f"unexpected {model}.{method}")

        def get_model_fields(self, model):
            return {
                "id": {"type": "integer"},
                "result_ids": {"type": "one2many"},
                "search_term": {"type": "char"},
            }

        def read_records(self, model, ids, fields=None):
            return [{"id": 24, "result_ids": [1, 2, 3]}]

    result = server.execute_method(_Ctx(_Wizard()), "x.wizard", "action_search")
    assert result["result_counts"] == {"result_ids": 3}


def test_a8_unrelated_results_get_no_counts(server, monkeypatch):
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "x.wizard.action_open",
    )

    class _Plain:
        def execute_method(self, model, method, *args, **kwargs):
            return {"type": "ir.actions.act_window", "res_model": "other.model"}

        def get_model_fields(self, model):
            return {}

        def read_records(self, *args, **kwargs):
            raise AssertionError("must not read for a foreign act_window")

    result = server.execute_method(_Ctx(_Plain()), "x.wizard", "action_open")
    assert "result_counts" not in result


# ----- A10: binary payloads never arrive by accident ----------------------


class _AttachmentClient:
    def __init__(self):
        self.requested_fields = None

    def get_model_fields(self, model):
        return {
            "id": {"type": "integer"},
            "name": {"type": "char"},
            "datas": {"type": "binary"},
            "raw": {"type": "binary"},
            "mimetype": {"type": "char"},
        }

    def search_read(self, model_name, domain, fields=None, **kwargs):
        self.requested_fields = fields
        return [{"id": 1, "name": "scan.pdf"}]

    def execute_method(self, model, method, *args, **kwargs):
        if method == "search_count":
            return 1
        raise AssertionError(f"unexpected {model}.{method}")


def test_a10_wildcard_excludes_binary_fields(server):
    client = _AttachmentClient()
    result = server.search_records(
        _Ctx(client), "ir.attachment", limit=1, fields=["*"],
    )
    assert result["excluded_binary_fields"] == ["datas", "raw"]
    assert "datas" not in client.requested_fields
    assert "name" in client.requested_fields


def test_a10_explicitly_named_binary_field_still_works(server):
    client = _AttachmentClient()
    server.search_records(_Ctx(client), "ir.attachment", fields=["id", "datas"])
    assert client.requested_fields == ["id", "datas"]


# ----- B1/B2: reading documents ------------------------------------------


class _DocClient:
    def __init__(self, index_content="", mimetype="application/pdf"):
        self.index_content = index_content
        self.mimetype = mimetype
        self.helper_calls = []

    def read_records(self, model, ids, fields=None):
        row = {
            "id": ids[0],
            "name": "beleg.pdf",
            "mimetype": self.mimetype,
            "file_size": 4814,
            "res_model": "account.move",
            "res_id": 7,
        }
        if fields and "index_content" in fields:
            row["index_content"] = self.index_content
        return [row]

    def execute_method(self, model, method, *args, **kwargs):
        self.helper_calls.append((model, method))
        raise AssertionError(f"unexpected {model}.{method}")

    def get_model_fields(self, model):
        return {}


def test_b1_document_text_is_windowed(server):
    client = _DocClient(index_content="A" * 1000)
    result = server.get_document_text(_Ctx(client), 5, offset=0, limit=400)
    assert result["returned_chars"] == 400
    assert result["total_chars"] == 1000
    assert result["has_more"] is True
    assert result["next_offset"] == 400


def test_b1_second_window_continues_where_the_first_stopped(server):
    client = _DocClient(index_content="A" * 500)
    result = server.get_document_text(_Ctx(client), 5, offset=400, limit=400)
    assert result["returned_chars"] == 100
    assert result["has_more"] is False
    assert result["next_offset"] is None


def test_b1_empty_index_says_why(server):
    result = server.get_document_text(_Ctx(_DocClient()), 5)
    assert result["total_chars"] == 0
    assert "never text-indexed" in result["note"]


def test_b1_window_limit_is_capped(server):
    client = _DocClient(index_content="A" * 100_000)
    result = server.get_document_text(_Ctx(client), 5, limit=10 ** 6)
    assert result["limit"] == server.DOC_TEXT_WINDOW_MAX


def test_b2_pdf_falls_back_to_text(server):
    client = _DocClient(index_content="Junkers Gastherme")
    result = server.read_attachment(_Ctx(client), 5)
    assert result["success"] is True
    assert result["text"] == "Junkers Gastherme"


def test_b2_missing_helper_model_is_explained(server):
    class _NoHelper(_DocClient):
        def __init__(self):
            super().__init__(mimetype="image/jpeg")

        def execute_method(self, model, method, *args, **kwargs):
            raise RuntimeError("Object nesa.mcp.doc.helper doesn't exist")

    result = server.read_attachment(_Ctx(_NoHelper()), 5)
    assert result["success"] is False
    assert result["error_type"] == "helper_unavailable"
    assert "nesa_mcp_bridge" in result["error"]


# ----- B3/B4: handing out files ------------------------------------------


def test_b3_download_link_is_passed_through(server):
    class _LinkClient(_DocClient):
        def execute_method(self, model, method, *args, **kwargs):
            assert (model, method) == ("nesa.mcp.doc.helper", "mcp_create_download")
            return {
                "success": True,
                "url": "https://odoo.example/nesa/mcp/download/tok",
                "expires_in_seconds": 900,
            }

    result = server.create_attachment_download(_Ctx(_LinkClient()), 5, ttl_seconds=900)
    assert result["success"] is True
    assert result["url"].endswith("/tok")


def test_b3_rejects_absurdly_short_ttl(server):
    result = server.create_attachment_download(_Ctx(_DocClient()), 5, ttl_seconds=1)
    assert result["success"] is False
    assert "ttl_seconds" in result["error"]


def test_b4_requires_record_ids(server):
    result = server.render_report(_Ctx(_DocClient()), "account.move", [], "account.x")
    assert result["success"] is False
    assert "at least one ID" in result["error"]


def test_b4_requires_report_ref(server):
    result = server.render_report(_Ctx(_DocClient()), "account.move", [1], "  ")
    assert result["success"] is False
    assert "report_ref" in result["error"]


# ----- B5: the method policy is stated, not guessed -----------------------


def test_b5_reports_parity_mode(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    monkeypatch.setattr(
        importlib.import_module("odoo_mcp._nesa_per_user_auth"),
        "strict_mode_enabled",
        lambda: True,
    )
    report = server.list_allowed_methods(_Ctx(_DocClient()))
    assert report["authorization_mode"] == "native_acl_parity"
    assert "unlink" in report["always_blocked"]["crud_on_persistent_models"]
    assert "web_save" in report["always_blocked"]["write_equivalent_aliases"]


def test_b5_reports_exact_allowlist_mode(server, monkeypatch):
    monkeypatch.delenv("ODOO_MCP_NATIVE_ACL_PARITY", raising=False)
    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "sale.order.action_confirm",
    )
    report = server.list_allowed_methods(_Ctx(_DocClient()), model="sale.order")
    assert report["authorization_mode"] == "exact_allowlist"
    assert report["env_allowlist_entries"] == ["sale.order.action_confirm"]


def test_b5_documented_blocks_are_really_blocked(server, monkeypatch):
    """Negative test: the published policy must not outrun the guard.

    A documented allowlist that names a method as blocked while the guard lets
    it through is worse than no documentation at all — an agent would trust it.
    So every method the report calls always-blocked is executed against a
    persistent model here and has to come back refused.
    """
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    report = server.list_allowed_methods(_Ctx(_DocClient()))
    blocked = report["always_blocked"]
    methods = (
        list(blocked["crud_on_persistent_models"])
        + list(blocked["write_equivalent_aliases"])
    )
    assert methods, "report must name the blocked methods, not just a category"

    for method in methods:
        result = server.execute_method(
            _Ctx(_WizardClient()), "account.move", method, args=[[7], {"ref": "x"}],
        )
        assert result["success"] is False, f"{method} slipped past the guard"
        assert result["transient_model"] is False


# ----- B6/B7/B8 ----------------------------------------------------------


def test_b6_chatter_read_truncates_long_bodies(server):
    class _Chatter:
        def get_model_fields(self, model):
            return {}

        def search_read(self, model_name, domain, fields=None, **kwargs):
            assert model_name == "mail.message"
            assert ["model", "=", "account.move"] in domain
            return [{"id": 1, "body": "x" * 5000}]

        def execute_method(self, model, method, *args, **kwargs):
            return 1

    result = server.chatter_read(
        _Ctx(_Chatter()), "account.move", 7, body_char_limit=100,
    )
    assert result["truncated_bodies"] == 1
    assert len(result["messages"][0]["body"]) == 100
    assert result["messages"][0]["body_truncated"] is True


def test_b7_record_url_uses_configured_base_url(server):
    class _Base:
        def get_model_fields(self, model):
            return {}

        def execute_method(self, model, method, *args, **kwargs):
            if method == "get_param":
                return "https://odoo.example/"
            if method == "search_count":
                return 1
            raise AssertionError(f"unexpected {model}.{method}")

    result = server.get_record_url(_Ctx(_Base()), "account.move", 13248, verify=True)
    assert result["url"] == "https://odoo.example/odoo/account.move/13248"
    assert result["legacy_url"].endswith("model=account.move&view_type=form")
    assert result["record_visible"] is True


def test_b8_read_records_reports_missing_ids(server):
    class _Multi:
        def get_model_fields(self, model):
            return {"id": {"type": "integer"}, "name": {"type": "char"}}

        def read_records(self, model, ids, fields=None):
            return [{"id": ids[0], "name": "RE-1"}]

        def execute_method(self, *args, **kwargs):
            raise AssertionError("unused")

    result = server.read_records(
        _Ctx(_Multi()), "account.move", [1, 2], fields=["id", "name"],
    )
    assert result["count"] == 1
    assert result["missing_ids"] == [2]


def test_b8_rejects_oversized_id_lists(server):
    result = server.read_records(
        _Ctx(_DocClient()), "account.move", list(range(1, 500)),
    )
    assert result["success"] is False
    assert "limited to" in result["error"]


# ----- B9 ----------------------------------------------------------------


def test_b9_price_preview_passes_helper_result_through(server):
    class _Price(_DocClient):
        def execute_method(self, model, method, *args, **kwargs):
            assert (model, method) == ("nesa.mcp.doc.helper", "mcp_price_preview")
            return {"success": True, "resolved": {"price_unit": 260.0}}

    result = server.price_preview(
        _Ctx(_Price()), "sale.order.line", {"nesa_material_price": 140.0},
    )
    assert result["success"] is True
    assert result["resolved"]["price_unit"] == 260.0


def test_b9_rejects_non_mapping_values(server):
    result = server.price_preview(_Ctx(_DocClient()), "sale.order.line", None)
    assert result["success"] is False
    assert "values" in result["error"]


# ----- Follow-ups from the adversarial review (2026-08-22) ----------------


def test_wildcard_refuses_when_metadata_is_unavailable(server):
    """A10 must fail closed: no metadata is not a licence to read everything."""

    class _NoMeta:
        def get_model_fields(self, model):
            return {"error": "Access denied"}

    ctx = _Ctx(_NoMeta())
    life = ctx.request_context.lifespan_context
    with pytest.raises(ValueError, match="binary payloads"):
        server.resolve_read_fields(life, life.odoo, "ir.attachment", ["*"])


def test_confirm_false_does_not_consume_the_approval_token(server, monkeypatch):
    """The store never re-arms the same token, so a local gate must run first."""
    consumed = []

    def _spy(app_context, approval):
        consumed.append(approval)
        return {"ok": True, "payload": {}}

    monkeypatch.setattr(server, "require_validated_write_approval", _spy)
    agent_tools = importlib.import_module("odoo_mcp.agent_tools")
    payload = {
        "model": "res.partner",
        "operation": "write",
        "record_ids": [1],
        "values": {"name": "x"},
        "context": {},
    }
    approval = {**payload, "token": agent_tools.build_approval_token(payload)}

    result = server.execute_approved_write(_Ctx(_WizardClient()), approval, confirm=False)

    assert result["success"] is False
    assert result["reason_code"] == "confirm_missing"
    assert consumed == [], "token was consumed before the confirm gate"


def test_render_report_caps_the_record_count(server):
    result = server.render_report(
        _Ctx(_DocClient()),
        "account.move",
        list(range(1, server.MAX_REPORT_RECORDS + 2)),
        "account.account_invoices",
    )
    assert result["success"] is False
    assert str(server.MAX_REPORT_RECORDS) in result["error"]
