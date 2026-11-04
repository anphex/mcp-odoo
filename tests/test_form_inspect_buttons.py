"""Buttons in inspect_record_form (NESA 2026-11-04).

An agent guessed ``action_snooze`` for the certificate button "Spammy
pausieren" because the tool showed fields only.  The tests protect what the
agent must see: the exact method name, the label it knows from the UI, why a
button is hidden for this record, and how to press it through this server.
"""

import importlib

import pytest

from odoo_mcp import form_inspect as fi
from test_form_inspect import _Ctx, _FormClient


BUTTON_ARCH = """
<form>
  <header>
    <button name="action_snooze_reminders" type="object" string="Spammy pausieren"
            class="btn-secondary" confirm="Wirklich pausieren?"
            invisible="state != 'aktiv' or ampel != 'rot' or reminder_snooze_until"/>
    <button name="action_resume_reminders" type="object" string="Pause aufheben"
            invisible="state != 'aktiv' or not reminder_snooze_until"/>
    <button name="412" type="action" string="Erneuern"
            context="{'default_mode': 'renew'}"/>
    <button name="action_archive" type="object" string="Archivieren"/>
    <button name="action_hidden_hotkey" type="object" string="Intern" invisible="1"/>
    <button name="action_with_expression" type="object" string="Mit Kontext"
            context="{'default_partner_id': partner_id}"/>
    <button string="Verwerfen" special="cancel"/>
    <button name="no_type_button" string="Ohne Typ"/>
    <field name="state" widget="statusbar"/>
  </header>
  <sheet>
    <div name="button_box">
      <button name="action_open_docs" type="object" icon="fa-file">
        <field name="doc_count" widget="statinfo" string="Dokumente"/>
      </button>
    </div>
    <group string="Frist" invisible="state == 'entwurf'">
      <field name="name"/>
      <button name="action_check_now" type="object" string="Jetzt prüfen"/>
    </group>
    <field name="line_ids">
      <list>
        <field name="qty"/>
        <button name="action_line_only" type="object" string="Zeile"/>
      </list>
    </field>
  </sheet>
</form>
"""

BUTTON_FIELDS = {
    "state": {"type": "selection", "string": "Status",
              "selection": [["entwurf", "Entwurf"], ["aktiv", "Aktiv"]]},
    "ampel": {"type": "selection", "string": "Ampel",
              "selection": [["gruen", "Grün"], ["rot", "Rot"]]},
    "reminder_snooze_until": {"type": "date", "string": "Spammy pausiert bis"},
    "partner_id": {"type": "many2one", "string": "Partner", "relation": "res.partner"},
    "doc_count": {"type": "integer", "string": "Dokumente", "readonly": True},
    "name": {"type": "char", "string": "Name"},
    "line_ids": {"type": "one2many", "string": "Zeilen", "relation": "x.line"},
    "display_name": {"type": "char", "string": "Anzeigename"},
}


class _ButtonClient(_FormClient):
    def __init__(self, record=None, arch=BUTTON_ARCH):
        super().__init__()
        self.arch = arch
        self.record = {
            "display_name": "TÜV Sprinter", "state": "aktiv", "ampel": "rot",
            "reminder_snooze_until": False, "partner_id": [7, "Holding AG"],
            "doc_count": 2, "name": "TÜV Sprinter", "line_ids": [],
        }
        if record:
            self.record.update(record)

    def get_model_fields(self, model):
        if model == "nesa.zertifikat":
            return BUTTON_FIELDS
        return super().get_model_fields(model)

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args, kwargs))
        if method == "get_view":
            return {"arch": self.arch, "id": 77, "model": model}
        if model == "ir.ui.view":
            return [{"name": "nesa.zertifikat.form", "model": "nesa.zertifikat"}]
        if method == "fields_get":
            return {}
        if method == "default_get":
            return {"state": "entwurf"}
        if method == "read" and model == "nesa.zertifikat":
            return [{"id": args[0][0], **{n: self.record[n] for n in kwargs["fields"]}}]
        if method == "read" and model == "x.line":
            return []
        raise AssertionError(f"unexpected call {model}.{method}")


@pytest.fixture(autouse=True)
def _parity(monkeypatch):
    # The deployments run native ACL parity with strict per-user auth.
    monkeypatch.setenv("ODOO_MCP_NATIVE_ACL_PARITY", "1")
    monkeypatch.setenv("ODOO_MCP_REQUIRE_PER_USER", "1")
    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.delenv("ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", raising=False)
    monkeypatch.delenv("ODOO_MCP_METHOD_ALLOWLIST_MODEL", raising=False)


@pytest.fixture
def server():
    return importlib.import_module("odoo_mcp.server")


def _occurrence(name, button_type="object", attrs=None, static=False, conditions=None):
    return fi.ButtonOccurrence(
        name, button_type, None, ["form"], attrs or {}, static, conditions or [],
    )


def _button(result, name):
    for entry in result["buttons"]:
        if entry["name"] == name:
            return entry
    raise AssertionError(f"button {name} not in result")


def _inspect(server, client=None, record_id=9):
    return server.inspect_record_form(
        _Ctx(client or _ButtonClient()), "nesa.zertifikat", record_id=record_id,
    )


def test_arch_walk_collects_the_forms_own_buttons_in_order():
    buttons = []
    occurrences, _attrs = fi.parse_form_arch(BUTTON_ARCH, buttons=buttons)
    assert [b.name for b in buttons] == [
        "action_snooze_reminders", "action_resume_reminders", "412",
        "action_archive", "action_hidden_hotkey", "action_with_expression",
        "action_open_docs", "action_check_now",
    ]
    # Sub-view buttons belong to the comodel; special/typeless ones only drive
    # the web client.
    names = {b.name for b in buttons}
    assert "action_line_only" not in names and "no_type_button" not in names
    docs = next(b for b in buttons if b.name == "action_open_docs")
    assert docs.label == "Dokumente"
    assert docs.section_path == ["form", "sheet", "button_box"]
    # The stat button's inner field stays a field occurrence of the form.
    assert "doc_count" in [o.name for o in occurrences]
    # Without a list nothing changes for existing callers.
    assert [o.name for o in fi.parse_form_arch(BUTTON_ARCH)[0]] == [
        o.name for o in occurrences
    ]


def test_snooze_button_reports_exact_method_and_why_it_is_hidden(server):
    visible = _inspect(server)
    snooze = _button(visible, "action_snooze_reminders")
    assert snooze["label"] == "Spammy pausieren"
    assert snooze["type"] == "object" and snooze["mcp_call"] == "execute_method"
    assert snooze["visibility"] == "visible"
    assert snooze["visibility_condition"] == (
        "state != 'aktiv' or ampel != 'rot' or reminder_snooze_until"
    )
    assert snooze["confirm"] == "Wirklich pausieren?"
    assert snooze["section_path"] == "form / header"
    assert _button(visible, "action_resume_reminders")["visibility"] == "hidden"

    # Ampel not red: the UI hides the button, so does the answer.
    green = _inspect(server, _ButtonClient({"ampel": "gruen"}))
    assert _button(green, "action_snooze_reminders")["visibility"] == "hidden"

    paused = _inspect(server, _ButtonClient({"reminder_snooze_until": "2026-11-11"}))
    assert _button(paused, "action_snooze_reminders")["visibility"] == "hidden"
    assert _button(paused, "action_resume_reminders")["visibility"] == "visible"


def test_fields_read_only_by_a_button_modifier_are_read(server):
    client = _ButtonClient()
    _inspect(server, client)
    read_fields = {
        name for c in client.calls
        if c[0] == "nesa.zertifikat" and c[1] == "read"
        for name in c[3]["fields"]
    }
    # ampel and reminder_snooze_until are no form fields, only button inputs.
    assert {"ampel", "reminder_snooze_until"} <= read_fields


def test_button_routes_mirror_execute_method_gates(server):
    result = _inspect(server)
    renew = _button(result, "412")
    assert renew["mcp_call"] == "action" and renew["action_id"] == 412
    assert renew["context"] == {"default_mode": "renew"}
    # validate_write takes create/write/unlink only: an alias has no route.
    assert _button(result, "action_archive")["mcp_call"] == "not_supported_write_alias"
    expression = _button(result, "action_with_expression")
    assert expression["context_expression"] == "{'default_partner_id': partner_id}"
    assert "context" not in expression

    route = server._form_button_route
    assert route(None, "nesa.zertifikat", _occurrence("_secret")) == "not_callable_private"
    assert route(None, "nesa.agent.tool", _occurrence("action_x")) == "blocked_hard_deny"
    assert route(None, "nesa.zertifikat", _occurrence("a-b")) == "not_callable_invalid_name"
    assert route(None, "nesa.zertifikat", _occurrence("unlink")) == "approved_write_chain"


def test_routes_follow_the_review_policy_without_parity(server, monkeypatch):
    monkeypatch.delenv("ODOO_MCP_NATIVE_ACL_PARITY")
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "nesa.zertifikat.action_resume_reminders",
    )
    route = server._form_button_route
    # Exactly what execute_method answers with method_not_reviewed.
    assert route(None, "nesa.zertifikat", _occurrence("action_snooze_reminders")) == "not_reviewed"
    assert route(None, "nesa.zertifikat", _occurrence("action_confirm")) == "not_reviewed"
    assert route(None, "nesa.zertifikat", _occurrence("action_resume_reminders")) == "execute_method"
    assert route(None, "nesa.zertifikat", _occurrence("get_report_values")) == "execute_method"
    monkeypatch.setenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", "1")
    assert route(None, "nesa.zertifikat", _occurrence("action_snooze_reminders")) == "execute_method"


def test_transient_exemption_decides_create_and_write(server, monkeypatch):
    seen = []

    def fake_exempt(app_context, odoo, model, method):
        seen.append((model, method))
        return model == "x.wizard", {"transient": model == "x.wizard"}

    monkeypatch.setattr(server, "transient_write_is_exempt", fake_exempt)

    class _App:
        odoo = object()

    route = server._form_button_route
    assert route(_App(), "x.wizard", _occurrence("write")) == "execute_method"
    assert route(_App(), "res.partner", _occurrence("write")) == "approved_write_chain"
    # unlink and the aliases never take the exemption.
    assert route(_App(), "x.wizard", _occurrence("unlink")) == "approved_write_chain"
    assert route(_App(), "x.wizard", _occurrence("copy")) == "not_supported_write_alias"
    assert seen == [("x.wizard", "write"), ("res.partner", "write")]

    # The click's args go through the same x2many gate as execute_method.
    monkeypatch.setattr(
        server, "_cached_fields_metadata",
        lambda app_context, odoo, model: {"result_ids": {"type": "one2many"}},
    )
    mutating = _occurrence("write", attrs={"args": "[{'result_ids': [[2, 7, 0]]}]"})
    assert route(_App(), "x.wizard", mutating) == "approved_write_chain"
    linking = _occurrence("write", attrs={"args": "[{'result_ids': [[4, 7, 0]]}]"})
    assert route(_App(), "x.wizard", linking) == "execute_method"
    broken = _occurrence("write", attrs={"args": "[{'result_ids': True}"})
    assert route(_App(), "x.wizard", broken) == "approved_write_chain"


def test_action_buttons_carry_a_usable_reference(server):
    arch = (
        '<form><header>'
        '<button name="412" type="action" string="Nummer"/>'
        '<button name="account.action_move_line_select" type="action" string="XML-ID"/>'
        '</header><field name="state"/></form>'
    )
    result = _inspect(server, _ButtonClient(arch=arch))
    assert _button(result, "412")["action_id"] == 412
    xmlid = _button(result, "account.action_move_line_select")
    assert xmlid["action_xmlid"] == "account.action_move_line_select"
    assert "action_id" not in xmlid and xmlid["mcp_call"] == "action"


def test_context_keys_the_server_strips_are_named(server):
    arch = (
        '<form><header><button name="action_quiet" type="object" string="Leise" '
        'context="{\'tracking_disable\': True, \'default_x\': 1}"/>'
        '</header><field name="state"/></form>'
    )
    entry = _button(_inspect(server, _ButtonClient(arch=arch)), "action_quiet")
    assert entry["context"] == {"tracking_disable": True, "default_x": 1}
    assert entry["context_keys_removed_by_server"] == ["tracking_disable"]


def test_statically_hidden_buttons_are_counted_not_listed(server):
    result = _inspect(server)
    names = [b["name"] for b in result["buttons"]]
    assert "action_hidden_hotkey" not in names
    assert result["meta"]["static_hidden_buttons_skipped"] == 1
    assert result["meta"]["button_count"] == len(names)


def test_static_invisibility_wins_over_dynamic_conditions(server):
    # The view compiler drops these nodes whatever the other conditions say.
    arch = (
        '<form><sheet>'
        '<group invisible="state == \'entwurf\'">'
        '<button name="action_own_static" type="object" invisible="1"/>'
        '</group>'
        '<group invisible="1">'
        '<button name="action_under_static" type="object" invisible="not name"/>'
        '</group>'
        '<button name="action_kept" type="object" invisible="not name"/>'
        '</sheet><field name="state"/></form>'
    )
    result = _inspect(server, _ButtonClient(arch=arch))
    assert [b["name"] for b in result["buttons"]] == ["action_kept"]
    assert result["meta"]["static_hidden_buttons_skipped"] == 2


def test_button_inherits_its_group_condition(server):
    draft = _inspect(server, _ButtonClient({"state": "entwurf"}))
    check = _button(draft, "action_check_now")
    assert check["visibility"] == "hidden"
    assert check["inherited_conditions"][0]["condition"] == "state == 'entwurf'"


def test_buttons_without_record_are_conditional(server):
    result = server.inspect_record_form(_Ctx(_ButtonClient()), "nesa.zertifikat")
    assert _button(result, "action_snooze_reminders")["visibility"] == "conditional"
    assert _button(result, "412")["visibility"] == "visible"


def test_buttons_come_before_sections_in_the_answer(server):
    assert list(_inspect(server)) == ["success", "meta", "buttons", "sections"]


def test_only_read_methods_are_called_for_buttons(server):
    client = _ButtonClient()
    _inspect(server, client)
    assert {c[1] for c in client.calls} <= {
        "get_view", "read", "default_get", "fields_get",
    }


def test_button_budget_overflow_is_announced(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", "4000")
    help_text = "h" * 80
    arch = "<form><header>" + "".join(
        f'<button name="action_number_{i}" type="object" string="Knopf {i}" '
        f'invisible="state != \'aktiv\'" help="{help_text}"/>'
        for i in range(120)
    ) + '</header><field name="state"/></form>'
    result = _inspect(server, _ButtonClient(arch=arch))
    meta = result["meta"]
    assert meta["truncated"] is True
    kept = result["buttons"]
    # Leading buttons stay complete, trailing ones go as a whole.
    assert kept and all("help" not in b for b in kept)
    assert [b["name"] for b in kept] == [f"action_number_{i}" for i in range(len(kept))]
    assert meta["omitted_buttons_count"] == 120 - len(kept)
    assert meta["omitted_buttons"][0] == f"action_number_{len(kept)}"
    assert len(meta["omitted_buttons"]) <= server.MAX_OMITTED_BUTTON_NAMES
    assert any("buttons omitted" in w for w in meta["warnings"])
    assert fi.payload_chars(result) <= 4000


def test_budget_keeps_call_relevant_button_keys(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", "4000")
    arch = "<form><header>" + "".join(
        f'<button name="action_ctx_{i}" type="object" string="Knopf {i}" '
        f'context="{{\'default_partner_id\': partner_id}}" help="{"h" * 200}"/>'
        for i in range(12)
    ) + '</header><field name="state"/></form>'
    result = _inspect(server, _ButtonClient(arch=arch))
    assert result["buttons"]
    for entry in result["buttons"]:
        assert entry["context_expression"] == "{'default_partner_id': partner_id}"
        assert entry["mcp_call"] == "execute_method"


def test_omitted_button_names_are_capped(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", "4000")
    arch = "<form><header>" + "".join(
        f'<button name="action_regular_button_{i}" type="object" string="Knopf {i}"/>'
        for i in range(400)
    ) + '</header><field name="state"/></form>'
    result = _inspect(server, _ButtonClient(arch=arch))
    meta = result["meta"]
    assert meta["omitted_buttons_count"] + len(result["buttons"]) == 400
    assert len(meta["omitted_buttons"]) == server.MAX_OMITTED_BUTTON_NAMES
    assert fi.payload_chars(result) <= 4000


def test_long_omitted_button_names_still_fit_the_budget(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", "4000")
    stem = "action_" + "x" * 56
    arch = "<form><header>" + "".join(
        f'<button name="{stem}_{i:03d}" type="object" string="Knopf {i}"/>'
        for i in range(60)
    ) + '</header><field name="state"/></form>'
    result = _inspect(server, _ButtonClient(arch=arch))
    meta = result["meta"]
    assert meta["omitted_buttons_count"] + len(result["buttons"]) == 60
    # The name list itself was cut for size, below the count cap.
    assert 0 < len(meta["omitted_buttons"]) < min(
        server.MAX_OMITTED_BUTTON_NAMES, meta["omitted_buttons_count"],
    )
    assert fi.payload_chars(result) <= 4000


def test_static_context_accepts_literals_only():
    assert fi.static_context("{'a': 1, 'b': [2]}") == {"a": 1, "b": [2]}
    assert fi.static_context("{'a': partner_id}") is None
    assert fi.static_context("[1, 2]") is None
    assert fi.static_context("{[1]: 2}") is None
    assert fi.static_context(None) is None
