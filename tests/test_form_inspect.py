"""Tests for inspect_record_form (NESA 2026-09-18).

The tool exists because agents judged records from ad-hoc field lists and
missed custom form fields such as "Anrede".  The tests therefore protect what
an agent observes: every form field occurrence is there, in order; an
undecidable modifier is never reported as plain visible/hidden; binary content
never leaves the server; every shortening is announced.
"""

import importlib
import json

import pytest

from odoo_mcp import form_inspect as fi


ARCH = """
<form edit="0">
  <header>
    <field name="state" widget="statusbar"/>
  </header>
  <sheet>
    <div name="button_box"><button name="x" type="object"><field name="order_count"/></button></div>
    <field name="image_1920" widget="image"/>
    <group string="Kontakt">
      <field name="name" required="1"/>
      <field name="x_anrede"/>
      <field name="secret_code" invisible="1"/>
      <field name="vat" invisible="not is_company" readonly="state == 'done'"/>
      <field name="ref" invisible="context.get('hide_ref')"/>
      <field name="parent_id"/>
      <field name="is_company" invisible="True"/>
    </group>
    <notebook>
      <page string="Anlage" name="plant" invisible="state == 'draft'">
        <separator string="Heizung"/>
        <field name="x_heizungsanlage"/>
        <field name="name" readonly="1" string="Name (Anlage)"/>
      </page>
      <page string="Zeilen">
        <field name="line_ids">
          <list>
            <field name="product_id"/>
            <field name="qty"/>
            <field name="photo"/>
            <field name="internal" column_invisible="1"/>
          </list>
          <form><field name="deep_only_in_subform"/></form>
        </field>
        <field name="tag_ids" widget="many2many_tags"/>
        <field name="comment"/>
        <field name="ghost_field"/>
      </page>
    </notebook>
  </sheet>
</form>
"""

PARTNER_FIELDS = {
    "state": {"type": "selection", "string": "Status",
              "selection": [["draft", "Entwurf"], ["done", "Erledigt"]]},
    "order_count": {"type": "integer", "string": "Aufträge", "readonly": True},
    "image_1920": {"type": "binary", "string": "Bild"},
    "name": {"type": "char", "string": "Name", "required": True},
    "x_anrede": {"type": "selection", "string": "Anrede",
                 "selection": [["herr", "Herr"], ["frau", "Frau"]]},
    "secret_code": {"type": "char", "string": "Code"},
    "vat": {"type": "char", "string": "USt-IdNr."},
    "ref": {"type": "char", "string": "Referenz"},
    "parent_id": {"type": "many2one", "string": "Firma", "relation": "res.partner"},
    "is_company": {"type": "boolean", "string": "Ist Firma"},
    "x_heizungsanlage": {"type": "char", "string": "Heizungsanlage"},
    "line_ids": {"type": "one2many", "string": "Zeilen", "relation": "x.line"},
    "tag_ids": {"type": "many2many", "string": "Tags", "relation": "x.tag"},
    "comment": {"type": "html", "string": "Notiz"},
    "display_name": {"type": "char", "string": "Anzeigename"},
}

LINE_FIELDS = {
    "display_name": {"type": "char", "string": "Anzeigename"},
    "product_id": {"type": "many2one", "string": "Produkt", "relation": "x.product"},
    "qty": {"type": "float", "string": "Menge"},
    "photo": {"type": "binary", "string": "Foto"},
    "internal": {"type": "char", "string": "Intern"},
}

BASE64_BLOB = "QUJD" * 5000


class _FormClient:
    def __init__(self, record=None, line_count=3):
        self.calls = []
        self.record = {
            "display_name": "Muster GmbH",
            "state": "done",
            "order_count": 4,
            "image_1920": "12.30 Kb",
            "name": "Muster GmbH",
            "x_anrede": False,
            "secret_code": "abc",
            "vat": "DE123",
            "ref": False,
            "parent_id": [7, "Holding AG"],
            "is_company": True,
            "x_heizungsanlage": "Viessmann Vitodens",
            "line_ids": list(range(101, 101 + line_count)),
            "tag_ids": [],
            "comment": "x" * 5000,
        }
        if record:
            self.record.update(record)

    def get_user_context(self):
        return {"lang": "de_DE", "tz": "Europe/Berlin", "uid": 2}

    def get_model_fields(self, model):
        return {
            "res.partner": PARTNER_FIELDS,
            "x.line": LINE_FIELDS,
            "x.tag": {"display_name": {"type": "char", "string": "Name"}},
        }.get(model, {})

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args, kwargs))
        if method == "get_view":
            return {"arch": ARCH, "id": 55, "model": model, "models": {}}
        if model == "ir.ui.view":
            return [{"id": 55, "name": "res.partner.form.nesa", "type": "form",
                     "model": "res.partner"}]
        if method == "fields_get":
            assert kwargs["attributes"] == ["string", "selection"]
            return {"parent_id": {"string": "Übergeordnete Firma"}}
        if method == "default_get":
            assert args and isinstance(args[0], list) and "fields_list" not in kwargs
            return {"state": "draft", "is_company": False}
        if method == "read" and model == "res.partner":
            if args[0] == [404]:
                return []
            row = {"id": args[0][0]}
            for name in kwargs["fields"]:
                if name == "image_1920" and not kwargs["context"].get("bin_size"):
                    row[name] = BASE64_BLOB
                else:
                    row[name] = self.record[name]
            return [row]
        if method == "read" and model == "x.line":
            full = {"display_name": None, "product_id": [1, "Brenner"], "qty": 2.0,
                    "photo": BASE64_BLOB, "internal": "geheim"}
            return [
                {"id": i, **{n: (f"Zeile {i}" if n == "display_name" else full[n])
                             for n in kwargs["fields"]}}
                for i in args[0]
            ]
        raise AssertionError(f"unexpected call {model}.{method}")


class _Life:
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


def _fields(result):
    return [f for section in result["sections"] for f in section["fields"]]


def _one(result, name, occurrence="1"):
    for entry in _fields(result):
        if entry["name"] == name and entry["occurrence"].startswith(occurrence + "/"):
            return entry
    raise AssertionError(f"{name} not in result")


# ----- pure helpers ---------------------------------------------------------


def test_static_modifiers_are_recognised():
    assert fi.static_modifier("1") is True
    assert fi.static_modifier("True") is True
    assert fi.static_modifier("0") is False
    assert fi.static_modifier(None) is False
    assert fi.static_modifier("state == 'x'") is None


@pytest.mark.parametrize(
    "expression, names, expected",
    [
        ("state == 'draft'", {"state": "draft"}, True),
        ("state not in ('draft', 'sent')", {"state": "done"}, True),
        ("not is_company", {"is_company": True}, False),
        ("a or context.get('x')", {"a": True}, True),
        ("a or context.get('x')", {"a": False}, fi.UNKNOWN),
        ("a and parent.state == 'x'", {"a": False}, False),
        ("a and parent.state == 'x'", {"a": True}, fi.UNKNOWN),
        ("missing_field", {}, fi.UNKNOWN),
        ("qty > 3", {"qty": False}, False),
        ("name < 3", {"name": "abc"}, fi.UNKNOWN),
        ("not line_ids", {"line_ids": []}, True),
        ("this is not python", {}, fi.UNKNOWN),
    ],
)
def test_modifier_evaluation_is_three_valued(expression, names, expected):
    assert fi.evaluate_modifier(expression, names) is expected


def test_expression_field_names_skip_foreign_namespaces():
    names = fi.expression_field_names("state == 'x' and parent.kind and context.get('y')")
    assert names == ["state"]


def test_arch_walk_keeps_order_sections_and_occurrences():
    occurrences, attrs = fi.parse_form_arch(ARCH)
    names = [o.name for o in occurrences]
    assert names[:4] == ["state", "order_count", "image_1920", "name"]
    assert "deep_only_in_subform" not in names and "product_id" not in names
    assert attrs["edit"] == "0"
    second_name = [o for o in occurrences if o.name == "name"][1]
    assert (second_name.index, second_name.total) == (2, 2)
    assert second_name.section_path == [
        "form", "sheet", "page:Anlage", "separator:Heizung",
    ]
    lines = next(o for o in occurrences if o.name == "line_ids")
    assert [c["name"] for c in lines.subview_columns] == [
        "product_id", "qty", "photo", "internal",
    ]


def test_shape_binary_never_passes_content_through():
    assert fi.shape_binary(False) == {"present": False}
    assert fi.shape_binary("12.30 Kb") == {"present": True, "size": "12.30 Kb"}
    assert fi.shape_binary(BASE64_BLOB) == {"present": True, "content_omitted": True}


# ----- tool behaviour -------------------------------------------------------


def test_custom_fields_appear_with_values_in_form_order(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    assert result["success"] is True
    meta = result["meta"]
    assert meta["view_id"] == 55 and meta["view_name"] == "res.partner.form.nesa"
    assert meta["record_display_name"] == "Muster GmbH"
    assert meta["user_context"]["lang"] == "de_DE"
    anrede = _one(result, "x_anrede")
    assert anrede["label"] == "Anrede" and anrede["value"] is False
    assert anrede["visibility"] == "visible"
    assert anrede["section_path"] == "form / sheet / group:Kontakt"
    heizung = _one(result, "x_heizungsanlage")
    assert heizung["value"] == "Viessmann Vitodens"
    assert [f["name"] for f in _fields(result)][:3] == [
        "state", "order_count", "image_1920",
    ]
    assert _one(result, "state")["display_value"] == "Erledigt"
    parent = _one(result, "parent_id")
    assert (parent["value"], parent["display_value"], parent["relation"]) == (
        7, "Holding AG", "res.partner",
    )


def test_static_invisible_field_is_hidden(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    assert _one(result, "secret_code")["visibility"] == "hidden"
    assert _one(result, "is_company")["visibility"] == "hidden"


def test_record_dependent_visibility_is_evaluated_with_condition(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    vat = _one(result, "vat")
    assert vat["visibility"] == "visible"
    assert vat["visibility_condition"] == "not is_company"
    assert vat["readonly"] is True
    assert vat["readonly_condition"] == "state == 'done'"

    hidden = server.inspect_record_form(
        _Ctx(_FormClient({"is_company": False, "state": "draft"})),
        "res.partner", record_id=5,
    )
    assert _one(hidden, "vat")["visibility"] == "hidden"
    assert _one(hidden, "vat")["readonly"] is False
    # The page is invisible in draft: its fields inherit that.
    heizung = _one(hidden, "x_heizungsanlage")
    assert heizung["visibility"] == "hidden"
    assert heizung["inherited_conditions"][0]["condition"] == "state == 'draft'"


def test_undecidable_condition_is_never_plain_visible(server):
    with_record = server.inspect_record_form(
        _Ctx(_FormClient()), "res.partner", record_id=5
    )
    ref = _one(with_record, "ref")
    assert ref["visibility"] == "unknown"
    assert ref["visibility_condition"] == "context.get('hide_ref')"

    without_record = server.inspect_record_form(_Ctx(_FormClient()), "res.partner")
    assert _one(without_record, "vat")["visibility"] == "conditional"
    assert _one(without_record, "vat")["readonly"] == "conditional"
    assert _one(without_record, "x_heizungsanlage")["visibility"] == "conditional"
    assert without_record["meta"]["values_source"] == "defaults"
    assert _one(without_record, "state")["value"] == "draft"


def test_repeated_field_keeps_each_occurrence(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    first, second = _one(result, "name", "1"), _one(result, "name", "2")
    assert (first["occurrence"], second["occurrence"]) == ("1/2", "2/2")
    assert first["readonly"] is False and second["readonly"] is True
    assert second["label"] == "Name (Anlage)"
    assert first["section_path"] != second["section_path"]


def test_binary_is_presence_only_and_read_with_bin_size(server):
    client = _FormClient()
    result = server.inspect_record_form(_Ctx(client), "res.partner", record_id=5)
    assert _one(result, "image_1920")["value"] == {"present": True, "size": "12.30 Kb"}
    assert BASE64_BLOB not in json.dumps(result)
    image_reads = [
        c for c in client.calls
        if c[1] == "read" and "image_1920" in c[3].get("fields", [])
    ]
    assert image_reads and all(c[3]["context"].get("bin_size") for c in image_reads)


def test_caller_cannot_switch_bin_size_off(server):
    client = _FormClient()
    result = server.inspect_record_form(
        _Ctx(client), "res.partner", record_id=5, context={"bin_size": False},
    )
    assert BASE64_BLOB not in json.dumps(result)
    assert any("bin_size" in w for w in result["meta"]["warnings"])


def test_x2many_rows_are_bounded_and_flagged(server):
    result = server.inspect_record_form(
        _Ctx(_FormClient(line_count=30)), "res.partner", record_id=5,
        max_relational_rows=4,
    )
    lines = _one(result, "line_ids")["value"]
    assert lines["count"] == 30 and len(lines["rows"]) == 4 and lines["truncated"]
    assert set(lines["rows"][0]) == {"id", "display_name", "product_id", "qty"}
    assert lines["binary_columns_skipped"] == ["photo"]
    assert result["meta"]["truncated"] is True
    assert any("line_ids" in w for w in result["meta"]["warnings"])
    assert _one(result, "tag_ids")["value"] == {"count": 0, "ids": []}


def test_long_text_is_clipped_loudly(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    comment = _one(result, "comment")
    assert comment["value_truncated"] and comment["value_length"] == 5000
    assert len(comment["value"]) == server.FORM_INSPECT_TEXT_LIMIT
    assert result["meta"]["truncated"] is True


def test_field_without_metadata_is_reported_not_dropped(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    ghost = _one(result, "ghost_field")
    assert ghost["type"] == "unknown" and ghost["value_available"] is False
    assert any("ghost_field" in w for w in result["meta"]["warnings"])


def test_include_empty_false_lists_what_it_left_out(server):
    result = server.inspect_record_form(
        _Ctx(_FormClient()), "res.partner", record_id=5, include_empty=False,
    )
    names = [f["name"] for f in _fields(result)]
    assert "x_anrede" not in names and "x_heizungsanlage" in names
    assert "x_anrede" in result["meta"]["omitted_empty_fields"]


def test_budget_overflow_is_announced_never_silent(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", "4000")
    result = server.inspect_record_form(
        _Ctx(_FormClient(line_count=30)), "res.partner", record_id=5,
    )
    meta = result["meta"]
    assert meta["truncated"] is True
    assert fi.payload_chars(result) <= 4000
    returned = {f["name"] for f in _fields(result)}
    all_names = {o.name for o in fi.parse_form_arch(ARCH)[0]}
    accounted = (
        returned | set(meta.get("omitted_fields", []))
        | set(meta.get("omitted_hidden_fields", []))
    )
    assert accounted == all_names
    assert "secret_code" in meta["omitted_hidden_fields"]
    assert any("Answer budget" in w for w in meta["warnings"])


def test_large_form_reads_in_blocks_and_loses_nothing(server):
    count = 130
    arch = "<form><sheet>" + "".join(
        f'<field name="f{i}"/>' for i in range(count)
    ) + "</sheet></form>"
    fields = {f"f{i}": {"type": "char", "string": f"F{i}"} for i in range(count)}

    class _Wide(_FormClient):
        def get_model_fields(self, model):
            return fields

        def execute_method(self, model, method, *args, **kwargs):
            self.calls.append((model, method, args, kwargs))
            if method == "get_view":
                return {"arch": arch, "id": 1, "model": model}
            if model == "ir.ui.view":
                return [{"name": "wide", "type": "form", "model": "x.wide"}]
            return [{"id": 1, **{n: "v" for n in kwargs["fields"]}}]

    client = _Wide()
    result = server.inspect_record_form(_Ctx(client), "x.wide", record_id=1)
    assert [f["name"] for f in _fields(result)] == [f"f{i}" for i in range(count)]
    assert result["meta"]["truncated"] is False
    blocks = [c[3]["fields"] for c in client.calls if c[0] == "x.wide" and c[1] == "read"]
    assert max(len(b) for b in blocks) <= server.FORM_INSPECT_READ_CHUNK


def test_one_broken_field_does_not_lose_the_block(server):
    class _Flaky(_FormClient):
        def execute_method(self, model, method, *args, **kwargs):
            if (model, method) == ("res.partner", "read") and "vat" in kwargs["fields"]:
                if len(kwargs["fields"]) > 1 or kwargs["fields"] == ["vat"]:
                    raise RuntimeError("ValueError: compute exploded")
            return super().execute_method(model, method, *args, **kwargs)

    result = server.inspect_record_form(_Ctx(_Flaky()), "res.partner", record_id=5)
    assert "compute exploded" in _one(result, "vat")["value_error"]
    assert _one(result, "x_heizungsanlage")["value"] == "Viessmann Vitodens"
    # vat decides nothing here, but a modifier reading it must not be guessed.
    assert any("vat" in w for w in result["meta"]["warnings"])


def test_missing_record_is_not_found(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=404)
    assert result["success"] is False and result["error_type"] == "not_found"


class _NonAdmin(_FormClient):
    """ir.ui.view is readable by admins only — the normal case is a refusal."""

    def execute_method(self, model, method, *args, **kwargs):
        if model == "ir.ui.view":
            raise RuntimeError("odoo.exceptions.AccessError: not allowed")
        return super().execute_method(model, method, *args, **kwargs)


def test_wrong_view_type_is_refused_without_view_access(server):
    class _ListView(_NonAdmin):
        def execute_method(self, model, method, *args, **kwargs):
            if method == "get_view":
                return {"arch": '<list><field name="name"/></list>', "id": 9,
                        "model": model}
            return super().execute_method(model, method, *args, **kwargs)

    result = server.inspect_record_form(
        _Ctx(_ListView()), "res.partner", record_id=5, view_id=9,
    )
    assert result["success"] is False and "not a form view" in result["error"]


def test_view_of_another_model_is_refused(server):
    # get_view echoes the model it was called on; only ir.ui.view tells.
    class _Foreign(_FormClient):
        def execute_method(self, model, method, *args, **kwargs):
            if model == "ir.ui.view":
                return [{"name": "sale.order.form", "model": "sale.order"}]
            return super().execute_method(model, method, *args, **kwargs)

    result = server.inspect_record_form(
        _Ctx(_Foreign()), "res.partner", record_id=5, view_id=9,
    )
    assert result["success"] is False and "sale.order" in result["error"]

    # Without view access the mismatch cannot be proven — but it is flagged.
    unverified = server.inspect_record_form(
        _Ctx(_NonAdmin()), "res.partner", record_id=5, view_id=9,
    )
    assert unverified["success"] is True
    assert any("could not be verified" in w for w in unverified["meta"]["warnings"])


def test_row_many2one_keeps_its_id_when_the_name_is_clipped(server):
    class _LongName(_FormClient):
        def execute_method(self, model, method, *args, **kwargs):
            rows = super().execute_method(model, method, *args, **kwargs)
            if model == "x.line":
                for row in rows:
                    row["product_id"] = [77, "Brenner " * 60]
            return rows

    result = server.inspect_record_form(_Ctx(_LongName()), "res.partner", record_id=5)
    lines = _one(result, "line_ids")["value"]
    assert lines["rows"][0]["product_id"][0] == 77
    assert len(lines["rows"][0]["product_id"][1]) == server.FORM_INSPECT_DEGRADED_TEXT_LIMIT
    assert result["meta"]["truncated"] is True


def test_false_or_id_idiom_stays_decidable():
    assert fi.evaluate_modifier("pid in [False, 3]", {"pid": 3}) is True
    assert fi.evaluate_modifier("pid in [False, 3]", {"pid": False}) is True
    assert fi.evaluate_modifier("pid not in [False, 3]", {"pid": 4}) is True


def test_data_uri_with_parameters_is_scrubbed():
    value = "x data:image/svg+xml;charset=utf-8;base64," + "QUJD" * 30 + " y"
    scrubbed, count = fi.scrub_inline_base64(value)
    assert count == 1 and "QUJDQUJD" not in scrubbed


def test_non_admin_gets_the_form_without_a_view_name(server):
    result = server.inspect_record_form(_Ctx(_NonAdmin()), "res.partner", record_id=5)
    assert result["success"] is True and result["meta"]["view_name"] is None
    assert not any("View name" in w for w in result["meta"]["warnings"])


def test_view_readonly_zero_overrides_model_readonly(server):
    class _Editable(_FormClient):
        def execute_method(self, model, method, *args, **kwargs):
            if method == "get_view":
                arch = ARCH.replace(
                    '<field name="order_count"/>',
                    '<field name="order_count" readonly="0"/>',
                )
                return {"arch": arch, "id": 55, "model": model}
            return super().execute_method(model, method, *args, **kwargs)

    assert fi.resolve_readonly(None, True, None) == (True, None)
    result = server.inspect_record_form(_Ctx(_Editable()), "res.partner", record_id=5)
    assert _one(result, "order_count")["readonly"] is False


def test_model_required_stays_required_and_says_so(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    name = _one(result, "name")
    assert name["required"] is True and name["required_source"] == "model"


def test_x2many_defaults_are_decoded_and_cuts_announced(server):
    class _Defaults(_FormClient):
        def execute_method(self, model, method, *args, **kwargs):
            if method == "default_get":
                return {"tag_ids": [[6, 0, list(range(1, 51))]],
                        "line_ids": [[0, 0, {"qty": 1}], [4, 9, 0]]}
            return super().execute_method(model, method, *args, **kwargs)

    result = server.inspect_record_form(
        _Ctx(_Defaults()), "res.partner", max_relational_rows=5, include_empty=False,
    )
    tags = _one(result, "tag_ids")["value"]
    assert tags["count"] == 50 and len(tags["ids"]) == 5 and tags["truncated"]
    assert _one(result, "line_ids")["value"] == {"count": 1, "ids": [9], "new_rows": 1}
    assert result["meta"]["truncated"] is True
    assert any("tag_ids" in w for w in result["meta"]["warnings"])
    # A binary default is never requested, so it is "not available", not "empty".
    assert _one(result, "image_1920")["value_available"] is False


def test_caller_cannot_spoof_uid(server):
    class _Uid(_FormClient):
        def execute_method(self, model, method, *args, **kwargs):
            if method == "get_view":
                arch = ARCH.replace('<field name="x_anrede"/>',
                                    '<field name="x_anrede" invisible="uid != 2"/>')
                return {"arch": arch, "id": 55, "model": model}
            return super().execute_method(model, method, *args, **kwargs)

    result = server.inspect_record_form(
        _Ctx(_Uid()), "res.partner", record_id=5, context={"uid": 99},
    )
    assert _one(result, "x_anrede")["visibility"] == "visible"
    assert result["meta"]["user_context"]["uid"] == 2


@pytest.mark.parametrize(
    "expression, names",
    [
        ("tag_ids == []", {"tag_ids": []}),
        ("tag_ids != []", {"tag_ids": [1]}),
        ("flag in [1, 2]", {"flag": True}),
        ("1 in [True]", {}),
    ],
)
def test_comparisons_the_web_client_decides_differently_are_unknown(expression, names):
    assert fi.evaluate_modifier(expression, names) is fi.UNKNOWN


def test_hostile_expression_is_unknown_not_a_crash():
    assert fi.evaluate_modifier("not " * 100000 + "x", {"x": 1}) is fi.UNKNOWN
    assert fi.expression_field_names("(" * 5000 + "x" + ")" * 5000) == []
    assert fi.evaluate_modifier("'a' * 10 ** 9", {}) is fi.UNKNOWN


def test_small_base64_is_not_mistaken_for_a_size():
    assert fi.shape_binary("aGVsbG8gd29ybGQ=") == {
        "present": True, "content_omitted": True,
    }
    assert fi.shape_binary("1.5 Mb")["size"] == "1.5 Mb"
    assert fi.shape_binary("812 bytes")["size"] == "812 bytes"


def test_inline_base64_in_html_is_removed_and_announced(server):
    html = '<p>Hallo</p><img src="data:image/png;base64,' + "QUJD" * 200 + '"/>'
    result = server.inspect_record_form(
        _Ctx(_FormClient({"comment": html})), "res.partner", record_id=5,
    )
    comment = _one(result, "comment")
    assert "QUJDQUJD" not in comment["value"] and "omitted" in comment["value"]
    assert comment["value_truncated"] and result["meta"]["truncated"] is True


def test_every_read_carries_bin_size(server):
    client = _FormClient()
    server.inspect_record_form(_Ctx(client), "res.partner", record_id=5)
    reads = [c for c in client.calls if c[1] == "read" and c[0] != "ir.ui.view"]
    assert reads and all(c[3]["context"]["bin_size"] is True for c in reads)


def test_subview_columns_are_direct_children_only():
    arch = (
        '<form><field name="line_ids"><list><field name="qty"/>'
        '<groupby name="product_id"><field name="foreign"/></groupby>'
        "</list></field></form>"
    )
    lines = fi.parse_form_arch(arch)[0][0]
    assert [c["name"] for c in lines.subview_columns] == ["qty"]


def test_row_columns_without_metadata_are_announced(server):
    class _Blind(_FormClient):
        def get_model_fields(self, model):
            return {} if model == "x.line" else super().get_model_fields(model)

    result = server.inspect_record_form(_Ctx(_Blind()), "res.partner", record_id=5)
    lines = _one(result, "line_ids")["value"]
    assert "product_id" in lines["columns_unavailable"]
    assert result["meta"]["truncated"] is True
    assert any("line_ids" in w for w in result["meta"]["warnings"])


def test_budget_holds_even_when_the_omitted_lists_are_large(server, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", "4000")
    count = 400
    arch = "<form><sheet>" + "".join(
        f'<group string="Gruppe {i}"><field name="field_number_{i}"/></group>'
        for i in range(count)
    ) + "</sheet></form>"
    fields = {f"field_number_{i}": {"type": "char", "string": f"F{i}"} for i in range(count)}

    class _Wide(_FormClient):
        def get_model_fields(self, model):
            return fields

        def execute_method(self, model, method, *args, **kwargs):
            if method == "get_view":
                return {"arch": arch, "id": 1, "model": model}
            if model == "ir.ui.view":
                return [{"name": "wide"}]
            return [{"id": 1, **{n: "v" for n in kwargs["fields"]}}]

    result = server.inspect_record_form(
        _Ctx(_Wide()), "x.wide", record_id=1, context={"note": "x" * 3000},
    )
    meta = result["meta"]
    assert fi.payload_chars(result) <= 4000
    assert meta["truncated"] is True
    returned = len(_fields(result))
    assert returned + meta["omitted_field_occurrences"] == count
    assert any("themselves cut" in w for w in meta["warnings"])


def test_only_read_methods_are_called(server):
    client = _FormClient()
    server.inspect_record_form(_Ctx(client), "res.partner", record_id=5)
    server.inspect_record_form(_Ctx(client), "res.partner")
    assert {c[1] for c in client.calls} <= {
        "get_view", "read", "default_get", "fields_get",
    }


def test_labels_come_in_the_users_language(server):
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    assert _one(result, "parent_id")["label"] == "Übergeordnete Firma"
    assert _one(result, "x_anrede")["label"] == "Anrede"


def test_hidden_technical_fields_are_compacted_before_anything_is_lost(server, monkeypatch):
    full = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    size = fi.payload_chars(full)
    monkeypatch.setenv("ODOO_MCP_FORM_INSPECT_MAX_CHARS", str(size - 50))
    result = server.inspect_record_form(_Ctx(_FormClient()), "res.partner", record_id=5)
    secret = _one(result, "secret_code")
    assert set(secret) == {"name", "type", "value", "visibility", "occurrence"}
    assert "label" in _one(result, "x_anrede")
    assert "rows" in _one(result, "line_ids")["value"]
    assert result["meta"]["truncated"] is True
    assert any("statically hidden" in w for w in result["meta"]["warnings"])
