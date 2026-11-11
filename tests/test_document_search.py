"""Tests for the keyword document search (NESA Patch 10, 2026-11-11).

The tool exists because a single generic word over 100,000+ text-indexed
attachments returns hundreds of hits.  The tests therefore protect what makes
a narrow search cheap for an agent: AND-combined keywords, literal matching,
merged copies, name matches first, snippets, and an answer that says what to
change when a search is too broad or empty.
"""

import asyncio
import importlib

import pytest

from odoo_mcp import document_search as ds


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


def _row(id_, name, checksum=None, res_model="documents.document", res_id=None,
         mimetype="application/pdf", file_size=50_000):
    return {
        "id": id_,
        "name": name,
        "mimetype": mimetype,
        "file_size": file_size,
        "res_model": res_model,
        "res_id": res_id if res_id is not None else id_ + 1000,
        "create_date": "2026-04-04 10:00:00",
        "checksum": checksum if checksum is not None else f"sum{id_}",
    }


class _SearchClient:
    """Odoo double: preset candidate rows, texts by id, counts by keyword."""

    def __init__(self, rows=(), texts=None, total=None, keyword_counts=None,
                 fail_text_read=False, fail_count=False):
        self.rows = list(rows)
        self.texts = dict(texts or {})
        self.total = total
        self.keyword_counts = dict(keyword_counts or {})
        self.fail_text_read = fail_text_read
        self.fail_count = fail_count
        self.search_calls = []
        self.count_domains = []
        self.read_calls = []

    def search_read(self, model_name, domain, fields=None, offset=None,
                    limit=None, order=None):
        self.search_calls.append(
            {"model": model_name, "domain": domain, "fields": fields,
             "offset": offset, "limit": limit, "order": order}
        )
        return self.rows[:limit]

    def execute_method(self, model, method, *args, **kwargs):
        assert (model, method) == ("ir.attachment", "search_count")
        if self.fail_count:
            raise ValueError("count refused")
        domain = args[0]
        self.count_domains.append(domain)
        patterns = [leaf[2] for leaf in domain if isinstance(leaf, list) and leaf[0] == "name"]
        if len(patterns) == 1 and patterns[0] in self.keyword_counts:
            return self.keyword_counts[patterns[0]]
        return self.total if self.total is not None else len(self.rows)

    def read_records(self, model, ids, fields=None):
        self.read_calls.append({"model": model, "ids": list(ids), "fields": fields})
        if self.fail_text_read:
            raise ValueError("text read refused")
        assert fields == ["index_content"]
        return [{"id": id_, "index_content": self.texts.get(id_, "")} for id_ in ids]


# ----- keywords ------------------------------------------------------------


def test_keywords_are_trimmed_and_deduplicated_case_insensitively():
    assert ds.normalize_keywords(["  Tesla ", "tesla", "Zulassung", ""]) == [
        "Tesla", "Zulassung",
    ]


def test_bare_string_is_split_at_whitespace():
    # The search-box habit: as ONE phrase it would match nothing, because
    # file names carry no spaces.
    assert ds.normalize_keywords("Tesla  Zulassung") == ["Tesla", "Zulassung"]


def test_list_element_with_space_stays_one_phrase():
    assert ds.normalize_keywords(["Model   Y", "Tesla"]) == ["Model Y", "Tesla"]


@pytest.mark.parametrize(
    "keywords, reason",
    [
        ([], "keywords_missing"),
        (["  "], "keywords_missing"),
        ("", "keywords_missing"),
        (["a"], "keyword_too_short"),
        (["x" * 81], "keyword_too_long"),
        (["k1", "k2", "k3", "k4", "k5", "k6", "k7"], "too_many_keywords"),
        (["ok", 7], "invalid_keywords"),
        ({"a": 1}, "invalid_keywords"),
        (None, "invalid_keywords"),
    ],
)
def test_bad_keywords_are_refused_with_a_reason(keywords, reason):
    with pytest.raises(ds.DocumentSearchInputError) as error:
        ds.normalize_keywords(keywords)
    assert error.value.details["reason_code"] == reason
    assert error.value.details["invalid_parameter"] == "keywords"


def test_like_wildcards_are_escaped_so_keywords_match_literally():
    assert ds.escape_like("TGZ_61488") == "TGZ\\_61488"
    assert ds.escape_like("100%") == "100\\%"
    assert ds.escape_like("a\\b") == "a\\\\b"


# ----- domain --------------------------------------------------------------


def test_domain_requires_every_keyword_in_name_or_text():
    domain = ds.build_domain(["Tesla", "Zulassung"], ds.SCOPE_NAME_AND_TEXT, [])
    assert domain == [
        "|", ["name", "ilike", "Tesla"], ["index_content", "ilike", "Tesla"],
        "|", ["name", "ilike", "Zulassung"], ["index_content", "ilike", "Zulassung"],
    ]


def test_domain_scopes():
    assert ds.build_domain(["Tesla"], ds.SCOPE_NAME, []) == [["name", "ilike", "Tesla"]]
    assert ds.build_domain(["Tesla"], ds.SCOPE_TEXT, []) == [
        ["index_content", "ilike", "Tesla"],
    ]


def test_domain_never_names_id_or_res_field():
    # ir.attachment._search adds res_field = False only when the domain names
    # neither; naming one would pull avatar/product-image attachments in.
    filters = ds.filter_conditions(
        res_model="account.move", res_id=7, mimetype="image/",
        created_from="2026-01-01", created_to="2026-01-31",
    )
    domain = ds.build_domain(["Tesla", "Zulassung"], ds.SCOPE_NAME_AND_TEXT, filters)
    leaves = [leaf[0] for leaf in domain if isinstance(leaf, list)]
    assert "id" not in leaves and "res_field" not in leaves
    assert ["res_model", "=", "account.move"] in domain
    assert ["res_id", "=", 7] in domain
    assert ["mimetype", "=like", "image/%"] in domain
    assert ["create_date", ">=", "2026-01-01 00:00:00"] in domain
    assert ["create_date", "<=", "2026-01-31 23:59:59"] in domain


def test_mimetype_aliases_and_validation():
    assert ds.normalize_mimetype("pdf") == "application/pdf"
    assert ds.normalize_mimetype("Image") == "image/"
    assert ds.normalize_mimetype("application/pdf") == "application/pdf"
    assert ds.normalize_mimetype("  ") is None
    assert ds.normalize_mimetype(None) is None
    with pytest.raises(ds.DocumentSearchInputError) as error:
        ds.normalize_mimetype("pdf%")
    assert error.value.details["reason_code"] == "invalid_mimetype"


def test_dates_must_be_calendar_dates():
    assert ds.normalize_date("2026-02-28", "created_from") == "2026-02-28"
    assert ds.normalize_date(None, "created_from") is None
    for bad in ("28.02.2026", "2026-02-30", "2026-2-3"):
        with pytest.raises(ds.DocumentSearchInputError) as error:
            ds.normalize_date(bad, "created_to")
        assert error.value.details["invalid_parameter"] == "created_to"


# ----- dedup and ranking ---------------------------------------------------


def test_identical_files_collapse_and_name_matches_rank_first():
    rows = [
        _row(50, "Kontokorrent.csv"),
        _row(40, "Bescheid_Tesla_Zulassungsbescheinigung_2023-07-13.pdf", checksum="same"),
        _row(30, "scan_0031.pdf", checksum="same", res_model="project.task", res_id=9),
        _row(20, "Geschaeftsbrief_TeslaGermany.pdf"),
    ]
    groups = ds.group_and_rank(rows, ["Tesla", "Zulassung"])
    assert [group["row"]["id"] for group in groups] == [40, 20, 50]
    assert groups[0]["name_hits"] == ["Tesla", "Zulassung"]
    assert [copy["id"] for copy in groups[0]["copies"]] == [30]


def test_better_named_copy_becomes_the_representative():
    rows = [
        _row(90, "scan.pdf", checksum="same"),
        _row(80, "Tesla_Zulassung.pdf", checksum="same"),
    ]
    groups = ds.group_and_rank(rows, ["Tesla", "Zulassung"])
    assert len(groups) == 1
    assert groups[0]["row"]["id"] == 80
    assert [copy["id"] for copy in groups[0]["copies"]] == [90]


def test_attachments_without_checksum_are_never_merged():
    rows = [_row(2, "a.pdf", checksum=""), _row(1, "b.pdf", checksum="")]
    rows[0]["checksum"] = False
    assert len(ds.group_and_rank(rows, ["a"])) == 2


# ----- snippets ------------------------------------------------------------


def test_snippet_surrounds_the_match_and_collapses_whitespace():
    text = ("Kopfzeile " * 40) + "Zulassungsbescheinigung\nTeil  I   fuer Tesla Model 3" + (" Fuss" * 60)
    snippets, found = ds.extract_snippets(text, ["Tesla", "Zulassung"], 80)
    assert found == ["Tesla", "Zulassung"]
    assert len(snippets) == 1  # both keywords close together: one merged window
    assert "Zulassungsbescheinigung Teil I fuer Tesla Model 3" in snippets[0]
    assert snippets[0].startswith("…") and snippets[0].endswith("…")
    assert "\n" not in snippets[0]


def test_distant_keywords_give_separate_bounded_snippets():
    text = "Tesla " + ("x " * 2000) + "Zulassung " + ("y " * 2000) + "Berlin"
    snippets, found = ds.extract_snippets(text, ["Tesla", "Zulassung", "Berlin"], 60)
    assert found == ["Tesla", "Zulassung", "Berlin"]
    assert len(snippets) == 3
    assert not snippets[0].startswith("…")  # starts at the beginning of the text
    assert not snippets[-1].endswith("…")   # ends at the end of the text
    assert all(len(snippet) <= 60 + 2 * ds.SNIPPET_WORD_SLACK + 20 for snippet in snippets)


def test_snippet_matching_is_case_insensitive_and_literal():
    snippets, found = ds.extract_snippets("Betrag 100% (TGZ_61488) tesla", ["TESLA", "100%", "TGZ.61488"])
    assert found == ["TESLA", "100%"]  # '.' is not a wildcard here
    assert snippets


def test_no_text_no_snippet():
    assert ds.extract_snippets("", ["Tesla"]) == ([], [])
    assert ds.extract_snippets(None, ["Tesla"]) == ([], [])
    assert ds.extract_snippets("nichts davon", ["Tesla"]) == ([], [])


def test_large_text_files_are_not_pulled_for_a_snippet():
    # Only for text-like files does the file size bound the text: a big scan
    # or photo usually carries a short OCR text and keeps its snippet.
    assert ds.snippet_source_allowed(_row(1, "a.pdf", file_size=40_000_000)) is True
    assert ds.snippet_source_allowed(
        _row(4, "foto.jpg", mimetype="image/jpeg", file_size=400_000)
    ) is True
    assert ds.snippet_source_allowed(
        _row(5, "export.json", mimetype="application/json", file_size=400_000)
    ) is False
    assert ds.snippet_source_allowed(
        _row(2, "konto.xml", mimetype="text/xml", file_size=700_000)
    ) is False
    assert ds.snippet_source_allowed(
        _row(3, "notiz.txt", mimetype="text/plain", file_size=2_000)
    ) is True


# ----- hints ---------------------------------------------------------------


def test_broad_hint_only_from_the_threshold_on():
    assert ds.broad_result_hint(ds.BROAD_MATCH_THRESHOLD - 1, ["Tesla", "Brief"], False) is None
    hint = ds.broad_result_hint(227, ["Tesla"], False)
    assert "227 different files" in hint
    assert "single keyword 'Tesla'" in hint
    assert "Do not page" in hint


def test_broad_hint_names_the_ranked_window():
    hint = ds.broad_result_hint(5000, ["Rechnung", "2025"], True)
    assert "5000 attachments" in hint
    assert f"newest {ds.CANDIDATE_WINDOW}" in hint


def test_empty_hint_names_the_keyword_without_hits():
    hint = ds.empty_result_hint(
        ["Tesla", "Zulasung"], {"Tesla": 227, "Zulasung": 0}, False, ds.SCOPE_NAME_AND_TEXT,
    )
    assert "'Zulasung'" in hint and "'Tesla'" not in hint.split("Alone without any hit:")[1].split("—")[0]


def test_empty_hint_explains_phrases_and_filters():
    hint = ds.empty_result_hint(["Tesla Zulassung"], None, True, ds.SCOPE_NAME)
    assert "one literal phrase" in hint
    assert "Filters" in hint
    assert "search_in='name'" in hint


# ----- the tool ------------------------------------------------------------


def test_tool_ranks_merges_and_returns_snippets(server):
    rows = [
        _row(50, "Kontokorrent.csv", mimetype="text/csv"),
        _row(40, "Bescheid_Tesla_Zulassungsbescheinigung.pdf", checksum="same"),
        _row(30, "scan_0031.pdf", checksum="same", res_model="project.task", res_id=9),
    ]
    texts = {
        40: "Zulassungsbescheinigung Teil I, Halter NESA, Fahrzeug Tesla Model 3",
        50: "... Tesla Germany GmbH ... Zulassung ...",
    }
    client = _SearchClient(rows=rows, texts=texts)
    answer = server.search_documents(_Ctx(client), ["Tesla", "Zulassung"])

    assert answer["success"] is True
    assert answer["keywords"] == ["Tesla", "Zulassung"]
    assert answer["total_count"] == 3 and answer["unique_count"] == 2
    assert answer["has_more"] is False and answer["next_offset"] is None
    first, second = answer["result"]
    assert first["attachment_id"] == 40
    assert first["keywords_in_name"] == ["Tesla", "Zulassung"]
    assert first["copies"] == 2
    assert first["also_attached_to"] == [
        {"attachment_id": 30, "model": "project.task", "res_id": 9},
    ]
    assert "Tesla Model 3" in first["snippets"][0]
    assert first["text_chars"] == len(texts[40])
    assert second["attachment_id"] == 50 and second["keywords_in_name"] == []
    assert "hint" not in answer  # two files are not a broad result

    # One metadata window, no count RPC for a short window, one text read for
    # the page only — and never index_content in the metadata read.
    assert len(client.search_calls) == 1
    call = client.search_calls[0]
    assert call["model"] == "ir.attachment"
    assert "index_content" not in call["fields"]
    assert call["limit"] == ds.CANDIDATE_WINDOW and call["order"] == "id desc"
    assert client.count_domains == []
    assert client.read_calls == [
        {"model": "ir.attachment", "ids": [40], "fields": ["index_content"]},
        {"model": "ir.attachment", "ids": [50], "fields": ["index_content"]},
    ]


def test_text_transfer_stops_at_the_budget(server):
    # Odoo cannot cut a substring over RPC: each snippet costs a whole text.
    # Texts are read one file at a time and the reads stop at the budget, so
    # a page of huge PDFs never arrives as 25 full texts.
    rows = [_row(100 - i, f"Tesla_Sammelmappe_{i}.pdf") for i in range(6)]
    huge = "Tesla " + "x" * (ds.SNIPPET_TEXT_BUDGET_CHARS // 2)
    client = _SearchClient(rows=rows, texts={row["id"]: huge for row in rows})
    answer = server.search_documents(_Ctx(client), ["Tesla"])

    assert [call["ids"] for call in client.read_calls] == [[100], [99]]
    hits = answer["result"]
    assert all("snippets" in hit for hit in hits[:2])
    for hit in hits[2:]:
        assert "snippets" not in hit and "text_chars" not in hit
        assert "budget" in hit["snippet_skipped"]
        assert "get_document_text" in hit["snippet_skipped"]


def test_bad_input_is_answered_without_creating_the_odoo_client(server):
    # The client is created lazily; a wrong argument must come back as that,
    # even while Odoo is unreachable.
    class _Unreachable:
        @property
        def odoo(self):
            raise ConnectionError("connection refused")

    ctx = type("_C", (), {})()
    ctx.request_context = type("_Req", (), {"lifespan_context": _Unreachable()})()
    answer = server.search_documents(ctx, [])
    assert answer["success"] is False and answer["reason_code"] == "keywords_missing"

    answer = server.search_documents(ctx, ["Tesla", "Zulassung"])
    assert answer["success"] is False and answer["tool"] == "search_documents"
    assert answer["error_type"] == "transport" and answer["retryable"] is True


def test_failed_keyword_counts_are_unknown_not_hits(server):
    client = _SearchClient(rows=[], fail_count=True)
    answer = server.search_documents(_Ctx(client), ["Tesla", "Zulassung"])
    assert answer["keyword_counts"] == {"Tesla": None, "Zulassung": None}
    assert "has hits on its own" not in answer["hint"]
    assert "Could not be counted" in answer["hint"]


def test_partly_failed_keyword_counts_make_no_claim_about_the_unknown_one():
    hint = ds.empty_result_hint(
        ["Tesla", "Zulassung"], {"Tesla": 227, "Zulassung": None}, False,
        ds.SCOPE_NAME_AND_TEXT,
    )
    assert "has hits on its own" not in hint
    assert "Could not be counted alone" in hint and "'Zulassung'" in hint
    hint = ds.empty_result_hint(
        ["Tesla", "Zulasung", "Berlin"], {"Tesla": 227, "Zulasung": 0, "Berlin": None},
        False, ds.SCOPE_NAME_AND_TEXT,
    )
    assert "Alone without any hit: 'Zulasung'" in hint
    assert "Could not be counted alone" in hint and "'Berlin'" in hint


def test_tool_pages_over_unique_ranked_files(server):
    rows = [_row(100 - i, f"Tesla_{i}.pdf") for i in range(30)]
    client = _SearchClient(rows=rows)
    first = server.search_documents(_Ctx(client), ["Tesla"], limit=10)
    assert first["count"] == 10 and first["has_more"] is True
    assert first["next_offset"] == 10
    # 30 different files for one keyword: the answer says "narrow".
    assert "single keyword 'Tesla'" in first["hint"]
    second = server.search_documents(_Ctx(client), ["Tesla"], limit=10, offset=20)
    assert second["count"] == 10 and second["has_more"] is False


def test_tool_reports_a_truncated_window_and_the_real_total(server):
    rows = [_row(10_000 - i, f"Rechnung_{i}.pdf") for i in range(ds.CANDIDATE_WINDOW)]
    client = _SearchClient(rows=rows, total=4321)
    answer = server.search_documents(_Ctx(client), ["Rechnung"], limit=5)
    assert answer["total_count"] == 4321
    assert answer["window_truncated"] is True and answer["window"] == ds.CANDIDATE_WINDOW
    assert "4321 attachments" in answer["hint"]
    assert len(client.count_domains) == 1


def test_tool_survives_a_failed_count(server):
    rows = [_row(10_000 - i, f"Rechnung_{i}.pdf") for i in range(ds.CANDIDATE_WINDOW)]
    client = _SearchClient(rows=rows, fail_count=True)
    answer = server.search_documents(_Ctx(client), ["Rechnung"], limit=5)
    assert answer["success"] is True
    assert answer["total_count"] is None
    assert answer["window_truncated"] is True
    assert "total_count_error" in answer


def test_many_copies_of_one_file_are_not_a_broad_result(server):
    rows = [_row(500 - i, "TGZ-61488.pdf", checksum="same") for i in range(120)]
    client = _SearchClient(rows=rows, texts={500: "TGZ-61488 Arbeitsbericht"})
    answer = server.search_documents(_Ctx(client), ["TGZ-61488"])
    assert answer["unique_count"] == 1 and answer["total_count"] == 120
    assert answer["result"][0]["copies"] == 120
    assert len(answer["result"][0]["also_attached_to"]) == ds.MAX_LISTED_COPIES
    assert "hint" not in answer


def test_empty_result_says_which_keyword_has_no_match(server):
    client = _SearchClient(rows=[], keyword_counts={"Tesla": 227, "Zulasung": 0})
    answer = server.search_documents(
        _Ctx(client), ["Tesla", "Zulasung"], search_in="name",
    )
    assert answer["success"] is True and answer["count"] == 0
    assert answer["keyword_counts"] == {"Tesla": 227, "Zulasung": 0}
    assert "'Zulasung'" in answer["hint"]
    assert client.read_calls == []


def test_single_keyword_without_hits_needs_no_keyword_counts(server):
    client = _SearchClient(rows=[])
    answer = server.search_documents(_Ctx(client), ["Xyzzy"])
    assert "keyword_counts" not in answer
    assert client.count_domains == []
    assert "'Xyzzy'" in answer["hint"]


def test_name_scope_reads_no_text(server):
    client = _SearchClient(rows=[_row(1, "Tesla_Zulassung.pdf")])
    answer = server.search_documents(_Ctx(client), ["Tesla"], search_in="name")
    assert client.read_calls == []
    assert "snippets" not in answer["result"][0]
    assert "snippet_skipped" not in answer["result"][0]
    assert client.search_calls[0]["domain"] == [["name", "ilike", "Tesla"]]


def test_large_text_file_is_listed_without_pulling_its_text(server):
    rows = [_row(7, "Tesla_Kontoauszug.xml", mimetype="text/xml", file_size=700_000)]
    client = _SearchClient(rows=rows)
    answer = server.search_documents(_Ctx(client), ["Tesla"])
    assert client.read_calls == []
    assert "get_document_text" in answer["result"][0]["snippet_skipped"]


def test_failed_text_read_still_returns_the_hits(server):
    rows = [_row(3, "Tesla_a.pdf"), _row(2, "Tesla_b.pdf"), _row(1, "Tesla_c.pdf")]
    client = _SearchClient(rows=rows, fail_text_read=True)
    answer = server.search_documents(_Ctx(client), ["Tesla"])
    assert answer["success"] is True and answer["count"] == 3
    assert "snippet_error" in answer
    # The cause will not differ for the next file: one failed read, not three.
    assert len(client.read_calls) == 1


def test_text_read_failure_without_message_still_stops_and_is_reported(server):
    # TimeoutError() has no text; an empty string must not read as "no error".
    class _SilentFailure(_SearchClient):
        def read_records(self, model, ids, fields=None):
            self.read_calls.append({"model": model, "ids": list(ids), "fields": fields})
            raise KeyError()

    rows = [_row(3, "Tesla_a.pdf"), _row(2, "Tesla_b.pdf"), _row(1, "Tesla_c.pdf")]
    client = _SilentFailure(rows=rows)
    answer = server.search_documents(_Ctx(client), ["Tesla"])
    assert answer["success"] is True and answer["count"] == 3
    assert answer["snippet_error"]
    assert len(client.read_calls) == 1


def test_filters_reach_the_domain(server):
    client = _SearchClient(rows=[])
    server.search_documents(
        _Ctx(client), ["Tesla"], res_model="account.move", res_id=7,
        mimetype="pdf", created_from="2026-01-01",
    )
    domain = client.search_calls[0]["domain"]
    assert ["res_model", "=", "account.move"] in domain
    assert ["res_id", "=", 7] in domain
    assert ["mimetype", "=", "application/pdf"] in domain
    assert ["create_date", ">=", "2026-01-01 00:00:00"] in domain


@pytest.mark.parametrize(
    "kwargs, reason",
    [
        ({"keywords": ["a"]}, "keyword_too_short"),
        ({"keywords": ["Tesla"], "search_in": "everywhere"}, "invalid_search_in"),
        ({"keywords": ["Tesla"], "res_id": 7}, "res_id_without_model"),
        ({"keywords": ["Tesla"], "mimetype": "pdf%"}, "invalid_mimetype"),
        ({"keywords": ["Tesla"], "created_to": "gestern"}, "invalid_date"),
    ],
)
def test_input_errors_are_diagnosed_before_any_rpc(server, kwargs, reason):
    client = _SearchClient(rows=[])
    answer = server.search_documents(_Ctx(client), **kwargs)
    assert answer["success"] is False
    assert answer["error_type"] == "request" and answer["retryable"] is False
    assert answer["reason_code"] == reason
    assert answer["error_details"]["reason_code"] == reason
    assert client.search_calls == []


def test_keyword_named_timeout_is_not_a_transport_error(server):
    # The message quotes the input; the word "timeout" in it must not turn a
    # diagnosed input error into a retryable transport failure.
    answer = server.search_documents(
        _Ctx(_SearchClient()), ["Tesla"], mimetype="timeout",
    )
    assert "timeout" in answer["error"]
    assert answer["error_type"] == "request" and answer["retryable"] is False


def test_limit_and_snippet_chars_are_capped(server):
    rows = [_row(100 - i, f"Tesla_{i}.pdf") for i in range(40)]
    client = _SearchClient(rows=rows, texts={100: "Tesla " + "wort " * 500})
    answer = server.search_documents(
        _Ctx(client), ["Tesla"], limit=1000, snippet_chars=100_000,
    )
    assert answer["limit"] == ds.PAGE_MAX and answer["count"] == ds.PAGE_MAX
    snippet = answer["result"][0]["snippets"][0]
    assert len(snippet) <= ds.SNIPPET_CHARS_MAX + 2 * ds.SNIPPET_WORD_SLACK + 20


def test_invalid_model_filter_is_refused(server):
    answer = server.search_documents(
        _Ctx(_SearchClient()), ["Tesla"], res_model="account.move; drop",
    )
    assert answer["success"] is False


# ----- surface: schema, description, cross references ----------------------


def _tools(server):
    return {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}


def test_tool_is_registered_read_only_with_a_keyword_array(server):
    tool = _tools(server)["search_documents"]
    assert tool.annotations.readOnlyHint is True
    schema = tool.inputSchema
    assert schema["required"] == ["keywords"]
    variants = schema["properties"]["keywords"]["anyOf"]
    assert {"type": "array", "items": {"type": "string"}} in variants
    assert tool.outputSchema is not None


def test_description_teaches_the_narrow_search(server):
    description = _tools(server)["search_documents"].description
    for marker in (
        "ONE generic word",
        "2-4 keywords",
        "[\"Tesla\", \"Zulassung\"]",
        "ALL keywords must occur",
        "substring",
        "file names have no spaces",
        "add a keyword, do not page",
        "keyword_counts",
        "get_document_text",
        "read_attachment",
        "create_attachment_download",
    ):
        assert marker in description


def test_neighbour_tools_point_to_the_document_search(server):
    tools = _tools(server)
    assert "search_documents" in tools["search_records"].description
    # ilike is a pattern match, not a literal one: only search_documents
    # escapes '%' and '_'.
    assert "ONE contiguous pattern" in tools["search_records"].description
    assert "are wildcards" in tools["search_records"].description
    assert "literal substring" not in tools["search_records"].description
    assert "search_documents" in tools["get_document_text"].description
    assert "search_records('ir.attachment'" not in tools["get_document_text"].description
    assert "search_documents" in tools["read_attachment"].description


class _AttachmentListClient:
    def get_model_fields(self, model):
        return {
            "id": {"type": "integer"},
            "name": {"type": "char"},
            "index_content": {"type": "text"},
            "res_model": {"type": "char"},
            "res_id": {"type": "many2one_reference"},
        }

    def search_read(self, model_name, domain, fields=None, **kwargs):
        return [{"id": 1, "name": "scan.pdf"}]

    def execute_method(self, model, method, *args, **kwargs):
        raise AssertionError(f"unexpected {model}.{method}")


def test_search_records_points_text_searches_on_attachments_to_the_tool(server):
    client = _AttachmentListClient()
    answer = server.search_records(
        _Ctx(client), "ir.attachment",
        domain=[["index_content", "ilike", "Tesla"]], fields=["id", "name"],
    )
    assert "search_documents" in answer["hint"]


def test_search_records_keeps_quiet_for_a_plain_attachment_listing(server):
    client = _AttachmentListClient()
    answer = server.search_records(
        _Ctx(client), "ir.attachment",
        domain=[["res_model", "=", "sale.order"], ["res_id", "=", 5]],
        fields=["id", "name"],
    )
    assert "hint" not in answer
