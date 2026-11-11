"""Keyword search over Odoo attachments (NESA Patch 10, 2026-11-11).

Pure helpers for the ``search_documents`` tool: no Odoo client, no FastMCP.

Why a dedicated tool: well over 100,000 attachments carry several thousand
characters of indexed text each.  The database answers an ``ilike`` in about
half a second, so the cost of a document search is never the query — it is
the agent reading through hundreds of hits for a single generic word, opening
candidates one by one, and running the search again.  These helpers make the
narrow search the easy one: several keywords are AND-combined, identical files
attached to many records collapse into one hit, file-name matches rank first,
and each hit carries a short text snippet around the match.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

MAX_KEYWORDS = 6
MIN_KEYWORD_CHARS = 2
MAX_KEYWORD_CHARS = 80

# Metadata rows fetched per search (newest first).  They are deduplicated and
# ranked in memory; a search that matches more than this is too broad to be
# read through anyway, and the answer says so instead of paging blindly.
CANDIDATE_WINDOW = 300

PAGE_DEFAULT = 10
PAGE_MAX = 25

SNIPPET_CHARS_DEFAULT = 160
SNIPPET_CHARS_MIN = 40
SNIPPET_CHARS_MAX = 400
MAX_SNIPPETS_PER_HIT = 3
# A snippet may grow by this many characters per side to end on a word.
SNIPPET_WORD_SLACK = 12

# Odoo cannot return a substring of index_content over RPC, so a snippet costs
# the transfer of the whole text of that file.  Two bounds keep that small:
#
# 1. For text-like files the file size IS the text size, known before the
#    read.  Above this size the text is not pulled (bank statement XML, CSV
#    exports: up to several MB per file).  For every other type the file size
#    says nothing about the text: a 5 MB scan carries 3,000 OCR characters, a
#    400 kB photo a few hundred.
SNIPPET_SOURCE_MAX_BYTES = 300_000
TEXT_LIKE_MIMETYPES = frozenset({
    "application/xml",
    "application/json",
    "application/csv",
    "application/x-ndjson",
})
# 2. Texts are read one file at a time, best hit first, until this many
#    characters have been transferred for one search; the remaining hits are
#    listed without snippet.  The worst case is therefore this budget plus one
#    oversized text — the same single-file read get_document_text does —
#    instead of a page of 25 full texts in one answer.
SNIPPET_TEXT_BUDGET_CHARS = 1_000_000

SNIPPET_SKIPPED_LARGE = "large text file: read it with get_document_text"
SNIPPET_SKIPPED_BUDGET = (
    "text budget of this search used up by earlier hits: read it with "
    "get_document_text"
)

# From this many matching attachments on the answer tells the agent to narrow
# the search instead of reading on.
BROAD_MATCH_THRESHOLD = 25

# Other records the same file is attached to, listed per hit.
MAX_LISTED_COPIES = 5

SCOPE_NAME_AND_TEXT = "name_and_text"
SCOPE_NAME = "name"
SCOPE_TEXT = "text"
SEARCH_SCOPES = (SCOPE_NAME_AND_TEXT, SCOPE_NAME, SCOPE_TEXT)

CANDIDATE_FIELDS = [
    "id",
    "name",
    "mimetype",
    "file_size",
    "res_model",
    "res_id",
    "create_date",
    "checksum",
]

MIMETYPE_ALIASES = {
    "pdf": "application/pdf",
    "image": "image/",
    "images": "image/",
    "text": "text/",
}

KEYWORDS_SCHEMA: Dict[str, Any] = {
    "type": "array",
    "items": {"type": "string", "minLength": MIN_KEYWORD_CHARS, "maxLength": MAX_KEYWORD_CHARS},
    "minItems": 1,
    "maxItems": MAX_KEYWORDS,
    "description": (
        "Separate keywords that must all occur, e.g. [\"Tesla\", \"Zulassung\"]."
    ),
}

_WHITESPACE_RE = re.compile(r"\s+")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MIMETYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+\-]*/[A-Za-z0-9.+\-]*$")


class DocumentSearchInputError(ValueError):
    """A locally diagnosed input error of ``search_documents``."""

    def __init__(
        self, message: str, *, reason_code: str, invalid_parameter: str,
        expected_schema: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.details: Dict[str, Any] = {
            "reason_code": reason_code,
            "invalid_parameter": invalid_parameter,
        }
        if expected_schema is not None:
            self.details["expected_schema"] = expected_schema


def normalize_keywords(keywords: Any) -> List[str]:
    """Return the cleaned keyword list or raise a diagnosed input error.

    A list is taken as given: each element is one keyword, and an element with
    a space stays one literal phrase.  A bare string is the search-box habit
    ("Tesla Zulassung") and is split at whitespace, because as one phrase it
    would match almost nothing — file names carry no spaces at all.
    """
    if isinstance(keywords, str):
        raw: List[Any] = keywords.split()
    elif isinstance(keywords, (list, tuple)):
        raw = list(keywords)
    else:
        raise DocumentSearchInputError(
            "keywords must be a list of strings.",
            reason_code="invalid_keywords", invalid_parameter="keywords",
            expected_schema=KEYWORDS_SCHEMA,
        )
    cleaned: List[str] = []
    seen = set()
    for item in raw:
        if not isinstance(item, str):
            raise DocumentSearchInputError(
                f"Every keyword must be a string, got {type(item).__name__}.",
                reason_code="invalid_keywords", invalid_parameter="keywords",
                expected_schema=KEYWORDS_SCHEMA,
            )
        keyword = _WHITESPACE_RE.sub(" ", item).strip()
        if not keyword:
            continue
        if len(keyword) < MIN_KEYWORD_CHARS:
            raise DocumentSearchInputError(
                f"Keyword {keyword!r} is too short: a keyword needs at least "
                f"{MIN_KEYWORD_CHARS} characters, otherwise it matches nearly "
                "every document.",
                reason_code="keyword_too_short", invalid_parameter="keywords",
                expected_schema=KEYWORDS_SCHEMA,
            )
        if len(keyword) > MAX_KEYWORD_CHARS:
            raise DocumentSearchInputError(
                f"A keyword has {len(keyword)} characters (maximum "
                f"{MAX_KEYWORD_CHARS}). Pass single words or short phrases, "
                "not a sentence.",
                reason_code="keyword_too_long", invalid_parameter="keywords",
                expected_schema=KEYWORDS_SCHEMA,
            )
        key = keyword.casefold()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(keyword)
    if not cleaned:
        raise DocumentSearchInputError(
            "At least one keyword is required.",
            reason_code="keywords_missing", invalid_parameter="keywords",
            expected_schema=KEYWORDS_SCHEMA,
        )
    if len(cleaned) > MAX_KEYWORDS:
        raise DocumentSearchInputError(
            f"{len(cleaned)} keywords given, at most {MAX_KEYWORDS} are "
            "searched. Keep the terms that identify the document: subject, "
            "document type, sender, year, reference number.",
            reason_code="too_many_keywords", invalid_parameter="keywords",
            expected_schema=KEYWORDS_SCHEMA,
        )
    return cleaned


def escape_like(term: str) -> str:
    """Escape LIKE wildcards so a keyword is matched literally.

    Odoo wraps the value of ``ilike`` in ``%...%`` and passes it on unescaped;
    PostgreSQL's default LIKE escape character is the backslash.  Without this
    an underscore in ``TGZ_61488`` would match any character.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def normalize_scope(search_in: Any) -> str:
    if search_in in SEARCH_SCOPES:
        return search_in
    raise DocumentSearchInputError(
        f"search_in must be one of {', '.join(SEARCH_SCOPES)}.",
        reason_code="invalid_search_in", invalid_parameter="search_in",
        expected_schema={"type": "string", "enum": list(SEARCH_SCOPES)},
    )


def normalize_mimetype(mimetype: Optional[str]) -> Optional[str]:
    """Return an exact MIME type, a ``type/`` prefix, or None for no filter."""
    if mimetype is None:
        return None
    if not isinstance(mimetype, str):
        raise DocumentSearchInputError(
            "mimetype must be a string.",
            reason_code="invalid_mimetype", invalid_parameter="mimetype",
        )
    value = mimetype.strip().lower()
    if not value:
        return None
    value = MIMETYPE_ALIASES.get(value, value)
    if not _MIMETYPE_RE.match(value):
        raise DocumentSearchInputError(
            f"mimetype {mimetype!r} is not a MIME type. Use 'pdf', 'image', "
            "an exact type such as 'application/pdf', or a prefix such as "
            "'image/'.",
            reason_code="invalid_mimetype", invalid_parameter="mimetype",
            expected_schema={
                "type": "string",
                "examples": ["pdf", "image", "application/pdf", "image/"],
            },
        )
    return value


def normalize_date(value: Optional[str], parameter: str) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    if not isinstance(value, str) or not _DATE_RE.match(value.strip()):
        raise DocumentSearchInputError(
            f"{parameter} must be a date 'YYYY-MM-DD'.",
            reason_code="invalid_date", invalid_parameter=parameter,
            expected_schema={"type": "string", "format": "date"},
        )
    text = value.strip()
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        raise DocumentSearchInputError(
            f"{parameter} {text!r} is not a calendar date.",
            reason_code="invalid_date", invalid_parameter=parameter,
            expected_schema={"type": "string", "format": "date"},
        ) from None
    return text


def keyword_condition(keyword: str, scope: str) -> List[Any]:
    """Domain fragment (prefix notation) for one keyword."""
    pattern = escape_like(keyword)
    if scope == SCOPE_NAME:
        return [["name", "ilike", pattern]]
    if scope == SCOPE_TEXT:
        return [["index_content", "ilike", pattern]]
    return ["|", ["name", "ilike", pattern], ["index_content", "ilike", pattern]]


def filter_conditions(
    *, res_model: Optional[str] = None, res_id: Optional[int] = None,
    mimetype: Optional[str] = None, created_from: Optional[str] = None,
    created_to: Optional[str] = None,
) -> List[Any]:
    """Domain leaves for the optional filters (already normalized values)."""
    conditions: List[Any] = []
    if res_model:
        conditions.append(["res_model", "=", res_model])
    if res_id:
        conditions.append(["res_id", "=", res_id])
    if mimetype:
        if mimetype.endswith("/"):
            conditions.append(["mimetype", "=like", escape_like(mimetype) + "%"])
        else:
            conditions.append(["mimetype", "=", mimetype])
    if created_from:
        conditions.append(["create_date", ">=", f"{created_from} 00:00:00"])
    if created_to:
        conditions.append(["create_date", "<=", f"{created_to} 23:59:59"])
    return conditions


def build_domain(
    keywords: Sequence[str], scope: str, filters: Sequence[Any],
) -> List[Any]:
    """AND of all keyword conditions plus the filter leaves.

    The domain names neither ``id`` nor ``res_field``, so Odoo's
    ``ir.attachment._search`` adds ``res_field = False`` itself: files stored
    behind a binary field (avatars, product images) stay out, as in the UI.
    """
    domain: List[Any] = []
    for keyword in keywords:
        domain.extend(keyword_condition(keyword, scope))
    domain.extend(filters)
    return domain


def _contains(haystack: Any, keyword: str) -> bool:
    return isinstance(haystack, str) and keyword.casefold() in haystack.casefold()


def keywords_in_name(name: Any, keywords: Sequence[str]) -> List[str]:
    return [keyword for keyword in keywords if _contains(name, keyword)]


def group_and_rank(
    rows: Sequence[Dict[str, Any]], keywords: Sequence[str],
) -> List[Dict[str, Any]]:
    """Collapse identical files and rank the unique ones.

    The same scan is often attached to the task, the order and the invoice;
    those are one document, not three hits.  Files are identical when their
    checksum is; an attachment without checksum (URL type) stands alone.

    Rank: more keywords in the file name first (a file *named* after the
    search terms is almost always the document itself, a text-only match is
    often a passing mention), then newest.
    """
    groups: Dict[Any, Dict[str, Any]] = {}
    order: List[Any] = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        checksum = row.get("checksum")
        key = ("checksum", checksum) if isinstance(checksum, str) and checksum else ("id", row["id"])
        name_hits = keywords_in_name(row.get("name"), keywords)
        group = groups.get(key)
        if group is None:
            groups[key] = {"row": row, "name_hits": name_hits, "copies": []}
            order.append(key)
            continue
        current = group["row"]
        better = (len(name_hits), row["id"]) > (len(group["name_hits"]), current["id"])
        if better:
            group["copies"].append(current)
            group["row"] = row
            group["name_hits"] = name_hits
        else:
            group["copies"].append(row)
    ranked = [groups[key] for key in order]
    ranked.sort(key=lambda group: (-len(group["name_hits"]), -group["row"]["id"]))
    return ranked


def snippet_source_allowed(row: Dict[str, Any]) -> bool:
    """Whether ``index_content`` of this attachment is read for a snippet.

    Only text-like files are refused by size, because only there the file
    size bounds the text.  A large image or PDF usually has little text.
    """
    mimetype = str(row.get("mimetype") or "").lower()
    text_like = mimetype.startswith("text/") or mimetype in TEXT_LIKE_MIMETYPES
    if not text_like:
        return True
    file_size = row.get("file_size")
    if (
        isinstance(file_size, int) and not isinstance(file_size, bool)
        and file_size > SNIPPET_SOURCE_MAX_BYTES
    ):
        return False
    return True


def clamp_snippet_chars(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DocumentSearchInputError(
            "snippet_chars must be an integer.",
            reason_code="invalid_snippet_chars", invalid_parameter="snippet_chars",
        )
    return max(SNIPPET_CHARS_MIN, min(value, SNIPPET_CHARS_MAX))


def _word_start(text: str, position: int) -> int:
    """Move left to the start of the word, at most SNIPPET_WORD_SLACK chars."""
    floor = max(0, position - SNIPPET_WORD_SLACK)
    cursor = position
    while cursor > floor and not text[cursor - 1].isspace():
        cursor -= 1
    if cursor == floor and cursor > 0 and not text[cursor - 1].isspace():
        return position
    return cursor


def _word_end(text: str, position: int) -> int:
    """Move right to the end of the word, at most SNIPPET_WORD_SLACK chars."""
    ceiling = min(len(text), position + SNIPPET_WORD_SLACK)
    cursor = position
    while cursor < ceiling and not text[cursor].isspace():
        cursor += 1
    if cursor == ceiling and cursor < len(text) and not text[cursor].isspace():
        return position
    return cursor


def extract_snippets(
    text: Any, keywords: Sequence[str], snippet_chars: int = SNIPPET_CHARS_DEFAULT,
    max_snippets: int = MAX_SNIPPETS_PER_HIT,
) -> Tuple[List[str], List[str]]:
    """Return ``(snippets, keywords_found_in_text)`` for one document text.

    One window around the first occurrence of each keyword; windows that touch
    are merged, so two keywords in the same sentence yield one snippet.  Runs
    of whitespace (OCR line breaks) collapse to one space.
    """
    if not isinstance(text, str) or not text:
        return [], []
    half = max(snippet_chars // 2, 1)
    windows: List[List[int]] = []
    found: List[str] = []
    for keyword in keywords:
        match = re.search(re.escape(keyword), text, re.IGNORECASE)
        if match is None:
            continue
        found.append(keyword)
        start = _word_start(text, max(0, match.start() - half))
        end = _word_end(text, min(len(text), match.end() + half))
        windows.append([start, end])
    if not windows:
        return [], []
    windows.sort()
    merged: List[List[int]] = [windows[0]]
    for start, end in windows[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    snippets: List[str] = []
    for start, end in merged[:max_snippets]:
        body = _WHITESPACE_RE.sub(" ", text[start:end]).strip()
        if not body:
            continue
        prefix = "…" if start > 0 else ""
        suffix = "…" if end < len(text) else ""
        snippets.append(f"{prefix}{body}{suffix}")
    return snippets, found


def build_hit(
    group: Dict[str, Any], keywords: Sequence[str], *, text: Any = None,
    text_available: bool = False, snippet_chars: int = SNIPPET_CHARS_DEFAULT,
) -> Dict[str, Any]:
    """Shape one ranked group into the answer row the agent reads."""
    row = group["row"]
    hit: Dict[str, Any] = {
        "attachment_id": row["id"],
        "name": row.get("name"),
        "mimetype": row.get("mimetype"),
        "file_size": row.get("file_size"),
        "create_date": row.get("create_date"),
        "attached_to": {
            "model": row.get("res_model") or None,
            "res_id": row.get("res_id") or None,
        },
        "keywords_in_name": list(group["name_hits"]),
    }
    if text_available:
        content = text if isinstance(text, str) else ""
        snippets, text_hits = extract_snippets(content, keywords, snippet_chars)
        hit["keywords_in_text"] = text_hits
        hit["text_chars"] = len(content)
        if snippets:
            hit["snippets"] = snippets
    copies = group["copies"]
    if copies:
        hit["copies"] = len(copies) + 1
        hit["also_attached_to"] = [
            {
                "attachment_id": copy["id"],
                "model": copy.get("res_model") or None,
                "res_id": copy.get("res_id") or None,
            }
            for copy in copies[:MAX_LISTED_COPIES]
        ]
    return hit


_NARROW_ADVICE = (
    "add a keyword that only the wanted document has — the document type "
    "(Rechnung, Angebot, Bescheid, Vertrag, Lieferschein), the sender, a "
    "year or month as written in file names ('2025' or '2025-03'), or a "
    "reference/invoice number — or set res_model or mimetype"
)


def broad_result_hint(
    match_count: Optional[int], keywords: Sequence[str], window_truncated: bool,
) -> Optional[str]:
    """Tell the agent to narrow instead of reading on, when that is the case.

    ``match_count`` is the number of different files when the whole result was
    ranked, and the number of matching attachments when it was not.
    """
    if match_count is None:
        return None
    if match_count < BROAD_MATCH_THRESHOLD and not window_truncated:
        return None
    lead = f"{match_count} {'attachments' if window_truncated else 'different files'} match"
    if len(keywords) == 1:
        lead += f" the single keyword {keywords[0]!r}"
    hint = f"{lead}: too many to read through. Do not page; {_NARROW_ADVICE}."
    if window_truncated:
        hint += (
            f" Only the newest {CANDIDATE_WINDOW} matches were ranked, older "
            "ones are not in this result."
        )
    return hint


def empty_result_hint(
    keywords: Sequence[str], keyword_counts: Optional[Dict[str, Optional[int]]],
    has_filters: bool, scope: str,
) -> str:
    """Say what to change after a search without hits."""
    parts: List[str] = []
    phrases = [keyword for keyword in keywords if " " in keyword]
    if len(keywords) > 1:
        parts.append("No document contains all keywords.")
        if keyword_counts:
            dead = [k for k in keywords if keyword_counts.get(k) == 0]
            # A failed count is None: unknown, never "has hits".
            unknown = [
                k for k in keywords
                if not isinstance(keyword_counts.get(k), int)
                or isinstance(keyword_counts.get(k), bool)
            ]
            if dead:
                parts.append(
                    "Alone without any hit: "
                    + ", ".join(repr(k) for k in dead)
                    + " — respell or drop exactly these (OCR text has typos; "
                    "a word stem such as 'Zulassung' also finds "
                    "'Zulassungsbescheinigung')."
                )
            elif not unknown:
                parts.append(
                    "Each keyword has hits on its own (keyword_counts), they "
                    "just never meet in one document: drop the least certain "
                    "one."
                )
            if unknown:
                parts.append(
                    "Could not be counted alone (keyword_counts null, not "
                    "zero): " + ", ".join(repr(k) for k in unknown) + "."
                )
    else:
        parts.append(
            f"No document contains {keywords[0]!r}. Try a shorter word stem "
            "or another spelling (OCR text has typos, umlauts may be written "
            "ae/oe/ue)."
        )
    if phrases:
        parts.append(
            "Keywords with a space are searched as one literal phrase ("
            + ", ".join(repr(k) for k in phrases)
            + "); file names contain no spaces, so pass the words separately."
        )
    if scope != SCOPE_NAME_AND_TEXT:
        parts.append(f"search_in={scope!r} was set; the default searches name and text.")
    if has_filters:
        parts.append("Filters (res_model, res_id, mimetype, dates) were set; try without them.")
    parts.append(
        "Only files the user may read are searched, and photos or scans "
        "without OCR have no text. A file can also be reached through its "
        "record: search_records on ir.attachment with res_model and res_id."
    )
    return " ".join(parts)
