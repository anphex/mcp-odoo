"""
MCP server for Odoo integration

Provides MCP tools and resources for interacting with Odoo ERP systems
"""

import base64
import hashlib
import json
import logging
import os
import re
import threading
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, AsyncIterator, Callable, Dict, List, Optional, Union

from mcp.server.fastmcp import Context, FastMCP, Image
from mcp.types import Annotations, ToolAnnotations
from pydantic import BaseModel, Field

from .agent_tools import (
    DEFAULT_MAX_SMART_FIELDS,
    build_approval_token,
    build_domain_report,
    build_write_preview_report,
    business_pack_report as build_business_pack_report,
    scan_addons_source_report,
    select_smart_fields,
    validate_write_report,
    verify_write_approval,
)
from .diagnostics import (
    DESTRUCTIVE_METHODS,
    classify_method_safety,
    diagnose_odoo_call_report,
    fit_gap_report as build_fit_gap_report,
    generate_json2_payload_report,
    inspect_model_relationships_report,
    sanitize_odoo_error,
    upgrade_risk_report as build_upgrade_risk_report,
)
from ._nesa_file_intake import FileIntakeError, fetch_allowlisted_url
from .odoo_client import (
    FIELD_METADATA_RPC_ATTRIBUTES,
    OdooClient,
    get_odoo_client,
)

logger = logging.getLogger(__name__)

MODEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*$")
METHOD_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
MAX_SEARCH_LIMIT = 100
WRITE_APPROVAL_TTL_SECONDS = 10 * 60

# NESA A4: search_records without an explicit order used to inherit whatever
# order Postgres happened to return, which makes offset paging silently lossy
# (rows can repeat or disappear between pages).  Fall back to a total order.
#
# This makes paging deterministic, not transaction-safe: a record inserted or
# deleted between two pages still shifts every following offset, and the page
# and its total_count are read in separate RPC transactions.  For a snapshot,
# page by keyset (``id < last_id_of_previous_page``) instead.
DEFAULT_SEARCH_ORDER = "id desc"

# NESA A1: transient (wizard) records are scratch space that ir.autovacuum
# deletes; setting a search term on a wizard is not a business write.  Only
# these two ORM entry points are exempted — unlink and every write-equivalent
# alias stay on the approval chain even for transient models.
TRANSIENT_EXEMPT_METHODS = frozenset({"create", "write"})

# Reviewed wizards that may be filled in without the approval chain.  This is
# the positive authorizer and it is code-owned on purpose: a heuristic cannot
# prove that writing a record has no persistent effect, so a model earns its
# place here by having been read.  The deployment can add further exact
# ``model.method`` pairs through the side-effect allowlist (env or the
# ``nesa.mcp.allowed_method`` model) without touching this file.
TRANSIENT_EXEMPT_MODELS = frozenset({
    # Dealer product search: Char search term, Boolean, m2o to a product, and
    # a one2many whose comodel is itself transient.  No create/write override.
    "nesa.shk.product.match.wizard",
    "nesa.shk.product.match.wizard.result",
})

# NESA B1/B2: bounded text windows so a single OCR read cannot flood context.
DOC_TEXT_WINDOW_DEFAULT = 8000
DOC_TEXT_WINDOW_MAX = 40_000

# NESA B4: mirrors the cap in nesa_mcp_bridge.  Rendering is the most
# expensive path in the bridge — one QWeb render plus one wkhtmltopdf process
# per record — so an unbounded record list could tie up the Odoo workers.
MAX_REPORT_RECORDS = 20

# NESA B2/B3/B4: Odoo-side helper model (nesa_mcp_bridge).  Kept in one
# constant so a rename only has to happen here.
NESA_DOC_HELPER_MODEL = "nesa.mcp.doc.helper"

# Public ORM aliases that create or update records without spelling the
# operation as create/write.  They must use the same preview/validation path
# as direct CRUD instead of slipping through execute_method in parity mode.
#
# The list is derived from the public, RPC-reachable mutators on
# ``odoo.models.BaseModel`` — a method is reachable unless it is name-private
# or carries ``@api.private``.  ``update`` in particular reads like a helper
# but assigns fields one by one, and on a persisted recordset each assignment
# ends in ``write()``; ``toggle_active`` / ``action_archive`` /
# ``action_unarchive`` write ``active`` directly.  Every one of them would
# otherwise be a token-free write under native ACL parity.
WRITE_EQUIVALENT_METHODS = frozenset({
    "action_archive",
    "action_unarchive",
    "copy",
    "copy_data",
    "copy_multi",
    "copy_translations",
    "create_multi",
    "import_data",
    "load",
    "name_create",
    "toggle_active",
    "update",
    "update_field_translations",
    "web_override_translations",
    "web_save",
})

# These prefixes protect the bridge's own authorization, approval, audit and
# orchestration control plane.  They are deliberately code-owned so a missing
# or malformed deployment env var cannot make the agent self-authorizing.
NON_DELEGABLE_METHOD_PREFIXES = frozenset({
    "nesa.agent.definition.",
    "nesa.agent.mcp.server.",
    "nesa.agent.pending.action.",
    "nesa.agent.run.",
    "nesa.agent.runner.",
    "nesa.agent.skill.",
    "nesa.agent.tool.",
    "nesa.mcp.allowed_method.",
    "nesa.mcp.approval.token.",
    "nesa.mcp.audit_log.",
    "nesa.mcp.doc.helper.",
    "nesa.mcp.download.token.",
    "nesa.mcp.shadow.",
    # Der Upload-Token ist ein Schreibrecht auf Zeit. Ueber execute_method
    # koennte ein Agent sonst mcp_issue mit beliebigem TTL aufrufen und die
    # Obergrenzen von create_attachment_upload umgehen.
    "nesa.mcp.upload.token.",
})

AUDIT_SUPPRESSION_CONTEXT_KEYS = frozenset({
    "mail_create_nolog",
    "mail_notrack",
    "tracking_disable",
})


@dataclass
class AppContext:
    """Application context with lazy Odoo client access.

    NESA Patch 3 (2026-05-20): write_approvals wurde aus dem AppContext
    entfernt — Token-Store lebt jetzt in der Odoo-Tabelle
    nesa.mcp.approval.token. Grund: StreamableHTTPSessionManager spawnt
    pro Mcp-Session-Id einen eigenen app.run()-Aufruf mit eigener
    AppContext-Instanz. Die NESA-Bridge baut pro Tool-Call eine neue
    Client-Session auf (siehe nesa_mcp_bridge/services/mcp_proxy.py
    Lifetime-Kommentar) — Token aus validate_write war nicht in der
    AppContext-Instanz von execute_approved_write sichtbar.
    Sub-Agent-Smoke 2026-05-20 bestätigte das Verhalten.
    Helper-Funktionen register/require/revoke_write_approval rufen jetzt
    via app_context.odoo die Tabellen-Methoden mcp_register_approval /
    mcp_consume_approval / mcp_revoke_approval auf.
    """

    odoo_factory: Callable[[], OdooClient] = field(
        default_factory=lambda: get_odoo_client
    )
    _odoo: OdooClient | None = None
    schema_cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # NESA A1: ir.model.transient lookups per model name.  Cheap, but one
    # XML-RPC roundtrip per wizard call would defeat the point of the
    # exemption, so the answer is memoized for the lifespan.
    transient_cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def odoo(self) -> OdooClient:
        """Resolve the Odoo client only when a live Odoo tool needs it."""
        if self._odoo is None:
            self._odoo = self.odoo_factory()
        return self._odoo


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """
    Application lifespan for initialization and cleanup
    """
    yield AppContext()


# Create MCP server
SERVER_INSTRUCTIONS = (
    "Odoo 18 ERP of NESA Haustechnik, per-user: every call runs with the "
    "Odoo rights of the authenticated user.\n"
    "READ: name_search to turn a name into ids -> search_records (paged, "
    "total_count) -> read_record/read_records by id -> aggregate_records "
    "for counts/sums per group -> chatter_read for message history. Use "
    "get_model_fields before guessing a field "
    "name; list_models to find a model. Never use execute_method for "
    "plain reads.\n"
    "WRITE: validate_write -> execute_approved_write (preview_write is an "
    "optional dry run). execute_method runs business methods "
    "(action_confirm, action_done, ...); CRUD on persistent models is "
    "refused there. list_allowed_methods explains the policy instead of "
    "probing. A rejected approval token that was 'already consumed' means "
    "the write DID run: read the record back, do not repeat.\n"
    "FORMATS: domain = JSON list of [field, operator, value] triples, e.g. "
    "[[\"partner_id\", \"=\", 42], [\"state\", \"in\", [\"sale\", \"done\"]]]; "
    "prefix operators \"&\"/\"|\"/\"!\" are allowed. Dates are "
    "\"YYYY-MM-DD\", datetimes are naive UTC \"YYYY-MM-DD HH:MM:SS\" (the "
    "company runs on Europe/Berlin, so convert before comparing). many2one "
    "values come back as [id, display_name], x2many as id lists, empty "
    "values as false. Without 'fields' a curated subset is returned; "
    "fields=[\"*\"] returns every non-binary field. limit is capped at 100.\n"
    "ODOO 18 NAMES (not 17): project.task uses date_deadline (no "
    "planned_date_end), product cost is standard_price (no "
    "purchase_price), task effort is allocated_hours (no planned_hours), "
    "invoice payment reference is payment_reference. Legacy work "
    "reports are searched as 'TGZ-<nr>' in the task name, never as a bare "
    "number. bank.rec.widget is a UI widget and cannot be driven over RPC."
)

def _result_summary(result: Any) -> tuple[Optional[bool], Optional[int], int]:
    """(success, record_count, bytes) of a tool result as the agent sees it."""
    structured = _structured_of(result)
    size = 0
    blocks = result[0] if isinstance(result, tuple) else result
    if not isinstance(blocks, dict):
        # FastMCP already serialized the payload into text blocks; measuring
        # those costs nothing and is exactly what the agent receives.
        try:
            for block in blocks or []:
                text = getattr(block, "text", None)
                size += len(text.encode("utf-8")) if isinstance(text, str) else 0
        except TypeError:
            pass
    if isinstance(structured, dict):
        success = structured.get("success")
        count: Optional[int] = None
        for key in ("count", "row_count", "record_count"):
            value = structured.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                count = value
                break
        if count is None:
            payload = structured.get("result", structured.get("records"))
            if isinstance(payload, list):
                count = len(payload)
        if size == 0 and isinstance(result, dict):
            try:
                size = len(json.dumps(structured, default=str).encode("utf-8"))
            except Exception:  # noqa: BLE001 — a log line never fails the call
                size = -1
        return (success if isinstance(success, bool) else None), count, size
    return None, None, size


_LOG_FIELD_SAFE = re.compile(r"[^\w.@+\-]")


def _log_field(value: Any, limit: int = 80) -> str:
    """Whitelist a log field: no control characters, no line breaks."""
    text = _LOG_FIELD_SAFE.sub("_", str(value))[:limit]
    return text or "-"


def log_tool_call(
    tool: str, arguments: Dict[str, Any], result: Any, started: float,
    error_class: Optional[str],
) -> None:
    """One structured INFO line per tool call.

    The Odoo-side audit log only sees calls that go through the NESA bridge;
    the Claude.ai connector (the bulk of the traffic) was invisible.  This line
    carries what an operator needs to size and debug agent usage — never
    argument values, never the result itself.
    """
    from ._nesa_per_user_auth import current_user_context

    user_context = current_user_context()
    login = user_context[0] if user_context else "<service-account>"
    success, count, size = _result_summary(result)
    model = arguments.get("model") if isinstance(arguments, dict) else None
    if success is False and isinstance(structured := _structured_of(result), dict):
        error_class = error_class or str(structured.get("error_type") or "tool_error")
    logger.info(
        "[mcp_call] tool=%s login=%s model=%s ok=%s n=%s bytes=%s ms=%d error=%s",
        _log_field(tool),
        _log_field(login),
        _log_field(model) if model else "-",
        "-" if success is None else str(success).lower(),
        "-" if count is None else count,
        size,
        int((time.perf_counter() - started) * 1000),
        _log_field(error_class) if error_class else "-",
    )


def _structured_of(result: Any) -> Any:
    """The tool's own response dict out of what FastMCP.call_tool returned.

    Tools annotated ``Dict[str, Any]`` get ``wrap_output=True`` in the SDK, so
    the structured half is ``{"result": <our dict>}``; unwrap that layer.
    """
    structured = result[1] if isinstance(result, tuple) and len(result) == 2 else result
    if not isinstance(structured, dict):
        return None
    inner = structured.get("result")
    if set(structured) == {"result"} and isinstance(inner, dict):
        return inner
    return structured


class NesaFastMCP(FastMCP):
    """FastMCP with a per-call log line (see ``log_tool_call``)."""

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        started = time.perf_counter()
        result: Any = None
        error_class: Optional[str] = None
        try:
            result = await super().call_tool(name, arguments)
            return result
        except BaseException as exc:
            error_class = type(exc).__name__
            raise
        finally:
            try:
                log_tool_call(name, arguments, result, started, error_class)
            except Exception:  # noqa: BLE001 — logging must never break a call
                logger.debug("[mcp_call] log line failed", exc_info=True)


mcp = NesaFastMCP(
    "Odoo MCP Server",
    instructions=SERVER_INSTRUCTIONS,
    dependencies=["requests"],
    lifespan=app_lifespan,
)

READ_ONLY_TOOL = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
PREVIEW_TOOL = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)
DESTRUCTIVE_TOOL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
# Neither read-only nor destructive: these tools leave a short-lived artefact
# behind (a download token, a temporary PDF attachment) without touching a
# business record.  Saying "read-only" would be a promise the tool breaks.
SIDE_EFFECT_TOOL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
RESOURCE_HINT = Annotations(audience=["assistant"], priority=0.8)


# ----- MCP Resources -----


@mcp.resource(
    "odoo://models",
    description="List all available models in the Odoo system",
    mime_type="application/json",
    annotations=RESOURCE_HINT,
)
def get_models() -> str:
    """Lists all available models in the Odoo system"""
    odoo_client = get_odoo_client()
    models = odoo_client.get_models()
    return json.dumps(models, indent=2)


@mcp.resource(
    "odoo://model/{model_name}",
    description="Get detailed information about a specific model including fields",
    mime_type="application/json",
    annotations=RESOURCE_HINT,
)
def get_model_info(model_name: str) -> str:
    """
    Get information about a specific model

    Parameters:
        model_name: Name of the Odoo model (e.g., 'res.partner')
    """
    odoo_client = get_odoo_client()
    try:
        validate_model_name(model_name)
        # Get model info
        model_info = odoo_client.get_model_info(model_name)

        # Get field definitions
        fields = odoo_client.get_model_fields(model_name)
        model_info["fields"] = fields

        return json.dumps(model_info, indent=2)
    except Exception as e:
        return json.dumps({"error": compact_error_message(e)[0]}, indent=2)


@mcp.resource(
    "odoo://record/{model_name}/{record_id}",
    description="Get detailed information of a specific record by ID",
    mime_type="application/json",
    annotations=RESOURCE_HINT,
)
def get_record(model_name: str, record_id: str) -> str:
    """
    Get a specific record by ID

    Parameters:
        model_name: Name of the Odoo model (e.g., 'res.partner')
        record_id: ID of the record
    """
    odoo_client = get_odoo_client()
    try:
        validate_model_name(model_name)
        record_id_int = int(record_id)
        if record_id_int < 1:
            raise ValueError("record_id must be greater than 0")
        record = odoo_client.read_records(model_name, [record_id_int])
        if not record:
            return json.dumps(
                {"error": f"Record not found: {model_name} ID {record_id}"}, indent=2
            )
        return json.dumps(record[0], indent=2)
    except Exception as e:
        return json.dumps({"error": compact_error_message(e)[0]}, indent=2)


@mcp.resource(
    "odoo://search/{model_name}/{domain}",
    description="Search for records matching the domain",
    mime_type="application/json",
    annotations=RESOURCE_HINT,
)
def search_records_resource(model_name: str, domain: str) -> str:
    """
    Search for records that match a domain

    Parameters:
        model_name: Name of the Odoo model (e.g., 'res.partner')
        domain: Search domain in JSON format (e.g., '[["name", "ilike", "test"]]')
    """
    odoo_client = get_odoo_client()
    try:
        validate_model_name(model_name)
        # Parse domain from JSON string
        domain_list = json.loads(domain)
        if not isinstance(domain_list, list):
            raise ValueError("domain must decode to an Odoo domain list")

        # Set a reasonable default limit
        limit = 10

        # Perform search_read for efficiency
        results = odoo_client.search_read(model_name, domain_list, limit=limit)

        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": compact_error_message(e)[0]}, indent=2)


# ----- Pydantic models for type safety -----


class DomainCondition(BaseModel):
    """A single condition in a search domain"""

    field: str = Field(description="Field name to search")
    operator: str = Field(
        description="Operator (e.g., '=', '!=', '>', '<', 'in', 'not in', 'like', 'ilike')"
    )
    value: Any = Field(description="Value to compare against")

    def to_tuple(self) -> List:
        """Convert to Odoo domain condition tuple"""
        return [self.field, self.operator, self.value]


class SearchDomain(BaseModel):
    """Search domain for Odoo models"""

    conditions: List[DomainCondition] = Field(
        default_factory=list,
        description="List of conditions for searching. All conditions are combined with AND operator.",
    )

    def to_domain_list(self) -> List[List]:
        """Convert to Odoo domain list format"""
        return [condition.to_tuple() for condition in self.conditions]


class EmployeeSearchResult(BaseModel):
    """Represents a single employee search result."""

    id: int = Field(description="Employee ID")
    name: str = Field(description="Employee name")


class SearchEmployeeResponse(BaseModel):
    """Response model for the search_employee tool."""

    success: bool = Field(description="Indicates if the search was successful")
    result: Optional[List[EmployeeSearchResult]] = Field(
        default=None, description="List of employee search results"
    )
    error: Optional[str] = Field(default=None, description="Error message, if any")


class Holiday(BaseModel):
    """Represents a single holiday."""

    display_name: str = Field(description="Display name of the holiday")
    start_datetime: str = Field(description="Start date and time of the holiday")
    stop_datetime: str = Field(description="End date and time of the holiday")
    employee_id: List[Union[int, str]] = Field(
        description="Employee ID associated with the holiday"
    )
    name: str = Field(description="Name of the holiday")
    state: str = Field(description="State of the holiday")


class SearchHolidaysResponse(BaseModel):
    """Response model for the search_holidays tool."""

    success: bool = Field(description="Indicates if the search was successful")
    result: Optional[List[Holiday]] = Field(
        default=None, description="List of holidays found"
    )
    error: Optional[str] = Field(default=None, description="Error message, if any")


def validate_model_name(model_name: str) -> None:
    """Reject obviously unsafe model names before forwarding to Odoo."""
    if not MODEL_NAME_RE.fullmatch(model_name):
        raise ValueError(
            "Invalid model name. Use Odoo technical model names like 'res.partner'."
        )


def validate_method_name(method_name: str) -> None:
    """Reject obviously unsafe method names before forwarding to Odoo."""
    if not METHOD_NAME_RE.fullmatch(method_name):
        raise ValueError(
            "Invalid method name. Use Odoo method names like 'search_read'."
        )


def clamp_limit(limit: int, maximum: int = MAX_SEARCH_LIMIT) -> int:
    """Keep read-only tools bounded for agent safety."""
    if limit < 1:
        raise ValueError("limit must be greater than 0")
    return min(limit, maximum)


def max_smart_fields() -> int:
    """Read configured cap for smart-field selection (default 15)."""
    raw = os.environ.get("ODOO_MCP_MAX_SMART_FIELDS", "").strip()
    if not raw:
        return DEFAULT_MAX_SMART_FIELDS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_SMART_FIELDS
    return max(1, value)


DEFAULT_SCHEMA_CACHE_TTL_SECONDS = 900
SCHEMA_CACHE_MAX_ENTRIES = 500
_PROCESS_SCHEMA_CACHE: Dict[str, tuple[float, Any]] = {}
_PROCESS_SCHEMA_CACHE_LOCK = threading.Lock()


def schema_cache_ttl_seconds() -> float:
    """TTL of the process-wide schema cache (``ODOO_MCP_SCHEMA_CACHE_TTL``).

    The NESA bridge opens a fresh MCP session — and with it a fresh
    ``AppContext`` — for every tool call, so a per-session cache never hits:
    each call without ``fields`` paid a full ``fields_get`` (hundreds of KB on
    account.move) and every ``list_models`` re-read 900+ models.  Metadata
    changes only on module upgrades, so a few minutes of staleness is safe.
    ``0`` disables the process cache.
    """
    raw = os.environ.get("ODOO_MCP_SCHEMA_CACHE_TTL", "").strip()
    if not raw:
        return DEFAULT_SCHEMA_CACHE_TTL_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_SCHEMA_CACHE_TTL_SECONDS


def process_cache_get(key: str) -> Any:
    """Return a live process-cache entry or ``None``.

    Entries are shared between sessions of the same principal: treat them as
    read-only, never mutate in place.
    """
    ttl = schema_cache_ttl_seconds()
    if ttl <= 0:
        return None
    with _PROCESS_SCHEMA_CACHE_LOCK:
        entry = _PROCESS_SCHEMA_CACHE.get(key)
        if entry is None:
            return None
        stored_at, value = entry
        if time.monotonic() - stored_at > ttl:
            _PROCESS_SCHEMA_CACHE.pop(key, None)
            return None
        return value


def process_cache_set(key: str, value: Any) -> None:
    """Store ``value`` under ``key``; oldest entries go first when full."""
    if schema_cache_ttl_seconds() <= 0:
        return
    with _PROCESS_SCHEMA_CACHE_LOCK:
        if key not in _PROCESS_SCHEMA_CACHE and len(_PROCESS_SCHEMA_CACHE) >= SCHEMA_CACHE_MAX_ENTRIES:
            oldest = sorted(_PROCESS_SCHEMA_CACHE.items(), key=lambda kv: kv[1][0])
            for stale_key, _ in oldest[: max(1, SCHEMA_CACHE_MAX_ENTRIES // 10)]:
                _PROCESS_SCHEMA_CACHE.pop(stale_key, None)
        _PROCESS_SCHEMA_CACHE[key] = (time.monotonic(), value)


def process_cache_clear() -> None:
    with _PROCESS_SCHEMA_CACHE_LOCK:
        _PROCESS_SCHEMA_CACHE.clear()


def _user_scope_key() -> str:
    """``login:digest`` of the acting user, or ``service`` — never the key."""
    from ._nesa_per_user_auth import current_user_context

    context = current_user_context()
    if not context:
        return "service"
    login, api_key = context
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return f"{login}:{digest}"


def _models_cache_key() -> str:
    return f"models:{_user_scope_key()}"


def _cached_models(app_context: AppContext, odoo: OdooClient) -> Dict[str, Any]:
    """``get_models()`` through the process cache (user-scoped key)."""
    cache_key = _models_cache_key()
    cached = process_cache_get(cache_key)
    if isinstance(cached, dict):
        return cached
    models = odoo.get_models()
    if isinstance(models, dict) and "error" not in models:
        process_cache_set(cache_key, models)
    return models


def _fields_cache_key(model: str) -> str:
    """Cache key for ``fields_get`` metadata, scoped to the requesting user.

    ``fields_get`` omits fields the calling user may not see (``groups=``), so
    a single entry per model would let whoever warms the cache first decide
    what every later caller is allowed to name — a restricted user would hide
    a manager's field, and the suggestions in an error message would show a
    restricted user names they never had access to (NESA).  The API key only
    ever enters the key as a digest.
    """
    from ._nesa_per_user_auth import current_user_context

    context = current_user_context()
    if not context:
        return f"fields:service:{model}"
    login, api_key = context
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return f"fields:{login}:{digest}:{model}"


def _cached_fields_metadata(
    app_context: AppContext, odoo: OdooClient, model: str, *, refresh: bool = False
) -> Dict[str, Any]:
    """Return fields_get metadata for ``model`` using the lifespan cache."""
    cache_key = _fields_cache_key(model)
    if not refresh:
        cached = app_context.schema_cache.get(cache_key)
        if isinstance(cached, dict):
            return cached
        shared = process_cache_get(cache_key)
        if isinstance(shared, dict):
            app_context.schema_cache[cache_key] = shared
            return shared
    fields_metadata = odoo.get_model_fields(model)
    if isinstance(fields_metadata, dict) and "error" not in fields_metadata:
        app_context.schema_cache[cache_key] = fields_metadata
        process_cache_set(cache_key, fields_metadata)
        return fields_metadata
    if isinstance(fields_metadata, dict) and "error" in fields_metadata:
        # Kept for the caller that wants the cause (get_model_fields) without
        # paying the RPC twice; never enters the shared cache.
        app_context.schema_cache[cache_key + ":error"] = fields_metadata
    return {}


def model_is_transient(
    app_context: AppContext, odoo: OdooClient, model: str
) -> Optional[bool]:
    """Return True when ``model`` is an Odoo TransientModel.

    Resolved through ``ir.model.transient`` because the MCP process only ever
    talks RPC and cannot inspect ``env[model]._transient`` directly.  A name
    pattern such as ``*.wizard`` is deliberately not used: persistent models
    are free to carry that suffix.

    Returns ``None`` when the metadata could not be read — callers must treat
    "unknown" like "not transient" so an unreadable lookup can never widen the
    write guard.
    """
    profile = transient_write_profile(app_context, odoo, model)
    if profile is None:
        return None
    return bool(profile.get("transient"))


def transient_write_profile(
    app_context: AppContext, odoo: OdooClient, model: str
) -> Optional[Dict[str, Any]]:
    """Describe how harmless ``create``/``write`` on ``model`` really are.

    Being transient is necessary for the exemption but not sufficient: an
    Odoo wizard is free to override ``create``/``write`` and touch persistent
    records from there — ``account.setup.bank.manual.config.create()`` creates
    a ``res.bank``, ``account.financial.year.op.write()`` writes ``res.company``.
    Exempting those from the approval chain would hand out token-free business
    writes under the banner of "it's only a wizard".

    So the decision is delegated to the Odoo side, which can actually look at
    the class: ``nesa.mcp.doc.helper.mcp_transient_write_profile`` reports
    whether the model overrides those methods or carries ``inverse`` fields.

    Returns ``None`` when the profile could not be obtained — every caller
    must then treat the model as persistent, so a missing bridge module or an
    unreachable Odoo can only ever narrow the exemption, never widen it.
    """
    cached = app_context.transient_cache.get(model)
    if cached is not None:
        return cached
    try:
        profile = call_doc_helper(odoo, "mcp_transient_write_profile", model)
    except Exception:  # noqa: BLE001 — metadata lookup must never mask the call
        logger.warning(
            "[transient] write profile unavailable for model=%s — treating it "
            "as persistent", model,
        )
        return None
    if not isinstance(profile, dict) or not profile.get("exists"):
        return None
    app_context.transient_cache[model] = profile
    return profile


def transient_write_is_exempt(
    app_context: AppContext, odoo: OdooClient, model: str, method: str
) -> tuple[bool, Optional[Dict[str, Any]]]:
    """Decide whether ``model.method`` may skip the approval chain.

    The positive authorizer is the **allowlist**, not the heuristic.  A
    property like "writing this record has no persistent effect" cannot be
    proven from outside: x2many commands reach into the comodel, ``_inherits``
    forwards writes to a parent table, constraints and computes run arbitrary
    code.  So a model only becomes eligible by being reviewed and named —
    either in ``TRANSIENT_EXEMPT_MODELS`` here, or as an exact
    ``model.method`` entry in the deployment's side-effect allowlist.

    On top of that the Odoo-side profile still has to agree that the model is
    transient and that this method is inert on it.  Both conditions must hold,
    so the heuristic can only ever narrow the allowlist, never widen it.
    """
    if method not in TRANSIENT_EXEMPT_METHODS:
        return False, None
    listed = (
        model in TRANSIENT_EXEMPT_MODELS
        or side_effect_method_allowed(model, method)
    )
    if not listed:
        return False, transient_write_profile(app_context, odoo, model)
    profile = transient_write_profile(app_context, odoo, model)
    if profile is None:
        return False, None
    if not profile.get("transient"):
        # An allowlist entry does not turn a persistent model into a wizard.
        logger.warning(
            "[transient] %s is allowlisted for %s but is not transient — "
            "keeping it on the approval chain", model, method,
        )
        return False, profile
    if not profile.get(f"inert_{method}"):
        logger.warning(
            "[transient] %s.%s is allowlisted but the model overrides %s — "
            "keeping it on the approval chain", model, method,
            profile.get("overrides"),
        )
        return False, profile
    return True, profile


# Values that mutate the *other* side of a relation: create (0), update (1),
# delete (2) and, on a one2many, unlink (3) — all of them write comodel rows.
# Linking commands (4/5/6) only touch the relation itself.
_MUTATING_X2MANY_COMMANDS = frozenset({0, 1, 2, 3})
_X2MANY_TYPES = frozenset({"one2many", "many2many"})


def collect_write_values(
    method: str, args: Optional[List[Any]], kwargs: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Return every values dict a create/write call would apply.

    RPC offers more than one shape for the same call and a guard that only
    knows the common one is not a guard:

    * ``write`` takes its values positionally *or* as ``vals=`` keyword —
      Odoo passes keywords straight through to the method.
    * ``create`` accepts a single dict *or* a list of dicts (batch create).

    All of them are collected here so the caller can inspect them uniformly.
    """
    positional = list(args or [])
    keyword = dict(kwargs or {})
    raw: List[Any] = []
    if method == "create":
        if positional:
            raw.append(positional[0])
        for key in ("vals", "vals_list", "values"):
            if key in keyword:
                raw.append(keyword[key])
    elif method == "write":
        if len(positional) > 1:
            raw.append(positional[1])
        for key in ("vals", "values"):
            if key in keyword:
                raw.append(keyword[key])

    collected: List[Dict[str, Any]] = []
    for entry in raw:
        if isinstance(entry, dict):
            collected.append(entry)
        elif isinstance(entry, (list, tuple)):
            collected.extend(item for item in entry if isinstance(item, dict))
    return collected


def x2many_commands_are_inert(
    app_context: AppContext,
    odoo: OdooClient,
    model: str,
    method: str,
    args: Optional[List[Any]],
    kwargs: Optional[Dict[str, Any]],
) -> Optional[str]:
    """Return a reason when the call would write through a relation.

    Even a wizard that never overrides ``create``/``write`` can reach
    persistent data: ``base.language.install`` carries a
    ``Many2many('res.lang')``, and a ``(2, id)`` command on it deletes a
    language.  The exempt path therefore accepts only linking commands.

    Returns ``None`` when nothing objectionable was found.
    """
    values_list = collect_write_values(method, args, kwargs)
    if not values_list:
        return None
    metadata = _cached_fields_metadata(app_context, odoo, model)
    if not metadata:
        # Without field types this function cannot tell a Char from a
        # Many2many, so it cannot promise anything. Refuse the fast path
        # rather than wave the call through.
        return (
            f"field metadata for {model} is unavailable, so the relation "
            "commands in this call cannot be checked."
        )
    for values in values_list:
        for field_name, value in values.items():
            field_type = (metadata.get(field_name) or {}).get("type")
            if field_type not in _X2MANY_TYPES:
                continue
            if not isinstance(value, (list, tuple)):
                continue
            for command in value:
                if not isinstance(command, (list, tuple)) or not command:
                    continue
                if command[0] in _MUTATING_X2MANY_COMMANDS:
                    return (
                        f"{field_name} carries x2many command {command[0]}, "
                        "which creates, updates or deletes records on the "
                        "other side of the relation. Only linking commands "
                        "(4/5/6) run without the approval chain."
                    )
    return None


def _binary_field_names(metadata: Dict[str, Any]) -> List[str]:
    """Return the binary-typed fields of a model.

    NESA A10: ``fields=["*"]`` used to mean "read literally everything",
    which pulls ``datas``/``raw``/``image_1920`` into the answer as base64 and
    can blow a whole session's context on a single call.  Binary payloads are
    therefore only returned when the caller names the field explicitly.
    """
    if not isinstance(metadata, dict):
        return []
    return sorted(
        name
        for name, meta in metadata.items()
        if isinstance(meta, dict) and str(meta.get("type", "")) == "binary"
    )


# Exception types that indicate the call never reached Odoo's business logic
# (socket/HTTP/protocol level).  Only these are retried — a wrong domain or an
# AccessError must fail immediately and visibly.
_TRANSPORT_ERROR_MARKERS = (
    "connection reset",
    "connection refused",
    "connection aborted",
    "broken pipe",
    "timed out",
    "timeout",
    "temporary failure in name resolution",
    "bad gateway",
    "service unavailable",
    "gateway timeout",
    "remote end closed connection",
    "eof occurred",
)


def classify_call_error(exc: BaseException) -> Dict[str, Any]:
    """Classify why an Odoo call failed, and whether a retry can help.

    NESA A6: the bridge used to surface transport hiccups as an anonymous
    "Error occurred during tool execution", which an agent cannot tell apart
    from "there is no such data".  The distinction is now explicit.
    """
    import socket
    import xmlrpc.client

    text = str(exc)
    lowered = text.casefold()
    if isinstance(exc, xmlrpc.client.Fault):
        return {
            "error_type": "odoo_error",
            "retryable": False,
            "detail": sanitize_odoo_error(text),
        }
    transport_types = (
        socket.timeout,
        socket.gaierror,
        ConnectionError,
        TimeoutError,
        OSError,
        xmlrpc.client.ProtocolError,
    )
    if isinstance(exc, transport_types) or any(
        marker in lowered for marker in _TRANSPORT_ERROR_MARKERS
    ):
        return {"error_type": "transport", "retryable": True, "detail": {"message": text}}
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return {"error_type": "request", "retryable": False, "detail": {"message": text}}
    return {
        "error_type": "odoo_error",
        "retryable": False,
        "detail": sanitize_odoo_error(text),
    }


# ORM entry points that only read.  A transport failure on one of these can
# be retried safely; anything else may already have committed on the server.
IDEMPOTENT_READ_METHODS = frozenset({
    "default_get",
    "exists",
    "fields_get",
    "get_views",
    "name_get",
    "name_search",
    "read",
    "read_group",
    "search",
    "search_count",
    "search_fetch",
    "search_read",
    "web_read",
    "web_read_group",
    "web_search_read",
})


class UnknownOutcomeError(RuntimeError):
    """A call was sent, the answer was lost, and the effect is unknown.

    Odoo commits an RPC transaction *before* it writes the answer back to the
    socket, so a timeout or a reset proves nothing about whether the work
    happened.  Retrying a non-read method here would risk posting an invoice
    or sending a mail twice, so the bridge stops and says so instead.
    """

    def __init__(self, label: str, cause: BaseException):
        super().__init__(
            f"{label} was sent to Odoo, but the answer was lost in transport. "
            "The call may have completed on the server — it was NOT retried, "
            "because repeating a non-read call could duplicate its effect. "
            "Verify the record before trying again."
        )
        self.label = label
        self.cause = cause


def call_with_transport_retry(
    callback: Callable[[], Any], *, label: str, idempotent: bool = True,
) -> Any:
    """Run an Odoo call and retry it exactly once on a transport failure.

    Business failures (invalid domain, AccessError, ValidationError) are never
    retried — repeating them only doubles the cost of a deterministic error.

    ``idempotent=False`` marks a call whose repetition could change the world
    twice.  Such a call is never retried; a lost answer is reported as an
    unknown outcome so the caller verifies instead of guessing.
    """
    try:
        return callback()
    except Exception as exc:  # noqa: BLE001 — classified immediately below
        classification = classify_call_error(exc)
        if not classification["retryable"]:
            raise
        if not idempotent:
            logger.warning(
                "[retry] %s hit a transport error and is NOT retried "
                "(non-idempotent): %s", label, exc,
            )
            raise UnknownOutcomeError(label, exc) from exc
        logger.warning(
            "[retry] %s failed with a transport error, retrying once: %s", label, exc,
        )
        time.sleep(0.5)
        return callback()


# "ValueError: ...", "odoo.exceptions.AccessError: ...", "UserError: ..."
_EXCEPTION_LINE_RE = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception|Warning):\s")


def compact_error_message(exc: BaseException) -> tuple[str, Optional[str]]:
    """Reduce an Odoo XML-RPC fault to its actual cause.

    Odoo answers a bad domain with a full server traceback. Repeating all of
    it makes the agent pay several thousand tokens to learn one sentence, so
    the final exception line becomes the message.

    The second return value is the *full* un-escaped traceback, meant for the
    server log only.  It is never part of a tool answer: an Odoo fault carries
    absolute source paths and code lines, and the agent's answers can end up
    in a chat transcript or a mail.
    """
    text = str(exc)
    if "Traceback (most recent call last)" not in text:
        return text, None
    # xmlrpc.client.Fault stringifies to a single line with literal "\n"
    # escapes, so the traceback has to be un-escaped before it can be split.
    unescaped = text.replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'")
    lines = [line.rstrip() for line in unescaped.splitlines() if line.strip()]
    cause = ""
    for line in reversed(lines):
        stripped = line.strip().rstrip(">").rstrip("'\"").strip()
        if not stripped or stripped.startswith(("File \"", "^", "~")):
            continue
        if _EXCEPTION_LINE_RE.match(stripped):
            cause = stripped
            break
    if not cause:
        cause = lines[-1].strip() if lines else text
    return cause, unescaped


def error_response(tool: str, exc: BaseException, **extra: Any) -> Dict[str, Any]:
    """Build a uniform, non-anonymous error payload for a failed tool call.

    The agent gets the cause line and a correlation id; the traceback stays in
    the server log under that same id.  That keeps the answer readable and
    keeps Odoo's internal paths out of whatever the agent quotes.
    """
    classification = classify_call_error(exc)
    message, full_traceback = compact_error_message(exc)
    response: Dict[str, Any] = {
        "success": False,
        "tool": tool,
        "error": message,
        "error_type": classification["error_type"],
        "retryable": classification["retryable"],
    }
    if isinstance(exc, UnknownOutcomeError):
        # The call was sent and the answer was lost — never presented as a
        # clean failure, because the write may well have happened.
        response["outcome_unknown"] = True
        response["retryable"] = False
        response["remedy"] = (
            "Read the affected record back before repeating this call."
        )
    if full_traceback:
        error_ref = uuid.uuid4().hex[:12]
        response["error_ref"] = error_ref
        logger.error(
            "[error_ref=%s] %s failed: %s\n%s",
            error_ref, tool, message, full_traceback,
        )
    response.update(extra)
    return response


def odoo_base_url(app_context: AppContext, odoo: OdooClient) -> str:
    """Return the Odoo ``web.base.url`` for building user-facing links.

    Never hard-coded: staging and production must produce their own host.
    Falls back to the configured RPC URL when the parameter is unreadable.
    """
    cached = app_context.schema_cache.get("__web_base_url__")
    if isinstance(cached, str) and cached:
        return cached
    base = ""
    try:
        value = odoo.execute_method(
            "ir.config_parameter", "get_param", "web.base.url",
        )
        if isinstance(value, str):
            base = value.strip().rstrip("/")
    except Exception:  # noqa: BLE001 — link building must not break the tool
        logger.warning("[base-url] web.base.url unreadable, falling back to RPC URL")
    if not base:
        base = str(getattr(odoo, "url", "")).rstrip("/")
    app_context.schema_cache["__web_base_url__"] = base  # type: ignore[assignment]
    return base


def _act_window_result_counts(
    app_context: AppContext, odoo: OdooClient, model: str, result: Any
) -> Optional[Dict[str, int]]:
    """Count the x2many rows a wizard action produced, if it returned itself.

    NESA A8: methods such as ``action_search`` only return
    ``{"type": "ir.actions.act_window", "res_model": ..., "res_id": ...}``.
    When that window points back at the very record the method was called on,
    the interesting outcome sits in the record's x2many fields — count them so
    the caller learns "13 matches" instead of having to guess and re-read.

    Returns ``None`` whenever this is not that pattern, or when the follow-up
    read fails; the primary result is never put at risk by this convenience.
    """
    if not isinstance(result, dict):
        return None
    if result.get("type") != "ir.actions.act_window":
        return None
    if result.get("res_model") != model:
        return None
    res_id = result.get("res_id")
    if not isinstance(res_id, int) or res_id < 1:
        return None
    metadata = _cached_fields_metadata(app_context, odoo, model)
    x2many_fields = sorted(
        name
        for name, meta in metadata.items()
        if isinstance(meta, dict)
        and str(meta.get("type", "")) in {"one2many", "many2many"}
    )
    if not x2many_fields:
        return None
    try:
        rows = odoo.read_records(model, [res_id], fields=x2many_fields)
    except Exception:  # noqa: BLE001 — best-effort enrichment only
        logger.warning(
            "[act-window-counts] follow-up read failed for %s#%s", model, res_id,
        )
        return None
    if not rows:
        return None
    counts = {
        name: len(value)
        for name, value in rows[0].items()
        if name != "id" and isinstance(value, list)
    }
    return counts or None


def call_doc_helper(odoo: OdooClient, method: str, *args: Any, **kwargs: Any) -> Any:
    """Call a ``nesa.mcp.doc.helper`` method under the acting user's rights.

    The helper lives in ``nesa_mcp_bridge`` and exists because these operations
    need Odoo-side libraries (Pillow, wkhtmltopdf) and private ORM entry points
    that RPC refuses to dispatch.  It is code-owned: the model is on the
    non-delegable deny list so an agent cannot reach it through execute_method
    and bypass the caps enforced by the tools below.
    """
    return odoo.execute_method(NESA_DOC_HELPER_MODEL, method, *args, **kwargs)


_AGGREGATION_FUNCTIONS = {
    "sum",
    "avg",
    "min",
    "max",
    "count",
    "count_distinct",
    "array_agg",
    "bool_and",
    "bool_or",
}


def parse_measure_spec(spec: str) -> tuple[str, str]:
    """Split a 'field:agg' measure into (field, agg).

    Defaults to 'sum' when no aggregator is supplied.
    Raises ValueError on invalid shapes.
    """
    cleaned = str(spec).strip()
    if not cleaned:
        raise ValueError("measure entries must be non-empty strings")
    if ":" not in cleaned:
        return cleaned, "sum"
    field, agg = cleaned.split(":", 1)
    field = field.strip()
    agg = agg.strip().lower()
    if not field or not agg:
        raise ValueError(f"invalid measure spec: {spec!r}")
    if agg not in _AGGREGATION_FUNCTIONS:
        raise ValueError(
            f"unsupported aggregator {agg!r}; expected one of "
            f"{sorted(_AGGREGATION_FUNCTIONS)}."
        )
    return field, agg


def odoo_major_version(odoo: OdooClient) -> int | None:
    """Return the connected Odoo major version, or None if unknown.

    Tries the server-version metadata first; falls back to the
    ``ir.module.module`` ``latest_version`` of the ``base`` module (which
    starts with the major version on every Odoo deployment) so that
    JSON-2 clients still detect the correct major when ``/web/version``
    is unavailable or returns a non-standard payload.
    """
    info = odoo.get_server_version()
    if isinstance(info, dict):
        raw = info.get("server_version") or info.get("server_serie") or ""
        match = re.match(r"\s*(\d+)", str(raw))
        if match:
            return int(match.group(1))
    try:
        result = odoo.execute_method(
            "ir.module.module",
            "search_read",
            [["name", "=", "base"]],
            fields=["latest_version"],
            limit=1,
        )
    except Exception:
        return None
    if not result:
        return None
    raw_version = str(result[0].get("latest_version", ""))
    fallback_match = re.match(r"\s*(\d+)", raw_version)
    return int(fallback_match.group(1)) if fallback_match else None


def resolve_read_fields(
    app_context: AppContext,
    odoo: OdooClient,
    model: str,
    fields: Optional[List[str]],
) -> tuple[Optional[List[str]], Dict[str, Any]]:
    """Pick the field list for read-only tools.

    - ``fields=None`` → smart selection (cap via ODOO_MCP_MAX_SMART_FIELDS).
      Binary fields are already dropped by the smart selector.
    - ``fields=["*"]`` → every field **except binary ones** (NESA A10).  A
      single unqualified read of ``ir.attachment`` would otherwise return
      ``datas``/``raw`` as base64 and can exhaust the agent's context in one
      call.  Binary payloads stay reachable by naming the field explicitly, or
      through ``read_attachment`` / ``create_attachment_download``.
    - Otherwise return the caller list unchanged.

    Returns ``(fields, notes)``; ``notes`` is surfaced to the caller so the
    filtering is visible rather than silent.
    """
    notes: Dict[str, Any] = {"smart_fields_applied": fields is None}
    if fields is None:
        metadata = _cached_fields_metadata(app_context, odoo, model)
        if not metadata:
            # Failing open here would mean fields=None → Odoo reads *every*
            # field, binaries included — exactly the payload A10 exists to
            # prevent.  Fall back to the two fields every model has.
            notes["fields_metadata_available"] = False
            notes["warning"] = (
                "fields_get metadata was unavailable, so the field selection "
                "fell back to id/display_name instead of reading every field. "
                "Name the fields you need explicitly."
            )
            return ["id", "display_name"], notes
        return select_smart_fields(metadata, max_fields=max_smart_fields()), notes
    if len(fields) == 1 and fields[0] == "*":
        metadata = _cached_fields_metadata(app_context, odoo, model)
        if not metadata:
            # Same reasoning, but the caller explicitly asked for everything,
            # so a silent narrowing would be a lie — refuse instead.
            raise ValueError(
                f"fields=['*'] cannot be expanded for {model}: fields_get "
                "metadata is unavailable, and reading every field would "
                "include binary payloads. Name the fields you need."
            )
        binary_fields = _binary_field_names(metadata)
        expanded = [name for name in metadata if name not in set(binary_fields)]
        notes["expanded_wildcard"] = True
        if binary_fields:
            notes["excluded_binary_fields"] = binary_fields
            notes["warning"] = (
                "Binary fields were excluded from fields=['*']. Request them by "
                "name, or use read_attachment / create_attachment_download."
            )
        return expanded, notes
    unknown = _unknown_field_names(app_context, odoo, model, fields)
    if unknown:
        raise ValueError(_unknown_fields_message(app_context, odoo, model, unknown))
    return fields, notes


def _unknown_field_names(
    app_context: AppContext, odoo: OdooClient, model: str, fields: List[str]
) -> List[str]:
    """Explicit field names that ``fields_get`` does not know for ``model``.

    Checked BEFORE the RPC (NESA): a guessed name such as
    ``project.task.planned_date_end`` otherwise reaches Odoo, which logs a
    full ``Invalid field`` traceback at ERROR level on the production server
    for every attempt (~10 per day in the daily log report, 2026-09-01) and
    hands the agent back only the bare ValueError.  The metadata is served
    from the lifespan cache, so the cost is one ``fields_get`` per model per
    process.  Fails open: without metadata the list is returned unchanged
    and Odoo rejects as before.
    """
    metadata = _cached_fields_metadata(app_context, odoo, model)
    if not metadata:
        return []
    unknown = _names_missing_from(fields, metadata)
    if not unknown:
        return []
    # A field that appeared after this process cached the model — a Studio
    # deployment, a module install — must not stay "unknown" until the next
    # restart.  Re-read once before refusing; the cost falls on the rare
    # failing call, not on the hot path.
    metadata = _cached_fields_metadata(app_context, odoo, model, refresh=True)
    if not metadata:
        return []
    return _names_missing_from(fields, metadata)


def _names_missing_from(fields: List[str], metadata: Dict[str, Any]) -> List[str]:
    return [
        name
        for name in fields
        if not isinstance(name, str) or name not in metadata
    ]


def _unknown_fields_message(
    app_context: AppContext, odoo: OdooClient, model: str, unknown: List[str]
) -> str:
    import difflib

    metadata = _cached_fields_metadata(app_context, odoo, model)
    parts = []
    for name in unknown:
        close = difflib.get_close_matches(
            str(name), list(metadata), n=3, cutoff=0.6
        )
        hint = f" (did you mean: {', '.join(close)})" if close else ""
        parts.append(f"{name!r}{hint}")
    return (
        f"Unknown field(s), or fields inaccessible to this user, on {model}: "
        f"{'; '.join(parts)}. Only names from "
        "the model's fields_get are readable — omit 'fields' for the smart "
        "default selection, or pass fields=['*'] for every non-binary field."
    )


DOMAIN_FORMAT_HINT = (
    "Pass the domain as a JSON list of [field, operator, value] triples, "
    'e.g. [["state", "=", "sale"], ["partner_id", "in", [7, 9]]]; the prefix '
    'operators "&", "|" and "!" are allowed as bare strings. An empty list '
    "means no filter."
)


def _domain_error(reason: str) -> ValueError:
    return ValueError(f"Invalid domain: {reason}. {DOMAIN_FORMAT_HINT}")


def normalize_domain_input(domain: Any) -> List[Any]:
    """Normalize common MCP/JSON domain shapes to an Odoo domain list.

    Empty input (``None``, ``""``, ``[]``, ``[[]]``, ``{}``) means "no
    filter".  Anything else that cannot be turned into a domain raises
    ``ValueError`` instead of being dropped: a silently emptied domain used to
    turn "find the invoices of partner X" into "find every invoice" and the
    agent had no way to notice.
    """
    if domain is None:
        return []
    if isinstance(domain, SearchDomain):
        return domain.to_domain_list()

    domain_value = domain
    if isinstance(domain_value, str):
        if not domain_value.strip():
            return []
        try:
            domain_value = json.loads(domain_value)
        except json.JSONDecodeError:
            try:
                import ast

                domain_value = ast.literal_eval(domain_value)
            except (SyntaxError, ValueError):
                raise _domain_error(
                    f"the string {domain_value[:120]!r} is neither JSON nor a "
                    "Python literal"
                ) from None

    if isinstance(domain_value, dict):
        if not domain_value:
            return []
        conditions = domain_value.get("conditions")
        if not isinstance(conditions, list):
            raise _domain_error(
                "a dict domain needs a 'conditions' list of "
                "{field, operator, value} objects"
            )
        normalized: List[Any] = []
        for cond in conditions:
            if not (
                isinstance(cond, dict)
                and isinstance(cond.get("field"), str)
                and isinstance(cond.get("operator"), str)
                and "value" in cond
            ):
                raise _domain_error(
                    f"condition {cond!r:.120} needs string field/operator and a value"
                )
            normalized.append([cond["field"], cond["operator"], cond["value"]])
        return normalized

    if isinstance(domain_value, tuple):
        domain_value = list(domain_value)
    if not isinstance(domain_value, list):
        raise _domain_error(
            f"got {type(domain_value).__name__} {domain_value!r:.120}"
        )

    if (
        len(domain_value) == 1
        and isinstance(domain_value[0], (list, tuple))
        and domain_value[0]
    ):
        domain_value = list(domain_value[0])

    if not domain_value or domain_value == [[]]:
        return []
    if (
        len(domain_value) == 3
        and isinstance(domain_value[0], str)
        and domain_value[0] not in ["&", "|", "!"]
        and isinstance(domain_value[1], str)
    ):
        domain_list = [domain_value]
    else:
        domain_list = domain_value

    valid_conditions: List[Any] = []
    for cond in domain_list:
        if isinstance(cond, str) and cond in ["&", "|", "!"]:
            valid_conditions.append(cond)
            continue
        if (
            isinstance(cond, (list, tuple))
            and len(cond) == 3
            and isinstance(cond[0], str)
            and isinstance(cond[1], str)
        ):
            valid_conditions.append(list(cond))
            continue
        raise _domain_error(
            f"element {cond!r:.120} is not a [field, operator, value] triple"
        )

    return valid_conditions


def truthy_env(name: str) -> bool:
    """Read a common boolean environment flag."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def writes_enabled() -> bool:
    """Return whether destructive approved writes are enabled for this process."""
    return truthy_env("ODOO_MCP_ENABLE_WRITES")


def allowed_side_effect_methods() -> List[str]:
    """Return exact model.method names configured for reviewed side effects."""
    raw_value = os.environ.get("ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "")
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def denied_method_prefixes() -> List[str]:
    """Return model/method prefixes that no execution mode may bypass.

    This is a negative policy, not a second positive allowlist. Deployments can
    keep a very small set of non-delegable boundaries while native ACL parity
    lets Odoo decide every other positive authorization question.
    """
    raw_value = os.environ.get("ODOO_MCP_DENIED_METHOD_PREFIXES", "")
    configured = {
        item.strip().casefold()
        for item in raw_value.split(",")
        if item.strip()
    }
    return sorted(configured | NON_DELEGABLE_METHOD_PREFIXES)


def denied_method_prefix(model: str, method: str) -> Optional[str]:
    """Return the matching hard-deny prefix, if one is configured."""
    target = f"{model}.{method}".casefold()
    return next(
        (prefix for prefix in denied_method_prefixes() if target.startswith(prefix)),
        None,
    )


def hard_deny_result(tool: str, model: str, operation: str) -> Optional[Dict[str, Any]]:
    """Return a uniform refusal for a non-delegable mutation target."""
    deny_prefix = denied_method_prefix(model, operation)
    if not deny_prefix:
        return None
    return {
        "success": False,
        "tool": tool,
        "error": (
            "Mutation is blocked by the deployment's hard-deny policy "
            f"({deny_prefix}). This cannot be bypassed by native ACL parity, "
            "an exact allowlist, broad mode, or the approved-write flow."
        ),
    }


def sanitized_execution_kwargs(
    kwargs: Optional[Dict[str, Any]],
) -> tuple[Dict[str, Any], List[str]]:
    """Remove caller context flags that suppress Odoo's normal audit trail."""
    sanitized = dict(kwargs or {})
    context = sanitized.get("context")
    removed: List[str] = []
    if isinstance(context, dict):
        clean_context = dict(context)
        for key in sorted(AUDIT_SUPPRESSION_CONTEXT_KEYS):
            if key in clean_context:
                removed.append(key)
                clean_context.pop(key, None)
        sanitized["context"] = clean_context
    return sanitized, removed


def audit_odoo_execution(tool: str, model: str, method: str) -> None:
    """Log the acting login and target without ever logging its API key."""
    from ._nesa_per_user_auth import current_user_context

    user_context = current_user_context()
    login = user_context[0] if user_context else "<service-account>"
    logger.info(
        "[odoo_execution] tool=%s login=%s model=%s method=%s native_acl_parity=%s",
        tool,
        login,
        model,
        method,
        native_acl_parity_enabled(),
    )


def native_acl_parity_requested() -> bool:
    """Return whether the deployment requests Odoo-native authorization.

    This is intentionally separate from ``ODOO_MCP_ALLOW_UNKNOWN_METHODS``:
    parity mode is only valid with strict per-user authentication, while the
    older broad switch can also run with a service credential.
    """
    return truthy_env("ODOO_MCP_NATIVE_ACL_PARITY")


def native_acl_parity_enabled() -> bool:
    """Trust native Odoo ACLs only when every request has a user identity."""
    if not native_acl_parity_requested():
        return False
    from ._nesa_per_user_auth import strict_mode_enabled

    return strict_mode_enabled()


def side_effect_method_allowed(model: str, method: str) -> bool:
    """Check exact side-effect allowlist entries.

    NESA: in addition to the upstream CSV env var, an optional DB-driven
    allowlist is consulted when ``ODOO_MCP_METHOD_ALLOWLIST_MODEL`` points
    at an Odoo model (typically ``nesa.mcp.allowed_method``). The DB-side
    can be managed via Odoo backend without touching the systemd unit and
    enforces NESA's DATEV/Payroll blocklist on the constraint layer.
    """
    target = f"{model}.{method}"
    if target in set(allowed_side_effect_methods()):
        return True
    # NESA DB-Allowlist (additive). Returns frozenset() when env unset.
    from . import _nesa_db_allowlist
    return target in _nesa_db_allowlist.methods()


def chatter_direct_enabled() -> bool:
    """Return True when chatter_post may bypass approval-token gating."""
    return truthy_env("MCP_CHATTER_DIRECT")


def runtime_security_report() -> Dict[str, Any]:
    """Expose MCP runtime safety posture without including secrets."""
    security = getattr(mcp.settings, "transport_security", None)
    broad_unknown_enabled = truthy_env("ODOO_MCP_ALLOW_UNKNOWN_METHODS")
    native_parity_requested = native_acl_parity_requested()
    native_parity_enabled = native_acl_parity_enabled()
    db_allowlist_state = __import__(
        "odoo_mcp._nesa_db_allowlist", fromlist=["describe_state"],
    ).describe_state()
    if db_allowlist_state.get("last_error"):
        db_allowlist_state["last_error"] = "[redacted: refresh failed]"
    per_user_auth_state = __import__(
        "odoo_mcp._nesa_per_user_auth", fromlist=["describe_state"],
    ).describe_state()
    return {
        "transport": per_user_auth_state["runtime_transport"],
        "host": getattr(mcp.settings, "host", None),
        "port": getattr(mcp.settings, "port", None),
        "streamable_http_path": getattr(mcp.settings, "streamable_http_path", None),
        "remote_http_allowed": truthy_env("MCP_ALLOW_REMOTE_HTTP"),
        "write_execution_enabled": writes_enabled(),
        "unknown_execute_method_enabled": (
            broad_unknown_enabled or native_parity_enabled
        ),
        "chatter_direct_enabled": chatter_direct_enabled(),
        "allowed_side_effect_methods": allowed_side_effect_methods(),
        "denied_method_prefixes": denied_method_prefixes(),
        "nesa_db_allowlist": db_allowlist_state,
        "nesa_per_user_auth": per_user_auth_state,
        "broad_unknown_method_mode": {
            "enabled": broad_unknown_enabled,
            "risk": ("broad" if broad_unknown_enabled else "off"),
            "recommendation": (
                "Prefer ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS exact entries over "
                "ODOO_MCP_ALLOW_UNKNOWN_METHODS=1."
            ),
        },
        "native_acl_parity": {
            "requested": native_parity_requested,
            "enabled": native_parity_enabled,
            "requires_strict_per_user": True,
            "positive_authorizer": (
                "odoo_acl_record_rules_and_business_validation"
                if native_parity_enabled
                else (
                    "broad_unreviewed_method_mode"
                    if broad_unknown_enabled
                    else "exact_method_allowlist"
                )
            ),
        },
        "allowed_hosts": getattr(security, "allowed_hosts", None),
        "allowed_origins": getattr(security, "allowed_origins", None),
        "notes": [
            "HTTP transports are local-only by default in the CLI entry point.",
            "execute_approved_write requires ODOO_MCP_ENABLE_WRITES and confirm=true.",
            "execute_method blocks direct CRUD and write-equivalent aliases in every mode.",
            "Native ACL parity requires strict per-user authentication and never grants sudo access.",
        ],
    }


def mcp_surface_counts() -> Dict[str, int]:
    """Read current registered MCP surface counts from FastMCP managers."""
    tool_manager = getattr(mcp, "_tool_manager", None)
    resource_manager = getattr(mcp, "_resource_manager", None)
    prompt_manager = getattr(mcp, "_prompt_manager", None)
    resources = getattr(resource_manager, "_resources", {})
    templates = getattr(resource_manager, "_templates", {})
    return {
        "tool_count": len(getattr(tool_manager, "_tools", {})),
        "resource_count": len(resources) + len(templates),
        "prompt_count": len(getattr(prompt_manager, "_prompts", {})),
    }


def _canonical_payload_hash(payload: Dict[str, Any]) -> str:
    """SHA-256 ueber kanonische JSON-Serialisierung (sort_keys, no whitespace).

    Identisch zur Hash-Funktion im NESA-Modul (nesa_mcp_bridge/models/
    nesa_mcp_approval_token.py) — beide Seiten muessen denselben Hash
    fuer denselben Payload errechnen, sonst matcht der Approval-Vergleich
    beim consume nicht.
    """
    if not isinstance(payload, dict):
        return ""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def register_write_approval(app_context: AppContext, report: Dict[str, Any]) -> bool:
    """Persist validated write approval via NESA bridge (DB-backed token store).

    NESA Patch 3 (2026-05-20): ersetzt In-Memory-Dict (per-lifespan, also
    per-MCP-Session) durch persistierte Odoo-Tabelle nesa.mcp.approval.token.
    Begrundung siehe AppContext-Docstring + Modul-Datei
    nesa_mcp_approval_token.py.

    Aufrufer behaelt boolean-API. Erfolgs/Fehler-Branch identisch zum
    Vorgaenger — Caller (validate_write) annotiert ``approval_status.stored``.
    """
    approval = report.get("approval")
    if not report.get("success") or not isinstance(approval, dict):
        return False
    token = str(approval.get("token", ""))
    if not token:
        return False

    payload = write_approval_payload(approval)
    now = time.time()
    validated_at_iso = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    try:
        result = app_context.odoo.execute_method(
            "nesa.mcp.approval.token",
            "mcp_register_approval",
            token,
            str(approval.get("model", "")),
            str(approval.get("operation", "")),
            payload,
            validated_at_iso,
        )
    except Exception:  # noqa: BLE001 — odoo_client wraps multiple xmlrpc/json2 errors
        logger.exception("[approval-token] DB register failed for token=%s", token)
        return False

    if not isinstance(result, dict) or not result.get("success"):
        logger.warning(
            "[approval-token] DB register rejected token=%s reason=%s",
            token, (result or {}).get("error") if isinstance(result, dict) else "non-dict reply",
        )
        return False

    # Surface validated_at + expires_at back to the LLM via the report —
    # downstream prompt-engineering refers to expires_at_iso for retry windows.
    approval["validated_at"] = now
    approval["expires_at"] = now + WRITE_APPROVAL_TTL_SECONDS
    return True


def require_validated_write_approval(
    app_context: AppContext, approval: Dict[str, Any]
) -> Dict[str, Any]:
    """Consume the server-side validation record for an approval token.

    NESA Patch 3 (2026-05-20): liest aus DB-Tabelle nesa.mcp.approval.token
    statt aus In-Memory-Dict. Payload-Hash wird ge-pruef damit der Token
    nicht fuer einen abweichenden Payload missbraucht werden kann.

    NESA A2/A7: returns ``{"ok": True, ...}`` on success and
    ``{"ok": False, "reason_code": ..., "reason": ...}`` otherwise, so the
    caller can tell "never validated" from "expired", "already consumed" and
    "token store unreachable" instead of printing one catch-all sentence.
    """
    token = str(approval.get("token", ""))
    if not token:
        return {
            "ok": False,
            "reason_code": "token_missing",
            "reason": (
                "No approval token was supplied. validate_write returns one; "
                "preview_write deliberately does not."
            ),
        }
    expected_hash = _canonical_payload_hash(write_approval_payload(approval))

    try:
        result = app_context.odoo.execute_method(
            "nesa.mcp.approval.token",
            "mcp_consume_approval",
            token,
            expected_hash,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("[approval-token] DB consume failed for token=%s", token)
        return {
            "ok": False,
            "reason_code": "token_store_unreachable",
            "reason": f"The approval-token store could not be reached: {exc}",
        }

    if not isinstance(result, dict) or not result.get("success"):
        reason = (
            str(result.get("error"))
            if isinstance(result, dict) and result.get("error")
            else "the approval-token store returned an unexpected reply"
        )
        logger.info(
            "[approval-token] consume rejected token=%s reason=%s", token, reason,
        )
        return {
            "ok": False,
            "reason_code": _approval_reason_code(reason),
            "reason": reason,
        }

    payload = result.get("payload") or {}
    return {
        "ok": True,
        "approval": dict(approval),
        "payload": payload,
        "validated_at_iso": result.get("validated_at_iso"),
        "expires_at_iso": result.get("expires_at_iso"),
    }


def _approval_reason_code(reason: str) -> str:
    """Map the token store's message onto a stable machine-readable code.

    NESA A2/A7: "never validated", "expired" and "already consumed" used to
    collapse into one sentence, so a caller could not tell whether re-running
    validate_write would help or whether the write had already landed.
    """
    lowered = reason.casefold()
    # Order matters: the legacy "has not been validated ... or has expired"
    # wording contains both markers, and "unknown token" is the more useful
    # answer of the two because it tells the caller to validate, not to hurry.
    if "has not been validated" in lowered or "unknown" in lowered:
        return "token_unknown"
    if "already consumed" in lowered:
        return "token_already_consumed"
    if "does not belong to this user" in lowered:
        return "token_foreign_user"
    if "payload does not match" in lowered:
        return "payload_mismatch"
    if "expired" in lowered:
        return "token_expired"
    return "token_rejected"


def revoke_write_approval(app_context: AppContext, token: str) -> None:
    """Best-effort token revocation after successful execute_approved_write.

    Failures are logged but never re-raised — at this point the write has
    already landed; a dangling token will be cleaned up by the bridge cron
    within an hour anyway. Caller should not block the success-response on
    revoke errors.
    """
    if not token:
        return
    try:
        app_context.odoo.execute_method(
            "nesa.mcp.approval.token",
            "mcp_revoke_approval",
            token,
        )
    except Exception:  # noqa: BLE001
        logger.warning(
            "[approval-token] revoke failed for token=%s — cleanup-cron will sweep",
            token,
        )


def write_approval_payload(approval: Dict[str, Any]) -> Dict[str, Any]:
    """Return the canonical approval payload fields used for execution."""
    return {
        "model": approval.get("model"),
        "operation": approval.get("operation"),
        "record_ids": approval.get("record_ids") or [],
        "values": approval.get("values") or {},
        "context": approval.get("context") or {},
    }


def configured_addons_roots() -> List[Path]:
    """Return trusted local addon roots configured by the operator."""
    roots: List[Path] = []
    for raw_path in os.environ.get("ODOO_ADDONS_PATHS", "").split(os.pathsep):
        if not raw_path:
            continue
        roots.append(Path(raw_path).expanduser().resolve(strict=False))
    return roots


def restrict_addons_paths(addons_paths: Optional[List[str]]) -> Optional[List[str]]:
    """Restrict source scans to ODOO_ADDONS_PATHS roots."""
    if addons_paths is None:
        return None
    roots = configured_addons_roots()
    if not roots:
        raise ValueError(
            "scan_addons_source requires ODOO_ADDONS_PATHS when addons_paths are provided."
        )

    restricted_paths: List[str] = []
    for raw_path in addons_paths:
        candidate = Path(raw_path).expanduser().resolve(strict=False)
        if not any(
            candidate == root or _is_relative_to(candidate, root) for root in roots
        ):
            raise ValueError(
                f"{candidate} is outside configured ODOO_ADDONS_PATHS roots."
            )
        restricted_paths.append(str(candidate))
    return restricted_paths


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def access_permission_field(operation: str) -> str:
    """Map an Odoo operation or method name to the closest ACL permission flag."""
    normalized = operation.strip().lower()
    if normalized in {"create"}:
        return "perm_create"
    if normalized in {"write"}:
        return "perm_write"
    if normalized in {"unlink", "delete"}:
        return "perm_unlink"
    if normalized in {"read", "search", "search_read", "search_count", "name_search"}:
        return "perm_read"
    safety = classify_method_safety(normalized)
    if safety["safety"] in {"side_effect", "unknown"}:
        return "perm_write"
    return "perm_read"


def _safe_odoo_read(
    label: str, callback: Callable[[], Any]
) -> tuple[Any, Dict[str, Any] | None]:
    """Run a read-only Odoo metadata call and normalize failure shape."""
    try:
        return callback(), None
    except Exception as exc:
        return None, {
            "stage": label,
            "error": sanitize_odoo_error(str(exc)),
        }


def _m2o_id(value: Any) -> int | None:
    if isinstance(value, list) and value and isinstance(value[0], int):
        return int(value[0])
    if isinstance(value, tuple) and value and isinstance(value[0], int):
        return int(value[0])
    if isinstance(value, int):
        return value
    return None


def _m2m_ids(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()
    result: set[int] = set()
    for item in value:
        if isinstance(item, int):
            result.add(item)
        elif isinstance(item, (list, tuple)) and item and isinstance(item[0], int):
            result.add(int(item[0]))
    return result


def _field_names(metadata: Any) -> set[str]:
    if not isinstance(metadata, dict):
        return set()
    return {str(name) for name in metadata.keys()}


def _available_user_read_fields(available_fields: set[str]) -> list[str]:
    base_candidates = ["id", "name", "login", "company_id", "company_ids"]
    group_candidates = ["groups_id", "group_ids", "all_group_ids"]
    if not available_fields:
        return base_candidates
    return [
        field_name
        for field_name in base_candidates + group_candidates
        if field_name in available_fields
    ]


def _group_field_names(record: Dict[str, Any]) -> tuple[str | None, str | None]:
    direct_group_field = None
    for field_name in ("groups_id", "group_ids"):
        if field_name in record:
            direct_group_field = field_name
            break
    all_group_field = "all_group_ids" if "all_group_ids" in record else None
    return direct_group_field, all_group_field


def _acl_row_applies(row: Dict[str, Any], user_group_ids: set[int] | None) -> bool:
    group_id = _m2o_id(row.get("group_id"))
    if group_id is None:
        return True
    return user_group_ids is not None and group_id in user_group_ids


def _rule_applies(row: Dict[str, Any], user_group_ids: set[int] | None) -> bool:
    group_ids = _m2m_ids(row.get("groups"))
    if not group_ids:
        return True
    return user_group_ids is not None and bool(group_ids & user_group_ids)


def _record_id_domain(record_ids: Optional[List[int]]) -> List[Any]:
    ids = [int(record_id) for record_id in record_ids or [] if int(record_id) > 0]
    return [["id", "in", ids]] if ids else []


_RULE_DOMAIN_PREVIEW_CHARS = 300


def _compact_acl_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the fields that decide an ACL question, drop the rest (NESA A9)."""
    return {
        "id": row.get("id"),
        "name": row.get("name"),
        "group": row.get("group_id") or "global",
        "perm_read": row.get("perm_read"),
        "perm_write": row.get("perm_write"),
        "perm_create": row.get("perm_create"),
        "perm_unlink": row.get("perm_unlink"),
    }


def _compact_rule_row(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Same for record rules; long domain_force strings are previewed only."""
    domain = str(rule.get("domain_force") or "")
    return {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "global": not _m2m_ids(rule.get("groups")),
        "domain_force": (
            domain
            if len(domain) <= _RULE_DOMAIN_PREVIEW_CHARS
            else domain[:_RULE_DOMAIN_PREVIEW_CHARS] + " …[truncated, use verbose=true]"
        ),
    }


def _access_diagnosis_codes(
    *,
    metadata_errors: list[Dict[str, Any]],
    acl_rows: list[Dict[str, Any]],
    granting_acl_rows: list[Dict[str, Any]],
    active_rules: list[Dict[str, Any]],
    applicable_rules: list[Dict[str, Any]],
    actual_count: int | None,
    expected_count: int | None,
    record_ids: list[int],
) -> list[Dict[str, str]]:
    codes: list[Dict[str, str]] = []
    if metadata_errors:
        codes.append(
            {
                "code": "metadata_access_unavailable",
                "severity": "warning",
                "message": "Some ACL, rule, user, or count metadata could not be read.",
            }
        )
    if acl_rows and not granting_acl_rows:
        codes.append(
            {
                "code": "acl_denied_likely",
                "severity": "warning",
                "message": "No readable ACL row appears to grant the requested operation.",
            }
        )

    mismatch = False
    if expected_count is not None and actual_count is not None:
        mismatch = actual_count < expected_count
    if record_ids and actual_count is not None:
        mismatch = mismatch or actual_count < len(record_ids)
    if mismatch:
        if applicable_rules or active_rules:
            codes.append(
                {
                    "code": "record_rule_filter_likely",
                    "severity": "warning",
                    "message": "Visible record count is lower than expected and active record rules exist.",
                }
            )
        else:
            codes.append(
                {
                    "code": "domain_or_rule_filter_likely",
                    "severity": "warning",
                    "message": "Visible record count is lower than expected; inspect domain and access context.",
                }
            )
    if not codes:
        codes.append(
            {
                "code": "no_access_issue_detected",
                "severity": "info",
                "message": "No obvious ACL or record-rule mismatch was detected from readable metadata.",
            }
        )
    return codes


# ----- MCP Tools -----


@mcp.tool(
    description="Diagnose an Odoo model call without executing it",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def diagnose_odoo_call(
    model: str,
    method: str,
    args: Optional[List[Any]] = None,
    kwargs: Optional[Dict[str, Any]] = None,
    transport: str = "auto",
    target_version: Optional[str] = None,
    observed_error: Optional[Any] = None,
    include_debug: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
    use_live_metadata: bool = False,
) -> Dict[str, Any]:
    """
    Diagnose model/method/payload issues without executing the candidate call.
    """
    report = diagnose_odoo_call_report(
        model=model,
        method=method,
        args=args,
        kwargs=kwargs,
        transport=transport,
        target_version=target_version,
        observed_error=observed_error,
        include_debug=include_debug,
        metadata=metadata,
    )
    if use_live_metadata:
        report["issues"].append(
            {
                "code": "live_metadata_not_used",
                "severity": "info",
                "message": (
                    "diagnose_odoo_call is preview-only; pass metadata explicitly "
                    "or use inspect_model_relationships for live fields_get metadata."
                ),
            }
        )
    return report


@mcp.tool(
    description="Build a JSON-2 request preview without network access",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def generate_json2_payload(
    model: str,
    method: str,
    args: Optional[List[Any]] = None,
    kwargs: Optional[Dict[str, Any]] = None,
    base_url: Optional[str] = None,
    database: Optional[str] = None,
    include_database_header: bool = True,
) -> Dict[str, Any]:
    """
    Generate a JSON-2 endpoint, headers, and named JSON body.
    """
    return generate_json2_payload_report(
        model=model,
        method=method,
        args=args,
        kwargs=kwargs,
        base_url=base_url,
        database=database,
        include_database_header=include_database_header,
    )


@mcp.tool(
    description="Inspect model relationships and required field metadata",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def inspect_model_relationships(
    ctx: Context,
    model: str,
    fields_metadata: Optional[Dict[str, Any]] = None,
    include_readonly: bool = True,
    include_computed: bool = True,
    use_live_metadata: bool = True,
) -> Dict[str, Any]:
    """
    Summarize relationship fields using provided metadata or bounded fields_get.
    """
    try:
        validate_model_name(model)
        metadata_source = "input" if fields_metadata is not None else "none"
        metadata_error = None
        if fields_metadata is None and use_live_metadata:
            metadata_source = "server"
            try:
                odoo = ctx.request_context.lifespan_context.odoo
                fields_metadata = odoo.get_model_fields(model)
                if "error" in fields_metadata:
                    metadata_error = str(fields_metadata["error"])
                    fields_metadata = None
            except Exception as exc:
                metadata_error = str(exc)
                fields_metadata = None
        return inspect_model_relationships_report(
            model=model,
            fields_metadata=fields_metadata,
            metadata_source=metadata_source,
            metadata_error=metadata_error,
            include_readonly=include_readonly,
            include_computed=include_computed,
        )
    except Exception as e:
        return error_response("inspect_model_relationships", e, model=model)


@mcp.tool(
    description=(
        "Diagnose ACL and record-rule visibility for an Odoo model. Returns "
        "only the groups that matter for the decision, with names; set "
        "verbose=true for the full group-membership dumps."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def diagnose_access(
    ctx: Context,
    model: str,
    operation: str = "read",
    domain: Optional[Any] = None,
    record_ids: Optional[List[int]] = None,
    expected_count: Optional[int] = None,
    include_rules: bool = True,
    limit: int = 50,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Inspect readable ACL/rule metadata for the current Odoo credential.

    This tool never uses sudo, never impersonates another user, and only performs
    read-only metadata/count calls.

    NESA A9: by default the answer no longer repeats the caller's ~100 raw
    group IDs three times over (``groups_id``/``group_ids``/
    ``direct_group_ids``). Numeric IDs without names are unreadable for an
    agent and were pure context cost. Only the groups that actually decide the
    ACL/rule question are returned, resolved to names.
    """
    try:
        validate_model_name(model)
        limit = clamp_limit(limit, maximum=500)
        if expected_count is not None and expected_count < 0:
            raise ValueError("expected_count must be greater than or equal to 0")
        normalized_record_ids = [
            int(record_id) for record_id in record_ids or [] if int(record_id) > 0
        ]
        permission_field = access_permission_field(operation)
        normalized_domain = normalize_domain_input(domain)
        count_domain = (
            _record_id_domain(normalized_record_ids)
            if normalized_record_ids
            else normalized_domain
        )

        odoo = ctx.request_context.lifespan_context.odoo
        metadata_errors: list[Dict[str, Any]] = []

        model_rows, error = _safe_odoo_read(
            "ir.model",
            lambda: odoo.execute_method(
                "ir.model",
                "search_read",
                [["model", "=", model]],
                fields=["id", "name", "model"],
                limit=1,
            ),
        )
        if error:
            metadata_errors.append(error)
            model_rows = []
        model_record = (
            model_rows[0] if isinstance(model_rows, list) and model_rows else None
        )
        model_id = (
            int(model_record["id"])
            if isinstance(model_record, dict) and model_record.get("id")
            else None
        )
        if model_id is None:
            metadata_errors.append(
                {
                    "stage": "ir.model",
                    "error": {"message": f"Model metadata not found for {model}."},
                }
            )

        user_context, error = _safe_odoo_read(
            "res.users.context_get",
            lambda: (
                odoo.get_user_context()
                if hasattr(odoo, "get_user_context")
                else odoo.execute_method("res.users", "context_get")
            ),
        )
        if error:
            metadata_errors.append(error)
            user_context = {}
        if isinstance(user_context, dict) and user_context.get("error"):
            metadata_errors.append(
                {
                    "stage": "res.users.context_get",
                    "error": sanitize_odoo_error(str(user_context["error"])),
                }
            )
            user_context = {}

        uid = getattr(odoo, "uid", None)
        if uid is None and isinstance(user_context, dict):
            uid = user_context.get("uid")
        current_user: Dict[str, Any] = {
            "uid": uid,
            "context": user_context if isinstance(user_context, dict) else {},
            "record": None,
            "group_ids": None,
            "direct_group_ids": None,
            "group_field": None,
            "all_group_field": None,
        }
        user_group_ids: set[int] | None = None
        if isinstance(uid, int) and uid > 0:
            user_fields, error = _safe_odoo_read(
                "res.users.fields_get",
                lambda: odoo.execute_method(
                    "res.users",
                    "fields_get",
                    [],
                    attributes=["type", "relation", "string"],
                ),
            )
            if error:
                metadata_errors.append(error)
            available_user_fields = _field_names(user_fields)
            user_rows, error = _safe_odoo_read(
                "res.users.read",
                lambda: odoo.execute_method(
                    "res.users",
                    "read",
                    [uid],
                    fields=_available_user_read_fields(available_user_fields),
                ),
            )
            if error:
                metadata_errors.append(error)
            elif isinstance(user_rows, list) and user_rows:
                current_user["record"] = user_rows[0]
                direct_group_field, all_group_field = _group_field_names(user_rows[0])
                current_user["group_field"] = direct_group_field
                current_user["all_group_field"] = all_group_field
                direct_group_ids = (
                    _m2m_ids(user_rows[0].get(direct_group_field))
                    if direct_group_field
                    else set()
                )
                all_group_ids = (
                    _m2m_ids(user_rows[0].get(all_group_field))
                    if all_group_field
                    else set()
                )
                user_group_ids = all_group_ids or direct_group_ids
                current_user["group_ids"] = sorted(user_group_ids)
                current_user["direct_group_ids"] = sorted(direct_group_ids)

        acl_rows: list[Dict[str, Any]] = []
        if model_id is not None:
            acl_rows_raw, error = _safe_odoo_read(
                "ir.model.access",
                lambda: odoo.execute_method(
                    "ir.model.access",
                    "search_read",
                    [["model_id", "=", model_id]],
                    fields=[
                        "id",
                        "name",
                        "model_id",
                        "group_id",
                        "perm_read",
                        "perm_write",
                        "perm_create",
                        "perm_unlink",
                    ],
                    limit=limit,
                ),
            )
            if error:
                metadata_errors.append(error)
            elif isinstance(acl_rows_raw, list):
                acl_rows = [row for row in acl_rows_raw if isinstance(row, dict)]

        active_rules: list[Dict[str, Any]] = []
        global_rules: list[Dict[str, Any]] = []
        group_bound_rules: list[Dict[str, Any]] = []
        applicable_rules: list[Dict[str, Any]] = []
        if include_rules and model_id is not None:
            rules_raw, error = _safe_odoo_read(
                "ir.rule",
                lambda: odoo.execute_method(
                    "ir.rule",
                    "search_read",
                    [["model_id", "=", model_id]],
                    fields=[
                        "id",
                        "name",
                        "model_id",
                        "domain_force",
                        "groups",
                        "active",
                        "perm_read",
                        "perm_write",
                        "perm_create",
                        "perm_unlink",
                    ],
                    limit=limit,
                ),
            )
            if error:
                metadata_errors.append(error)
            elif isinstance(rules_raw, list):
                for rule in rules_raw:
                    if not isinstance(rule, dict):
                        continue
                    if not rule.get("active", True) or not rule.get(
                        permission_field, True
                    ):
                        continue
                    active_rules.append(rule)
                    if _m2m_ids(rule.get("groups")):
                        group_bound_rules.append(rule)
                    else:
                        global_rules.append(rule)
                    if _rule_applies(rule, user_group_ids):
                        applicable_rules.append(rule)

        actual_count: int | None = None
        if expected_count is not None or normalized_record_ids:
            count_value, error = _safe_odoo_read(
                f"{model}.search_count",
                lambda: odoo.execute_method(model, "search_count", count_domain),
            )
            if error:
                metadata_errors.append(error)
            elif isinstance(count_value, int):
                actual_count = count_value

        granting_acl_rows = [
            row
            for row in acl_rows
            if bool(row.get(permission_field)) and _acl_row_applies(row, user_group_ids)
        ]
        # NESA A9: collapse the three redundant membership lists into the few
        # groups that carry the decision, and give them readable names.
        decisive_group_ids: set[int] = set()
        for row in granting_acl_rows:
            group_id = _m2o_id(row.get("group_id"))
            if group_id is not None:
                decisive_group_ids.add(group_id)
        member_group_ids = user_group_ids or set()
        for rule in applicable_rules:
            decisive_group_ids |= _m2m_ids(rule.get("groups")) & member_group_ids
        relevant_groups: list[Dict[str, Any]] = []
        if decisive_group_ids:
            group_rows, error = _safe_odoo_read(
                "res.groups.read",
                lambda: odoo.execute_method(
                    "res.groups",
                    "read",
                    sorted(decisive_group_ids),
                    fields=["display_name"],
                ),
            )
            if error:
                metadata_errors.append(error)
            elif isinstance(group_rows, list):
                relevant_groups = [
                    {
                        "id": row.get("id"),
                        "name": row.get("display_name"),
                        "member": row.get("id") in member_group_ids,
                    }
                    for row in group_rows
                    if isinstance(row, dict)
                ]
        user_record = current_user.get("record")
        compact_user: Dict[str, Any] = {
            "uid": current_user.get("uid"),
            "login": (user_record or {}).get("login"),
            "name": (user_record or {}).get("name"),
            "group_count": len(user_group_ids) if user_group_ids is not None else None,
            "decisive_groups": relevant_groups,
        }
        if verbose:
            compact_user["context"] = current_user.get("context")
            compact_user["record"] = user_record
            compact_user["all_group_ids"] = current_user.get("group_ids")
            compact_user["direct_group_ids"] = current_user.get("direct_group_ids")
            compact_user["group_field"] = current_user.get("group_field")
            compact_user["all_group_field"] = current_user.get("all_group_field")
        else:
            context_value = current_user.get("context")
            if isinstance(context_value, dict):
                compact_user["context"] = {
                    key: context_value[key]
                    for key in ("lang", "tz", "uid", "allowed_company_ids")
                    if key in context_value
                }
        diagnosis_codes = _access_diagnosis_codes(
            metadata_errors=metadata_errors,
            acl_rows=acl_rows,
            granting_acl_rows=granting_acl_rows,
            active_rules=active_rules,
            applicable_rules=applicable_rules,
            actual_count=actual_count,
            expected_count=expected_count,
            record_ids=normalized_record_ids,
        )
        return {
            "success": True,
            "tool": "diagnose_access",
            "model": model,
            "operation": operation,
            "permission_field": permission_field,
            "domain": normalized_domain,
            "record_ids": normalized_record_ids,
            "expected_count": expected_count,
            "actual_count": actual_count,
            "model_metadata": {"record": model_record},
            "current_user": compact_user,
            "verbose": verbose,
            "access": {
                "rows": acl_rows if verbose else None,
                "row_count": len(acl_rows),
                "granting_rows": (
                    granting_acl_rows
                    if verbose
                    else [_compact_acl_row(row) for row in granting_acl_rows]
                ),
                "granting_count": len(granting_acl_rows),
            },
            "rules": {
                "included": include_rules,
                "active": active_rules if verbose else None,
                "active_count": len(active_rules),
                "global": global_rules if verbose else None,
                "global_count": len(global_rules),
                "group_bound": group_bound_rules if verbose else None,
                "group_bound_count": len(group_bound_rules),
                "applicable": (
                    applicable_rules
                    if verbose
                    else [_compact_rule_row(rule) for rule in applicable_rules]
                ),
                "applicable_count": len(applicable_rules),
            },
            "diagnosis": {"codes": diagnosis_codes},
            "metadata_errors": metadata_errors,
            "metadata_used": {
                "live_odoo": True,
                "acl": bool(acl_rows),
                "rules": include_rules,
                "current_user": current_user["record"] is not None,
                "sudo": False,
                "impersonation": False,
            },
        }
    except Exception as e:
        return error_response("diagnose_access", e, model=model)


@mcp.tool(
    description="Report Odoo upgrade and JSON-2 migration risks",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def upgrade_risk_report(
    source_version: Optional[str] = None,
    target_version: Optional[str] = None,
    modules: Optional[List[Dict[str, Any]]] = None,
    methods: Optional[List[Dict[str, Any]]] = None,
    source_findings: Optional[List[Dict[str, Any]]] = None,
    observed_errors: Optional[List[Any]] = None,
    use_live_metadata: bool = False,
    include_debug: bool = False,
) -> Dict[str, Any]:
    """
    Build an input-driven upgrade risk report without executing Odoo calls.
    """
    report = build_upgrade_risk_report(
        source_version=source_version,
        target_version=target_version,
        modules=modules,
        methods=methods,
        source_findings=source_findings,
        observed_errors=observed_errors,
        include_debug=include_debug,
    )
    if use_live_metadata:
        report["risks"].append(
            {
                "code": "live_metadata_not_used",
                "severity": "info",
                "evidence": "upgrade_risk_report is input-driven in this release.",
                "recommendation": "Pass module/method/source findings explicitly.",
            }
        )
    return report


@mcp.tool(
    description="Classify Odoo requirements into fit/gap implementation buckets",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def fit_gap_report(
    requirements: List[Any],
    available_models: Optional[List[str]] = None,
    available_fields: Optional[Dict[str, Any]] = None,
    installed_modules: Optional[List[Any]] = None,
    business_context: Optional[Dict[str, Any]] = None,
    use_live_metadata: bool = False,
) -> Dict[str, Any]:
    """
    Normalize requirements into standard/config/Studio/custom/avoid/unknown buckets.
    """
    report = build_fit_gap_report(
        requirements=requirements,
        available_models=available_models,
        available_fields=available_fields,
        installed_modules=installed_modules,
        business_context=business_context,
    )
    if use_live_metadata:
        report["assumptions"].append(
            "fit_gap_report is input-driven in this release; use list_models/get_model_fields first."
        )
    return report


@mcp.tool(
    description="Read a bounded profile of the connected Odoo environment",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def get_odoo_profile(
    ctx: Context,
    include_modules: bool = True,
    module_limit: int = 100,
) -> Dict[str, Any]:
    """Return server, user-context, transport, and installed-module metadata."""
    try:
        module_limit = clamp_limit(module_limit, maximum=500)
        odoo = ctx.request_context.lifespan_context.odoo
        if include_modules:
            profile = odoo.get_profile(module_limit=module_limit)
        else:
            profile = {
                "url": getattr(odoo, "url", None),
                "hostname": getattr(odoo, "hostname", None),
                "database": getattr(odoo, "db", None),
                "username": getattr(odoo, "username", None),
                "transport": getattr(odoo, "transport", None),
                "timeout": getattr(odoo, "timeout", None),
                "verify_ssl": getattr(odoo, "verify_ssl", None),
                "json2_database_header": getattr(odoo, "json2_database_header", None),
                "server_version": odoo.get_server_version(),
                "user_context": odoo.get_user_context(),
                "installed_modules": [],
                "installed_module_count": None,
            }
        return {
            "success": True,
            "tool": "get_odoo_profile",
            "profile": profile,
            "metadata_used": {
                "live_odoo": True,
                "installed_modules": include_modules,
            },
        }
    except Exception as e:
        return error_response("get_odoo_profile", e)


@mcp.tool(
    description="Build and cache a bounded Odoo model schema catalog",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def schema_catalog(
    ctx: Context,
    query: Optional[str] = None,
    models: Optional[List[str]] = None,
    include_fields: bool = False,
    refresh: bool = False,
    limit: int = 50,
) -> Dict[str, Any]:
    """Return a cached catalog of model names, labels, and optional fields."""
    try:
        limit = clamp_limit(limit, maximum=500)
        if models:
            for model_name in models:
                validate_model_name(model_name)

        app_context = ctx.request_context.lifespan_context
        cache_key = json.dumps(
            {
                "query": query,
                "models": sorted(models or []),
                "include_fields": include_fields,
                "limit": limit,
            },
            sort_keys=True,
        )
        if not refresh and cache_key in app_context.schema_cache:
            cached = dict(app_context.schema_cache[cache_key])
            cached["metadata_used"] = {**cached["metadata_used"], "cache_hit": True}
            return cached

        odoo = app_context.odoo
        raw_models = odoo.get_models()
        if "error" in raw_models:
            return {
                "success": False,
                "tool": "schema_catalog",
                "error": raw_models["error"],
            }

        model_names = list(raw_models.get("model_names", []))
        model_details = raw_models.get("models_details", {})
        if models:
            model_filter = set(models)
            model_names = [name for name in model_names if name in model_filter]
        if query:
            query_lower = query.lower()
            model_names = [
                name
                for name in model_names
                if query_lower in name.lower()
                or query_lower
                in str(model_details.get(name, {}).get("name", "")).lower()
            ]

        records: List[Dict[str, Any]] = []
        for model_name in model_names[:limit]:
            record: Dict[str, Any] = {
                "model": model_name,
                "name": model_details.get(model_name, {}).get("name", ""),
            }
            if include_fields:
                fields = odoo.get_model_fields(model_name)
                record["fields"] = fields if "error" not in fields else {}
                record["field_error"] = (
                    fields.get("error") if "error" in fields else None
                )
            records.append(record)

        report = {
            "success": True,
            "tool": "schema_catalog",
            "count": len(records),
            "result": records,
            "metadata_used": {
                "live_odoo": True,
                "fields_get": include_fields,
                "cache_hit": False,
            },
        }
        app_context.schema_cache[cache_key] = dict(report)
        return report
    except Exception as e:
        return error_response("schema_catalog", e)


@mcp.tool(
    description=(
        "Read-only dry run for create, write, or unlink. Issues NO approval "
        "token — validate_write mints the token and it is valid for 600 "
        "seconds. Chain: (optional preview_write) -> validate_write -> "
        "execute_approved_write(confirm=true)."
    ),
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def preview_write(
    model: str,
    operation: str,
    values: Optional[Dict[str, Any]] = None,
    record_ids: Optional[List[int]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a canonical approval token for a later approved write."""
    try:
        validate_model_name(model)
        denied = hard_deny_result("preview_write", model, operation)
        if denied:
            return denied
        return build_write_preview_report(
            model=model,
            operation=operation,
            values=values,
            record_ids=record_ids,
            context=context,
        )
    except Exception as e:
        return error_response("preview_write", e, model=model)


@mcp.tool(
    description=(
        "Validate a write payload against live fields_get metadata and mint the "
        "approval token for execute_approved_write. The token is valid for 600 "
        "seconds (approval_status.expires_at_iso) and is bound to this exact "
        "payload — do not research or ask back between validate and execute."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def validate_write(
    ctx: Context,
    model: str,
    operation: str,
    values: Optional[Dict[str, Any]] = None,
    record_ids: Optional[List[int]] = None,
    context: Optional[Dict[str, Any]] = None,
    fields_metadata: Optional[Dict[str, Any]] = None,
    use_live_metadata: bool = True,
) -> Dict[str, Any]:
    """Validate write shape and return an approval payload when safe."""
    try:
        validate_model_name(model)
        denied = hard_deny_result("validate_write", model, operation)
        if denied:
            return denied
        metadata_source = "input" if fields_metadata is not None else "none"
        if fields_metadata is None and use_live_metadata:
            metadata_source = "server"
            fields_metadata = (
                ctx.request_context.lifespan_context.odoo.get_model_fields(model)
            )
            if "error" in fields_metadata:
                return {
                    "success": False,
                    "tool": "validate_write",
                    "error": fields_metadata["error"],
                    "metadata_used": {"fields_get": False, "source": metadata_source},
                }
            if not fields_metadata:
                return {
                    "success": False,
                    "tool": "validate_write",
                    "error": "live fields_get metadata was empty; refusing to approve writes",
                    "metadata_used": {"fields_get": False, "source": metadata_source},
                    "approval_status": {
                        "stored": False,
                        "source": metadata_source,
                        "reason": "trusted live metadata was empty",
                    },
                }
        report = validate_write_report(
            model=model,
            operation=operation,
            values=values,
            record_ids=record_ids,
            context=context,
            fields_metadata=fields_metadata,
            metadata_source=metadata_source,
        )
        trusted_live_metadata = (
            metadata_source == "server"
            and isinstance(fields_metadata, dict)
            and bool(fields_metadata)
        )
        if trusted_live_metadata:
            stored = register_write_approval(
                ctx.request_context.lifespan_context, report
            )
            approval = report.get("approval")
            expires_at = (
                approval.get("expires_at") if isinstance(approval, dict) else None
            )
            report["approval_status"] = {
                "stored": stored,
                "expires_in_seconds": WRITE_APPROVAL_TTL_SECONDS,
                "expires_at_iso": (
                    datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
                    if isinstance(expires_at, (int, float))
                    else None
                ),
                "source": metadata_source,
            }
        else:
            report["approval_status"] = {
                "stored": False,
                "source": metadata_source,
                "reason": (
                    "execute_approved_write requires validation against trusted "
                    "live Odoo fields_get metadata"
                ),
            }
        return report
    except Exception as e:
        return error_response("validate_write", e, model=model)


@mcp.tool(
    description=(
        "Execute a create/write/unlink that validate_write approved. Requires "
        "the approval object from validate_write (valid 600 seconds) plus "
        "confirm=true. On rejection the answer carries reason_code and remedy."
    ),
    annotations=DESTRUCTIVE_TOOL,
    structured_output=True,
)
def execute_approved_write(
    ctx: Context,
    approval: Dict[str, Any],
    confirm: bool = False,
) -> Dict[str, Any]:
    """Execute create/write/unlink only after token, confirm, and env gates pass."""
    try:
        if not str((approval or {}).get("token", "")).strip():
            # NESA A2: the most common first-timer mistake is passing the
            # preview_write payload straight through.  Say so, instead of
            # reporting a token mismatch for a token that was never there.
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": (
                    "approval token rejected (token_missing): the approval "
                    "object carries no token"
                ),
                "reason_code": "token_missing",
                "remedy": (
                    "preview_write issues no token. Call validate_write with "
                    "the same arguments and pass its 'approval' object here."
                ),
                "approval_ttl_seconds": WRITE_APPROVAL_TTL_SECONDS,
            }
        is_valid, expected_token = verify_write_approval(approval)
        if not is_valid:
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "approval token does not match the canonical payload",
                "reason_code": "token_payload_mismatch",
                "remedy": (
                    "The token does not belong to these values. Re-run "
                    "validate_write with the exact payload you intend to write."
                ),
                "expected_token": expected_token,
            }
        model = str(approval.get("model", ""))
        operation = str(approval.get("operation", "")).strip().lower()
        validate_model_name(model)
        if operation not in {"create", "write", "unlink"}:
            raise ValueError("operation must be one of create, write, or unlink")
        denied = hard_deny_result("execute_approved_write", model, operation)
        if denied:
            return denied
        # Both gates below are local and cost nothing, and consuming the token
        # is irreversible: the store deliberately does not re-arm the same
        # deterministic token.  Checking them first means a forgotten
        # confirm=true no longer burns a valid approval.
        if not confirm:
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "confirm=true is required for destructive execution",
                "reason_code": "confirm_missing",
                "remedy": "Repeat this call with confirm=true. The token is still valid.",
            }
        if not writes_enabled():
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "write execution disabled; set ODOO_MCP_ENABLE_WRITES=1 to enable",
                "reason_code": "writes_disabled",
                "remedy": (
                    "This is a deployment setting, not a permission problem. "
                    "The token was not consumed."
                ),
            }
        app_context = ctx.request_context.lifespan_context
        validation_record = require_validated_write_approval(app_context, approval)
        if not validation_record.get("ok"):
            reason_code = str(validation_record.get("reason_code", "token_rejected"))
            remedies = {
                "token_missing": (
                    "Call validate_write to obtain an approval token "
                    "(preview_write issues none)."
                ),
                "token_unknown": (
                    "The token was never validated, or the MCP process restarted "
                    "since. Re-run validate_write."
                ),
                "token_expired": (
                    f"Approval tokens are valid for {WRITE_APPROVAL_TTL_SECONDS} "
                    "seconds. Re-run validate_write directly before executing."
                ),
                "token_already_consumed": (
                    "This token was already used — the write may have been "
                    "executed. Verify the record before retrying."
                ),
                "token_foreign_user": (
                    "The token belongs to a different Odoo user. Re-run "
                    "validate_write with the current credentials."
                ),
                "payload_mismatch": (
                    "The payload changed after validation. Re-run validate_write "
                    "with the exact values you intend to write."
                ),
                "token_store_unreachable": (
                    "Odoo could not be reached for token validation. Retry once; "
                    "if it persists this is an infrastructure problem, not a "
                    "permission problem."
                ),
            }
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": (
                    f"approval token rejected ({reason_code}): "
                    f"{validation_record.get('reason')}"
                ),
                "reason_code": reason_code,
                "remedy": remedies.get(reason_code, "Re-run validate_write."),
                "approval_ttl_seconds": WRITE_APPROVAL_TTL_SECONDS,
            }
        # NESA Patch 3 — payload-hash already verified inside mcp_consume_approval;
        # this extra equality check stays as defense-in-depth in case the DB store
        # ever returns a partial record. Cheap dict-equality, no roundtrip.
        stored_payload = validation_record.get("payload") or {}
        if write_approval_payload(approval) != stored_payload:
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "approval payload does not match the stored validation record",
            }

        values = dict(approval.get("values") or {})
        record_ids = [int(record_id) for record_id in approval.get("record_ids") or []]
        context = dict(approval.get("context") or {})
        sanitized_kwargs, removed_context_keys = sanitized_execution_kwargs(
            {"context": context} if context else {}
        )
        kwargs = sanitized_kwargs
        if operation == "create":
            args: List[Any] = [values]
        elif operation == "write":
            args = [record_ids, values]
        else:
            args = [record_ids]

        audit_odoo_execution("execute_approved_write", model, operation)
        result = app_context.odoo.execute_method(model, operation, *args, **kwargs)
        # NESA Patch 3 — DB-backed token revocation (replaces in-memory pop).
        revoke_write_approval(app_context, str(approval.get("token", "")))
        response = {
            "success": True,
            "tool": "execute_approved_write",
            "model": model,
            "operation": operation,
            "result": result,
        }
        if removed_context_keys:
            response["warnings"] = [
                "Removed audit-suppression context keys: "
                + ", ".join(removed_context_keys)
            ]
        return response
    except Exception as e:
        return error_response("execute_approved_write", e)


@mcp.tool(
    description=(
        "Scan local Odoo addon source without importing addon code. Requires "
        "ODOO_ADDONS_PATHS to be configured on the MCP host; fails loudly when "
        "it is not, instead of reporting an empty scan."
    ),
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def scan_addons_source(
    addons_paths: Optional[List[str]] = None,
    max_files: int = 200,
    max_file_bytes: int = 300_000,
) -> Dict[str, Any]:
    """Summarize manifests, custom models, risky methods, views, and ACL files.

    NESA A5: an unconfigured scan used to answer ``success: true`` with zero
    modules, which reads like "there is no addon code" rather than "I cannot
    look".  Missing or unreadable roots are now hard errors.
    """
    try:
        max_files = clamp_limit(max_files, maximum=1000)
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be greater than 0")
        roots = restrict_addons_paths(addons_paths)
        effective_roots = roots or [str(root) for root in configured_addons_roots()]
        if not effective_roots:
            return {
                "success": False,
                "tool": "scan_addons_source",
                "error": (
                    "No addons roots configured: ODOO_ADDONS_PATHS is unset on "
                    "the MCP host, so source analysis is unavailable. This is "
                    "NOT evidence that the deployment has no custom addons."
                ),
                "error_type": "not_configured",
                "retryable": False,
                "configured_addons_paths": [],
            }
        unreadable = [
            root
            for root in effective_roots
            if not os.path.isdir(root) or not os.access(root, os.R_OK | os.X_OK)
        ]
        if len(unreadable) == len(effective_roots):
            return {
                "success": False,
                "tool": "scan_addons_source",
                "error": (
                    "All configured addons roots are missing or unreadable for "
                    "the MCP service user: " + ", ".join(unreadable)
                ),
                "error_type": "not_readable",
                "retryable": False,
                "configured_addons_paths": effective_roots,
            }
        report = scan_addons_source_report(
            addons_paths=roots,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
        )
        if unreadable:
            report.setdefault("warnings", []).append(
                "Unreadable addons roots were skipped: " + ", ".join(unreadable)
            )
        return report
    except Exception as e:
        return error_response("scan_addons_source", e)


@mcp.tool(
    description="Build a validated Odoo domain from structured conditions",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def build_domain(
    conditions: List[Dict[str, Any]],
    logical_operator: str = "and",
    fields_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build safe domain arrays for search_records and Odoo ORM calls."""
    try:
        return build_domain_report(
            conditions=conditions,
            logical_operator=logical_operator,
            fields_metadata=fields_metadata,
        )
    except Exception as e:
        return error_response("build_domain", e)


@mcp.tool(
    description="Report expected modules, models, and safe discovery calls for a business pack",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def business_pack_report(
    ctx: Context,
    pack: str,
    use_live_metadata: bool = True,
) -> Dict[str, Any]:
    """Summarize a domain pack such as sales, crm, inventory, accounting, or hr."""
    try:
        available_models: List[str] | None = None
        installed_modules: List[str] | None = None
        if use_live_metadata:
            odoo = ctx.request_context.lifespan_context.odoo
            models_report = odoo.get_models()
            if "error" not in models_report:
                available_models = list(models_report.get("model_names", []))
            installed_modules = [
                str(module.get("name"))
                for module in odoo.get_installed_modules(limit=200)
                if module.get("name")
            ]
        return build_business_pack_report(
            pack=pack,
            available_models=available_models,
            installed_modules=installed_modules,
        )
    except Exception as e:
        return error_response("business_pack_report", e)


@mcp.tool(
    description="Report this MCP server's non-secret runtime safety posture",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def health_check() -> Dict[str, Any]:
    """Return local process health and hardening flags without opening Odoo."""
    surface_counts = mcp_surface_counts()
    return {
        "success": True,
        "tool": "health_check",
        "server": {
            "name": mcp.name,
            "instructions": mcp.instructions,
            **surface_counts,
        },
        "runtime": runtime_security_report(),
    }


# Positional index of ``limit`` / ``fields`` in the Odoo 18 ORM signatures
# that execute_method is most often (mis)used for.  search_read(domain, fields,
# offset, limit, order), search(domain, offset, limit, order),
# search_fetch(domain, field_names, offset, limit, order), read(ids, fields).
_EXECUTE_READ_LIMIT_POSITION = {"search_read": 3, "search": 2, "search_fetch": 3}
_EXECUTE_READ_FIELDS_POSITION = {"search_read": 1, "search_fetch": 1, "read": 1}
_EXECUTE_READ_FIELDS_KWARG = {"search_read": "fields", "search_fetch": "field_names", "read": "fields"}


def _bounded_execute_limit(value: Any) -> int:
    """Clamp an execute_method ``limit`` to the read-tool page size.

    ``None``/``False``/``0`` mean "no limit" in the ORM and therefore become
    the cap; anything that is not a positive integer is rejected.
    """
    if value is None or value is False or value == 0:
        return MAX_SEARCH_LIMIT
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(
            f"limit must be a positive integer (max {MAX_SEARCH_LIMIT}), got {value!r:.60}"
        )
    return min(value, MAX_SEARCH_LIMIT)


def bound_execute_method_read(
    app_context: "AppContext",
    odoo: OdooClient,
    model: str,
    method: str,
    args: List[Any],
    kwargs: Dict[str, Any],
) -> tuple[List[Any], Dict[str, Any], List[str]]:
    """Apply the read-tool limits to reads that arrive through execute_method.

    search_records/read_records cap the page at ``MAX_SEARCH_LIMIT`` and never
    return binary fields unless named.  The same ``search_read`` issued through
    execute_method used to bypass both, so one unbounded call on ir.attachment
    could hand the agent every ``datas`` blob in the database.  Explicit field
    lists win; limits are clamped to the cap; every adjustment is reported.
    """
    notes: List[str] = []
    limit_pos = _EXECUTE_READ_LIMIT_POSITION.get(method)
    if limit_pos is not None:
        if len(args) > limit_pos:
            bounded = _bounded_execute_limit(args[limit_pos])
            if bounded != args[limit_pos]:
                notes.append(
                    f"limit {args[limit_pos]!r} clamped to {bounded}. Prefer "
                    "search_records, which pages and reports total_count."
                )
            args[limit_pos] = bounded
        elif "limit" in kwargs:
            bounded = _bounded_execute_limit(kwargs["limit"])
            if bounded != kwargs["limit"]:
                notes.append(
                    f"limit {kwargs['limit']!r} clamped to {bounded}. Prefer "
                    "search_records, which pages and reports total_count."
                )
            kwargs["limit"] = bounded
        else:
            kwargs["limit"] = MAX_SEARCH_LIMIT
            notes.append(
                f"No limit given; limit={MAX_SEARCH_LIMIT} applied. Prefer "
                "search_records, which pages and reports total_count."
            )
    if method == "read":
        ids = args[0] if args else kwargs.get("ids")
        if isinstance(ids, (list, tuple)) and len(ids) > MAX_SEARCH_LIMIT:
            raise ValueError(
                f"read accepts at most {MAX_SEARCH_LIMIT} record ids per call "
                f"(got {len(ids)}); page the ids or use read_records."
            )
    fields_pos = _EXECUTE_READ_FIELDS_POSITION.get(method)
    if fields_pos is not None:
        fields_kwarg = _EXECUTE_READ_FIELDS_KWARG[method]
        positional_present = len(args) > fields_pos
        keyword_present = fields_kwarg in kwargs
        if positional_present and keyword_present:
            raise ValueError(
                f"{fields_kwarg} was given both positionally and as a keyword"
            )
        explicit = args[fields_pos] if positional_present else kwargs.get(fields_kwarg)
        if not explicit:
            # ``None``/``[]`` mean "every field" in the ORM, binaries included.
            try:
                expanded, _ = resolve_read_fields(app_context, odoo, model, ["*"])
            except Exception as exc:
                raise ValueError(
                    f"Cannot expand the omitted {fields_kwarg} for {model} "
                    f"({compact_error_message(exc)[0]}); name the fields you "
                    "need or use search_records/read_records."
                ) from exc
            if positional_present:
                args[fields_pos] = expanded
            else:
                kwargs[fields_kwarg] = expanded
            notes.append(
                f"No {fields_kwarg} given; every non-binary field was requested "
                "instead of the raw default that includes binary payloads. "
                "Name the fields you need, or use read_records."
            )
    return args, kwargs, notes


def is_unmarshallable_response_fault(exc: BaseException) -> bool:
    """True for an Odoo-side XML-RPC response encoding fault.

    ``service.model.execute`` runs the model method through an inner cursor and
    commits it before returning the value to the HTTP controller. A later
    marshalling failure therefore loses only the result; repeating the method
    could duplicate its committed effect.
    """
    import xmlrpc.client

    # Only a Fault proves the request reached Odoo.  xmlrpc.client raises a
    # client-side TypeError with the very same text when *our* arguments
    # contain None — nothing was sent then, and "do not repeat" would lie.
    if not isinstance(exc, xmlrpc.client.Fault):
        return False
    if exc.faultCode != 1:
        return False
    message = str(exc.faultString).casefold()
    return "cannot marshal" in message and (
        "xmlrpc/client.py" in message
        or "unless allow_none is enabled" in message
        or "objects" in message
    )


@mcp.tool(
    description=(
        "Run one Odoo model method, e.g. sale.order.action_confirm or "
        "mail.activity.action_done, with the acting user's rights. Not for "
        "reads (use search_records/read_records/aggregate_records) and not "
        "for create/write/unlink on persistent models (use validate_write -> "
        "execute_approved_write). Reads that still arrive here are capped at "
        "100 rows and exclude binary fields unless named."
    ),
    annotations=DESTRUCTIVE_TOOL,
    structured_output=True,
)
def execute_method(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'sale.order'.")],
    method: Annotated[
        str,
        Field(
            description=(
                "Method name, e.g. 'action_confirm'. For plain reads use "
                "search_records/read_records instead; create/write/unlink on "
                "persistent models go through validate_write -> "
                "execute_approved_write."
            )
        ),
    ],
    args: Annotated[
        Optional[List[Any]],
        Field(
            description=(
                "Positional arguments. Record methods take the id list first, "
                "e.g. [[42]] for sale.order.action_confirm on id 42."
            )
        ),
    ] = None,
    kwargs: Annotated[
        Optional[Dict[str, Any]],
        Field(description="Keyword arguments, e.g. {\"limit\": 20} or {\"context\": {...}}."),
    ] = None,
) -> Dict[str, Any]:
    """
    Execute a custom method on an Odoo model

    Parameters:
        model: The model name (e.g., 'res.partner')
        method: Method name to execute
        args: Positional arguments
        kwargs: Keyword arguments

    Returns:
        Dictionary containing:
        - success: Boolean indicating success
        - result: Result of the method (if success)
        - error: Error message (if failure)
    """
    app_context = ctx.request_context.lifespan_context
    try:
        validate_model_name(model)
        validate_method_name(method)
        safety = classify_method_safety(method)
        if method.startswith("_"):
            return {
                "success": False,
                "error": "Private underscore methods cannot be called via execute_method.",
                "classification": safety,
            }
        # Hard-deny is evaluated before every other gate so that no exemption
        # below (including the transient one) can widen it.
        deny_prefix = denied_method_prefix(model, method)
        if deny_prefix:
            return {
                "success": False,
                "error": (
                    "Method execution is blocked by the deployment's hard-deny "
                    f"policy ({deny_prefix}). This cannot be bypassed by native "
                    "ACL parity, an exact allowlist, or broad mode."
                ),
                "classification": safety,
            }
        transient_model = False
        transient_profile: Optional[Dict[str, Any]] = None
        exempt = False
        relation_block: Optional[str] = None
        gated_method = (
            method in DESTRUCTIVE_METHODS or method in WRITE_EQUIVALENT_METHODS
        )
        if gated_method:
            # NESA A1: filling in a wizard is not a business write.  Transient
            # records live in scratch tables that ir.autovacuum clears, so
            # forcing them through preview -> validate -> execute cost four
            # calls per wizard field and bought no safety.  unlink and the
            # write-equivalent aliases stay on the chain regardless — and so
            # does any wizard that overrides create/write, because those
            # overrides can and do write persistent records.
            exempt, transient_profile = transient_write_is_exempt(
                app_context, app_context.odoo, model, method,
            )
            if exempt:
                # Defense in depth: even a reviewed wizard must not be used as
                # a pipe into a persistent comodel via x2many commands.
                relation_reason = x2many_commands_are_inert(
                    app_context, app_context.odoo, model, method, args, kwargs,
                )
                if relation_reason:
                    exempt = False
                    relation_block = relation_reason
            if transient_profile is None:
                transient_profile = transient_write_profile(
                    app_context, app_context.odoo, model,
                )
            transient_model = bool((transient_profile or {}).get("transient"))
        if gated_method and not exempt:
            if relation_block:
                reason = (
                    f"{relation_block} Use validate_write -> "
                    "execute_approved_write for this write."
                )
            elif transient_model and method in TRANSIENT_EXEMPT_METHODS:
                overrides = (transient_profile or {}).get("overrides") or []
                inverse_fields = (transient_profile or {}).get("inverse_fields") or []
                if not overrides and not inverse_fields:
                    reason = (
                        f"{model} is a transient wizard, but it has not been "
                        "reviewed for direct writes. Use validate_write -> "
                        "execute_approved_write, or have the model reviewed "
                        f"and add '{model}.{method}' to the side-effect "
                        "allowlist. Being transient is not on its own a "
                        "guarantee that writing it stays inside the wizard."
                    )
                else:
                    reason = (
                        f"{model} is transient, but {method!r} is not inert on "
                        f"it (overrides={list(overrides)}, "
                        f"inverse_fields={list(inverse_fields)[:5]}), so it can "
                        "write persistent records. Use validate_write -> "
                        "execute_approved_write."
                    )
            elif transient_model:
                reason = (
                    f"{method!r} stays on the approved-write chain even for "
                    "transient models — only create and write are exempt. Use "
                    "validate_write -> execute_approved_write."
                )
            else:
                reason = (
                    "Direct execute_method blocks CRUD and write-equivalent "
                    "aliases on persistent models. Use validate_write -> "
                    "execute_approved_write (preview_write is an optional "
                    "read-only dry run). Transient wizard models accept "
                    "create/write directly as long as they do not override "
                    "those methods."
                )
            return {
                "success": False,
                "error": reason,
                "transient_model": transient_model,
            }
        review_required = safety["safety"] in {"side_effect", "unknown"}
        if (
            review_required
            and not native_acl_parity_enabled()
            and not side_effect_method_allowed(model, method)
            and not truthy_env("ODOO_MCP_ALLOW_UNKNOWN_METHODS")
        ):
            from . import _nesa_db_allowlist

            model_prefix = f"{model}."
            allowed_here = sorted(
                entry
                for entry in set(_nesa_db_allowlist.methods()) | set(allowed_side_effect_methods())
                if entry.startswith(model_prefix)
            )
            if allowed_here:
                alternatives = (
                    f"Methods reviewed for {model}: "
                    + ", ".join(entry[len(model_prefix):] for entry in allowed_here)
                    + "."
                )
            else:
                alternatives = f"No method of {model} is on the reviewed list yet."
            return {
                "success": False,
                "error": (
                    f"{model}.{method} is a side-effect method that has not been "
                    "reviewed for this deployment, so it is not executed. "
                    f"{alternatives} Call list_allowed_methods(model=...) for "
                    "the full policy. If the goal is a create/write, use "
                    "validate_write -> execute_approved_write. Reviewing a "
                    "method is an administrator task in Odoo (NESA MCP > "
                    "Allowed Methods), not something this session can change."
                ),
                "reason_code": "method_not_reviewed",
                "allowed_methods_for_model": allowed_here,
                "classification": safety,
            }
        args = args or []
        kwargs, removed_context_keys = sanitized_execution_kwargs(kwargs)
        warnings: List[str] = []

        # Special handling for search methods like search, search_count, search_read
        search_methods = ["search", "search_count", "search_read"]
        if method in search_methods and args:
            # Search methods usually have domain as the first parameter
            # args: [[domain], limit, offset, ...] or [domain, limit, offset, ...]
            normalized_args = list(
                args
            )  # Create a copy to avoid affecting the original args

            if len(normalized_args) > 0:
                normalized_args[0] = normalize_domain_input(normalized_args[0])
                args = normalized_args

        odoo = app_context.odoo
        args, kwargs, read_notes = bound_execute_method_read(
            app_context, odoo, model, method, list(args), dict(kwargs),
        )
        warnings.extend(read_notes)
        audit_odoo_execution("execute_method", model, method)
        call_args = list(args)
        call_kwargs = dict(kwargs)
        try:
            result = call_with_transport_retry(
                lambda: odoo.execute_method(model, method, *call_args, **call_kwargs),
                label=f"{model}.{method}",
                idempotent=method in IDEMPOTENT_READ_METHODS,
            )
        except Exception as call_exc:
            if not is_unmarshallable_response_fault(call_exc):
                raise
            is_read = method in IDEMPOTENT_READ_METHODS
            logger.warning(
                "[xmlrpc-result-unavailable] %s.%s completed but its result "
                "could not be marshalled; automatic retry suppressed (read=%s)",
                model,
                method,
                is_read,
            )
            if is_read:
                result_warning = (
                    f"{model}.{method} completed, but XML-RPC could not encode "
                    "its return value. This read may be retried after narrowing "
                    "the requested fields or fields_get attributes."
                )
            else:
                result_warning = (
                    f"{model}.{method} executed and committed, but XML-RPC "
                    "could not encode its return value. Do not repeat it; "
                    "read the target record back to verify the effect."
                )
            warnings.append(result_warning)
            if removed_context_keys:
                warnings.append(
                    "Removed audit-suppression context keys: "
                    + ", ".join(removed_context_keys)
                )
            response = {
                "success": True,
                "result": None,
                "result_unavailable": True,
                "warnings": warnings,
                "classification": safety,
            }
            if transient_model:
                response["transient_model"] = True
            return response
        response: Dict[str, Any] = {"success": True, "result": result}
        if warnings:
            response["warnings"] = warnings
        if transient_model:
            response["transient_model"] = True
        result_counts = _act_window_result_counts(app_context, odoo, model, result)
        if result_counts is not None:
            # NESA A8: a bare act_window dict tells the agent nothing about
            # whether the action produced rows.  Count them here instead of
            # forcing a blind follow-up read.
            response["result_counts"] = result_counts
        if removed_context_keys:
            response.setdefault("warnings", []).append(
                "Removed audit-suppression context keys: "
                + ", ".join(removed_context_keys)
            )
        return response
    except Exception as e:
        return error_response("execute_method", e, model=model, method=method)


@mcp.tool(
    description="List Odoo models with optional name filtering",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def list_models(
    ctx: Context,
    query: Annotated[
        Optional[str],
        Field(description="Case-insensitive substring of technical name or label, e.g. 'invoice'."),
    ] = None,
    limit: Annotated[int, Field(description="Maximum models to return (cap 500).", ge=1)] = 100,
) -> Dict[str, Any]:
    """
    List available Odoo model technical names and display names.

    Prefer this read-only tool over execute_method when discovering models.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        limit = clamp_limit(limit, maximum=500)
        models = _cached_models(ctx.request_context.lifespan_context, odoo)
        if "error" in models:
            return error_response("list_models", RuntimeError(str(models["error"])))

        model_names = models.get("model_names", [])
        models_details = models.get("models_details", {})
        if query:
            query_lower = query.lower()
            model_names = [
                model_name
                for model_name in model_names
                if query_lower in model_name.lower()
                or query_lower
                in str(models_details.get(model_name, {}).get("name", "")).lower()
            ]

        records = [
            {
                "model": model_name,
                "name": models_details.get(model_name, {}).get("name", ""),
            }
            for model_name in model_names[:limit]
        ]
        return {"success": True, "count": len(records), "result": records}
    except Exception as e:
        return error_response("list_models", e)


FIELD_METADATA_DEFAULT_ATTRIBUTES = (
    "type", "string", "required", "readonly", "relation", "selection", "store",
)


def project_field_metadata(
    fields: Dict[str, Any],
    *,
    field_names: Optional[List[str]] = None,
    query: Optional[str] = None,
    attributes: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Narrow a raw ``fields_get`` result for an agent.

    A full ``fields_get`` of res.partner is roughly 250 fields with a dozen
    attributes each — well over 100 KB for one question like "is there a
    mobile field".  This keeps the answer to the attributes that decide how a
    field is read or written, and lets the caller filter by name or label.
    """
    wanted = (
        list(attributes)
        if attributes is not None
        else list(FIELD_METADATA_DEFAULT_ATTRIBUTES)
    )
    all_attributes = "*" in wanted
    needle = (query or "").strip().casefold()
    selected: Dict[str, Dict[str, Any]] = {}
    name_filter = set(field_names or [])
    for name, meta in fields.items():
        if not isinstance(meta, dict):
            continue
        if name_filter and name not in name_filter:
            continue
        if needle:
            label = str(meta.get("string") or "")
            relation = str(meta.get("relation") or "")
            if (
                needle not in name.casefold()
                and needle not in label.casefold()
                and needle not in relation.casefold()
            ):
                continue
        if all_attributes:
            selected[name] = dict(meta)
            continue
        projected = {key: meta[key] for key in wanted if key in meta}
        # Drop the noise that says nothing: false flags and empty selections.
        for key in ("required", "readonly", "store"):
            if key in projected and projected[key] is False and key not in (attributes or ()):
                projected.pop(key)
        if "selection" in projected and not projected["selection"]:
            projected.pop("selection")
        selected[name] = projected
    return selected


@mcp.tool(
    description=(
        "Field metadata of one Odoo model, compact by default: type, label, "
        "required/readonly flags, relation target, selection values and storage per "
        "field. Filter with 'query' (substring of technical name, label or "
        "relation) or 'field_names'; ask for another cached XML-RPC-safe "
        "attribute (e.g. 'help', 'compute', 'tracking' or 'groups') via "
        "'attributes'. Raw 'domain' metadata is intentionally unavailable "
        "because Odoo 18 can put non-marshallable None values there. Call this before "
        "guessing a field name."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def get_model_fields(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'res.partner'.")],
    field_names: Annotated[
        Optional[List[str]],
        Field(description="Only these technical field names."),
    ] = None,
    query: Annotated[
        Optional[str],
        Field(
            description=(
                "Case-insensitive substring matched against technical name, "
                "label and relation, e.g. 'phone' or 'res.partner'."
            )
        ),
    ] = None,
    attributes: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "fields_get attributes to return. Default: type, string, "
                "required, readonly, relation, selection, store. Use ['*'] for all "
                "XML-RPC-safe metadata cached by this server; raw domain "
                "metadata is excluded."
            )
        ),
    ] = None,
) -> Dict[str, Any]:
    """
    Read field definitions for a model.

    Prefer this read-only tool over execute_method for model introspection.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        app_context = ctx.request_context.lifespan_context
        fields = _cached_fields_metadata(app_context, odoo, model)
        if not fields:
            fields = app_context.schema_cache.pop(_fields_cache_key(model) + ":error", None) or {}
        if "error" in fields:
            return error_response(
                "get_model_fields", RuntimeError(str(fields["error"])), model=model,
            )
        explicit_attributes = attributes is not None
        requested_attributes = (
            list(attributes)
            if explicit_attributes
            else list(FIELD_METADATA_DEFAULT_ATTRIBUTES)
        )
        unknown_attributes = []
        if "*" not in requested_attributes:
            safe_attributes = set(FIELD_METADATA_RPC_ATTRIBUTES)
            unknown_attributes = [
                name for name in requested_attributes if name not in safe_attributes
            ]
            requested_attributes = [
                name for name in requested_attributes if name in safe_attributes
            ]
        total = sum(1 for meta in fields.values() if isinstance(meta, dict))
        result = project_field_metadata(
            fields,
            field_names=field_names,
            query=query,
            attributes=requested_attributes if explicit_attributes else None,
        )
        response: Dict[str, Any] = {
            "success": True,
            "model": model,
            "count": len(result),
            "total_fields": total,
            "attributes": (
                ["*"] if "*" in requested_attributes else requested_attributes
            ),
            "result": result,
        }
        if field_names:
            missing = [name for name in field_names if name not in fields]
            if missing:
                response["unknown_field_names"] = missing
        if unknown_attributes:
            response["unknown_attributes"] = unknown_attributes
            response["warnings"] = [
                "Unknown or XML-RPC-unsafe field metadata attributes were "
                "ignored: " + ", ".join(unknown_attributes)
            ]
        return response
    except Exception as e:
        return error_response("get_model_fields", e, model=model)


@mcp.tool(
    description=(
        "Search Odoo records with read-only search_read. Returns the page in "
        "'result' plus 'total_count' (all matches, not just this page), "
        "'has_more' and 'next_offset' for paging. Without an explicit 'order' "
        "the result is sorted by 'id desc'. That makes paging deterministic "
        "but not snapshot-safe: records created or deleted while you page "
        "still shift the offsets, so page by 'id < last_id' when that matters."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def search_records(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'sale.order'.")],
    domain: Annotated[
        Optional[Any],
        Field(
            description=(
                "Odoo domain as JSON list of [field, operator, value] triples, "
                'e.g. [["partner_id", "=", 42], ["state", "in", ["sale", "done"]]]. '
                'Prefix operators "&", "|", "!" allowed. Datetimes are naive '
                'UTC "YYYY-MM-DD HH:MM:SS", dates "YYYY-MM-DD". Omit for no filter.'
            )
        ),
    ] = None,
    fields: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Fields to return. Omit for a curated subset (id, display_name "
                "and the most telling fields), [\"*\"] for every non-binary field. "
                "many2one comes back as [id, display_name], x2many as id list, "
                "empty as false."
            )
        ),
    ] = None,
    limit: Annotated[
        int, Field(description="Page size, 1-100 (capped at 100).", ge=1)
    ] = 10,
    offset: Annotated[
        int, Field(description="Rows to skip; use next_offset from the previous page.", ge=0)
    ] = 0,
    order: Annotated[
        Optional[str],
        Field(description="Odoo order string, e.g. 'date_order desc, id desc'. Default 'id desc'."),
    ] = None,
) -> Dict[str, Any]:
    """
    Search and read records with bounded read-only semantics.

    Domain accepts standard Odoo domain arrays, a JSON string, or
    {"conditions": [{"field": ..., "operator": ..., "value": ...}]}.

    ``count`` is the size of the returned page. ``total_count`` is the real
    number of matching records (NESA A3) — never confuse the two: a ``count``
    equal to ``limit`` almost always means the result was truncated.
    """
    app_context = ctx.request_context.lifespan_context
    odoo = app_context.odoo
    try:
        validate_model_name(model)
        limit = clamp_limit(limit)
        if offset < 0:
            raise ValueError("offset must be greater than or equal to 0")
        resolved_fields, field_notes = resolve_read_fields(
            app_context, odoo, model, fields
        )
        normalized_domain = normalize_domain_input(domain)
        # NESA A4: an unordered search_read has no total order, so offset
        # paging can repeat or skip rows without anybody noticing.
        order_used = order or DEFAULT_SEARCH_ORDER
        records = call_with_transport_retry(
            lambda: odoo.search_read(
                model_name=model,
                domain=normalized_domain,
                fields=resolved_fields,
                offset=offset,
                limit=limit,
                order=order_used,
            ),
            label=f"search_read({model})",
        )
        total_count: Optional[int] = None
        count_error: Optional[str] = None
        try:
            if offset == 0 and len(records) < limit:
                # A short first page is the whole result set; the second
                # RPC would only confirm what the page already proves.
                total_count = len(records)
            else:
                counted = call_with_transport_retry(
                    lambda: odoo.execute_method(model, "search_count", normalized_domain),
                    label=f"search_count({model})",
                )
                if isinstance(counted, int):
                    total_count = counted
        except Exception as count_exc:  # noqa: BLE001 — page result is still valid
            # Same rule as error_response: cause line to the agent, full
            # traceback only to the log.
            count_error, count_traceback = compact_error_message(count_exc)
            logger.warning(
                "[search_records] search_count failed: %s\n%s",
                count_error, count_traceback or "",
            )

        returned = len(records)
        if total_count is None:
            # Without a trustworthy total, a full page is still evidence that
            # more rows may exist.  Say "unknown" instead of implying "no".
            has_more: Optional[bool] = True if returned >= limit else None
        else:
            has_more = (offset + returned) < total_count
        response: Dict[str, Any] = {
            "success": True,
            "count": returned,
            "total_count": total_count,
            "has_more": has_more,
            "next_offset": (offset + returned) if has_more else None,
            "offset": offset,
            "limit": limit,
            "order_used": order_used,
            "order_defaulted": order is None,
            "result": records,
            "smart_fields_applied": fields is None,
            "fields_used": resolved_fields,
        }
        if count_error:
            response["total_count_error"] = count_error
        for key in ("excluded_binary_fields", "expanded_wildcard", "warning"):
            if key in field_notes:
                response[key] = field_notes[key]
        return response
    except Exception as e:
        return error_response("search_records", e, model=model)


@mcp.tool(
    description="Read a single Odoo record by model and ID",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def read_record(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'res.partner'.")],
    record_id: Annotated[int, Field(description="Database id of the record.", ge=1)],
    fields: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Fields to return. Omit for a curated subset, [\"*\"] for every "
                "non-binary field. many2one comes back as [id, display_name]."
            )
        ),
    ] = None,
) -> Dict[str, Any]:
    """
    Read one record by ID with bounded read-only semantics.

    When ``fields`` is omitted the server picks a curated subset
    (business identifiers + state + relations) to keep LLM context small.
    Pass ``fields=["*"]`` to fetch every available field.
    """
    app_context = ctx.request_context.lifespan_context
    odoo = app_context.odoo
    try:
        validate_model_name(model)
        if record_id < 1:
            raise ValueError("record_id must be greater than 0")
        resolved_fields, field_notes = resolve_read_fields(
            app_context, odoo, model, fields
        )
        records = call_with_transport_retry(
            lambda: odoo.read_records(model, [record_id], fields=resolved_fields),
            label=f"read({model})",
        )
        if not records:
            return {
                "success": False,
                "tool": "read_record",
                "error": f"Record not found: {model} ID {record_id}",
                "error_type": "not_found",
                "retryable": False,
            }
        response: Dict[str, Any] = {
            "success": True,
            "result": records[0],
            "smart_fields_applied": fields is None,
            "fields_used": resolved_fields,
        }
        for key in ("excluded_binary_fields", "expanded_wildcard", "warning"):
            if key in field_notes:
                response[key] = field_notes[key]
        return response
    except Exception as e:
        return error_response("read_record", e, model=model, record_id=record_id)


@mcp.tool(
    description=(
        "Read several Odoo records of one model in a single call. Prefer this "
        "over repeated read_record calls or a search_records detour via "
        "[['id','in',[...]]]."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def read_records(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'res.partner'.")],
    record_ids: Annotated[
        List[int], Field(description="Database ids, at most 100 per call.", min_length=1)
    ],
    fields: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Fields to return. Omit for a curated subset, [\"*\"] for every "
                "non-binary field. many2one comes back as [id, display_name]."
            )
        ),
    ] = None,
) -> Dict[str, Any]:
    """Read many records by ID with the same field semantics as read_record.

    ``fields=None`` picks a curated subset, ``fields=["*"]`` returns every
    non-binary field. Missing IDs are reported in ``missing_ids`` instead of
    failing the whole call — a record can be absent because it was deleted or
    because a record rule hides it.
    """
    app_context = ctx.request_context.lifespan_context
    odoo = app_context.odoo
    try:
        validate_model_name(model)
        normalized_ids = [int(record_id) for record_id in record_ids or []]
        if not normalized_ids:
            raise ValueError("record_ids must contain at least one ID")
        if any(record_id < 1 for record_id in normalized_ids):
            raise ValueError("record_ids must all be greater than 0")
        if len(normalized_ids) > MAX_SEARCH_LIMIT:
            raise ValueError(
                f"record_ids is limited to {MAX_SEARCH_LIMIT} entries per call"
            )
        resolved_fields, field_notes = resolve_read_fields(
            app_context, odoo, model, fields
        )
        records = call_with_transport_retry(
            lambda: odoo.read_records(model, normalized_ids, fields=resolved_fields),
            label=f"read({model})",
        )
        found_ids = {
            int(row["id"]) for row in records if isinstance(row, dict) and "id" in row
        }
        response: Dict[str, Any] = {
            "success": True,
            "model": model,
            "count": len(records),
            "requested_count": len(normalized_ids),
            "missing_ids": [rid for rid in normalized_ids if rid not in found_ids],
            "result": records,
            "smart_fields_applied": fields is None,
            "fields_used": resolved_fields,
        }
        for key in ("excluded_binary_fields", "expanded_wildcard", "warning"):
            if key in field_notes:
                response[key] = field_notes[key]
        return response
    except Exception as e:
        return error_response("read_records", e, model=model)


@mcp.tool(
    description=(
        "Aggregate Odoo records server-side using Postgres groupby/sum/count. "
        "Uses formatted_read_group on Odoo 19+ and falls back to read_group."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def aggregate_records(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'account.move.line'.")],
    group_by: Annotated[
        List[str],
        Field(
            description=(
                "Fields to group by, e.g. ['partner_id'] or ['date:month', 'state']. "
                "Date granularity suffixes :day/:week/:month/:quarter/:year."
            ),
            min_length=1,
        ),
    ],
    measures: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Aggregates as 'field:agg', e.g. ['amount_total:sum', 'id:count']. "
                "agg is sum, avg, min, max, count or count_distinct. A bare field "
                "name means sum. The row count per group is always included."
            )
        ),
    ] = None,
    domain: Annotated[
        Optional[Any],
        Field(description="Odoo domain as JSON list of [field, operator, value] triples."),
    ] = None,
    lazy: Annotated[
        bool, Field(description="read_group lazy flag; keep false for full grouping.")
    ] = False,
    limit: Annotated[
        Optional[int],
        Field(description="Maximum number of groups to return (default and cap 100).", ge=1),
    ] = None,
    offset: Annotated[int, Field(description="Groups to skip.", ge=0)] = 0,
    order: Annotated[
        Optional[str],
        Field(description="Order of groups, e.g. 'amount_total:sum desc'."),
    ] = None,
) -> Dict[str, Any]:
    """Group records server-side and aggregate measures.

    ``measures`` are ``"field:agg"`` strings (default agg ``sum``).
    Allowed aggregators: sum, avg, min, max, count, count_distinct,
    array_agg, bool_and, bool_or.

    Returns ``rows`` (list of dicts) plus the chosen ``method`` and
    detected Odoo ``major_version``. Limit is capped at ``MAX_SEARCH_LIMIT``
    when provided.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        if not group_by:
            raise ValueError("group_by must include at least one field")
        if offset < 0:
            raise ValueError("offset must be greater than or equal to 0")
        clamped_limit = clamp_limit(limit if limit is not None else MAX_SEARCH_LIMIT)
        normalized_domain = normalize_domain_input(domain)
        normalized_measures: List[str] = []
        parsed_measures: List[tuple[str, str]] = []
        for spec in measures or []:
            field, agg = parse_measure_spec(spec)
            normalized_measures.append(f"{field}:{agg}")
            parsed_measures.append((field, agg))

        major = odoo_major_version(odoo)
        method_used = "read_group"
        rows: list[dict[str, Any]]

        if major is not None and major >= 19:
            method_used = "formatted_read_group"
            kwargs: Dict[str, Any] = {
                "domain": normalized_domain,
                "groupby": group_by,
                "aggregates": normalized_measures,
            }
            if offset:
                kwargs["offset"] = offset
            if clamped_limit is not None:
                kwargs["limit"] = clamped_limit + 1
            if order:
                kwargs["order"] = order
            try:
                rows = odoo.execute_method(model, "formatted_read_group", **kwargs)
            except Exception as exc:  # pragma: no cover - rare server-version drift
                method_used = "read_group"
                kwargs_fallback = {
                    "domain": normalized_domain,
                    "fields": normalized_measures,
                    "groupby": group_by,
                    "lazy": lazy,
                }
                if offset:
                    kwargs_fallback["offset"] = offset
                if clamped_limit is not None:
                    kwargs_fallback["limit"] = clamped_limit + 1
                if order:
                    kwargs_fallback["orderby"] = order
                rows = odoo.execute_method(model, "read_group", **kwargs_fallback)
                fallback_reason = str(exc)
            else:
                fallback_reason = ""
        else:
            kwargs = {
                "domain": normalized_domain,
                "fields": normalized_measures,
                "groupby": group_by,
                "lazy": lazy,
            }
            if offset:
                kwargs["offset"] = offset
            if clamped_limit is not None:
                # One extra group tells us whether the page is complete.
                kwargs["limit"] = clamped_limit + 1
            if order:
                kwargs["orderby"] = order
            rows = odoo.execute_method(model, "read_group", **kwargs)
            fallback_reason = ""

        truncated = len(rows) > clamped_limit
        rows = [strip_read_group_internals(row) for row in rows[:clamped_limit]]
        response = {
            "success": True,
            "method": method_used,
            "major_version": major,
            "fallback_reason": fallback_reason or None,
            "model": model,
            "group_by": group_by,
            "measures": normalized_measures,
            "row_count": len(rows),
            "limit": clamped_limit,
            "offset": offset,
            "rows": rows,
        }
        if truncated:
            response["truncated"] = True
            response["warning"] = (
                f"More than {clamped_limit} groups exist; only the first "
                f"{clamped_limit} are returned. Narrow the domain, group "
                "coarser, or page with offset."
            )
        return response
    except Exception as e:
        return error_response("aggregate_records", e, model=model)


READ_GROUP_INTERNAL_KEYS = ("__domain", "__context", "__fold")


def strip_read_group_internals(row: Any) -> Any:
    """Drop read_group bookkeeping (``__domain`` repeats the whole domain per
    row, ``__context`` the lazy-groupby context) that no agent needs.
    ``__count`` and ``__range`` (exact date-group bounds) stay."""
    if not isinstance(row, dict):
        return row
    return {k: v for k, v in row.items() if k not in READ_GROUP_INTERNAL_KEYS}


def _message_post_returning_id(odoo, model: str, record_id: int, kwargs: Dict[str, Any]) -> int:
    """Run message_post and return the created mail.message id as int.

    Odoo 18's message_post returns a mail.message recordset, which the RPC
    layer cannot serialize; the transaction is already committed when the
    response marshaling fails (Fault "cannot marshal"). Swallow exactly that
    fault and resolve the persisted id via a follow-up search. Raise when no
    new message exists (call genuinely failed / rolled back).
    """
    baseline = odoo.execute_method(
        "mail.message", "search",
        [["model", "=", model], ["res_id", "=", int(record_id)]],
        limit=1, order="id desc",
    )
    baseline_id = int(baseline[0]) if baseline else 0
    try:
        result = odoo.execute_method(model, "message_post", [record_id], **kwargs)
        if isinstance(result, int) and result > 0:
            return result
        if isinstance(result, dict) and isinstance(result.get("id"), int):
            return result["id"]
    except Exception as exc:
        if not is_unmarshallable_response_fault(exc):
            raise
    created = odoo.execute_method(
        "mail.message", "search",
        [
            ["model", "=", model],
            ["res_id", "=", int(record_id)],
            ["id", ">", baseline_id],
        ],
        limit=1, order="id desc",
    )
    if created:
        return int(created[0])
    raise RuntimeError(
        "message_post persisted no new mail.message (rolled back?)"
    )


def _build_chatter_payload(
    *,
    model: str,
    record_id: int,
    body: str,
    message_type: str,
    subtype_xmlid: Optional[str],
    partner_ids: Optional[List[int]],
    attachment_ids: Optional[List[int]],
) -> Dict[str, Any]:
    """Build the canonical message_post call payload (deterministic ordering)."""
    kwargs: Dict[str, Any] = {"body": body, "message_type": message_type}
    if subtype_xmlid:
        kwargs["subtype_xmlid"] = subtype_xmlid
    if partner_ids:
        kwargs["partner_ids"] = [int(pid) for pid in partner_ids]
    if attachment_ids:
        kwargs["attachment_ids"] = [int(aid) for aid in attachment_ids]
    return {
        "model": model,
        "method": "message_post",
        "record_ids": [int(record_id)],
        "kwargs": kwargs,
    }


@mcp.tool(
    description=(
        "Post a chatter message on a mail.thread record. Default mode requires "
        "an approval token returned from a preview call; set MCP_CHATTER_DIRECT=1 "
        "to bypass and post immediately."
    ),
    annotations=DESTRUCTIVE_TOOL,
    structured_output=True,
)
def chatter_post(
    ctx: Context,
    model: str,
    record_id: int,
    body: str,
    message_type: str = "comment",
    subtype_xmlid: Optional[str] = None,
    partner_ids: Optional[List[int]] = None,
    attachment_ids: Optional[List[int]] = None,
    approval: Optional[Dict[str, Any]] = None,
    confirm: bool = False,
) -> Dict[str, Any]:
    """Post a message on the chatter of a mail.thread-derived record.

    Modes:
    - Default (gated): first call returns ``mode=preview`` with an approval
      token. Re-call with the same arguments plus ``approval`` and
      ``confirm=true`` to send.
    - Direct (``MCP_CHATTER_DIRECT=1``): the message is posted on the first
      call without a token.

    Allowed ``message_type`` values: ``comment`` (default), ``notification``.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        denied = hard_deny_result("chatter_post", model, "message_post")
        if denied:
            return denied
        if record_id < 1:
            raise ValueError("record_id must be greater than 0")
        body_text = (body or "").strip()
        if not body_text:
            raise ValueError("body must be a non-empty string")
        if message_type not in {"comment", "notification"}:
            raise ValueError(
                "message_type must be 'comment' or 'notification'."
            )

        canonical = _build_chatter_payload(
            model=model,
            record_id=record_id,
            body=body_text,
            message_type=message_type,
            subtype_xmlid=subtype_xmlid,
            partner_ids=partner_ids,
            attachment_ids=attachment_ids,
        )
        token = build_approval_token(canonical)

        direct_mode = chatter_direct_enabled()
        if direct_mode:
            audit_odoo_execution("chatter_post", model, "message_post")
            message_id = _message_post_returning_id(
                odoo, model, record_id, canonical["kwargs"],
            )
            return {
                "success": True,
                "mode": "direct",
                "model": model,
                "record_id": record_id,
                "approval_required": False,
                "result": message_id,
            }

        if approval is None:
            return {
                "success": True,
                "mode": "preview",
                "model": model,
                "record_id": record_id,
                "approval": {**canonical, "token": token},
                "warnings": [
                    "Preview only. Re-call chatter_post with the returned approval "
                    "and confirm=true to actually post."
                ],
            }

        provided_token = str(approval.get("token", ""))
        if provided_token != token:
            raise ValueError(
                "Approval token does not match the chatter payload — re-run preview."
            )
        if not confirm:
            raise ValueError(
                "confirm=true is required to execute an approved chatter post."
            )

        audit_odoo_execution("chatter_post", model, "message_post")
        message_id = _message_post_returning_id(
            odoo, model, record_id, canonical["kwargs"],
        )
        return {
            "success": True,
            "mode": "execute",
            "model": model,
            "record_id": record_id,
            "approval_required": True,
            "result": message_id,
        }
    except Exception as e:
        return error_response("chatter_post", e, model=model)


@mcp.tool(
    description=(
        "Resolve a name to record ids in one RPC: returns [{id, display_name}] "
        "using the model's own name_search (matches name, ref, email, ... as "
        "the model defines). Use this instead of search_records with ilike "
        "when you only need to find the record."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def name_search(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name, e.g. 'res.partner'.")],
    name: Annotated[str, Field(description="Text to match, e.g. 'Müller' or 'S00042'.")],
    limit: Annotated[int, Field(description="Maximum matches, 1-100.", ge=1)] = 20,
    domain: Annotated[
        Optional[Union[str, List[Any], Dict[str, Any]]],
        Field(description="Optional extra domain to restrict candidates, same format as search_records."),
    ] = None,
    operator: Annotated[
        str, Field(description="Odoo match operator: 'ilike' (default), '=', '=ilike', 'not ilike'."),
    ] = "ilike",
) -> Dict[str, Any]:
    """Find records by display name; one round trip, no field list needed."""
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        limit = clamp_limit(limit)
        if operator not in {"ilike", "=", "=ilike", "not ilike", "like", "=like"}:
            raise ValueError("operator must be one of ilike, =, =ilike, not ilike, like, =like")
        normalized_domain = normalize_domain_input(domain)
        audit_odoo_execution("name_search", model, "name_search")
        pairs = call_with_transport_retry(
            # Odoo 18 signature: name_search(name='', args=None, operator='ilike', limit=100)
            lambda: odoo.execute_method(
                model, "name_search", name=name, args=normalized_domain,
                operator=operator, limit=limit,
            ),
            label=f"name_search({model})",
        )
        result = [
            {"id": pair[0], "display_name": pair[1]}
            for pair in (pairs or [])
            if isinstance(pair, (list, tuple)) and len(pair) >= 2
        ]
        response: Dict[str, Any] = {
            "success": True,
            "model": model,
            "count": len(result),
            "limit": limit,
            "result": result,
        }
        if len(result) >= limit:
            response["truncated"] = True
            response["warning"] = (
                f"{limit} matches returned; more may exist. Refine the name or "
                "add a domain."
            )
        return response
    except Exception as e:
        return error_response("name_search", e, model=model)


@mcp.tool(
    description="Search for employees by name",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def search_employee(
    ctx: Context,
    name: str,
    limit: int = 20,
) -> SearchEmployeeResponse:
    """
    Search for employees by name using Odoo's name_search method.

    Parameters:
        name: The name (or part of the name) to search for.
        limit: The maximum number of results to return (default 20).

    Returns:
        SearchEmployeeResponse containing results or error information.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    model = "hr.employee"
    method = "name_search"

    args: List[Any] = []
    kwargs: Dict[str, Any] = {"name": name, "limit": limit}

    try:
        result = odoo.execute_method(model, method, *args, **kwargs)
        parsed_result = [
            EmployeeSearchResult(id=item[0], name=item[1]) for item in result
        ]
        return SearchEmployeeResponse(success=True, result=parsed_result)
    except Exception as e:
        return SearchEmployeeResponse(success=False, error=compact_error_message(e)[0])


@mcp.tool(
    description="Search for holidays within a date range",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def search_holidays(
    ctx: Context,
    start_date: str,
    end_date: str,
    employee_id: Optional[int] = None,
) -> SearchHolidaysResponse:
    """
    Searches for holidays within a specified date range.

    Parameters:
        start_date: Start date in YYYY-MM-DD format.
        end_date: End date in YYYY-MM-DD format.
        employee_id: Optional employee ID to filter holidays.

    Returns:
        SearchHolidaysResponse:  Object containing the search results.
    """
    odoo = ctx.request_context.lifespan_context.odoo

    # Validate date format using datetime
    try:
        datetime.strptime(start_date, "%Y-%m-%d")
    except ValueError:
        return SearchHolidaysResponse(
            success=False, error="Invalid start_date format. Use YYYY-MM-DD."
        )
    try:
        datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError:
        return SearchHolidaysResponse(
            success=False, error="Invalid end_date format. Use YYYY-MM-DD."
        )

    # Calculate adjusted start_date (subtract one day)
    start_date_dt = datetime.strptime(start_date, "%Y-%m-%d")
    adjusted_start_date_dt = start_date_dt - timedelta(days=1)
    adjusted_start_date = adjusted_start_date_dt.strftime("%Y-%m-%d")

    # Build the domain
    domain: List[Any] = [
        "&",
        ["start_datetime", "<=", f"{end_date} 22:59:59"],
        # Use adjusted date
        ["stop_datetime", ">=", f"{adjusted_start_date} 23:00:00"],
    ]
    if employee_id:
        domain.append(
            ["employee_id", "=", employee_id],
        )

    try:
        holidays = odoo.search_read(
            model_name="hr.leave.report.calendar",
            domain=domain,
        )
        parsed_holidays = [Holiday(**holiday) for holiday in holidays]
        return SearchHolidaysResponse(success=True, result=parsed_holidays)

    except Exception as e:
        return SearchHolidaysResponse(success=False, error=compact_error_message(e)[0])


# ----- NESA document, report and pricing tools -----


_ATTACHMENT_META_FIELDS = [
    "id",
    "name",
    "mimetype",
    "file_size",
    "res_model",
    "res_id",
    "create_date",
    "type",
    "url",
]


def _read_attachment_meta(odoo: OdooClient, attachment_id: int) -> Dict[str, Any]:
    """Read attachment metadata without ever touching the binary payload."""
    rows = odoo.read_records(
        "ir.attachment", [attachment_id], fields=_ATTACHMENT_META_FIELDS,
    )
    if not rows:
        raise ValueError(
            f"Attachment {attachment_id} not found or not visible for this user."
        )
    return rows[0]


def _resolve_attachment_id(odoo: OdooClient, model: str, record_id: int) -> int:
    """Map a document-ish record onto its ir.attachment ID."""
    if model == "ir.attachment":
        return record_id
    rows = odoo.read_records(model, [record_id], fields=["attachment_id"])
    if not rows:
        raise ValueError(f"{model} {record_id} not found or not visible.")
    attachment = rows[0].get("attachment_id")
    resolved = _m2o_id(attachment)
    if not resolved:
        raise ValueError(f"{model} {record_id} has no attachment_id.")
    return resolved


def _doc_helper_missing_response(tool: str, exc: BaseException) -> Optional[Dict[str, Any]]:
    """Turn "helper model absent" into an actionable message, not a raw fault."""
    text = str(exc)
    if NESA_DOC_HELPER_MODEL not in text and "doesn't exist" not in text.casefold():
        return None
    return {
        "success": False,
        "tool": tool,
        "error": (
            f"The Odoo-side helper model {NESA_DOC_HELPER_MODEL} is not "
            "available. Install/upgrade the nesa_mcp_bridge module on this "
            "database to enable attachment previews, download links, report "
            "rendering and price previews."
        ),
        "error_type": "helper_unavailable",
        "retryable": False,
    }


@mcp.tool(
    description=(
        "Read the indexed text (OCR/PDF text layer) of an attachment in bounded "
        "windows. Use this after finding candidates via "
        "search_records('ir.attachment', [['index_content','ilike',...]]) — "
        "never pull index_content through a plain field read, it is unbounded."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def get_document_text(
    ctx: Context,
    attachment_id: int,
    offset: int = 0,
    limit: int = DOC_TEXT_WINDOW_DEFAULT,
    model: str = "ir.attachment",
) -> Dict[str, Any]:
    """Return a character window of ``ir.attachment.index_content``.

    ``model`` may also be ``documents.document`` (or any model exposing an
    ``attachment_id``); the attachment behind the record is resolved first.

    Returns ``text`` plus ``total_chars``, ``has_more`` and ``next_offset`` so
    long documents can be paged deterministically.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        if attachment_id < 1:
            raise ValueError("attachment_id must be greater than 0")
        if offset < 0:
            raise ValueError("offset must be greater than or equal to 0")
        if limit < 1:
            raise ValueError("limit must be greater than 0")
        limit = min(limit, DOC_TEXT_WINDOW_MAX)
        resolved_id = _resolve_attachment_id(odoo, model, attachment_id)
        rows = call_with_transport_retry(
            lambda: odoo.read_records(
                "ir.attachment",
                [resolved_id],
                fields=_ATTACHMENT_META_FIELDS + ["index_content"],
            ),
            label="read(ir.attachment.index_content)",
        )
        if not rows:
            return {
                "success": False,
                "tool": "get_document_text",
                "error": (
                    f"Attachment {resolved_id} not found or not visible for "
                    "this user."
                ),
                "error_type": "not_found",
                "retryable": False,
            }
        record = rows[0]
        content = record.get("index_content") or ""
        if not isinstance(content, str):
            content = str(content)
        total_chars = len(content)
        window = content[offset : offset + limit]
        end = offset + len(window)
        response: Dict[str, Any] = {
            "success": True,
            "tool": "get_document_text",
            "attachment_id": resolved_id,
            "name": record.get("name"),
            "mimetype": record.get("mimetype"),
            "file_size": record.get("file_size"),
            "offset": offset,
            "limit": limit,
            "returned_chars": len(window),
            "total_chars": total_chars,
            "has_more": end < total_chars,
            "next_offset": end if end < total_chars else None,
            "text": window,
        }
        if total_chars == 0:
            response["note"] = (
                "index_content is empty: the file was never text-indexed "
                "(images without OCR, or an attachment type Odoo does not "
                "index). Use read_attachment to look at it instead."
            )
        return response
    except Exception as e:
        return error_response("get_document_text", e, attachment_id=attachment_id)


@mcp.tool(
    description=(
        "Look at an attachment: images come back as an actual image (downscaled "
        "server-side), PDFs and text files as extracted text. Use "
        "create_attachment_download when the untouched original file is needed."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=False,
)
def read_attachment(
    ctx: Context,
    attachment_id: int,
    max_pixels: int = 1600,
    text_limit: int = DOC_TEXT_WINDOW_DEFAULT,
    model: str = "ir.attachment",
) -> Any:
    """Return an attachment in a form the agent can actually evaluate.

    Images are resized inside Odoo (Pillow lives there, not in the MCP venv)
    so a 6 MB site photo does not arrive as 8 MB of base64. PDFs and text
    files return their indexed text; everything else returns metadata plus a
    pointer to ``create_attachment_download``.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        if attachment_id < 1:
            raise ValueError("attachment_id must be greater than 0")
        if max_pixels < 64 or max_pixels > 4096:
            raise ValueError("max_pixels must be between 64 and 4096")
        text_limit = max(1, min(text_limit, DOC_TEXT_WINDOW_MAX))
        resolved_id = _resolve_attachment_id(odoo, model, attachment_id)
        meta = _read_attachment_meta(odoo, resolved_id)
        mimetype = str(meta.get("mimetype") or "")

        if mimetype.startswith("image/"):
            try:
                preview = call_doc_helper(
                    odoo, "mcp_attachment_preview", resolved_id, max_pixels,
                )
            except Exception as exc:  # noqa: BLE001 — mapped to guidance below
                missing = _doc_helper_missing_response("read_attachment", exc)
                if missing:
                    return missing
                raise
            if not isinstance(preview, dict) or not preview.get("success"):
                return {
                    "success": False,
                    "tool": "read_attachment",
                    "error": (
                        (preview or {}).get("error")
                        if isinstance(preview, dict)
                        else "image preview failed"
                    ),
                    "error_type": "preview_failed",
                    "retryable": False,
                }
            image_bytes = base64.b64decode(preview["data_b64"])
            return [
                Image(data=image_bytes, format=str(preview.get("format", "jpeg"))),
                {
                    "success": True,
                    "tool": "read_attachment",
                    "attachment_id": resolved_id,
                    "name": meta.get("name"),
                    "mimetype": mimetype,
                    "original_file_size": meta.get("file_size"),
                    "preview_bytes": len(image_bytes),
                    "preview_width": preview.get("width"),
                    "preview_height": preview.get("height"),
                    "downscaled": bool(preview.get("downscaled")),
                    "attached_to": {
                        "model": meta.get("res_model"),
                        "res_id": meta.get("res_id"),
                    },
                },
            ]

        text_rows = call_with_transport_retry(
            lambda: odoo.read_records(
                "ir.attachment", [resolved_id], fields=["index_content"],
            ),
            label="read(ir.attachment.index_content)",
        )
        content = (text_rows[0].get("index_content") if text_rows else "") or ""
        if not isinstance(content, str):
            content = str(content)
        window = content[:text_limit]
        payload: Dict[str, Any] = {
            "success": True,
            "tool": "read_attachment",
            "attachment_id": resolved_id,
            "name": meta.get("name"),
            "mimetype": mimetype,
            "file_size": meta.get("file_size"),
            "attached_to": {
                "model": meta.get("res_model"),
                "res_id": meta.get("res_id"),
            },
            "text": window,
            "total_chars": len(content),
            "has_more": len(content) > len(window),
            "next_offset": len(window) if len(content) > len(window) else None,
        }
        if not content:
            payload["note"] = (
                "No text layer available for this attachment. Use "
                "create_attachment_download to hand out the original file."
            )
        elif len(content) > len(window):
            payload["note"] = (
                "Text truncated — continue with "
                f"get_document_text(attachment_id={resolved_id}, offset=..)."
            )
        return payload
    except Exception as e:
        return error_response("read_attachment", e, attachment_id=attachment_id)


@mcp.tool(
    description=(
        "Create a time-limited HTTPS download link for the unmodified original "
        "file of an attachment. Use it to hand a file to a person or to attach "
        "it to a mail draft. Issues a short-lived token, so it is not a pure "
        "read."
    ),
    annotations=SIDE_EFFECT_TOOL,
    structured_output=True,
)
def create_attachment_download(
    ctx: Context,
    attachment_id: int,
    ttl_seconds: int = 900,
    model: str = "ir.attachment",
    max_downloads: int = 1,
) -> Dict[str, Any]:
    """Mint a single-purpose, expiring download URL for one attachment.

    The link is issued by ``nesa_mcp_bridge`` and only after Odoo confirmed
    that the acting user may read the attachment. It expires on its own; no
    permanent public access token is written onto the record.

    The token sits in the URL path, so it also lands in the web server's
    access log. ``max_downloads`` therefore defaults to 1: once the recipient
    has fetched the file, a later log reader gains nothing. Raise it only when
    the same link genuinely has to work more than once.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        if attachment_id < 1:
            raise ValueError("attachment_id must be greater than 0")
        if ttl_seconds < 60:
            raise ValueError("ttl_seconds must be at least 60")
        if max_downloads < 0:
            raise ValueError(
                "max_downloads must be 0 (unlimited until expiry) or greater"
            )
        resolved_id = _resolve_attachment_id(odoo, model, attachment_id)
        try:
            result = call_doc_helper(
                odoo, "mcp_create_download", resolved_id, ttl_seconds,
                max_downloads,
            )
        except Exception as exc:  # noqa: BLE001 — mapped to guidance below
            missing = _doc_helper_missing_response("create_attachment_download", exc)
            if missing:
                return missing
            raise
        if not isinstance(result, dict) or not result.get("success"):
            return {
                "success": False,
                "tool": "create_attachment_download",
                "error": (
                    (result or {}).get("error")
                    if isinstance(result, dict)
                    else "download link could not be created"
                ),
                "error_type": "link_failed",
                "retryable": False,
            }
        return {"success": True, "tool": "create_attachment_download", **result}
    except Exception as e:
        return error_response(
            "create_attachment_download", e, attachment_id=attachment_id
        )


@mcp.tool(
    description=(
        "Fetch a file from a short-lived NESA download link (mail-mcp.nesa.de "
        "or openarchiver.nesa.de) and attach it to an Odoo record. Use it to "
        "put a mail attachment onto a partner, a sales order or a task without "
        "the file ever passing through the conversation. Any other URL is "
        "refused: the allowlist is code-owned and cannot be widened."
    ),
    annotations=SIDE_EFFECT_TOOL,
    structured_output=True,
)
def create_attachment_from_url(
    ctx: Context,
    url: str,
    model: str,
    res_id: int,
    filename: Optional[str] = None,
) -> Dict[str, Any]:
    """Pull one allowlisted file into Odoo as an ``ir.attachment``.

    The download happens in this server process, never in Odoo: the URL comes
    out of a mail and is therefore attacker-influenced, and Odoo is the process
    with the database and the filestore.  HTTPS only, no redirects, 30 s
    timeout, hard 40 MB cap checked against ``Content-Length`` *and* while
    streaming.

    Odoo then decides whether the acting user may attach anything to that
    record — ``ir.attachment`` requires write access on the target, exactly as
    in the backend.  The checksum measured here travels with the payload and is
    compared *before* the attachment is created, so a corrupted transfer leaves
    nothing behind instead of a file plus an apology.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        denied = hard_deny_result("create_attachment_from_url", model, "create")
        if denied:
            return denied
        if res_id < 1:
            raise ValueError("res_id must be greater than 0")
        try:
            fetched = fetch_allowlisted_url(url, filename=filename)
        except FileIntakeError as exc:
            return {
                "success": False,
                "tool": "create_attachment_from_url",
                "error": str(exc),
                "error_type": exc.error_type,
                "retryable": exc.error_type in {"fetch_timeout", "fetch_failed"},
            }

        payload = base64.b64encode(fetched.content).decode("ascii")
        try:
            result = call_with_transport_retry(
                lambda: call_doc_helper(
                    odoo, "mcp_store_attachment", model, res_id,
                    fetched.filename, payload, fetched.mimetype or "",
                    fetched.sha256,
                ),
                label="mcp_store_attachment",
                # A stored attachment is a write.  A lost answer must be
                # verified, never repeated — otherwise the record ends up with
                # the same file twice.
                idempotent=False,
            )
        except UnknownOutcomeError:
            raise
        except Exception as exc:  # noqa: BLE001 — mapped to guidance below
            missing = _doc_helper_missing_response("create_attachment_from_url", exc)
            if missing:
                return missing
            raise
        if not isinstance(result, dict) or not result.get("success"):
            return {
                "success": False,
                "tool": "create_attachment_from_url",
                "error": (
                    (result or {}).get("error")
                    if isinstance(result, dict)
                    else "the file could not be stored"
                ),
                "error_type": "store_failed",
                "retryable": False,
            }
        response = {
            "success": True,
            "tool": "create_attachment_from_url",
            **result,
            "fetched_bytes": fetched.size,
            "source_host": urllib.parse.urlsplit(url).netloc,
        }
        # Odoo already refused a mismatching payload before creating anything
        # (``expected_sha256``).  This second comparison is the belt to that
        # braces: it catches a helper version that ignores the argument, and it
        # never leaves the caller believing a corrupted file was filed.
        if result.get("sha256") and result["sha256"] != fetched.sha256:
            response["success"] = False
            response["error"] = (
                "The stored file does not match what was downloaded "
                f"(source sha256 {fetched.sha256}, stored {result['sha256']}). "
                "Delete attachment "
                f"{result.get('attachment_id')} and retry."
            )
            response["error_type"] = "checksum_mismatch"
            response["retryable"] = False
        return response
    except Exception as e:
        return error_response("create_attachment_from_url", e, model=model)


@mcp.tool(
    description=(
        "Mint a short-lived, single-use HTTPS upload URL for one Odoo record. "
        "Use it to put a file you have locally onto a record: upload it with "
        "`curl -T <file> <upload_url>`. Filename and target are fixed when the "
        "URL is minted, the link works exactly once, and it expires."
    ),
    annotations=SIDE_EFFECT_TOOL,
    structured_output=True,
)
def create_attachment_upload(
    ctx: Context,
    model: str,
    res_id: int,
    filename: str,
    ttl_seconds: int = 900,
) -> Dict[str, Any]:
    """Mint a one-shot upload URL that files a local file onto a record.

    The mirror image of ``create_attachment_download``.  Odoo checks the acting
    user's write access on the target *before* handing out the URL, so an
    unusable link is never issued; the uploader itself stays anonymous and
    cannot choose the filename, the mimetype or the target.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        denied = hard_deny_result("create_attachment_upload", model, "create")
        if denied:
            return denied
        if res_id < 1:
            raise ValueError("res_id must be greater than 0")
        if not filename or not str(filename).strip():
            raise ValueError("filename must not be empty")
        if ttl_seconds < 60:
            raise ValueError("ttl_seconds must be at least 60")
        try:
            result = call_doc_helper(
                odoo, "mcp_create_upload", model, res_id, filename, ttl_seconds,
            )
        except Exception as exc:  # noqa: BLE001 — mapped to guidance below
            missing = _doc_helper_missing_response("create_attachment_upload", exc)
            if missing:
                return missing
            raise
        if not isinstance(result, dict) or not result.get("success"):
            return {
                "success": False,
                "tool": "create_attachment_upload",
                "error": (
                    (result or {}).get("error")
                    if isinstance(result, dict)
                    else "upload link could not be created"
                ),
                "error_type": "link_failed",
                "retryable": False,
            }
        return {
            "success": True,
            "tool": "create_attachment_upload",
            **result,
            "how_to_upload": (
                f"curl -T <local-file> '{result.get('upload_url')}' — one PUT, "
                "one file, then the link is dead."
            ),
        }
    except Exception as e:
        return error_response("create_attachment_upload", e, model=model)


@mcp.tool(
    description=(
        "Render an Odoo QWeb PDF report (invoice, quotation, delivery slip) for "
        "one or more records and return a time-limited download link. Rendering "
        "costs a wkhtmltopdf run per record and leaves a temporary attachment, "
        "so it is capped and not a pure read."
    ),
    annotations=SIDE_EFFECT_TOOL,
    structured_output=True,
)
def render_report(
    ctx: Context,
    model: str,
    record_ids: List[int],
    report_ref: str,
    ttl_seconds: int = 900,
    return_base64: bool = False,
) -> Dict[str, Any]:
    """Render a report to PDF without mutating the source records.

    ``report_ref`` is the report's XML ID, e.g.
    ``account.account_invoices``. The PDF is stored as a short-lived
    attachment that the download token's cleanup removes again; it is never
    attached to the business record.

    ``return_base64=True`` additionally embeds the PDF in the answer — only do
    that for small documents, a link is cheaper for the context window.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        normalized_ids = [int(record_id) for record_id in record_ids or []]
        if not normalized_ids:
            raise ValueError("record_ids must contain at least one ID")
        if any(record_id < 1 for record_id in normalized_ids):
            raise ValueError("record_ids must all be greater than 0")
        if len(normalized_ids) > MAX_REPORT_RECORDS:
            # Odoo enforces the same cap; refusing here saves the roundtrip and
            # names the number the caller has to split by.
            raise ValueError(
                f"record_ids is capped at {MAX_REPORT_RECORDS} per call "
                f"({len(normalized_ids)} given) — each record costs a QWeb "
                "render plus a wkhtmltopdf run"
            )
        if not str(report_ref).strip():
            raise ValueError("report_ref must be a non-empty report XML ID")
        if ttl_seconds < 60:
            raise ValueError("ttl_seconds must be at least 60")
        try:
            result = call_doc_helper(
                odoo,
                "mcp_render_report",
                str(report_ref).strip(),
                normalized_ids,
                model,
                ttl_seconds,
                bool(return_base64),
            )
        except Exception as exc:  # noqa: BLE001 — mapped to guidance below
            missing = _doc_helper_missing_response("render_report", exc)
            if missing:
                return missing
            raise
        if not isinstance(result, dict) or not result.get("success"):
            return {
                "success": False,
                "tool": "render_report",
                "error": (
                    (result or {}).get("error")
                    if isinstance(result, dict)
                    else "report rendering failed"
                ),
                "error_type": "render_failed",
                "retryable": False,
            }
        return {"success": True, "tool": "render_report", "model": model, **result}
    except Exception as e:
        return error_response("render_report", e, model=model, report_ref=report_ref)


@mcp.tool(
    description=(
        "Explain which Odoo methods execute_method will run, and which are "
        "blocked. Use this instead of probing methods on live business records."
    ),
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def list_allowed_methods(
    ctx: Context,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Report the effective method policy, optionally narrowed to one model.

    NESA B5: trial and error is a bad discovery mechanism when a wrong guess
    on ``account.move`` might post an invoice. This states the policy instead.
    """
    try:
        if model is not None:
            validate_model_name(model)
        from . import _nesa_db_allowlist

        db_entries = sorted(_nesa_db_allowlist.methods())
        env_entries = sorted(allowed_side_effect_methods())
        if model:
            prefix = f"{model}."
            db_entries = [entry for entry in db_entries if entry.startswith(prefix)]
            env_entries = [entry for entry in env_entries if entry.startswith(prefix)]
        parity = native_acl_parity_enabled()
        deny_prefixes = denied_method_prefixes()
        if model:
            model_deny = [
                prefix
                for prefix in deny_prefixes
                if prefix.startswith(model.casefold())
                or f"{model}.".casefold().startswith(prefix)
            ]
        else:
            model_deny = deny_prefixes
        if parity:
            positive_policy = (
                "Native Odoo ACL parity is active: every public, non-underscore "
                "method runs if and only if the acting Odoo user is allowed to "
                "run it. CRUD and its write-equivalent aliases are the "
                "exception — they stay on the approved-write chain regardless."
            )
        elif truthy_env("ODOO_MCP_ALLOW_UNKNOWN_METHODS"):
            positive_policy = (
                "Broad unknown-method mode is active: unreviewed side-effect "
                "methods are permitted. Prefer exact allowlist entries."
            )
        else:
            positive_policy = (
                "Exact-allowlist mode: only the listed model.method entries may "
                "run as side effects. Read-only methods always run."
            )
        return {
            "success": True,
            "tool": "list_allowed_methods",
            "model": model,
            "authorization_mode": (
                "native_acl_parity"
                if parity
                else (
                    "broad_unknown_methods"
                    if truthy_env("ODOO_MCP_ALLOW_UNKNOWN_METHODS")
                    else "exact_allowlist"
                )
            ),
            "positive_policy": positive_policy,
            "always_blocked": {
                "private_methods": "Any method starting with '_'.",
                "crud_on_persistent_models": sorted(DESTRUCTIVE_METHODS),
                "write_equivalent_aliases": sorted(WRITE_EQUIVALENT_METHODS),
                "hard_deny_prefixes": model_deny,
                "note": (
                    "create/write run directly only on a transient model that "
                    "is BOTH named on the reviewed exemption list AND reported "
                    "inert by Odoo (no create/write override, no inverse "
                    "fields); x2many commands 0/1/2/3 are refused even then. "
                    "unlink and the aliases never run directly."
                ),
            },
            "db_allowlist_entries": db_entries,
            "env_allowlist_entries": env_entries,
            "transient_exempt_models": sorted(
                entry for entry in TRANSIENT_EXEMPT_MODELS
                if not model or entry == model
            ),
            "write_path": (
                "validate_write -> execute_approved_write(confirm=true); the "
                f"approval token lives {WRITE_APPROVAL_TTL_SECONDS} seconds."
            ),
        }
    except Exception as e:
        return error_response("list_allowed_methods", e, model=model)


@mcp.tool(
    description=(
        "Read the chatter (mail.message history) of a record: who wrote what "
        "and when, newest first, with attachment IDs."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def chatter_read(
    ctx: Context,
    model: Annotated[str, Field(description="Technical model name of the record.")],
    record_id: Annotated[int, Field(description="Database id of the record.", ge=1)],
    limit: Annotated[int, Field(description="Messages per page, newest first.", ge=1)] = 20,
    offset: Annotated[int, Field(description="Messages to skip.", ge=0)] = 0,
    body_char_limit: Annotated[
        int,
        Field(description="Truncate each message body to this many characters.", ge=1),
    ] = 2000,
    message_types: Annotated[
        Optional[List[str]],
        Field(
            description=(
                "Filter by mail.message type: 'comment' (notes and mails), "
                "'email', 'notification' (tracking). Default: all."
            )
        ),
    ] = None,
) -> Dict[str, Any]:
    """Return the message history of one record in reverse chronological order.

    NESA B6: the counterpart to ``chatter_post``. Filtering ``mail.message`` by
    hand through ``search_records`` is easy to get wrong (``model`` plus
    ``res_id`` plus message type), and the chatter is often the only place a
    dispute is documented.
    """
    app_context = ctx.request_context.lifespan_context
    odoo = app_context.odoo
    try:
        validate_model_name(model)
        if record_id < 1:
            raise ValueError("record_id must be greater than 0")
        limit = clamp_limit(limit)
        if offset < 0:
            raise ValueError("offset must be greater than or equal to 0")
        if body_char_limit < 1:
            raise ValueError("body_char_limit must be greater than 0")
        domain: List[Any] = [["model", "=", model], ["res_id", "=", record_id]]
        if message_types:
            domain.append(["message_type", "in", list(message_types)])
        fields = [
            "id",
            "date",
            "author_id",
            "email_from",
            "message_type",
            "subtype_id",
            "subject",
            "body",
            "attachment_ids",
        ]
        messages = call_with_transport_retry(
            lambda: odoo.search_read(
                model_name="mail.message",
                domain=domain,
                fields=fields,
                offset=offset,
                limit=limit,
                order="id desc",
            ),
            label="search_read(mail.message)",
        )
        total_count: Optional[int] = None
        try:
            counted = odoo.execute_method("mail.message", "search_count", domain)
            if isinstance(counted, int):
                total_count = counted
        except Exception as count_exc:  # noqa: BLE001 — page is still valid
            logger.warning("[chatter_read] search_count failed: %s", count_exc)
        truncated = 0
        for message in messages:
            body = message.get("body")
            if isinstance(body, str) and len(body) > body_char_limit:
                message["body"] = body[:body_char_limit]
                message["body_truncated"] = True
                truncated += 1
        returned = len(messages)
        has_more = (
            (offset + returned) < total_count
            if total_count is not None
            else (True if returned >= limit else None)
        )
        return {
            "success": True,
            "tool": "chatter_read",
            "model": model,
            "record_id": record_id,
            "count": returned,
            "total_count": total_count,
            "has_more": has_more,
            "next_offset": (offset + returned) if has_more else None,
            "truncated_bodies": truncated,
            "body_char_limit": body_char_limit,
            "messages": messages,
        }
    except Exception as e:
        return error_response("chatter_read", e, model=model, record_id=record_id)


@mcp.tool(
    description=(
        "Build the web-interface URL of a record so it can be handed to a "
        "person without guessing the link format."
    ),
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def get_record_url(
    ctx: Context,
    model: str,
    record_id: int,
    verify: bool = False,
) -> Dict[str, Any]:
    """Return the backend URL of a record, based on Odoo's own web.base_url.

    ``verify=True`` additionally confirms that the record exists and is
    visible for the acting user — cheap insurance against handing out a link
    that opens on an error page.
    """
    app_context = ctx.request_context.lifespan_context
    odoo = app_context.odoo
    try:
        validate_model_name(model)
        if record_id < 1:
            raise ValueError("record_id must be greater than 0")
        base = odoo_base_url(app_context, odoo)
        if not base:
            raise ValueError(
                "web.base_url is not configured and no RPC URL is known."
            )
        response: Dict[str, Any] = {
            "success": True,
            "tool": "get_record_url",
            "model": model,
            "record_id": record_id,
            "base_url": base,
            # Odoo 17.2+/18 canonical deep link.
            "url": f"{base}/odoo/{model}/{record_id}",
            # Always-supported legacy hash route, kept as a fallback for
            # models without a resolvable action path.
            "legacy_url": (
                f"{base}/web#id={record_id}&model={model}&view_type=form"
            ),
        }
        if verify:
            exists = odoo.execute_method(
                model, "search_count", [["id", "=", record_id]],
            )
            response["record_visible"] = bool(exists)
            if not exists:
                response["warning"] = (
                    "The record does not exist or is not visible for this user; "
                    "the link would open on an error page."
                )
        return response
    except Exception as e:
        return error_response("get_record_url", e, model=model, record_id=record_id)


@mcp.tool(
    description=(
        "Preview how NESA material and labour values resolve into price_unit "
        "before anything is written. M-EK (purchase_price), M-VK "
        "(nesa_material_price) and M-Multi (nesa_multi_material) are the "
        "leading fields; price_unit is derived and must not be written."
    ),
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def price_preview(
    ctx: Context,
    model: str,
    values: Dict[str, Any],
    line_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Compute the resulting NESA line prices without touching the database.

    ``model`` is a line model such as ``sale.order.line`` or
    ``account.move.line``. ``values`` are the field values to try; when
    ``line_id`` is given, the stored values of that line are used as the base
    and ``values`` is applied on top.

    The calculation runs inside Odoo on an in-memory record, so it uses the
    module's own compute chain rather than a copy of the formula that could
    drift.
    """
    odoo = ctx.request_context.lifespan_context.odoo
    try:
        validate_model_name(model)
        if not isinstance(values, dict):
            raise ValueError("values must be a mapping of field names to values")
        try:
            result = call_doc_helper(
                odoo, "mcp_price_preview", model, values, line_id or 0,
            )
        except Exception as exc:  # noqa: BLE001 — mapped to guidance below
            missing = _doc_helper_missing_response("price_preview", exc)
            if missing:
                return missing
            raise
        if not isinstance(result, dict) or not result.get("success"):
            return {
                "success": False,
                "tool": "price_preview",
                "error": (
                    (result or {}).get("error")
                    if isinstance(result, dict)
                    else "price preview failed"
                ),
                "error_type": "preview_failed",
                "retryable": False,
            }
        return {"success": True, "tool": "price_preview", "model": model, **result}
    except Exception as e:
        return error_response("price_preview", e, model=model)


# ----- MCP Prompts -----


@mcp.prompt(
    name="diagnose_failed_odoo_call",
    description="Guide an assistant through diagnosing a failed Odoo model call.",
)
def prompt_diagnose_failed_odoo_call(
    model: str,
    method: str,
    error: str = "",
) -> str:
    """Prompt for root-causing failed Odoo calls using the safe tools first."""
    return (
        "Diagnose this Odoo call without retrying destructive methods first.\n"
        f"Model: {model}\n"
        f"Method: {method}\n"
        f"Observed error: {error or '<not provided>'}\n\n"
        "Use diagnose_odoo_call, diagnose_access, inspect_model_relationships, "
        "and get_model_fields before execute_method. Preserve Odoo error details, "
        "but do not expose secrets."
    )


@mcp.prompt(
    name="fit_gap_workshop",
    description="Structure an Odoo fit/gap workshop from raw requirements.",
)
def prompt_fit_gap_workshop(requirement: str) -> str:
    """Prompt for classifying a business requirement safely."""
    return (
        "Classify this requirement into standard Odoo, configuration, Studio, "
        "custom module, avoid, or unknown.\n"
        f"Requirement: {requirement}\n\n"
        "Use fit_gap_report first, then schema_catalog/list_models for evidence. "
        "Recommend the smallest Odoo-native implementation path."
    )


@mcp.prompt(
    name="json2_migration_plan",
    description="Plan migration from XML-RPC/JSON-RPC style calls to Odoo JSON-2.",
)
def prompt_json2_migration_plan(model: str, method: str) -> str:
    """Prompt for JSON-2 named-argument and transaction migration planning."""
    return (
        "Prepare a JSON-2 migration plan for this Odoo call.\n"
        f"Model: {model}\n"
        f"Method: {method}\n\n"
        "Use generate_json2_payload and upgrade_risk_report. Call out named "
        "arguments, per-call transaction behavior, database header expectations, "
        "and destructive-method safeguards."
    )


@mcp.prompt(
    name="safe_write_review",
    description="Review a proposed create/write/unlink before execution.",
)
def prompt_safe_write_review(model: str, operation: str) -> str:
    """Prompt for approval-token write review."""
    return (
        "Review this proposed Odoo write before any execution.\n"
        f"Model: {model}\n"
        f"Operation: {operation}\n\n"
        "Use preview_write and validate_write. Only execute through "
        "execute_approved_write when the approval token matches, confirm=true is "
        "explicit, and the runtime has ODOO_MCP_ENABLE_WRITES=1."
    )


@mcp.prompt(
    name="custom_module_audit",
    description="Guide a local source audit for custom Odoo addons.",
)
def prompt_custom_module_audit(addons_path: str) -> str:
    """Prompt for local custom-addon review without importing code."""
    return (
        "Audit local Odoo addon source without importing addon modules.\n"
        f"Addons path: {addons_path}\n\n"
        "Use scan_addons_source, upgrade_risk_report, and business_pack_report. "
        "Prioritize manifest dependencies, computed field dependencies, overridden "
        "create/write/unlink methods, sudo usage, automated actions, custom views, "
        "and security CSV files."
    )
