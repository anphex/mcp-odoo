"""NESA Patch 8: per-user invoice tools from the Odoo invoice gateway.

The Odoo module ``nesa_agent_invoice_mcp`` exposes the invoice tools of the
built-in invoice agent through the concrete model
``nesa.agent.invoice.mcp.gateway``.  This module asks that gateway, under the
acting user's own Odoo rights, which tools the user may see and forwards
calls to it.

Security contract:

* Fail-closed. Without a per-user request context there are no dynamic tools,
  and the service account is never used (``get_per_user_client`` returns
  ``None`` or raises; ``get_odoo_client`` is deliberately not called because
  its fallback is the service account).
* The gateway decides visibility (invoice group, kill switch, sync user,
  per-workflow allowlist).  This side only validates the shape: tool names,
  collisions with static tools and an object input schema.
* Calls carry a fresh ``call_id``; the gateway uses it as the dispatcher's
  idempotency key.  A transport failure is never retried
  (``idempotent=False``) because the call may already have written.
* The gateway model is on ``NON_DELEGABLE_METHOD_PREFIXES`` so an agent cannot
  reach it through ``execute_method`` with arbitrary arguments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations

logger = logging.getLogger(__name__)

GATEWAY_MODEL = "nesa.agent.invoice.mcp.gateway"
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_TOOLS = 100
_MAX_DESCRIPTION_CHARS = 8000
_NEGATIVE_TTL_SECONDS = 10


def _int_env(name: str, default: int, lower: int, upper: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(lower, min(upper, value))


def _list_ttl_seconds() -> int:
    return _int_env("ODOO_MCP_INVOICE_TOOLS_TTL", 60, 5, 600)


def _call_timeout_seconds() -> int:
    # Longest invoice tool runs 150 s, a parallel call on the same invoice may
    # wait up to the gateway's lock wait (default 240 s) before that.
    return _int_env("ODOO_MCP_INVOICE_TOOLS_TIMEOUT", 600, 60, 900)


_lock = threading.Lock()
# scope key -> (expires_at, tools)
_tool_cache: Dict[str, Tuple[float, List[Tool]]] = {}
# credential identity -> (expires_at, client) for the long-timeout client
_client_cache: Dict[Any, Tuple[float, Any]] = {}


def reset_for_tests() -> None:
    with _lock:
        _tool_cache.clear()
        _client_cache.clear()


def _scope_key() -> Optional[str]:
    """``login:digest`` of the acting user, ``None`` without request context."""
    from ._nesa_per_user_auth import current_user_context

    context = current_user_context()
    if not context:
        return None
    login, api_key = context
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return f"{login}:{digest}"


def _list_client() -> Optional[Any]:
    from ._nesa_per_user_auth import get_per_user_client

    return get_per_user_client()


def _call_client() -> Optional[Any]:
    """Per-user client with a timeout long enough for the slowest tool."""
    from . import _nesa_per_user_auth as per_user

    context = per_user.current_user_context()
    if not context:
        return None
    login, api_key = context
    identity = per_user._credential_identity(login, api_key)
    now = time.monotonic()
    with _lock:
        cached = _client_cache.get(identity)
        if cached and cached[0] > now:
            return cached[1]
    client = per_user._build_per_user_client(login, api_key)
    # A non-read call opens a fresh connection with ``client.timeout`` (XML-RPC
    # ``_execute_kw_once``, JSON-2 ``urlopen``), so raising it here is enough.
    client.timeout = _call_timeout_seconds()
    with _lock:
        for stale, (expires, _client) in list(_client_cache.items()):
            if expires <= now:
                _client_cache.pop(stale, None)
        if len(_client_cache) >= per_user._cache_max_entries():
            oldest = min(_client_cache, key=lambda k: _client_cache[k][0])
            _client_cache.pop(oldest, None)
        _client_cache[identity] = (now + per_user._cache_ttl_seconds(), client)
    return client


def _parse_tools(payload: Any, reserved: set) -> List[Tool]:
    if not isinstance(payload, dict) or not payload.get("success"):
        return []
    if not payload.get("enabled"):
        return []
    tools: List[Tool] = []
    seen: set = set()
    for spec in payload.get("tools") or []:
        if not isinstance(spec, dict):
            continue
        name = spec.get("name")
        schema = spec.get("input_schema")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            logger.warning("[invoice_tools] skipped tool with invalid name")
            continue
        if name in reserved or name in seen:
            logger.warning("[invoice_tools] skipped tool %s: name collision", name)
            continue
        if not isinstance(schema, dict) or schema.get("type") != "object":
            logger.warning("[invoice_tools] skipped tool %s: schema is no object", name)
            continue
        description = spec.get("description")
        description = description if isinstance(description, str) else ""
        read_only = spec.get("read_only") is True
        tools.append(Tool(
            name=name,
            description=description[:_MAX_DESCRIPTION_CHARS],
            inputSchema=schema,
            annotations=ToolAnnotations(
                readOnlyHint=read_only,
                destructiveHint=False,
                idempotentHint=read_only,
                openWorldHint=False,
            ),
        ))
        seen.add(name)
        if len(tools) >= _MAX_TOOLS:
            break
    return tools


def dynamic_tools(reserved: set) -> List[Tool]:
    """Invoice tools of the acting user (cached briefly, ``[]`` on any doubt)."""
    key = _scope_key()
    if key is None:
        return []
    now = time.monotonic()
    with _lock:
        cached = _tool_cache.get(key)
        if cached and cached[0] > now:
            return list(cached[1])
    from .server import call_with_transport_retry

    try:
        client = _list_client()
        if client is None:
            return []
        payload = call_with_transport_retry(
            lambda: client.execute_method(GATEWAY_MODEL, "mcp_list_tools"),
            label="invoice_tools.list",
        )
        ttl = _list_ttl_seconds()
    except Exception as exc:  # noqa: BLE001 — listing must never break tools/list
        # Missing module, no ACL or Odoo down: the user simply sees no invoice
        # tools.  Cache the empty answer briefly so tools/list stays cheap.
        logger.info("[invoice_tools] listing unavailable: %s", type(exc).__name__)
        payload = None
        ttl = min(_NEGATIVE_TTL_SECONDS, _list_ttl_seconds())
    tools = _parse_tools(payload, reserved)
    with _lock:
        for stale, (expires, _tools) in list(_tool_cache.items()):
            if expires <= now:
                _tool_cache.pop(stale, None)
        _tool_cache[key] = (now + ttl, tools)
    return list(tools)


def is_dynamic_tool(name: str, reserved: set) -> bool:
    return any(tool.name == name for tool in dynamic_tools(reserved))


def _result(text: str, meta: Dict[str, Any], is_error: bool) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structuredContent={"result": meta},
        isError=is_error,
    )


def call_dynamic_tool(name: str, arguments: Optional[Dict[str, Any]]) -> CallToolResult:
    """Forward one call to the gateway and turn its answer into a tool result."""
    from .server import UnknownOutcomeError, call_with_transport_retry, error_response

    call_id = uuid.uuid4().hex
    try:
        client = _call_client()
        if client is None:
            raise PermissionError("Invoice tools need a per-user MCP connection.")
        payload = call_with_transport_retry(
            # Keyword arguments work on XML-RPC and JSON-2 alike.
            lambda: client.execute_method(
                GATEWAY_MODEL, "mcp_call_tool",
                name=name, arguments=dict(arguments or {}), call_id=call_id,
            ),
            label=f"invoice_tools.{name}",
            idempotent=False,
        )
    except Exception as exc:  # noqa: BLE001 — becomes a uniform error payload
        response = error_response(name, exc)
        if isinstance(exc, UnknownOutcomeError):
            response["call_id"] = call_id
        return _result(json.dumps(response, ensure_ascii=False), response, True)
    if not isinstance(payload, dict):
        response = {
            "success": False, "tool": name, "error": "Unexpected gateway answer.",
        }
        return _result(response["error"], response, True)
    is_error = bool(payload.get("is_error"))
    meta = {
        # A tool error ran through the gateway but did not succeed; log and
        # telemetry must not count it as a success.
        "success": bool(payload.get("success")) and not is_error,
        "tool": name,
        "is_error": is_error,
        "session_id": payload.get("session_id") or None,
        "run_id": payload.get("run_id") or None,
        "workflow": payload.get("workflow") or None,
    }
    if not payload.get("success"):
        error = payload.get("error") or "Invoice tool failed."
        meta["error"] = error
        return _result(str(error), meta, True)
    content = payload.get("content")
    return _result(content if isinstance(content, str) else "", meta, meta["is_error"])
