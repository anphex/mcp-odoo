"""NESA DB-Allowlist reader for MCP-server.

Extends the upstream ``ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS`` CSV-Env
with a DB-driven allowlist read from the Odoo model
``nesa.mcp.allowed_method`` (or whatever ``ODOO_MCP_METHOD_ALLOWLIST_MODEL``
points at). Result: NESA can manage the allowlist via Odoo backend
(Settings -> NESA MCP -> Allowed Methods) instead of bouncing the
systemd unit on every change. DATEV/Payroll blocklist is enforced on
the Odoo-Model-Constraint side (cannot create blocked entries) so the
fork stays unaware of business policy.

Design rules:
  - Additive: when env var is unset, returns an empty set and the
    upstream CSV path keeps working unchanged.
  - Lazy + cached: first call triggers an XML-RPC fetch; subsequent
    calls within ``_CACHE_TTL_SECONDS`` (default 60s) reuse the cache.
  - Failure-soft: if the fetch fails, the last-known cache is returned
    (or an empty set if there is none). The MCP-server keeps serving
    on the upstream CSV allowlist; the failure is logged and exposed
    via :func:`describe_state`.
  - Thread-safe: a coarse-grained lock guards refresh; the gate
    function reads a snapshot tuple under the same lock.

Intended caller: :mod:`odoo_mcp.server` ``side_effect_method_allowed``
(see ``_nesa_*``-prefixed integration there).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

_logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = int(os.environ.get("ODOO_MCP_METHOD_ALLOWLIST_TTL", "60"))
_ALLOWLIST_MODEL_ENV = "ODOO_MCP_METHOD_ALLOWLIST_MODEL"

# State guarded by ``_lock``.
_lock = threading.Lock()
_cache_methods: frozenset[str] = frozenset()
_cache_descriptions: dict[str, str] = {}
_cache_fetched_at: float = 0.0
_cache_last_error: str | None = None
_cache_last_success_at: float = 0.0


def _model_name() -> str | None:
    """Return the configured allowlist model or ``None`` when disabled."""
    val = os.environ.get(_ALLOWLIST_MODEL_ENV, "").strip()
    return val or None


def _fetch_once() -> tuple[frozenset[str], dict[str, str]]:
    """Single XML-RPC fetch. Caller holds ``_lock``."""
    # Import lazily so that pure unit-test imports of this module do not
    # pull the full OdooClient stack (avoids import cycles during pytest).
    from .odoo_client import get_odoo_client

    model = _model_name()
    if not model:
        return frozenset(), {}
    odoo = get_odoo_client()
    rows: list[dict[str, Any]] = odoo.execute_method(
        model,
        "search_read",
        [("active", "=", True)],
        ["method_path", "description"],
    )
    methods: set[str] = set()
    descriptions: dict[str, str] = {}
    for row in rows or []:
        path = (row.get("method_path") or "").strip()
        if not path:
            continue
        methods.add(path)
        desc = row.get("description")
        if isinstance(desc, str) and desc.strip():
            descriptions[path] = desc.strip()
    return frozenset(methods), descriptions


def _refresh_if_stale() -> None:
    """Refresh cache under ``_lock`` when TTL expired and env var set."""
    global _cache_methods, _cache_descriptions
    global _cache_fetched_at, _cache_last_error, _cache_last_success_at
    if not _model_name():
        # Disabled -> drop any stale cache so describe_state is honest.
        if _cache_methods or _cache_descriptions:
            _cache_methods = frozenset()
            _cache_descriptions = {}
        return
    now = time.time()
    if now - _cache_fetched_at < _CACHE_TTL_SECONDS:
        return
    _cache_fetched_at = now
    try:
        methods, descriptions = _fetch_once()
    except Exception as exc:  # noqa: BLE001 — failure-soft by design
        _cache_last_error = f"{type(exc).__name__}: {exc}"
        _logger.warning(
            "[nesa_db_allowlist] fetch failed, keeping last known set "
            "(%d entries, last_success_age=%.1fs): %s",
            len(_cache_methods),
            now - _cache_last_success_at if _cache_last_success_at else -1,
            _cache_last_error,
        )
        return
    _cache_methods = methods
    _cache_descriptions = descriptions
    _cache_last_error = None
    _cache_last_success_at = now
    _logger.info(
        "[nesa_db_allowlist] cache refreshed: %d methods", len(methods),
    )


def methods() -> frozenset[str]:
    """Return the current allowlist set (cached, may trigger refresh)."""
    with _lock:
        _refresh_if_stale()
        return _cache_methods


def description(method_path: str) -> str | None:
    """Return the LLM-facing description for ``method_path`` if cached."""
    with _lock:
        _refresh_if_stale()
        return _cache_descriptions.get(method_path)


def is_allowed(model: str, method: str) -> bool:
    """Convenience: ``model.method`` membership in the current cache."""
    return f"{model}.{method}" in methods()


def describe_state() -> dict[str, Any]:
    """Expose cache state for ``runtime_security_report`` (no secrets)."""
    with _lock:
        return {
            "model": _model_name(),
            "enabled": _model_name() is not None,
            "ttl_seconds": _CACHE_TTL_SECONDS,
            "cached_method_count": len(_cache_methods),
            "cache_age_seconds": (
                round(time.time() - _cache_fetched_at, 1)
                if _cache_fetched_at else None
            ),
            "last_error": _cache_last_error,
            "last_success_age_seconds": (
                round(time.time() - _cache_last_success_at, 1)
                if _cache_last_success_at else None
            ),
        }


def reset_for_tests() -> None:
    """Drop all cached state. For unit tests only."""
    global _cache_methods, _cache_descriptions
    global _cache_fetched_at, _cache_last_error, _cache_last_success_at
    with _lock:
        _cache_methods = frozenset()
        _cache_descriptions = {}
        _cache_fetched_at = 0.0
        _cache_last_error = None
        _cache_last_success_at = 0.0
