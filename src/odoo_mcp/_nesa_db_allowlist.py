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
  - Thread-safe: state transitions are locked, while XML-RPC network calls
    happen outside the lock. Concurrent readers keep the last-known snapshot.
  - Service-owned: refresh always uses the configured service account, never
    credentials inherited from the human request that happened to trigger it.

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
_ALLOW_EMPTY_ENV = "ODOO_MCP_METHOD_ALLOWLIST_ALLOW_EMPTY"

# State guarded by ``_lock``.
_lock = threading.Lock()
_cache_methods: frozenset[str] = frozenset()
_cache_descriptions: dict[str, str] = {}
_cache_fetched_at: float = 0.0
_cache_last_error: str | None = None
_cache_last_success_at: float = 0.0
_refresh_in_progress = False


def _model_name() -> str | None:
    """Return the configured allowlist model or ``None`` when disabled."""
    val = os.environ.get(_ALLOWLIST_MODEL_ENV, "").strip()
    return val or None


def _allow_empty_result() -> bool:
    """Allow an intentional empty DB policy only after explicit opt-in."""
    return os.environ.get(_ALLOW_EMPTY_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _fetch_once() -> tuple[frozenset[str], dict[str, str]]:
    """Perform one XML-RPC fetch without holding the process state lock.

    Two-phase: first reads ``method_path`` + ``description`` from the
    allowlist model. For rows with an empty description, the Python
    docstring of the referenced method is fetched as a fallback via
    ``nesa.mcp.allowed_method.get_method_doc(model_name, method_name)``
    (NESA-Patch 4). Lets allowlist-authors skip writing descriptions
    when the source docstring is already LLM-ready.

    Docstring lookups are best-effort: if the fallback call fails or
    returns an empty string, the method stays in the allowlist set but
    contributes no description (consumers handle ``None``).
    """
    # Import lazily so that pure unit-test imports of this module do not
    # pull the full OdooClient stack (avoids import cycles during pytest).
    from .odoo_client import get_service_odoo_client

    model = _model_name()
    if not model:
        return frozenset(), {}
    odoo = get_service_odoo_client()
    rows: list[dict[str, Any]] = odoo.execute_method(
        model,
        "search_read",
        [("active", "=", True)],
        ["method_path", "description"],
    )
    methods: set[str] = set()
    descriptions: dict[str, str] = {}
    fallback_targets: list[tuple[str, str, str]] = []  # (path, model_name, method_name)
    for row in rows or []:
        path = (row.get("method_path") or "").strip()
        if not path:
            continue
        methods.add(path)
        desc = row.get("description")
        if isinstance(desc, str) and desc.strip():
            descriptions[path] = desc.strip()
            continue
        # Empty description -> queue for docstring fallback.
        if "." in path:
            model_name, _, method_name = path.rpartition(".")
            if model_name and method_name:
                fallback_targets.append((path, model_name, method_name))

    # Phase 2: docstring fallback. One XML-RPC call per target. Cheap (cache
    # TTL keeps refresh-rate low) and only hits rows without explicit desc.
    for path, model_name, method_name in fallback_targets:
        try:
            doc = odoo.execute_method(
                model, "get_method_doc", model_name, method_name,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort enrichment
            _logger.debug(
                "[nesa_db_allowlist] get_method_doc fallback failed for %s: %s",
                path, exc,
            )
            continue
        if isinstance(doc, str) and doc.strip():
            descriptions[path] = doc.strip()

    return frozenset(methods), descriptions


def _refresh_if_stale() -> None:
    """Refresh stale state once while concurrent callers use the old snapshot."""
    global _cache_methods, _cache_descriptions
    global _cache_fetched_at, _cache_last_error, _cache_last_success_at
    global _refresh_in_progress

    model = _model_name()
    with _lock:
        if not model:
            # Disabled -> drop stale state so describe_state is honest.
            _cache_methods = frozenset()
            _cache_descriptions = {}
            _cache_fetched_at = 0.0
            _cache_last_error = None
            _cache_last_success_at = 0.0
            _refresh_in_progress = False
            return
        now = time.monotonic()
        if (
            now - _cache_fetched_at < _CACHE_TTL_SECONDS
            or _refresh_in_progress
        ):
            return
        _refresh_in_progress = True

    try:
        methods, descriptions = _fetch_once()
        if not methods and not _allow_empty_result():
            raise RuntimeError(
                "DB allowlist returned no methods; keeping last-known policy. "
                f"Set {_ALLOW_EMPTY_ENV}=1 only for an intentional empty policy."
            )
    except Exception as exc:  # noqa: BLE001 — failure-soft by design
        finished_at = time.monotonic()
        error = f"{type(exc).__name__}: {exc}"
        with _lock:
            _cache_fetched_at = finished_at
            _cache_last_error = error
            cached_count = len(_cache_methods)
            success_age = (
                finished_at - _cache_last_success_at
                if _cache_last_success_at else -1
            )
        _logger.warning(
            "[nesa_db_allowlist] fetch failed, keeping last known set "
            "(%d entries, last_success_age=%.1fs): %s",
            cached_count,
            success_age,
            error,
        )
        return
    else:
        finished_at = time.monotonic()
        with _lock:
            _cache_methods = methods
            _cache_descriptions = descriptions
            _cache_fetched_at = finished_at
            _cache_last_error = None
            _cache_last_success_at = finished_at
        _logger.info(
            "[nesa_db_allowlist] cache refreshed: %d methods", len(methods),
        )
    finally:
        # Also reset on BaseException (shutdown/interrupt). Without this,
        # future readers could remain pinned to the last snapshot forever.
        with _lock:
            _refresh_in_progress = False


def methods() -> frozenset[str]:
    """Return the current allowlist set (cached, may trigger refresh)."""
    _refresh_if_stale()
    with _lock:
        return _cache_methods


def description(method_path: str) -> str | None:
    """Return the LLM-facing description for ``method_path`` if cached."""
    _refresh_if_stale()
    with _lock:
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
                round(time.monotonic() - _cache_fetched_at, 1)
                if _cache_fetched_at else None
            ),
            "last_error": _cache_last_error,
            "last_success_age_seconds": (
                round(time.monotonic() - _cache_last_success_at, 1)
                if _cache_last_success_at else None
            ),
            "refresh_in_progress": _refresh_in_progress,
            "empty_result_allowed": _allow_empty_result(),
        }


def reset_for_tests() -> None:
    """Drop all cached state. For unit tests only."""
    global _cache_methods, _cache_descriptions
    global _cache_fetched_at, _cache_last_error, _cache_last_success_at
    global _refresh_in_progress
    with _lock:
        _cache_methods = frozenset()
        _cache_descriptions = {}
        _cache_fetched_at = 0.0
        _cache_last_error = None
        _cache_last_success_at = 0.0
        _refresh_in_progress = False
