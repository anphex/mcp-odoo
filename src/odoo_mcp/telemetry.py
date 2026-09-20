"""Opt-in, bounded, value-free MCP usage telemetry (schema v1).

Only completed calls are recorded. Process termination can lose in-flight calls
and queued events; this is usage evidence, not a financial/audit ledger.
"""
import hashlib
import hmac
import json
import logging
import os
import queue
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger(__name__)
PARAMETERS = frozenset('model domain fields ids record_id limit offset order method args kwargs values context query report_name action confirm approval_token'.split())
ERROR_CLASSES = frozenset('request transport odoo_error tool_error not_found not_configured not_readable'.split())
# A tool's own reason_code is preferred over guessing a category from prose,
# but it is bounded like every other recorded identifier so a relayed Odoo
# string can never widen the taxonomy or the file size.
REASON_CODE = re.compile(r'\A[a-z][a-z0-9_]{0,39}\Z')


def argument_shape(arguments):
    """Never descend into caller dictionaries or retain strings/record IDs."""
    result = {}
    for key in PARAMETERS:
        if key not in arguments:
            continue
        value = arguments[key]
        kind = ('null' if value is None else 'bool' if isinstance(value, bool)
                else 'number' if isinstance(value, (int, float)) else
                'string' if isinstance(value, str) else 'list' if isinstance(value, list)
                else 'object' if isinstance(value, dict) else 'other')
        size = len(value) if isinstance(value, (list, dict, str)) else None
        result[key] = {'type': kind}
        if size is not None:
            result[key]['size_bucket'] = next((str(n) for n in (0, 1, 5, 20, 100, 1000) if size <= n), '1000+')
    return result


def safe_schema(schema, depth=0):
    """Trusted server definitions only; exclude defaults, examples and extensions."""
    if not isinstance(schema, dict) or depth > 10:
        return {}
    result = {key: schema[key] for key in ('type', 'description', 'required') if key in schema}
    if 'properties' in schema:
        result['properties'] = {k: safe_schema(v, depth + 1) for k, v in schema['properties'].items()}
    if 'items' in schema:
        result['items'] = safe_schema(schema['items'], depth + 1)
    for key in ('anyOf', 'oneOf', 'allOf'):
        if key in schema:
            result[key] = [safe_schema(v, depth + 1) for v in schema[key]]
    return result


class Telemetry:
    def __init__(self, directory, key, instance, max_bytes=256 * 1024 * 1024, models=()):
        self.directory = Path(directory)
        self.key = key
        self.instance = instance
        self.max_bytes = max_bytes
        self.models = frozenset(model.strip() for model in models if model.strip())
        self.queue = queue.Queue(maxsize=1024)
        self.dropped = 0
        self._versions = {}
        self._published = set()
        self._definition_retry_at = {}
        self._disk_bytes = 0
        self._disk_files = 0
        self._disk_scan_at = float('-inf')
        self._warned_at = 0.0
        # Code version changes even when a description/schema is unchanged.
        code = hashlib.sha256()
        for source in sorted(Path(__file__).parent.glob('*.py')):
            code.update(source.name.encode())
            code.update(source.read_bytes())
        self.code_version = code.hexdigest()[:16]
        self.thread = threading.Thread(target=self._worker, daemon=True, name='mcp-telemetry')
        self.thread.start()

    def pseudonym(self, namespace, value):
        payload = json.dumps([self.instance, namespace, value], separators=(',', ':')).encode()
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def definition(self, tool):
        if tool is None:
            return 'unknown', 'unknown'
        if tool.name not in self._versions:
            definition = {'name': tool.name, 'description': tool.description,
                          'input_schema': safe_schema(tool.parameters)}
            raw = json.dumps(definition, sort_keys=True).encode()
            version = hashlib.sha256(raw).hexdigest()[:24]
            self._versions[tool.name] = (version, raw)
        version, raw = self._versions[tool.name]
        if version not in self._published and time.monotonic() >= self._definition_retry_at.get(version, 0):
            # Lifespan runs per MCP session. Never enqueue the complete catalog
            # repeatedly when storage is unavailable; retry each version hourly.
            self._definition_retry_at[version] = time.monotonic() + 3600
            self._enqueue(('definition', version, raw))
        return tool.name, version

    def begin(self, arguments, tool, context, principal, start_at=None):
        # Unknown names are caller data and deliberately not persisted. They
        # have no definition file; the analyzer must report them as unknown.
        tool_name, version = self.definition(tool)
        headers = getattr(getattr(context, 'request', None), 'headers', {}) or {}
        workflow = headers.get('x-nesa-workflow-id', '')
        session = headers.get('mcp-session-id', '')
        # Explicit context is untrusted, bounded, and scoped to the authenticated principal.
        workflow = workflow if isinstance(workflow, str) and 0 < len(workflow) <= 256 else ''
        session = session if isinstance(session, str) and 0 < len(session) <= 256 else ''
        correlation = workflow or session
        quality = 'workflow' if workflow else 'session' if session else 'none'
        return {'schema_version': 1, 'event_id': uuid.uuid4().hex, 'instance': self.instance,
                'tool': tool_name, 'tool_version': version, 'code_version': self.code_version,
                'start_at': start_at or datetime.now(timezone.utc).isoformat(),
                'correlation_id': self.pseudonym(quality, [principal, correlation]) if correlation else None,
                'correlation_quality': quality,
                'session_id': self.pseudonym('session', [principal, session]) if session else None,
                'model': (arguments.get('model') if isinstance(arguments.get('model'), str) and arguments.get('model') in self.models else 'other') if 'model' in arguments else None,
                'argument_shape': argument_shape(arguments)}

    def finish(self, event, elapsed, success, count, size, structured, exception=None):
        error = exception is not None or success is False or (isinstance(structured, dict) and bool(structured.get('error')))
        # A tool that refuses a payload on purpose reports a verdict, not a
        # fault, and must not inflate the error rate.  Only an explicit marker
        # from the tool downgrades the status: an exception, or a failure that
        # carries no marker, still counts as an error.
        rejected = (exception is None and isinstance(structured, dict)
                    and structured.get('outcome') == 'rejected')
        if rejected and not error:
            # A tool that claims a refusal while reporting no failure breaks the
            # contract.  Book that as an error rather than let it disappear into
            # 'success', where nobody would ever see it.
            error, rejected = True, False
        event.update(end_at=datetime.now(timezone.utc).isoformat(), duration_ms=round(elapsed * 1000, 3),
                     status=('rejected' if rejected else 'error') if error
                     else 'success' if success is True else 'unknown',
                     record_count=count, result_bytes=size, error_class=None, error_code=None, error_fingerprint=None)
        if error:
            raw_class = structured.get('error_type') if isinstance(structured, dict) else None
            category = raw_class if isinstance(raw_class, str) and raw_class in ERROR_CLASSES else 'tool_error'
            # Inspect at most 4 KiB; never serialize error dictionaries or traceback.
            message = str(exception)[:4096] if exception is not None else (structured or {}).get('error', '')
            if isinstance(message, dict):
                message = message.get('message', '')
            message = message[:4096] if isinstance(message, str) else ''
            text = message.casefold()
            # The tool's own reason_code beats sniffing keywords out of prose.
            reason = structured.get('reason_code') if isinstance(structured, dict) else None
            reason = reason if isinstance(reason, str) and REASON_CODE.match(reason) else None
            code = reason or next((code for marker, code in (
                ('invalid field', 'invalid_field'), ('unknown field', 'invalid_field'),
                ('access', 'access_denied'), ('not allowed', 'not_allowed'),
                ('not found', 'not_found'), ('required', 'missing_parameter'),
                ('timeout', 'timeout'), ('timed out', 'timeout'),
                ('approval', 'approval'), ('domain', 'invalid_domain'),
                ('validation', 'validation')) if marker in text), 'other')
            normalized = re.sub(r'https?://\S+|[\w.+-]+@[\w.-]+', '<redacted>', text)
            normalized = re.sub(r"'[^']*'|\"[^\"]*\"|\b\d+\b", '<value>', normalized)
            event.update(error_class=category, error_code=code,
                         error_fingerprint=self.pseudonym('error', [category, code, normalized]))
            if exception is not None and type(exception).__name__ == 'CancelledError':
                event['status'] = 'cancelled'
        raw = json.dumps(event, separators=(',', ':'), ensure_ascii=True).encode() + b'\n'
        if len(raw) <= 16384:
            self._enqueue(('event', event['end_at'][:10], raw))
        else:
            self._drop()

    def _drop(self):
        self.dropped += 1
        if time.monotonic() - self._warned_at > 60:
            self._warned_at = time.monotonic()
            LOG.warning('MCP telemetry unavailable/full: dropped=%d (no payload logged)', self.dropped)

    def _enqueue(self, item):
        try:
            self.queue.put_nowait(item)
        except queue.Full:
            self._drop()

    def _write(self, kind, identifier, raw):
        # Single writer, no filesystem work on the request path. Refuse final
        # file symlinks; deployment must provision trusted parent directories.
        self.directory.mkdir(mode=0o750, parents=True, exist_ok=True)
        if time.monotonic() - self._disk_scan_at >= 60:
            # Rescan for external retention once per minute; count our writes
            # immediately. Directory ownership excludes unrelated writers.
            self._disk_bytes = self._disk_files = 0
            with os.scandir(self.directory) as entries:
                for entry in entries:
                    self._disk_files += 1
                    self._disk_bytes += entry.stat(follow_symlinks=False).st_size
                    if self._disk_files > 1024:
                        break
            self._disk_scan_at = time.monotonic()
        if self._disk_files > 1024 or self._disk_bytes + len(raw) > self.max_bytes:
            self._drop()
            return
        name = f'events-{identifier}.jsonl' if kind == 'event' else f'tools-{identifier}.json'
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if kind == 'event' else os.O_EXCL)
        try:
            fd = os.open(self.directory / name, flags, 0o640)
        except FileExistsError:
            if kind == 'definition':
                self._published.add(identifier)
            return
        with os.fdopen(fd, 'ab') as stream:
            previous_size = os.fstat(stream.fileno()).st_size
            stream.write(raw)
            stream.flush()
        self._disk_bytes += len(raw)
        if previous_size == 0:
            self._disk_files += 1
        if kind == 'definition':
            self._published.add(identifier)

    def _worker(self):
        while True:
            item = self.queue.get()
            try:
                self._write(*item)
            except Exception:
                self._drop()
            finally:
                self.queue.task_done()


_instance = None
_loaded = False


def get_telemetry():
    global _instance, _loaded
    if _loaded:
        return _instance
    _loaded = True
    if os.environ.get('ODOO_MCP_TELEMETRY_ENABLED') != '1':
        return None
    try:
        directory = os.environ['ODOO_MCP_TELEMETRY_DIR']
        key = Path(os.environ['ODOO_MCP_TELEMETRY_KEY_FILE']).read_bytes()
        instance = os.environ['ODOO_MCP_TELEMETRY_INSTANCE']
        if len(key) < 32 or not re.fullmatch(r'[a-zA-Z0-9_-]{1,40}', instance) or not Path(directory).is_absolute():
            raise ValueError('Invalid telemetry configuration')
        limit = int(os.environ.get('ODOO_MCP_TELEMETRY_MAX_BYTES', str(256 * 1024 * 1024)))
        if not 1024 * 1024 <= limit <= 4 * 1024 * 1024 * 1024:
            raise ValueError('Invalid telemetry capacity')
        _instance = Telemetry(directory, key, instance, limit,
                              os.environ.get('ODOO_MCP_TELEMETRY_MODELS', '').split(','))
    except Exception:
        LOG.warning('MCP telemetry disabled: invalid/unavailable configuration (details suppressed)')
    return _instance
