"""Privacy, correlation, backpressure and integration regressions."""
import asyncio
import json
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from odoo_mcp.telemetry import Telemetry, argument_shape, safe_schema


@pytest.fixture
def telemetry(tmp_path):
    return Telemetry(tmp_path, b'x' * 32, 'staging', models=['res.partner'])


def begin(telemetry, workflow='run-1', principal='alice', session='session-1'):
    context = SimpleNamespace(request=SimpleNamespace(headers={
        'x-nesa-workflow-id': workflow, 'mcp-session-id': session}))
    tool = SimpleNamespace(name='read_records', description='Read records',
                           parameters={'type': 'object', 'properties': {'ids': {'type': 'array', 'default': [999]}}})
    return telemetry.begin({'ids': [777], 'model': 'res.partner'}, tool, context, principal)


def test_principal_and_workflow_isolation(telemetry):
    first = begin(telemetry)
    assert first['correlation_id'] == begin(telemetry, session='session-2')['correlation_id']
    assert first['session_id'] != begin(telemetry, session='session-2')['session_id']
    assert first['correlation_id'] != begin(telemetry, principal='bob')['correlation_id']
    assert first['correlation_id'] != begin(telemetry, workflow='run-2')['correlation_id']
    assert begin(telemetry, workflow='')['correlation_quality'] == 'session'
    missing = begin(telemetry, workflow='', session='')
    assert missing['correlation_quality'] == 'none'
    assert missing['correlation_id'] is None


def test_no_values_or_raw_errors_persisted(telemetry):
    event = begin(telemetry)
    telemetry.finish(event, .4, False, 0, 30,
                     {'error_type': 'request', 'error': "Invalid field 'secret_name' for ID 777"})
    second = begin(telemetry)
    telemetry.finish(second, .2, False, 0, 30,
                     {'error_type': 'request', 'error': "Invalid field 'other_name' for ID 888"})
    telemetry.queue.join()
    events = [json.loads(line) for file in telemetry.directory.glob('events-*.jsonl') for line in file.read_text().splitlines()]
    assert events[0]['error_fingerprint'] == events[1]['error_fingerprint']
    assert events[0]['error_code'] == 'invalid_field'
    raw = '\n'.join(file.read_text() for file in telemetry.directory.iterdir())
    for secret in ('secret_name', 'other_name', 'alice', 'run-1', 'session-1'):
        assert secret not in raw
    assert '[999]' not in raw
    assert '[777]' not in raw
    assert 'default' not in raw


def test_shape_does_not_copy_unknown_keys_or_nested_values():
    shape = argument_shape({'values': {'password': 'sensitive'}, 'secret-field': 'key', 'ids': [45, 99]})
    assert shape == {'ids': {'type': 'list', 'size_bucket': '5'},
                     'values': {'type': 'object', 'size_bucket': '1'}}
    assert safe_schema({'default': 'secret', 'examples': ['secret'], 'type': 'string'}) == {'type': 'string'}


def test_writer_failure_and_capacity_are_fail_open(telemetry, monkeypatch):
    def fail(*args):
        raise OSError('secret disk message')
    monkeypatch.setattr(telemetry, '_write', fail)
    telemetry.finish(begin(telemetry), 0, True, 1, 10, {})
    telemetry.queue.join()
    assert telemetry.dropped >= 1


def test_full_queue_drops_instead_of_blocking(telemetry, monkeypatch):
    import queue
    full = queue.Queue(maxsize=1)
    full.put('occupied')
    monkeypatch.setattr(telemetry, 'queue', full)
    telemetry._enqueue(('event', '2026-09-09', b'{}'))
    assert telemetry.dropped == 1


def test_definition_backoff_and_code_independent_version(telemetry, monkeypatch):
    queued = []
    monkeypatch.setattr(telemetry, '_enqueue', queued.append)
    first = begin(telemetry)
    for _ in range(100):
        begin(telemetry)
    assert len(queued) == 1
    telemetry._versions.clear()
    telemetry.code_version = 'new-package-code'
    assert begin(telemetry)['tool_version'] == first['tool_version']
    telemetry._definition_retry_at.clear()
    begin(telemetry)
    assert len(queued) == 2


def test_disk_cap_and_symlink_not_followed(telemetry, tmp_path):
    telemetry.max_bytes = 1
    telemetry._write('event', '2026-09-09', b'{}\n')
    assert not list(tmp_path.glob('events-*'))
    telemetry.max_bytes = 10000
    target = tmp_path / 'target'
    target.write_text('unchanged')
    (tmp_path / 'events-2026-09-09.jsonl').symlink_to(target)
    with pytest.raises(OSError):
        telemetry._write('event', '2026-09-09', b'{}\n')
    assert target.read_text() == 'unchanged'


def test_server_wraps_success_exception_and_parallel_calls(telemetry, monkeypatch):
    from odoo_mcp import server
    from odoo_mcp import telemetry as module
    monkeypatch.setattr(module, 'get_telemetry', lambda: telemetry)
    mcp = server.NesaFastMCP('test')

    @mcp.tool()
    async def sample_tool(fail: bool = False) -> Dict[str, Any]:
        await asyncio.sleep(.01)
        if fail:
            raise ValueError('private detail')
        return {'success': True, 'records': []}

    async def run():
        results = await asyncio.gather(mcp.call_tool('sample_tool', {}),
                                       mcp.call_tool('sample_tool', {'fail': True}), return_exceptions=True)
        assert isinstance(results[1], Exception)
    asyncio.run(run())
    telemetry.queue.join()
    events = [json.loads(line) for file in telemetry.directory.glob('events-*') for line in file.read_text().splitlines()]
    assert sorted(e['status'] for e in events) == ['error', 'success']
    assert events[0]['start_at'] < events[1]['end_at']
    assert all(e['correlation_quality'] == 'none' for e in events)
    assert 'private detail' not in json.dumps(events)


def test_disabled_by_default_and_invalid_configuration(monkeypatch):
    from odoo_mcp import telemetry as module
    monkeypatch.setattr(module, '_loaded', False)
    monkeypatch.setattr(module, '_instance', None)
    monkeypatch.delenv('ODOO_MCP_TELEMETRY_ENABLED', raising=False)
    assert module.get_telemetry() is None
    monkeypatch.setattr(module, '_loaded', False)
    monkeypatch.setenv('ODOO_MCP_TELEMETRY_ENABLED', '1')
    monkeypatch.delenv('ODOO_MCP_TELEMETRY_KEY_FILE', raising=False)
    assert module.get_telemetry() is None
