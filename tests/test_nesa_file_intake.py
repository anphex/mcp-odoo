"""Tests for the file INTAKE side (NESA Patch 7, 2026-08-29).

The two tools are the only place where this server pulls bytes from the
outside and writes them into Odoo. The tests therefore aim at the boundary,
not at the happy path alone:

* the URL allowlist is exact — no other host, no http, no redirect;
* the 40 MB cap holds even when the source lies about ``Content-Length``;
* a filename from a foreign header never leaves this module as a path;
* a checksum mismatch is reported as a failure, not as a filed document.
"""

import base64
import hashlib
import importlib

import pytest
import requests


class _Life:
    def __init__(self, odoo):
        self.odoo = odoo
        self.schema_cache = {}
        self.transient_cache = {}


class _Ctx:
    def __init__(self, odoo):
        self.request_context = type("_Req", (), {"lifespan_context": _Life(odoo)})()


class _StoreClient:
    """Odoo double that accepts one stored attachment and remembers the call."""

    def __init__(self, sha256=None, success=True, error=None):
        self.calls = []
        self.sha256 = sha256
        self.success = success
        self.error = error

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args))
        if method == "mcp_store_attachment":
            if not self.success:
                return {"success": False, "error": self.error or "denied"}
            payload = args[3]
            content = base64.b64decode(payload)
            return {
                "success": True,
                "attachment_id": 42,
                "filename": args[2],
                "mimetype": args[4] or "application/pdf",
                "size": len(content),
                "sha256": self.sha256 or hashlib.sha256(content).hexdigest(),
                "res_model": args[0],
                "res_id": args[1],
                "record_url": f"https://odoo.example/odoo/{args[0]}/{args[1]}",
            }
        if method == "mcp_create_upload":
            return {
                "success": True,
                "upload_url": "https://odoo.example/nesa/mcp/upload/tok",
                "expires_at_iso": "2026-08-29 17:30:00",
                "expires_in_seconds": args[3],
                "filename": args[2],
                "res_model": args[0],
                "res_id": args[1],
                "single_use": True,
            }
        raise AssertionError(f"unexpected call {model}.{method}")


class _FakeResponse:
    """Minimal ``requests.Response`` stand-in for the streaming path."""

    def __init__(self, status_code=200, headers=None, chunks=(b"pdf-bytes",)):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = list(chunks)

    def iter_content(self, chunk_size=None):
        return iter(self._chunks)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


ALLOWED_URL = (
    "https://mail-mcp.nesa.de/mail-dl-c-neese/"
    "AbCdEfGhIjKlMnOpQrStUvWxYz01"
)
ARCHIVE_URL = (
    "https://openarchiver.nesa.de/oa-download-nesa/"
    "AbCdEfGhIjKlMnOpQrStUvWxYz01"
)


@pytest.fixture
def intake():
    return importlib.import_module("odoo_mcp._nesa_file_intake")


@pytest.fixture
def server():
    return importlib.import_module("odoo_mcp.server")


# ----- allowlist ----------------------------------------------------------


@pytest.mark.parametrize("url", [ALLOWED_URL, ARCHIVE_URL])
def test_allowlisted_urls_pass(intake, url):
    intake.assert_url_allowed(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://mail-mcp.nesa.de/mail-dl-x/AbCdEfGhIjKlMnOpQrStUvWxYz01",
        "https://mail-mcp.nesa.de.evil.example/mail-dl-x/AbCdEfGhIjKlMnOpQrStUvWxYz01",
        "https://evil.example/mail-dl-x/AbCdEfGhIjKlMnOpQrStUvWxYz01",
        "https://mail-mcp.nesa.de/other/AbCdEfGhIjKlMnOpQrStUvWxYz01",
        "https://mail-mcp.nesa.de/mail-dl-x/short",
        "https://mail-mcp.nesa.de/mail-dl-x/AbCdEfGhIjKlMnOpQrStUvWxYz01/../etc",
        "https://mail-mcp.nesa.de/mail-dl-x/AbCdEfGhIjKlMnOpQrStUvWxYz01?x=1",
        "https://user:pw@mail-mcp.nesa.de/mail-dl-x/AbCdEfGhIjKlMnOpQrStUvWxYz01",
        "",
        None,
    ],
)
def test_everything_else_is_denied(intake, url):
    with pytest.raises(intake.FileIntakeError) as excinfo:
        intake.assert_url_allowed(url)
    assert excinfo.value.error_type == "url_denied"


# ----- fetch limits -------------------------------------------------------


def test_redirects_are_never_followed(intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(302, {"Location": "https://evil.example/x"}),
    )
    with pytest.raises(intake.FileIntakeError) as excinfo:
        intake.fetch_allowlisted_url(ALLOWED_URL)
    assert excinfo.value.error_type == "redirect_refused"


def test_request_does_not_allow_redirects(intake, monkeypatch):
    seen = {}

    def _get(url, **kwargs):
        seen.update(kwargs)
        return _FakeResponse()

    monkeypatch.setattr(intake.requests, "get", _get)
    intake.fetch_allowlisted_url(ALLOWED_URL)
    assert seen["allow_redirects"] is False
    assert seen["stream"] is True
    assert seen["timeout"] == intake.FETCH_TIMEOUT_SECONDS


def test_announced_oversize_is_refused_before_streaming(intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(
            200, {"Content-Length": str(intake.MAX_FETCH_BYTES + 1)},
        ),
    )
    with pytest.raises(intake.FileIntakeError) as excinfo:
        intake.fetch_allowlisted_url(ALLOWED_URL)
    assert excinfo.value.error_type == "file_too_large"


def test_lying_content_length_is_caught_while_streaming(intake, monkeypatch):
    monkeypatch.setattr(intake, "MAX_FETCH_BYTES", 16)
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(
            200, {"Content-Length": "4"}, chunks=[b"x" * 8, b"y" * 16],
        ),
    )
    with pytest.raises(intake.FileIntakeError) as excinfo:
        intake.fetch_allowlisted_url(ALLOWED_URL)
    assert excinfo.value.error_type == "file_too_large"


def test_timeout_is_reported_as_such(intake, monkeypatch):
    def _boom(*a, **kw):
        raise requests.Timeout("too slow")

    monkeypatch.setattr(intake.requests, "get", _boom)
    with pytest.raises(intake.FileIntakeError) as excinfo:
        intake.fetch_allowlisted_url(ALLOWED_URL)
    assert excinfo.value.error_type == "fetch_timeout"


def test_empty_body_is_a_failure(intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get", lambda *a, **kw: _FakeResponse(200, {}, chunks=[]),
    )
    with pytest.raises(intake.FileIntakeError) as excinfo:
        intake.fetch_allowlisted_url(ALLOWED_URL)
    assert excinfo.value.error_type == "fetch_failed"


# ----- names and types ----------------------------------------------------


def test_filename_comes_from_the_header_but_sanitised(intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(
            200,
            {
                "Content-Disposition": 'attachment; filename="../../etc/passwd"',
                "Content-Type": "application/pdf; charset=binary",
            },
        ),
    )
    fetched = intake.fetch_allowlisted_url(ALLOWED_URL)
    assert fetched.filename == "passwd"
    assert fetched.mimetype == "application/pdf"


def test_explicit_filename_wins_over_the_header(intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(
            200, {"Content-Disposition": 'attachment; filename="fremd.pdf"'},
        ),
    )
    fetched = intake.fetch_allowlisted_url(ALLOWED_URL, filename="Rechnung 2026.pdf")
    assert fetched.filename == "Rechnung 2026.pdf"


def test_missing_name_falls_back_to_the_mimetype(intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(200, {"Content-Type": "application/pdf"}),
    )
    assert intake.fetch_allowlisted_url(ALLOWED_URL).filename == "download.pdf"


def test_bogus_mimetype_is_dropped(intake):
    assert intake.normalized_mimetype("not a type") is None
    assert intake.normalized_mimetype("IMAGE/JPEG; q=1") == "image/jpeg"


# ----- tool surface -------------------------------------------------------


def test_from_url_stores_and_reports_the_attachment(server, intake, monkeypatch):
    monkeypatch.setattr(
        intake.requests, "get",
        lambda *a, **kw: _FakeResponse(200, {"Content-Type": "application/pdf"}),
    )
    client = _StoreClient()
    result = server.create_attachment_from_url(
        _Ctx(client), ALLOWED_URL, "res.partner", 7, "beleg.pdf",
    )
    assert result["success"] is True
    assert result["attachment_id"] == 42
    assert result["res_model"] == "res.partner"
    assert result["source_host"] == "mail-mcp.nesa.de"
    model, method, args = client.calls[0]
    assert (model, method) == ("nesa.mcp.doc.helper", "mcp_store_attachment")
    assert args[:3] == ("res.partner", 7, "beleg.pdf")
    # The checksum travels WITH the payload so Odoo can refuse a corrupted
    # transfer before it creates anything.
    assert args[5] == hashlib.sha256(b"pdf-bytes").hexdigest()


def test_from_url_refuses_a_foreign_host_without_calling_odoo(server):
    client = _StoreClient()
    result = server.create_attachment_from_url(
        _Ctx(client), "https://evil.example/x", "res.partner", 7,
    )
    assert result["success"] is False
    assert result["error_type"] == "url_denied"
    assert client.calls == []


def test_from_url_refuses_the_control_plane(server, intake, monkeypatch):
    monkeypatch.setattr(intake.requests, "get", lambda *a, **kw: _FakeResponse())
    client = _StoreClient()
    result = server.create_attachment_from_url(
        _Ctx(client), ALLOWED_URL, "nesa.mcp.approval.token", 7,
    )
    assert result["success"] is False
    assert "hard-deny" in result["error"]
    assert client.calls == []


def test_from_url_reports_a_checksum_mismatch_as_a_failure(
    server, intake, monkeypatch,
):
    monkeypatch.setattr(intake.requests, "get", lambda *a, **kw: _FakeResponse())
    client = _StoreClient(sha256="0" * 64)
    result = server.create_attachment_from_url(
        _Ctx(client), ALLOWED_URL, "res.partner", 7,
    )
    assert result["success"] is False
    assert result["error_type"] == "checksum_mismatch"


def test_from_url_reports_an_odoo_side_checksum_refusal(server, intake, monkeypatch):
    """Odoo lehnt einen Mismatch ab, BEVOR es speichert — kein halber Zustand."""
    monkeypatch.setattr(intake.requests, "get", lambda *a, **kw: _FakeResponse())
    client = _StoreClient(success=False, error="Checksum mismatch: nothing was stored.")
    result = server.create_attachment_from_url(
        _Ctx(client), ALLOWED_URL, "res.partner", 7,
    )
    assert result["success"] is False
    assert "nothing was stored" in result["error"]


def test_from_url_passes_an_odoo_refusal_through(server, intake, monkeypatch):
    monkeypatch.setattr(intake.requests, "get", lambda *a, **kw: _FakeResponse())
    client = _StoreClient(success=False, error="res.partner 7 is not writable")
    result = server.create_attachment_from_url(
        _Ctx(client), ALLOWED_URL, "res.partner", 7,
    )
    assert result["success"] is False
    assert result["error_type"] == "store_failed"
    assert "not writable" in result["error"]


def test_upload_link_is_minted_with_a_curl_hint(server):
    client = _StoreClient()
    result = server.create_attachment_upload(
        _Ctx(client), "res.partner", 7, "foto.jpg", 900,
    )
    assert result["success"] is True
    assert result["upload_url"].endswith("/tok")
    assert "curl -T" in result["how_to_upload"]
    assert result["single_use"] is True


def test_upload_link_rejects_an_absurd_ttl_and_empty_names(server):
    client = _StoreClient()
    short = server.create_attachment_upload(
        _Ctx(client), "res.partner", 7, "foto.jpg", 1,
    )
    assert short["success"] is False
    assert "ttl_seconds" in short["error"]
    nameless = server.create_attachment_upload(_Ctx(client), "res.partner", 7, "  ")
    assert nameless["success"] is False
    assert "filename" in nameless["error"]
    assert client.calls == []
