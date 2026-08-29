"""NESA Patch 7 — Datei-EMPFANG aus zwei fest verdrahteten Quellen.

Warum der Fetch hier passiert und nicht in Odoo
-----------------------------------------------
``create_attachment_from_url`` bekommt seine URL aus einer Mail oder aus einem
Archiv-Treffer, also aus fremder Hand. Wuerde Odoo sie abrufen, waere der
ERP-Prozess der SSRF-Proxy: er sitzt im internen Netz, hat die DB-Verbindung
und den Filestore. Der MCP-Serverprozess ist der richtige Ort — er darf nach
aussen, kennt aber nur XML-RPC zurueck nach Odoo.

Warum die Allowlist im Code steht
---------------------------------
Sie ist die einzige Grenze zwischen "Agent laedt einen Mailanhang" und "Agent
laedt, was in der Mail steht". Eine per Tool-Parameter, ENV oder Odoo-Parameter
konfigurierbare Allowlist waere genau so weit weg vom Review wie der Angreifer:
wer den Prompt beeinflusst, beeinflusst dann auch das Ziel. Zwei Regexes,
hartkodiert, HTTPS-only, keine Wildcards, kein Schalter.

Grenzen des Abrufs (alle drei zusammen, nicht wahlweise):

* **Keine Redirects.** Ein 302 ist die uebliche Art, eine Allowlist zu
  umgehen; er wird nicht verfolgt, sondern gemeldet.
* **40 MB Cap, doppelt geprueft.** ``Content-Length`` ist eine Behauptung des
  Absenders — deshalb wird beim Streamen zusaetzlich mitgezaehlt und beim
  Ueberschreiten abgebrochen.
* **Zeit.** 30 s Socket-Timeout pro Lesevorgang und ein Gesamtbudget von
  60 s, das zwischen zwei Chunks geprueft wird. Das ist bewusst *nicht* als
  harte Wanduhr formuliert: ``iter_content`` blockiert bis zum vollstaendigen
  Chunk, ein Tropf-Server kann den Socket-Timeout also mehrfach zuruecksetzen,
  bevor Python wieder zur Pruefung kommt (Review-MINOR 2026-08-29). In der
  Praxis begrenzt das den Schaden auf ein Vielfaches von 30 s statt auf
  unbegrenzt; wer es haerter braucht, muesste den Abruf in einen eigenen
  Prozess mit Signal-Deadline auslagern.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Genau zwei Quellen. Der Pfad traegt bei beiden einen kurzlebigen Token, den
# die Gegenseite ausgestellt hat; er wird hier nur weitergereicht, nie geloggt.
ALLOWED_URL_PATTERNS = (
    re.compile(
        r"^https://mail-mcp\.nesa\.de/mail-dl-[a-z0-9-]{1,64}/[A-Za-z0-9_-]{20,}$"
    ),
    re.compile(
        r"^https://openarchiver\.nesa\.de/oa-download-[a-z0-9-]{1,64}/"
        r"[A-Za-z0-9_-]{20,}$"
    ),
)

MAX_FETCH_BYTES = 40 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 30
MAX_TOTAL_SECONDS = 60
CHUNK_BYTES = 64 * 1024

MAX_FILENAME_LENGTH = 200
DEFAULT_FILENAME = "download.bin"

_UNSAFE_FILENAME_CHARS = re.compile(r"[^\w.\-() ]", re.UNICODE)
_MIMETYPE_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,62}/[a-z0-9][a-z0-9.+-]{0,62}$")
_DISPOSITION_STAR_RE = re.compile(
    r"filename\*\s*=\s*[^']*'[^']*'([^;]+)", re.IGNORECASE
)
_DISPOSITION_PLAIN_RE = re.compile(
    r'filename\s*=\s*"([^"]*)"|filename\s*=\s*([^;]+)', re.IGNORECASE
)


class FileIntakeError(RuntimeError):
    """Ein Abruf, der nicht stattfinden durfte oder nicht sauber endete.

    ``error_type`` landet unveraendert im Tool-Fehler, damit der Agent
    "nicht erlaubt" von "zu gross" und "Quelle kaputt" unterscheiden kann,
    ohne den Text zu parsen.
    """

    def __init__(self, message: str, *, error_type: str) -> None:
        super().__init__(message)
        self.error_type = error_type


@dataclass(frozen=True)
class FetchedFile:
    """Ergebnis eines erlaubten Abrufs."""

    content: bytes
    filename: str
    mimetype: Optional[str]
    sha256: str

    @property
    def size(self) -> int:
        return len(self.content)


def assert_url_allowed(url: str) -> None:
    """Wirf, wenn die URL nicht exakt einem der beiden Muster entspricht."""
    if not isinstance(url, str) or not url:
        raise FileIntakeError("url must be a non-empty string.", error_type="url_denied")
    if not any(pattern.fullmatch(url) for pattern in ALLOWED_URL_PATTERNS):
        raise FileIntakeError(
            "This URL is not on the hard-wired download allowlist. Only "
            "short-lived links from mail-mcp.nesa.de and openarchiver.nesa.de "
            "can be fetched, and only over HTTPS. The allowlist is code-owned "
            "and cannot be widened from a tool call.",
            error_type="url_denied",
        )


def fetch_allowlisted_url(url: str, filename: Optional[str] = None) -> FetchedFile:
    """Hole eine Datei von einer allowlisteten URL.

    :raises FileIntakeError: URL nicht erlaubt, Redirect, HTTP-Fehler,
        Zeitueberschreitung oder Ueberschreiten des 40-MB-Caps.
    """
    assert_url_allowed(url)
    started = time.monotonic()
    try:
        with requests.get(
            url,
            stream=True,
            allow_redirects=False,
            timeout=FETCH_TIMEOUT_SECONDS,
            headers={"Accept": "*/*"},
        ) as response:
            _reject_non_200(response)
            _reject_announced_oversize(response)
            content = _stream_capped(response, started)
            header_name = _filename_from_headers(response.headers)
            header_type = normalized_mimetype(response.headers.get("Content-Type"))
    except requests.Timeout as exc:
        raise FileIntakeError(
            f"The source did not answer within {FETCH_TIMEOUT_SECONDS}s.",
            error_type="fetch_timeout",
        ) from exc
    except requests.RequestException as exc:
        raise FileIntakeError(
            f"The source could not be reached: {exc}", error_type="fetch_failed",
        ) from exc

    chosen_name = safe_filename(
        filename or header_name, fallback=_fallback_filename(header_type)
    )
    digest = hashlib.sha256(content).hexdigest()
    logger.info(
        "[file-intake] fetched %s bytes from %s (sha256=%s, name=%r)",
        len(content), urllib.parse.urlsplit(url).netloc, digest[:12], chosen_name,
    )
    return FetchedFile(
        content=content,
        filename=chosen_name,
        mimetype=header_type,
        sha256=digest,
    )


def _reject_non_200(response: requests.Response) -> None:
    """Nur ein glattes 200 ist ein Download."""
    if 300 <= response.status_code < 400:
        raise FileIntakeError(
            f"The source answered {response.status_code} (redirect). Redirects "
            "are never followed — a redirect is the usual way around an "
            "allowlist. Ask the source for a direct link.",
            error_type="redirect_refused",
        )
    if response.status_code != 200:
        raise FileIntakeError(
            f"The source answered HTTP {response.status_code}. Short-lived "
            "links expire and are often single-use; request a fresh one.",
            error_type="fetch_failed",
        )


def _reject_announced_oversize(response: requests.Response) -> None:
    """Verwirf, was schon laut Ankuendigung zu gross ist."""
    announced = response.headers.get("Content-Length")
    try:
        length = int(announced) if announced is not None else None
    except (TypeError, ValueError):
        length = None
    if length is not None and length > MAX_FETCH_BYTES:
        raise FileIntakeError(
            f"The file is {length} bytes and exceeds the {MAX_FETCH_BYTES} byte "
            "cap. Hand out a link to it instead of copying it into Odoo.",
            error_type="file_too_large",
        )


def _stream_capped(response: requests.Response, started: float) -> bytes:
    """Lies den Koerper blockweise, mit hartem Byte- und Zeitlimit."""
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=CHUNK_BYTES):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_FETCH_BYTES:
            raise FileIntakeError(
                f"The file exceeds the {MAX_FETCH_BYTES} byte cap "
                "(Content-Length was missing or wrong); the transfer was "
                "aborted and nothing was stored.",
                error_type="file_too_large",
            )
        if time.monotonic() - started > MAX_TOTAL_SECONDS:
            raise FileIntakeError(
                f"The transfer exceeded the {MAX_TOTAL_SECONDS}s budget and "
                "was aborted between two chunks.",
                error_type="fetch_timeout",
            )
        chunks.append(chunk)
    if not total:
        raise FileIntakeError(
            "The source returned an empty body.", error_type="fetch_failed",
        )
    return b"".join(chunks)


def _filename_from_headers(headers) -> str:
    """Zieh einen Dateinamen aus ``Content-Disposition`` — als Vorschlag.

    Der Wert kommt vom fremden Server und wird deshalb nur als Rohmaterial
    behandelt; entschaerft wird er in ``safe_filename``.
    """
    disposition = headers.get("Content-Disposition") or ""
    star = _DISPOSITION_STAR_RE.search(disposition)
    if star:
        return urllib.parse.unquote(star.group(1).strip().strip('"'))
    plain = _DISPOSITION_PLAIN_RE.search(disposition)
    if plain:
        return (plain.group(1) or plain.group(2) or "").strip()
    return ""


def _fallback_filename(mimetype: Optional[str]) -> str:
    """Ein Name, wenn die Quelle keinen brauchbaren geliefert hat."""
    suffixes = {
        "application/pdf": ".pdf",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "text/plain": ".txt",
        "text/csv": ".csv",
    }
    suffix = suffixes.get(mimetype or "", "")
    return f"download{suffix}" if suffix else DEFAULT_FILENAME


def safe_filename(raw: Optional[str], fallback: str = DEFAULT_FILENAME) -> str:
    """Mache aus einem fremden Dateinamen einen, den man speichern darf.

    Spiegelt ``nesa_mcp_bridge/models/_mcp_file_utils.safe_filename``: Odoo
    entschaerft ohnehin noch einmal, aber ein Tool, das einen Pfad
    weiterreicht, hat schon vorher etwas falsch gemacht.
    """
    text = raw if isinstance(raw, str) else ""
    text = text.replace("\\", "/").rsplit("/", 1)[-1]
    text = "".join(char for char in text if unicodedata.category(char)[0] != "C")
    text = _UNSAFE_FILENAME_CHARS.sub("_", text.strip())
    text = text.lstrip(". ").strip()
    if len(text) > MAX_FILENAME_LENGTH:
        stem, dot, extension = text.rpartition(".")
        if dot and 0 < len(extension) <= 10:
            text = f"{stem[: MAX_FILENAME_LENGTH - len(extension) - 1]}.{extension}"
        else:
            text = text[:MAX_FILENAME_LENGTH]
    return text or fallback


def normalized_mimetype(raw: Optional[str]) -> Optional[str]:
    """Uebernimm einen Mimetype nur, wenn er wie einer aussieht."""
    if not isinstance(raw, str):
        return None
    value = raw.split(";", 1)[0].strip().lower()
    if not value or not _MIMETYPE_RE.fullmatch(value):
        return None
    return value
