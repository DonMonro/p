"""Detect a locally-running 3x-ui installation.

The wizard step ``xui_detect`` probes the box for a reachable 3x-ui panel and
offers the user a sensible default URL. We use the canonical markers verified
during the Phase 1 spike (see ``docs/XUI_API.md``):

* HTML login page contains ``<meta name="csrf-token" ...>`` and the title
  tag is ``3x-ui`` (case-insensitive).
* ``window.X_UI_BASE_PATH = "/<webBasePath>/"`` is present in the login page's
  ``<script>`` block.
* The CLI installer writes the canonical SQLite DB to
  ``/usr/local/x-ui/x-ui.db`` (the path used by Sanaei/3x-ui's installer).

The probe is best-effort: it returns the first candidate URL whose root reply
looks like a 3x-ui login page (or notes that none matched). It does NOT
attempt login — that's the next wizard step (``xui_creds``) where the user
fills in credentials and we actually call ``XuiClient.login``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import httpx

# ---------------------------------------------------------------------------
# Probe candidates — common install-time defaults. The user can override via
# the wizard's xui-creds form (which also accepts an explicit base_url).
# ---------------------------------------------------------------------------

# 3x-ui CLI installer (`x-ui`) default depends on the chosen web-port. The
# Sanaei installer's quick-install (`x-ui.sh`) defaults to 2053 for HTTPS,
# but the user can pick any port during panel-admin setup. We probe a small
# ordered set of well-known defaults.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORTS: tuple[int, ...] = (2053, 8080, 80, 443)

# Look for these substrings on the login page either of which means 3x-ui.
XUI_MARKERS = (
    b"<title>3x-ui</title>",
    b'name="csrf-token"',
    b"window.X_UI_BASE_PATH",
    b'<meta name="base-path"',
)

# Canonical 3x-ui SQLite DB written by the Sanaei installer.
DEFAULT_DB_PATHS: tuple[str, ...] = (
    "/usr/local/x-ui/x-ui.db",
    "/etc/x-ui/x-ui.db",
)

# The CSRF / base-path regexes (mirrors panel.dashboard.xui_client).
CSRF_RE = re.compile(rb'name="csrf-token"\s+content="([^"]+)"')
BASE_PATH_RE = re.compile(rb'window\.X_UI_BASE_PATH\s*=\s*["\']([^"\']+)["\']')
TITLE_RE = re.compile(rb"<title>\s*([^<]+?)\s*</title>", re.IGNORECASE)


@dataclass
class XuiDetectResult:
    """Outcome of a single ``detect_xui`` invocation.

    Attributes:
        detected: ``True`` iff at least one candidate URL looked like a 3x-ui
            login page OR the canonical DB file exists.
        base_url: best-guess API base URL (``http(s)://host:port/{webBasePath}/``).
            ``""`` if undetected.
        db_path: canonical SQLite DB path if present, else ``""``.
        candidates_probed: full list of URLs tried (so the UI / docs can show
            what was searched).
        notes: human-readable hints, esp. on non-detection ("tried these URLs
            and didn't recognise any of them, did the user pick a custom web
            path?").
    """

    detected: bool = False
    base_url: str = ""
    db_path: str = ""
    candidates_probed: list[str] = None  # type: ignore[assignment]
    notes: str = ""


def _looks_like_xui(body: bytes) -> bool:
    return any(marker in body for marker in XUI_MARKERS)


def _extract_base_path(body: bytes) -> str | None:
    m = BASE_PATH_RE.search(body)
    if m:
        bp = m.group(1).decode("ascii", errors="ignore").strip()
        # Normalise to trailing-slash form ("/<webBasePath>/").
        if not bp.startswith("/"):
            bp = "/" + bp
        if not bp.endswith("/"):
            bp = bp + "/"
        return bp
    return None


def _candidate_urls(host: str, ports: tuple[int, ...]) -> list[str]:
    """Return ``[http://host:port/, http://host:port/, …]`` for the probe."""
    return [f"http://{host}:{port}/" for port in ports]


def _existing_db_path(db_paths: tuple[str, ...]) -> str:
    """Return the first canonical DB file that exists on disk, or ``""``."""
    for p in db_paths:
        try:
            if Path(p).is_file():
                return p
        except (OSError, ValueError):
            continue
    return ""


async def detect_xui(
    *,
    host: str = DEFAULT_HOST,
    ports: tuple[int, ...] = DEFAULT_PORTS,
    db_paths: tuple[str, ...] = DEFAULT_DB_PATHS,
    client: httpx.AsyncClient | None = None,
    timeout: float = 3.0,
) -> XuiDetectResult:
    """Probe the local host for a running 3x-ui panel.

    Returns a populated :class:`XuiDetectResult`. Probe is best-effort:
    timeouts / 404s / connection-refused are treated as "no 3x-ui here" and
    recorded in ``notes``.
    """
    candidates = _candidate_urls(host, ports)
    db_candidates = db_paths
    result = XuiDetectResult(
        detected=False,
        base_url="",
        db_path="",
        candidates_probed=list(candidates),
        notes="",
    )

    # Canonical DB-path quick check — gives a strong hint even when the panel
    # is firewalled off localhost.
    result.db_path = _existing_db_path(db_candidates)

    owns_client = client is None
    client = client or httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False)
    try:
        for url in candidates:
            try:
                r = await client.get(url)
            except (httpx.RequestError, httpx.HTTPError):
                continue
            # Both 200 and 401/302/etc are acceptable probe responses — we
            # only inspect the body to fingerprint the page.
            if r.status_code >= 500:
                continue
            body = r.content or b""
            if not _looks_like_xui(body):
                continue

            base_path = _extract_base_path(body) or "/"
            # XuiClient expects the "{scheme}://host:port/{webBasePath}/" form.
            detected_base = url.rstrip("/") + base_path
            # Append trailing slash to keep XuiClient's call shape consistent
            # (e.g. base + "login" lands on "<base>login").
            if not detected_base.endswith("/"):
                detected_base += "/"
            result.detected = True
            result.base_url = detected_base
            result.notes = f"detected 3x-ui login page at {url} (webBasePath={base_path})"
            return result
    finally:
        if owns_client and client is not None:
            await client.aclose()

    if result.db_path:
        result.notes = (
            f"3x-ui DB found at {result.db_path} but no reachable login page on "
            f"the probed URLs ({', '.join(candidates)})"
        )
    else:
        result.notes = (
            f"no 3x-ui login page recognised and no canonical DB found; "
            f"tried {', '.join(candidates)}"
        )
    return result


def detect_xui_sync(*, host: str = DEFAULT_HOST, timeout: float = 3.0) -> XuiDetectResult:
    """Synchronous wrapper around :func:`detect_xui` — used by tests and the
    panel's installer-side smoke check.

    Use :func:`detect_xui` from FastAPI handlers — this wrapper exists purely
    for code paths that aren't inside an event loop.
    """
    import asyncio

    return asyncio.run(detect_xui(host=host, timeout=timeout))


__all__ = [
    "DEFAULT_DB_PATHS",
    "DEFAULT_HOST",
    "DEFAULT_PORTS",
    "XuiDetectResult",
    "detect_xui",
    "detect_xui_sync",
]
