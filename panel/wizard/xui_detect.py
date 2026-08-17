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

Detection layers three strategies, in decreasing order of precision:

1. **Config-file discovery** — 3x-ui's own ``config.json`` (a json5 file with
   ``//`` comments, written next to the binary at ``/usr/local/x-ui/bin/``)
   records the exact ``webPort`` / ``webBasePath`` and whether a TLS cert is
   configured (``webCertFile``/``webKeyFile``). When readable, this yields the
   authoritative URL and is probed first.
2. **Listening-port discovery** — ``/proc/net/tcp{,6}`` lists every TCP port
   in LISTEN state on the box; each is probed (http first, then https). This
   catches panels on user-chosen ports no default list would guess.
3. **Well-known defaults** — the ordered ``DEFAULT_PORTS`` list, probed over
   both schemes, as a last resort.

Every stage is best-effort: the panel runs as the unprivileged ``psiphon3xui``
user, so config/proc reads may be denied — all of it is wrapped so a
permission error simply skips that strategy. The probe does NOT attempt login
— that's the next wizard step (``xui_creds``) where the user fills in
credentials and we actually call ``XuiClient.login``.
"""

from __future__ import annotations

import json
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
# but the user can pick any port during panel-admin setup. We probe an
# ordered set of well-known defaults (both http and https per port).
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORTS: tuple[int, ...] = (2053, 2087, 2096, 8443, 2083, 443, 8080, 80)

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

# 3x-ui's runtime config (json5 — keys may carry `//` comments). The installer
# writes it next to the binary; the /etc copy covers custom layouts.
DEFAULT_CONFIG_PATHS: tuple[str, ...] = (
    "/usr/local/x-ui/bin/config.json",
    "/etc/x-ui/bin/config.json",
)

# Bound on /proc-derived listening ports to probe, so a busy box cannot make
# the wizard step crawl (each hung probe costs the full timeout).
MAX_LISTENING_PORTS = 24

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
        return _normalise_base_path(bp)
    return None


def _normalise_base_path(bp: str) -> str:
    """Normalise a webBasePath to leading+trailing slash form ("/x/")."""
    bp = bp.strip()
    if not bp.startswith("/"):
        bp = "/" + bp
    if not bp.endswith("/"):
        bp = bp + "/"
    return bp


# ---------------------------------------------------------------------------
# Strategy 1 — read 3x-ui's own config.json for the authoritative port/path.
# ---------------------------------------------------------------------------


def _strip_json5_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments, respecting quoted strings.

    3x-ui writes config.json through a json5 encoder, so keys/values may be
    followed by ``//`` comments — ``json.loads`` rejects those outright.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:  # keep escaped char verbatim
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _read_xui_config(config_paths: tuple[str, ...]) -> dict | None:
    """Parse the first readable 3x-ui config.json into a dict, else ``None``.

    Best-effort: the panel user may not have read access to the install
    prefix, in which case this strategy is silently skipped.
    """
    for p in config_paths:
        try:
            text = Path(p).read_text(encoding="utf-8", errors="replace")
            cfg = json.loads(_strip_json5_comments(text))
        except (OSError, ValueError):
            continue
        if isinstance(cfg, dict):
            return cfg
    return None


def _config_candidates(host: str, cfg: dict) -> list[str]:
    """Derive probe URLs from a parsed 3x-ui config.json."""
    try:
        port = int(cfg.get("webPort") or 0)
    except (TypeError, ValueError):
        port = 0
    if not (1 <= port <= 65535):
        return []
    # Non-empty cert+key file settings mean the panel serves HTTPS.
    cert = str(cfg.get("webCertFile") or "").strip()
    key = str(cfg.get("webKeyFile") or "").strip()
    scheme = "https" if cert and key else "http"
    urls = [f"{scheme}://{host}:{port}/"]
    # Also probe the configured webBasePath directly — saves relying on the
    # panel's root redirect (which some hardened configs disable).
    bp = str(cfg.get("webBasePath") or "").strip()
    if bp:
        urls.append(f"{scheme}://{host}:{port}{_normalise_base_path(bp)}")
    return urls


# ---------------------------------------------------------------------------
# Strategy 2 — enumerate listening TCP ports from /proc.
# ---------------------------------------------------------------------------


def _listening_ports() -> list[int]:
    """Return every TCP port in LISTEN state per ``/proc/net/tcp{,6}``.

    Linux-only and best-effort: unreadable/absent proc files (non-Linux,
    sandboxed test runs) simply yield an empty list.
    """
    ports: list[int] = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            # fields: sl local_address rem_address st …; 0A == LISTEN
            if len(parts) < 4 or parts[3] != "0A":
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if 1 <= port <= 65535 and port not in ports:
                ports.append(port)
    return ports


# ---------------------------------------------------------------------------
# Probe driver
# ---------------------------------------------------------------------------


def _candidate_urls(host: str, ports: tuple[int, ...]) -> list[str]:
    """Return http+https root URLs for each port (http first per port)."""
    urls: list[str] = []
    for port in ports:
        urls.append(f"http://{host}:{port}/")
        urls.append(f"https://{host}:{port}/")
    return urls


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
    config_paths: tuple[str, ...] = DEFAULT_CONFIG_PATHS,
    client: httpx.AsyncClient | None = None,
    timeout: float = 3.0,
) -> XuiDetectResult:
    """Probe the local host for a running 3x-ui panel.

    Returns a populated :class:`XuiDetectResult`. Probe is best-effort:
    timeouts / 404s / connection-refused are treated as "no 3x-ui here" and
    recorded in ``notes``.
    """
    # Strategy 1 — authoritative URL straight from 3x-ui's config.json.
    cfg = _read_xui_config(config_paths)
    config_urls = _config_candidates(host, cfg) if cfg else []

    # Strategy 2 — every listening TCP port on the box (bounded).
    listen_ports = _listening_ports()[:MAX_LISTENING_PORTS]
    listen_urls = _candidate_urls(host, tuple(listen_ports))

    # Strategy 3 — well-known defaults, both schemes.
    default_urls = _candidate_urls(host, ports)

    # De-duplicate preserving priority order (config > listening > defaults).
    candidates: list[str] = []
    for url in config_urls + listen_urls + default_urls:
        if url not in candidates:
            candidates.append(url)

    result = XuiDetectResult(
        detected=False,
        base_url="",
        db_path="",
        candidates_probed=list(candidates),
        notes="",
    )

    # Canonical DB-path quick check — gives a strong hint even when the panel
    # is firewalled off localhost.
    result.db_path = _existing_db_path(db_paths)

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

            # Prefer the login page's own X_UI_BASE_PATH; fall back to the
            # config.json value when the page omits it.
            base_path = _extract_base_path(body)
            if base_path is None and cfg:
                cfg_bp = str(cfg.get("webBasePath") or "").strip()
                base_path = _normalise_base_path(cfg_bp) if cfg_bp else None
            base_path = base_path or "/"
            # XuiClient expects the "{scheme}://host:port/{webBasePath}/" form.
            # httpx reports port=None for scheme-default ports (80/443).
            origin = f"{r.url.scheme}://{r.url.host}"
            if r.url.port is not None:
                origin += f":{r.url.port}"
            detected_base = origin + base_path
            # Append trailing slash to keep XuiClient's call shape consistent
            # (e.g. base + "login" lands on "<base>login").
            if not detected_base.endswith("/"):
                detected_base += "/"
            result.detected = True
            result.base_url = detected_base
            source = "config.json" if url in config_urls else "probe"
            result.notes = (
                f"detected 3x-ui login page at {url} via {source} (webBasePath={base_path})"
            )
            return result
    finally:
        if owns_client and client is not None:
            await client.aclose()

    hints: list[str] = []
    if cfg is not None:
        hints.append(
            f"config.json read (webPort={cfg.get('webPort')}, "
            f"webBasePath={cfg.get('webBasePath')!r}) but its URL did not answer"
        )
    if listen_ports:
        hints.append(f"{len(listen_ports)} listening port(s) probed")
    if result.db_path:
        hints.append(f"3x-ui DB found at {result.db_path}")
    if hints:
        result.notes = (
            "no reachable 3x-ui login page; " + "; ".join(hints) + ". "
            f"Tried {len(candidates)} URL(s) — enter the base URL manually "
            "on the next step if the panel runs behind a custom path."
        )
    else:
        result.notes = (
            f"no 3x-ui login page recognised and no canonical DB found; "
            f"tried {len(candidates)} URL(s) incl. "
            f"{', '.join(default_urls[:8])}"
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
    "DEFAULT_CONFIG_PATHS",
    "DEFAULT_DB_PATHS",
    "DEFAULT_HOST",
    "DEFAULT_PORTS",
    "MAX_LISTENING_PORTS",
    "XuiDetectResult",
    "detect_xui",
    "detect_xui_sync",
]
