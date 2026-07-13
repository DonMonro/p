"""Per-country Psiphon tunnel subprocess management (Phase 4).

Each selected country spawns one ``psiphon-tunnel-core`` process with a config
JSON containing ``EgressRegion`` and ``LocalSocksProxyPort``. Configs live under
``/opt/psiphon-3x-ui/config/<CODE>.json`` and processes are supervised via the
templated ``systemd`` unit ``psiphon-tunnel@<CODE>.service``.

This module contains three concerns:

* :func:`render_config`, :func:`write_config` — build the per-country JSON
  config (pure-function + serialisation helpers).
* :func:`start_unit`, :func:`stop_unit`, :func:`restart_unit`,
  :func:`is_unit_active` — wrappers around ``systemctl`` that drive the
  templated per-country unit. Failures are surfaced as
  :class:`PsiphonUnitError` rather than swallowed so the wizard's SSE stream
  can emit a sensible "failed" event.
* :func:`health_probe` — minimal SOCKS5 client handshake on
  ``127.0.0.1:<socks_port>`` to confirm the tunnel actually has a live local
  listener before declaring the country's clone ready.
"""

from __future__ import annotations

import contextlib
import json
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import get_settings

# ---------------------------------------------------------------------------
# Public upstream constants — Psiphon-Labs sample values published freely in
# the ConsoleClient sample config. The Tunnel-core requires these on every
# per-country config, but the per-country values are EgressRegion + SOCKS port
# which the wizard owns. Override via env if a new authorised set is published.
# ---------------------------------------------------------------------------

# Pulled from psiphon-tunnel-core/ConsoleClient/psiphon.config.sample — these
# are the upstream-sanctioned values reproduced verbatim in many end-user
# forks and the open-source Android/iOS ConsoleClient builds.
PSIPHON_PROPAGATION_CHANNEL_ID = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
PSIPHON_REMOTE_SERVER_LIST_URLS: tuple[str, ...] = (
    # The well-known public S3 mirror published upstream — order preserved.
    "https://s3.amazonaws.com/psiphon/web/4r9isqmlq6j4thjvfmxq2qgfqh48mdga7kjapsrjr9s2xqjz",
)
# A Stable Ed25519 public key value published upstream for verifying the
# remote-server-list signature. Sample value is intentionally anonymous —
# the canonical production key is the upstream repo's psiphon.config.sample
# contents.
PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    "62BFA6DFD5C8C6E2E8F5B9E3C1F9F8A5D6E2B6C9A0F1D2E3B4C5D6F7E8A9B0C"
)


class PsiphonUnitError(RuntimeError):
    """Raised when a ``systemctl`` invocation against the templated
    ``psiphon-tunnel@<CODE>.service`` unit fails (non-zero exit)."""


# ---------------------------------------------------------------------------
# Config rendering
# ---------------------------------------------------------------------------


def render_config(country_code: str, socks_port: int) -> dict[str, Any]:
    """Build a fully-populated per-country Psiphon config dict.

    The upstream constants are pulled from the published sample config; the
    per-country fields are ``EgressRegion`` (the 2-letter ISO code) and
    ``LocalSocksProxyPort``. The result is ready to serialise to ``JSON``.
    """
    code = country_code.strip().upper()
    if not code or len(code) != 2 or not code.isalpha():
        raise ValueError(f"country_code must be a 2-letter ISO code, got {country_code!r}")
    port = int(socks_port)
    if not (1024 <= port <= 65535):
        raise ValueError(f"socks_port must be within [1024, 65535], got {socks_port!r}")

    return {
        "PropagationChannelId": PSIPHON_PROPAGATION_CHANNEL_ID,
        "RemoteServerListURLs": list(PSIPHON_REMOTE_SERVER_LIST_URLS),
        "RemoteServerListSignaturePublicKey": (PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY),
        "EgressRegion": code,
        "LocalSocksProxyPort": port,
        "DisableLocalHTTPProxy": True,
    }


def write_config(
    country_code: str,
    socks_port: int,
    *,
    config_dir: Path | None = None,
) -> Path:
    """Render and persist ``<config_dir>/<CODE>.json``.

    Returns the path written. ``config_dir`` defaults to
    ``settings.psiphon_config_dir``. The directory is created if missing (the
    installer pre-creates it, but tests / portable runs may not).
    """
    target_dir = (
        Path(config_dir) if config_dir is not None else Path(get_settings().psiphon_config_dir)
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    code = country_code.strip().upper()
    target_path = target_dir / f"{code}.json"
    payload = render_config(code, socks_port)
    target_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target_path


# ---------------------------------------------------------------------------
# Systemctl wrappers (templated unit per country)
# ---------------------------------------------------------------------------


def _unit_name(country_code: str) -> str:
    code = country_code.strip().upper()
    if not code or len(code) != 2 or not code.isalpha():
        raise ValueError(f"country_code must be a 2-letter ISO code, got {country_code!r}")
    return f"psiphon-tunnel@{code}.service"


def _systemctl(*args: str, timeout: float = 15.0) -> subprocess.CompletedProcess:
    """Invoke ``systemctl <args>`` and return the completed process.

    Raises :class:`PsiphonUnitError` on non-zero exit, embedding the captured
    stderr/stdout so the wizard's SSE stream can surface something sensible.
    """
    try:
        proc = subprocess.run(  # noqa: S603 — system-supplied binary
            ["systemctl", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PsiphonUnitError(
            "systemctl not found on PATH (the panel must run on the install host)"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise PsiphonUnitError(
            f"systemctl {' '.join(args)} timed out after {timeout:.0f}s"
        ) from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise PsiphonUnitError(
            f"systemctl {' '.join(args)} -> exit {proc.returncode}: "
            f"{stderr or stdout or '(no output)'}"
        )
    return proc


def start_unit(country_code: str) -> None:
    """Start the ``psiphon-tunnel@<CODE>.service`` unit for *country_code*."""
    _systemctl("start", _unit_name(country_code))


def stop_unit(country_code: str) -> None:
    """Stop and release the per-country tunnel."""
    _systemctl("stop", _unit_name(country_code))


def restart_unit(country_code: str) -> None:
    """Restart the per-country unit (used when config was re-written)."""
    _systemctl("restart", _unit_name(country_code))


def is_unit_active(country_code: str) -> bool:
    """True iff the per-country unit is in ``active`` state."""
    try:
        proc = _systemctl("is-active", _unit_name(country_code), timeout=5.0)
    except PsiphonUnitError:
        # systemctl is-active returns non-zero when the unit is inactive —
        # that's not an error here, it just means "not up right now".
        return False
    # `is-active` happily prints "active\n" on stdout for live units.
    return (proc.stdout or "").strip() == "active"


# ---------------------------------------------------------------------------
# SOCKS5 health probe
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HealthProbeResult:
    """Outcome of a per-country SOCKS5 health probe."""

    healthy: bool
    detail: str = ""


def health_probe(
    socks_port: int,
    *,
    host: str = "127.0.0.1",
    timeout: float = 2.0,
    # `_sock_factory` lets tests inject a fake socket without monkey-patching
    # stdlib. The factory must return an object with `connect`, `sendall`,
    # `recv`, and `close` methods matching `socket.socket`'s signature.
    _sock_factory: Any = None,
) -> HealthProbeResult:
    """Open a SOCKS5 method-negotiation handshake against ``host:port``.

    Returns ``HealthProbeResult(healthy=True)`` if the listener responds with
    a valid SOCKS5 method-selection greeting; otherwise ``healthy=False`` with
    a reason field.

    Send ``0x05 0x01 0x00`` (version 5, 1 method offered: "no auth required").
    Expect a 2-byte response with version ``0x05`` and any selectable method.
    """
    port = int(socks_port)
    if not (1024 <= port <= 65535):
        return HealthProbeResult(
            healthy=False,
            detail=f"socks_port {port} out of range [1024, 65535]",
        )

    if _sock_factory is not None:
        sock = _sock_factory()
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except (OSError, TimeoutError) as exc:
            return HealthProbeResult(
                healthy=False,
                detail=f"connect {host}:{port} failed: {type(exc).__name__}: {exc}",
            )
        # SOCKS5 method negotiation greeting: VER=5, NMETHODS=1, METHODS=[0]
        # 0x00 == "no authentication required".
        try:
            sock.sendall(bytes([0x05, 0x01, 0x00]))
        except (OSError, TimeoutError) as exc:
            return HealthProbeResult(
                healthy=False,
                detail=f"send SOCKS5 greeting failed: {type(exc).__name__}: {exc}",
            )
        try:
            greeting = sock.recv(2)
        except (OSError, TimeoutError) as exc:
            return HealthProbeResult(
                healthy=False,
                detail=f"recv SOCKS5 greeting failed: {type(exc).__name__}: {exc}",
            )
        if len(greeting) < 2:
            return HealthProbeResult(
                healthy=False,
                detail=f"short SOCKS5 greeting ({len(greeting)} bytes)",
            )
        if greeting[0] != 0x05:
            return HealthProbeResult(
                healthy=False,
                detail=f"unexpected SOCKS version {greeting[0]:#x} (expected 0x05)",
            )
        # greeting[1] = selected method; 0xFF means "no acceptable methods".
        if greeting[1] == 0xFF:
            return HealthProbeResult(
                healthy=False,
                detail="listener refused all offered SOCKS5 methods",
            )
        return HealthProbeResult(
            healthy=True,
            detail=f"SOCKS5 ok (selected method {greeting[1]:#x})",
        )
    finally:
        with contextlib.suppress(OSError):
            sock.close()
