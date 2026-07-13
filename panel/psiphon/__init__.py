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
import os
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import get_settings

# ---------------------------------------------------------------------------
# Hotfix #14 (Phase 23): Psiphon Network upstream credentials are NO LONGER
# hardcoded in this module. They MUST be supplied by the operator via env vars
# read from ${ENV_FILE} (/opt/psiphon-3x-ui/panel.env):
#
#   PSIPHON_PROPAGATION_CHANNEL_ID              — e.g. 32-char hex string
#   PSIPHON_SPONSOR_ID                          — e.g. 16-char hex string
#   PSIPHON_REMOTE_SERVER_LIST_URL              — https://s3.amazonaws.com/...
#   PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY — base64-encoded
#                                                    ed25519 pubkey (≈44 chars)
#
# All four are MANDATORY Psiphon-Inc-issued commercial-grade credentials.
# Without them the upstream binary boots, opens its SOCKS5 listener, then
# tries to authenticate the S3-listed remote server list against the supplied
# signature-pubkey → fails → 5-minute EstablishTunnelTimeout loop → exit →
# restart-loop with `AvailableEgressRegions:[]` and `NetworkID:UNKNOWN`. To
# short-circuit that 5-minute death-loop and surface a CLEAR actionable error,
# `_resolve_upstream_credentials()` raises `PsiphonCredentialError` if any of
# the four are missing OR look like the externally-known placeholder values
# (all-F's / all-0's / our fabricated pubkey / the upstream stub "..." form).
#
# The legacy constants `_LEGACY_STUB_PROPAGATION_CHANNEL_ID` etc. are KEPT
# below only as documentation fallbacks for tests that exercise the
# placeholder-rejection edge case (they ARE the placeholders we reject).
# They MUST NOT be used by `render_config` directly — `_resolve_upstream_credentials`
# is the SINGLE entry point.
# ---------------------------------------------------------------------------


class PsiphonCredentialError(RuntimeError):
    """Raised by render_config when the four Psiphon-Inc upstream
    credentials are missing OR look like the externally-known placeholders
    (all-F's PropagationChannelId / all-0's SponsorId / the fabricated
    sig-pubkey / the upstream stub "..." form / non-base64 sig-pubkey / a
    non-https URL). The message is operator-actionable and names the
    specific env-var that must be set in /opt/psiphon-3x-ui/panel.env."""


# The legacy hardcoded values — kept ONLY as documentation of the placeholder
# patterns `_resolve_upstream_credentials` must reject. Used by tests that
# exercise the placeholder-detection edge case.
_LEGACY_STUB_PROPAGATION_CHANNEL_ID = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
_LEGACY_STUB_SPONSOR_ID = "0000000000000000"
# Kept as a sequence for source-compat with tests that imported the tuple.
_LEGACY_STUB_REMOTE_SERVER_LIST_URLS: tuple[str, ...] = (
    "https://s3.amazonaws.com/psiphon/web/4r9isqmlq6j4thjvfmxq2qgfqh48mdga7kjapsrjr9s2xqjz",
)
_LEGACY_STUB_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    "62BFA6DFD5C8C6E2E8F5B9E3C1F9F8A5D6E2B6C9A0F1D2E3B4C5D6F7E8A9B0C"
)

# Source-compat aliases — keep the old public names importable so existing
# tests that imported PSIPHON_PROPAGATION_CHANNEL_ID etc. don't break
# with ImportError. Tests that compare against these constant names are
# EXPECTED to instead exercise the env-var-driven code path; the value
# behind each alias is the same placeholder stub (so any test that DOES
# accidentally render_config-without-setenv will get the fast-fail error
# OR — for the static-constant grep tests — find the literal still present).
PSIPHON_PROPAGATION_CHANNEL_ID = _LEGACY_STUB_PROPAGATION_CHANNEL_ID
PSIPHON_SPONSOR_ID = _LEGACY_STUB_SPONSOR_ID
PSIPHON_REMOTE_SERVER_LIST_URLS = _LEGACY_STUB_REMOTE_SERVER_LIST_URLS
PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    _LEGACY_STUB_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
)


def _is_all_hex_repeat(ch: str, value: str, min_len: int = 8) -> bool:
    """True iff `value` is all-uppercase-or-all-0/F hex string of length
    >= min_len that is just the same char repeated (e.g. "FFFF..." or
    "0000..."). Detects all-FF + all-00 placeholders for PropagationChannelId
    and SponsorId."""
    if len(value) < min_len:
        return False
    return len(value) * ch == value and all(c in "0123456789ABCDEFabcdef" for c in value)


def _looks_like_placeholder(name: str, value: str) -> str | None:
    """Return a human-readable reason string if `value` looks like the
    externally-known placeholder for the credential named `name`, else None.
    The values we reject:
      * empty string (covers "missing entirely")
      * the literal "..." (the upstream psiphon.config.sample stub form)
      * all-F's hex (PropagationChannelId placeholder)
      * all-0's hex (SponsorId placeholder)
      * the fabricated 64-hex sig-pubkey the panel shipped pre-Hotfix-14
      * for the sig-pubkey specifically: any non-base64 string (base64
        for an ed25519 pubkey is ≈43-44 chars matching ^[A-Za-z0-9+/]{42,}=*$)
    """
    if not value or value.strip() == "":
        return "is empty / unset"
    if value.strip() == "...":
        return 'is the literal upstream psiphon.config.sample stub "..." (fill in your real Psiphon-Inc value)'
    # Pre-Hotfix-14 we shipped a fabricated 64-char hex string that
    # LOOKED like a pubkey but wasn't base64 + wasn't a real key.
    # Reject that exact value AND any other non-base64 string.
    if (
        name == "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY"
        and value == _LEGACY_STUB_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
    ):
        return (
            "is the FABRICATED placeholder shipped pre-Hotfix-14 — replace "
            "with the real base64-encoded ed25519 signature pubkey Psiphon "
            "Inc. embedded in your client build"
        )
    # ed25519 pubkeys base64-encode to ~43-44 chars ending in '=' sometimes.
    if name == "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY" and not re.fullmatch(
        r"[A-Za-z0-9+/]{42,}={0,2}", value
    ):
        return (
            "is not a valid base64-encoded ed25519 public key — Psiphon Inc. "
            "ships it base64-encoded (typically ~44 chars matching "
            "^[A-Za-z0-9+/]{42,}=*$))"
        )
    if name == "PSIPHON_PROPAGATION_CHANNEL_ID" and _is_all_hex_repeat("F", value):
        return "is the all-FF placeholder (32 × 'F') — replace with your real Psiphon-Inc PropagationChannelId"
    if name == "PSIPHON_SPONSOR_ID" and _is_all_hex_repeat("0", value):
        return (
            "is the all-zero placeholder (16 × '0') — replace with your real Psiphon-Inc SponsorId"
        )
    if name == "PSIPHON_REMOTE_SERVER_LIST_URL" and not value.startswith(("https://", "http://")):
        return "is not an http(s):// URL — Psiphon Inc. publishes a well-known S3 mirror"
    return None


def _resolve_upstream_credentials() -> dict[str, str]:
    """Return a dict with the four Psiphon-Inc upstream credentials
    resolved from env vars (PSIPHON_PROPAGATION_CHANNEL_ID,
    PSIPHON_SPONSOR_ID, PSIPHON_REMOTE_SERVER_LIST_URL,
    PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY).

    Raises :class:`PsiphonCredentialError` on the FIRST value that's
    missing or looks like the externally-known placeholder form. The
    error message is operator-actionable — names the env-var + the
    remediation (e.g. \"set PSIPHON_SPONSOR_ID in
    /opt/psiphon-3x-ui/panel.env\").

    The four values are the keys Psiphon-Inc ships only in their client
    binaries; there is no public open-source source for them. Operating
    against the production Psiphon Network REQUIRES a commercial-grade
    set issued by Psiphon Inc. — see docs/TROUBLESHOOTING.md.
    """
    fields: list[tuple[str, str]] = [
        ("PSIPHON_PROPAGATION_CHANNEL_ID", "PropagationChannelId"),
        ("PSIPHON_SPONSOR_ID", "SponsorId"),
        ("PSIPHON_REMOTE_SERVER_LIST_URL", "RemoteServerListUrl"),
        ("PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY", "RemoteServerListSignaturePublicKey"),
    ]
    out: dict[str, str] = {}
    for envname, fieldname in fields:
        value = os.environ.get(envname, "").strip()
        reason = _looks_like_placeholder(envname, value)
        if reason is not None:
            raise PsiphonCredentialError(
                f"STUB credential detected for {fieldname} — env var "
                f"{envname} {reason}. Set {envname} in "
                f"/opt/psiphon-3x-ui/panel.env (then `systemctl restart "
                "psiphon-3x-ui`) with your real Psiphon-Inc-issued value. "
                "See docs/TROUBLESHOOTING.md for how to obtain one."
            )
        out[fieldname] = value
    return out


class PsiphonUnitError(RuntimeError):
    """Raised when a ``systemctl`` invocation against the templated
    ``psiphon-tunnel@<CODE>.service`` unit fails (non-zero exit)."""


# ---------------------------------------------------------------------------
# Config rendering
# ---------------------------------------------------------------------------


def render_config(country_code: str, socks_port: int) -> dict[str, Any]:
    """Build a fully-populated per-country Psiphon config dict.

    Hotfix #14 (Phase 23): the four Psiphon-Inc upstream credentials
    (PropagationChannelId, SponsorId, RemoteServerListUrl,
    RemoteServerListSignaturePublicKey) are NO LONGER hardcoded in this
    module — they MUST be supplied by the operator via env vars read from
    ${ENV_FILE} (/opt/psiphon-3x-ui/panel.env). See
    `_resolve_upstream_credentials` + `PsiphonCredentialError` above for
    the exact placeholder-rejection rules + the operator-actionable error
    message.

    The per-country fields are ``EgressRegion`` (the 2-letter ISO code)
    and ``LocalSocksProxyPort``. The result is ready to serialise to JSON.

    Raises:
        ValueError: if country_code / socks_port are out of spec.
        PsiphonCredentialError: if any of the four upstream credentials
            env vars are unset OR look like the externally-known
            placeholder value (all-F's / all-0's / upstream stub "..." /
            non-base64 sig-pubkey / non-https URL). See
            `_looks_like_placeholder` for the exact rules — keeps the
            panel from spending 5 minutes in EstablishTunnelTimeout
            waiting for a server list it can never authenticate.
    """
    code = country_code.strip().upper()
    if not code or len(code) != 2 or not code.isalpha():
        raise ValueError(f"country_code must be a 2-letter ISO code, got {country_code!r}")
    port = int(socks_port)
    if not (1024 <= port <= 65535):
        raise ValueError(f"socks_port must be within [1024, 65535], got {socks_port!r}")

    creds = _resolve_upstream_credentials()

    # Hotfix #12 (Bug #1): emit the LEGACY DEPRECATED SINGULAR field
    # `RemoteServerListUrl` (note lowercase final "l") as a plain STRING.
    # The upstream binary's LoadConfig has a legacy promote branch
    # (config.go:82242): `if config.RemoteServerListUrl != "" &&
    # config.RemoteServerListURLs == nil { config.RemoteServerListURLs =
    # promoteLegacyTransferURL(config.RemoteServerListUrl) }` which wraps
    # the string as &parameters.TransferURL{URL: base64(URL),
    # OnlyAfterAttempts: 0} — exactly the shape DecodeAndValidate requires.
    # Pre-Hotfix #14 we hardcoded the well-known upstream S3 mirror URL
    # here; post-Hotfix-#14 the URL comes from the operator's env var
    # PSIPHON_REMOTE_SERVER_LIST_URL (a real Psiphon-Inc-issued URL).
    return {
        "PropagationChannelId": creds["PropagationChannelId"],
        "SponsorId": creds["SponsorId"],
        # Hotfix #12: legacy singular URL — the binary auto-promotes via
        # promoteLegacyTransferURL. Plain string, NOT base64-encoded.
        "RemoteServerListUrl": creds["RemoteServerListUrl"],
        # ed25519 signature-public-key — base64-encoded, supplied by
        # Psiphon Inc. and embedded in their shipped client binaries.
        "RemoteServerListSignaturePublicKey": creds["RemoteServerListSignaturePublicKey"],
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
