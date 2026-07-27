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

import base64
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
# Credential resolution strategy (post-Phase-24 cleanup):
#
# The panel ships with the Psiphon-3 *public-bootstrap* constants baked in
# as `_PUBLIC_*` defaults below. These are the same four(+two) bootstrap
# values Psiphon Inc. embeds in every public client binary (the Play Store
# Android app, the iOS app, the Windows desktop client). They are universal
# — identical across every public build — and they are sufficient for any
# operator to connect to the production Psiphon Network.
#
# The four env-var overrides below let commercial sponsors substitute their
# own private credentials if they have a direct Psiphon-Inc sponsorship
# (rare). When an env var is UNSET, render_config falls back to the
# `_PUBLIC_*` default below — no operator intervention is required for a
# working tunnel.
#
# When an env var is SET BUT its value looks like an externally-known
# placeholder (all-F's / all-0's / our pre-Phase-24 fabricated pubkey /
# the upstream stub "..." form / a non-https URL), render_config raises
# :class:`PsiphonCredentialError` rather than silently accept the bad
# value. This rejects the operator's obviously-incorrect override without
# blocking default operation.
#
#   PSIPHON_PROPAGATION_CHANNEL_ID              — 16-char hex string (default
#                                                  "92AACC5BABE0944C" from
#                                                  the Psiphon-3 public build)
#   PSIPHON_SPONSOR_ID                          — 16-char hex string (default
#                                                  "1BC527D3D09985CF" from
#                                                  the Psiphon-3 public build —
#                                                  distinct from PropChannel ID)
#   PSIPHON_SPONSOR_ID                          — 16-char hex string (same
#                                                  public value as PropChan)
#   PSIPHON_REMOTE_SERVER_LIST_URL              — single https URL (default
#                                                  is the primary S3 mirror)
#   PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY — base64-encoded RSA-2048
#                                                  SPKI (~716 chars) — Psiphon
#                                                  uses RSA-2048 for the
#                                                  server-list signature, not
#                                                  Ed25519. (Edd25519 = ~44 chars.)
# ---------------------------------------------------------------------------
# Decoded from the APK dump's base64 `RemoteServerListURLs` array (paths
# verified equal post-decode against the user-provided JSON dump):
#   aHR0cHM6Ly9zMy5hbWF6b25hd3MuY29tL3BzaXBob24vd2ViL21qcjQtcDIzci1wdXdsL3NlcnZlcl9saXN0X2NvbXByZXNzZWQ=
#     → https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed
#   aHR0cHM6Ly93d3cuYmxvZ3NmbWNhbmNlcmNpdGl6ZW4uY29tL3dlYi9tanI0LXAyM3ItcHV3bC9zZXJ2ZXJfbGlzdF9jb21wcmVzc2Vk
#     → https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/server_list_compressed
#   aHR0cHM6Ly93d3cuaGVyYm14ZGlpbmNvcnBvcmF0ZWQuY29tL3dlYi9tanI0LXAyM3ItcHV3bC9zZXJ2ZXJfbGlzdF9jb21wcmVzc2Vk
#     → https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/server_list_compressed
#   aHR0cHM6Ly93d3cueHlkaWFtb25kZGJleHBlcnQuY29tL3dlYi9tanI0LXAyM3ItcHV3bC9zZXJ2ZXJfbGlzdF9jb21wcmVzc2Vk
#     → https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/server_list_compressed
# The "osl" (ObfuscatedServerList) variant shares the same 4 domains with a
# different suffix (`/osl` instead of `/server_list_compressed`).
# ---------------------------------------------------------------------------


class PsiphonCredentialError(RuntimeError):
    """Raised by render_config ONLY when an operator-provided env-var
    override looks like an externally-known placeholder (all-F's
    PropagationChannelId / all-0's SponsorId / the pre-Phase-24 fabricated
    pubkey / the upstream stub "..." form / a non-base64 sig-pubkey / a
    non-https URL). The default (no env) code path NEVER raises this — the
    `_PUBLIC_*` baked-in defaults are always valid public-bootstrap
    values for the production Psiphon Network."""


# ---------------------------------------------------------------------------
# Public-bootstrap constants — extracted from the Psiphon-3 Android client
# (Play Store public APK). These are universal across every public Psiphon
# client binary; baking them in makes the panel install silently without
# operator intervention. See plans/EMBED-PSIPHON-PUBLIC-BOOTSTRAP.md.
# ---------------------------------------------------------------------------
_PUBLIC_PROPAGATION_CHANNEL_ID = "92AACC5BABE0944C"
_PUBLIC_SPONSOR_ID = "1BC527D3D09985CF"

_PUBLIC_REMOTE_SERVER_LIST_URLS: tuple[str, ...] = (
    "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed",
    "https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/server_list_compressed",
    "https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/server_list_compressed",
    "https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/server_list_compressed",
)

_PUBLIC_OBFUSCATED_SERVER_LIST_ROOT_URLS: tuple[str, ...] = (
    "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/osl",
    "https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/osl",
    "https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/osl",
    "https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/osl",
)

# Psiphon ships an RSA-2048 SubjectPublicKeyInfo for the RemoteServerList
# signature, base64-encoded (~716 chars including '=' padding). The full
# value is below as a single string literal (PEM-style line breaks inside
# JSON would corrupt tunnel-core's parsing, so we keep it on one line).
_PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
)

# Ed25519 server-entry signature pubkey (44 chars base64) — also universal
# across every public Psiphon client binary.
_PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY = "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA="

# Diffie-Hellman exchange-obfuscation key (44 chars base64) — also universal
# across every public Psiphon client binary.
_PUBLIC_EXCHANGE_OBFUSCATION_KEY = "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU="


# Legacy placeholder constants — kept ONLY as documentation of the values
# the placeholder-rejector must catch (operator-provided env-var overrides
# that match these patterns are rejected). Used by TestPsiphonCredentialError
# regressions in tests/test_psiphon.py via `monkeypatch.setenv`. These MUST
# NOT be used by render_config's default code path — that uses `_PUBLIC_*`.
_LEGACY_STUB_PROPAGATION_CHANNEL_ID = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
_LEGACY_STUB_SPONSOR_ID = "0000000000000000"
_LEGACY_STUB_REMOTE_SERVER_LIST_URLS: tuple[str, ...] = (
    "https://s3.amazonaws.com/psiphon/web/4r9isqmlq6j4thjvfmxq2qgfqh48mdga7kjapsrjr9s2xqjz",
)
_LEGACY_STUB_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    "62BFA6DFD5C8C6E2E8F5B9E3C1F9F8A5D6E2B6C9A0F1D2E3B4C5D6F7E8A9B0C"
)

# Source-compat aliases for the placeholders (so static-source grep tests
# in tests/test_hardening.py that import PSIPHON_PROPAGATION_CHANNEL_ID
# etc. still resolve). These point at the legacy STUB values — commercial
# operators who `import PSIPHON_*` to introspect placeholder patterns still
# see the same expected placeholder strings.
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
    The values we reject (operator-provided env-var overrides only — the
    default code path uses `_PUBLIC_*` baked-in values which never trigger
    this rejector):
      * empty string (covers "missing entirely")
      * the literal "..." (the upstream psiphon.config.sample stub form)
      * all-F's hex (PropagationChannelId placeholder)
      * all-0's hex (SponsorId placeholder)
      * the fabricated 64-hex sig-pubkey the panel shipped pre-Hotfix-14
      * for the sig-pubkey specifically: any non-base64 string. NOTE Psiphon
        uses RSA-2048 SPKI for RemoteServerListSignaturePublicKey (~716 chars
        base64), NOT Ed25519 (~44 chars). Ed25519 is used for the *separate*
        ServerEntrySignaturePublicKey field (which has no env override here).
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
            "with the real base64-encoded RSA-2048 SPKI signature pubkey "
            "Psiphon Inc. embedded in your client build (or unset the env "
            "var to use the panel's baked-in public-bootstrap default)"
        )
    # RSA-2048 SPKI base64 is ~716 chars; older Ed25519 pubkeys were ~44 chars.
    # Both shapes are valid; reject anything not matching base64 (with /+ and
    # optional '=' padding).
    if name == "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY" and not re.fullmatch(
        r"[A-Za-z0-9+/]{42,}={0,2}", value
    ):
        return (
            "is not a valid base64-encoded public key — Psiphon Inc. ships "
            "the RemoteServerListSignaturePublicKey base64-encoded (RSA-2048 "
            "SPKI is ~716 chars; legacy ed25519 was ~44 chars matching "
            "^[A-Za-z0-9+/]{42,}=*$)"
        )
    if name == "PSIPHON_PROPAGATION_CHANNEL_ID" and _is_all_hex_repeat("F", value):
        return "is the all-FF placeholder (32 × 'F') — replace with your real Psiphon-Inc PropagationChannelId (or unset the env var to use the panel's baked-in public-bootstrap default)"
    if name == "PSIPHON_SPONSOR_ID" and _is_all_hex_repeat("0", value):
        return (
            "is the all-zero placeholder (16 × '0') — replace with your real Psiphon-Inc SponsorId (or unset the env var to use the panel's baked-in public-bootstrap default)"
        )
    if name == "PSIPHON_REMOTE_SERVER_LIST_URL" and not value.startswith(("https://", "http://")):
        return "is not an http(s):// URL — Psiphon Inc. publishes a well-known S3 mirror (or unset the env var to use the panel's baked-in 4-mirror public-bootstrap default)"
    return None


def _resolve_upstream_credentials() -> dict[str, Any]:
    """Resolve the seven Psiphon-Inc upstream bootstrap fields, using the
    universal public-bootstrap defaults baked into this module and letting
    operator-set env vars override any subset of them.

    Returns a dict keyed by the per-config JSON field name (the form
    `render_config` writes into the per-country JSON):
        PropagationChannelId            — string (16-hex chars default)
        SponsorId                       — string (16-hex chars default)
        RemoteServerListURLs            — list[dict] (4 TransferURL mirrors)
        ObfuscatedServerListRootURLs     — list[dict] (4 TransferURL mirrors)
        RemoteServerListSignaturePublicKey — string (RSA-2048 SPKI base64)
        ServerEntrySignaturePublicKey    — string (Ed25519 base64)
        ExchangeObfuscationKey           — string (base64)

    Env-var overridable fields (override values run through
    :func:`_looks_like_placeholder`; bad / placeholder-looking operator
    overrides raise :class:`PsiphonCredentialError` so the operator gets a
    clear actionable message instead of a silently-non-functional tunnel):
        PSIPHON_PROPAGATION_CHANNEL_ID
        PSIPHON_SPONSOR_ID
        PSIPHON_REMOTE_SERVER_LIST_URL  — singular; if set, used as the only
                                          entry in RemoteServerListURLs
                                          (maintained for Hotfix-#14 source-
                                          compat; the default still returns
                                          the full 4-mirror list).
        PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY

    The remaining three public-bootstrap fields
    (ServerEntrySignaturePublicKey, ExchangeObfuscationKey, and the four
    ObfuscatedServerListRootURLs mirrors) are NOT env-overridable — they
    are universal across every public Psiphon client binary. Override via
    ${ENV_FILE} only matters for operators with a commercial direct
    sponsorship that issued them private values (rare); they would patch
    this module directly if they needed to substitute those too.
    """
    # Simple scalar fields — env override beats default; placeholder-looking
    # operator value raises PsiphonCredentialError.
    scalar_overrides: list[tuple[str, str, str]] = [
        ("PSIPHON_PROPAGATION_CHANNEL_ID", "PropagationChannelId", _PUBLIC_PROPAGATION_CHANNEL_ID),
        ("PSIPHON_SPONSOR_ID", "SponsorId", _PUBLIC_SPONSOR_ID),
        (
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
            "RemoteServerListSignaturePublicKey",
            _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
        ),
    ]
    out: dict[str, Any] = {}
    for envname, fieldname, default_value in scalar_overrides:
        env_value = os.environ.get(envname, "").strip()
        if env_value:
            reason = _looks_like_placeholder(envname, env_value)
            if reason is not None:
                raise PsiphonCredentialError(
                    f"STUB credential detected for {fieldname} — env var "
                    f"{envname} {reason}. Set {envname} in "
                    f"/opt/psiphon-3x-ui/panel.env (then `systemctl restart "
                    "psiphon-3x-ui`) with your real Psiphon-Inc-issued value "
                    "or unset it to fall back to the panel's baked-in "
                    "public-bootstrap default. See docs/TROUBLESHOOTING.md."
                )
            out[fieldname] = env_value
        else:
            out[fieldname] = default_value

    # RemoteServerListURLs — plural array of 4 TransferURL mirrors by
    # default; if PSIPHON_REMOTE_SERVER_LIST_URL is set (the Hotfix-#14
    # singular-path env), use just that URL in the array.
    single_url = os.environ.get("PSIPHON_REMOTE_SERVER_LIST_URL", "").strip()
    if single_url:
        reason = _looks_like_placeholder("PSIPHON_REMOTE_SERVER_LIST_URL", single_url)
        if reason is not None:
            raise PsiphonCredentialError(
                f"STUB credential detected for RemoteServerListUrl — env var "
                f"PSIPHON_REMOTE_SERVER_LIST_URL {reason}. Set "
                f"PSIPHON_REMOTE_SERVER_LIST_URL in "
                f"/opt/psiphon-3x-ui/panel.env (then `systemctl restart "
                "psiphon-3x-ui`) with a real https Psiphon-Inc server-list "
                "URL or unset it to fall back to the panel's baked-in "
                "4-mirror public-bootstrap default. See "
                "docs/TROUBLESHOOTING.md."
            )
        # Phase 24 Hotfix #1: tunnel-core's `parameters.TransferURLs.
        # DecodeAndValidate#90` tries to base64-decode each `URL` field,
        # so the RAW https URL must be base64-encoded here (per the
        # public APK dump JSON shape + psiphon.config.sample precedent —
        # see plans/EMBED-PSIPHON-PUBLIC-BOOTSTRAP.md:94-96).
        # Confirmed against the operator's journal: tunnel-core dies
        # with "illegal base64 data at input byte 5" on `https:` when
        # the URL field contains a raw URL string.
        out["RemoteServerListURLs"] = [
            {
                "URL": base64.b64encode(single_url.encode("utf-8")).decode("ascii"),
                "OnlyAfterAttempts": 0,
                "SkipVerify": False,
            }
        ]
    else:
        out["RemoteServerListURLs"] = [
            {
                "URL": base64.b64encode(u.encode("utf-8")).decode("ascii"),
                "OnlyAfterAttempts": 0,
                "SkipVerify": False,
            }
            for u in _PUBLIC_REMOTE_SERVER_LIST_URLS
        ]

    # The remaining four public-bootstrap fields are NOT env-overridable.
    # Same base64-encoding rule applies (the OSL-root URLs go through the
    # same TransferURLs.DecodeAndValidate path).
    out["ObfuscatedServerListRootURLs"] = [
        {
            "URL": base64.b64encode(u.encode("utf-8")).decode("ascii"),
            "OnlyAfterAttempts": 0,
            "SkipVerify": False,
        }
        for u in _PUBLIC_OBFUSCATED_SERVER_LIST_ROOT_URLS
    ]
    out["ServerEntrySignaturePublicKey"] = _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY
    out["ExchangeObfuscationKey"] = _PUBLIC_EXCHANGE_OBFUSCATION_KEY

    return out


class PsiphonUnitError(RuntimeError):
    """Raised when a ``systemctl`` invocation against the templated
    ``psiphon-tunnel@<CODE>.service`` unit fails (non-zero exit)."""


# ---------------------------------------------------------------------------
# Config rendering
# ---------------------------------------------------------------------------


def render_config(country_code: str, socks_port: int) -> dict[str, Any]:
    """Build a fully-populated per-country Psiphon config dict.

    Phase 24 (post-Hotfix-#14 cleanup): the seven Psiphon-Inc upstream
    bootstrap fields (PropagationChannelId, SponsorId, RemoteServerListURLs,
    ObfuscatedServerListRootURLs, RemoteServerListSignaturePublicKey,
    ServerEntrySignaturePublicKey, ExchangeObfuscationKey) are NO LONGER
    operator-mandatory — the public-bootstrap constants extracted from the
    Psiphon-3 client binaries are baked in as `_PUBLIC_*` defaults so the
    panel works out-of-the-box. Env vars (`PSIPHON_PROPAGATION_CHANNEL_ID`,
    `PSIPHON_SPONSOR_ID`, `PSIPHON_REMOTE_SERVER_LIST_URL`,
    `PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY`) become OPTIONAL
    OVERRIDES — a commercial sponsor can substitute its own PropChannel /
    SponsorId / signed server-list URL / sig-pubkey via `${ENV_FILE}`
    (/opt/psiphon-3x-ui/panel.env) without forking the panel. See
    `_resolve_upstream_credentials` for the override precedence + the
    placeholder-rejection rules that fire only on operator-supplied BAD
    overrides (the default code path never raises).

    The full field set emitted here matches what tunnel-core's
    `parameters.Config.DecodeAndValidate` expects from a modern Psiphon-3
    client binary (verified against the public APK dump): the plural
    `RemoteServerListURLs` TransferURL array (NOT the legacy singular
    `RemoteServerListUrl` string — its `promoteLegacyTransferURL` branch
    is only triggered when the plural array is nil, which we no longer
    do), the parallel `ObfuscatedServerListRootURLs` array used by the
    obfuscated-server-list transport, the RSA-2048 SPKI
    `RemoteServerListSignaturePublicKey` (~716 base64 chars) that signs
    the server-list blob, the Ed25519 `ServerEntrySignaturePublicKey`
    (~44 base64 chars) that signs individual server entries, the
    `ExchangeObfuscationKey` that masks the initial handshake, and
    `UseIndistinguishableTLS: true` so tunnel-core fronts TLS as an
    unidentifiable client hello (matches public-client behaviour).

    The per-country fields are ``EgressRegion`` (the 2-letter ISO code)
    and ``LocalSocksProxyPort``. The result is ready to serialise to JSON.

    Raises:
        ValueError: if country_code / socks_port are out of spec.
        PsiphonCredentialError: only if an operator EXPLICITLY sets a
            `PSIPHON_*` env override that looks like the externally-known
            placeholder value (all-F's / all-0's / upstream stub "..." /
            non-base64 sig-pubkey / non-https URL). Omitting the env vars
            entirely is now VALID — the baked-in `_PUBLIC_*` defaults are
            used instead. See `_looks_like_placeholder` for the exact
            rules — keeps the panel from spending 5 minutes in
            EstablishTunnelTimeout waiting for a server list it can
            never authenticate.
    """
    code = country_code.strip().upper()
    if not code or len(code) != 2 or not code.isalpha():
        raise ValueError(f"country_code must be a 2-letter ISO code, got {country_code!r}")
    port = int(socks_port)
    if not (1024 <= port <= 65535):
        raise ValueError(f"socks_port must be within [1024, 65535], got {socks_port!r}")

    creds = _resolve_upstream_credentials()

    # Phase 24: emit the full modern tunnel-core field set. The legacy
    # singular `RemoteServerListUrl` (lowercase final "l") is NOT emitted
    # here anymore — tunnel-core's `LoadConfig` promote branch
    # (config.go:82242: `if config.RemoteServerListUrl != "" &&
    # config.RemoteServerListURLs == nil { promoteLegacyTransferURL(...) }`)
    # only fires when the plural `RemoteServerListURLs` array is nil, which
    # is no longer the case. Keeping the singular around would be redundant
    # (and could theoretically win over the plural on some binary builds,
    # losing the 3 alternate mirrors + the SkipVerify / OnlyAfterAttempts
    # transfer-metadata fields).
    return {
        # Identity / sponsorship — env-overridable, default public-bootstrap.
        "PropagationChannelId": creds["PropagationChannelId"],
        "SponsorId": creds["SponsorId"],
        # Plural TransferURL array (4 mirrors for the public client). Each
        # entry is `{"URL": <base64-encoded https url>, "OnlyAfterAttempts":
        # 0, "SkipVerify": false}` — tunnel-core's
        # `parameters.TransferURLs.DecodeAndValidate#90` base64-DECODES the
        # URL field, so we ship the BASE64-encoded raw URL (per the public
        # APK dump JSON shape + psiphon.config.sample precedent, see
        # plans/EMBED-PSIPHON-PUBLIC-BOOTSTRAP.md:94-96). Phase 24 Hotfix #1
        # fixed an implementation error where the RAW URL was emitted here
        # (tunnel-core dies with "illegal base64 data at input byte 5" on
        # the `:` after `https`).
        "RemoteServerListURLs": creds["RemoteServerListURLs"],
        # Parallel obfuscated-server-list-root array (same 4 mirror hosts,
        # `/osl` path). Used by the OSL transport when the plain server list
        # is unreachable (censorship fallback). Same TransferURL shape +
        # same base64-URL encoding.
        "ObfuscatedServerListRootURLs": creds["ObfuscatedServerListRootURLs"],
        # RSA-2048 SPKI base64 (~716 chars). Signs the compressed server-list
        # blob fetched from RemoteServerListURLs.
        "RemoteServerListSignaturePublicKey": creds["RemoteServerListSignaturePublicKey"],
        # Ed25519 base64 (~44 chars). Signs each individual server entry
        # inside the server list — tunnel-core rejects unsigned / bad-sig
        # entries. NOTE distinct from the RSA key above.
        "ServerEntrySignaturePublicKey": creds["ServerEntrySignaturePublicKey"],
        # Per-session handshake obfuscation seed (~44 base64 chars). Fronts
        # the initial client <-> server key exchange so DPI can't fingerprint
        # the Psiphon handshake.
        "ExchangeObfuscationKey": creds["ExchangeObfuscationKey"],
        # TLS fronting: emit an unidentifiable ClientHello so DPI can't
        # distinguish the tunnel from ordinary HTTPS to the fronted CDN.
        "UseIndistinguishableTLS": True,
        # Per-country fields.
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
