"""pytest coverage for :mod:`panel.psiphon` (Phase 4 — step 4j).

Covers the three concerns in ``panel/psiphon/__init__.py``:

* :func:`render_config` — schema, upstream constants, validation.
* :func:`write_config` — file round-trip + ``config_dir`` override.
* :func:`start_unit` / :func:`stop_unit` / :func:`restart_unit` /
  :func:`is_unit_active` — thin wrappers around ``_systemctl``; we drive
  them by monkey-patching ``subprocess.run`` (the only external call).
* :func:`health_probe` — exercised through a fake ``_sock_factory`` that
  returns a stub socket supporting ``settimeout`` / ``connect`` / ``sendall``
  / ``recv`` / ``close``.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import FrozenInstanceError

import pytest

from panel.psiphon import (
    HealthProbeResult,
    PsiphonCredentialError,
    PsiphonUnitError,
    _unit_name,
    health_probe,
    is_unit_active,
    render_config,
    restart_unit,
    start_unit,
    stop_unit,
    write_config,
)

# Hotfix #14 (Phase 23): the four Psiphon-Inc upstream credentials are now
# operator-supplied via env vars (see panel/psiphon/__init__.py +
# _resolve_upstream_credentials). Tests must `monkeypatch.setenv` real-looking
# values before calling render_config; otherwise the panel fast-fails with
# PsiphonCredentialError. These constants are the FAKE-but-real-shape values
# every setenv-using test sets: all four are formatted correctly so they pass
# the placeholder-rejection validators, but they are NOT real Psiphon-Inc creds.
_TEST_PROPAGATION_CHANNEL_ID = "0123456789ABCDEF0123456789ABCDEF"
_TEST_SPONSOR_ID = "0123456789ABCDEF"
_TEST_REMOTE_SERVER_LIST_URL = "https://s3.amazonaws.com/psiphon/web/test-mirror"
_TEST_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY = (
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # 43 'A' + '='
)


@pytest.fixture(autouse=True)
def _set_real_psiphon_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Populate every PSIPHON_* upstream credential env var with a
    fake-but-real-shape value. autouse so any test in this module that calls
    render_config / write_config without explicitly opting into the
    placeholder-rejection path still gets a working happy-path render."""
    monkeypatch.setenv("PSIPHON_PROPAGATION_CHANNEL_ID", _TEST_PROPAGATION_CHANNEL_ID)
    monkeypatch.setenv("PSIPHON_SPONSOR_ID", _TEST_SPONSOR_ID)
    monkeypatch.setenv("PSIPHON_REMOTE_SERVER_LIST_URL", _TEST_REMOTE_SERVER_LIST_URL)
    monkeypatch.setenv(
        "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        _TEST_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
    )


# --------------------------------------------------------------------------- #
# render_config                                                               #
# --------------------------------------------------------------------------- #
class TestRenderConfig:
    # Hotfix #12 (Bug #1) + Hotfix #13 (Bug #1 v2) + Hotfix #14 (Phase 23)
    # + Phase 24 (post-Hotfix-#14 cleanup). Phase 24 emitter:
    #   - PropagationChannelId, SponsorId           — env-overridable scalars
    #   - RemoteServerListURLs                     — plural TransferURL array
    #                                                (env var singular -> 1-elem
    #                                                list; no env -> 4-mirror
    #                                                `_PUBLIC_*` default)
    #   - ObfuscatedServerListRootURLs             — 4-mirror baked-in default
    #                                                (non env-overridable)
    #   - RemoteServerListSignaturePublicKey       — env-overridable scalar
    #   - ServerEntrySignaturePublicKey           — baked-in (Ed25519 ~44 chars)
    #                                                (non env-overridable)
    #   - ExchangeObfuscationKey                  — baked-in (~44 chars)
    #                                                (non env-overridable)
    #   - UseIndistinguishableTLS: true           — fronting switch
    #   - EgressRegion, LocalSocksProxyPort       — per-country
    #   - DisableLocalHTTPProxy: true             — SOCKS-only
    # Hotfix #14 + Phase 24: a missing env var is no longer fatal — the
    # baked-in `_PUBLIC_*` default from the public Psiphon-3 APK is used.
    # A bad-looking env var (placeholder-form) STILL raises
    # PsiphonCredentialError on the first render attempt.
    def test_returns_eleven_required_keys(self):
        cfg = render_config("US", 1080)
        # Phase 24: 11 keys. The legacy singular `RemoteServerListUrl` is
        # DROPPED — emit plural `RemoteServerListURLs` TransferURL array
        # directly (the binary's promote-branch is only triggered when the
        # plural is nil, which we no longer do).
        assert set(cfg) == {
            "PropagationChannelId",
            "SponsorId",
            "RemoteServerListURLs",
            "ObfuscatedServerListRootURLs",
            "RemoteServerListSignaturePublicKey",
            "ServerEntrySignaturePublicKey",
            "ExchangeObfuscationKey",
            "UseIndistinguishableTLS",
            "EgressRegion",
            "LocalSocksProxyPort",
            "DisableLocalHTTPProxy",
        }

    def test_render_config_uses_env_vars_for_upstream_credentials(self):
        """Phase 24 (was Hotfix #14): render_config still pulls the four
        ENV-OVERRIDABLE upstream credentials from the operator's env. The
        autouse fixture above set fake-but-real-shape values; assert they
        round-trip. Note `RemoteServerListUrl` (singular) is no longer a
        config key — env var `PSIPHON_REMOTE_SERVER_LIST_URL` is now wrapped
        into a 1-element `RemoteServerListURLs` TransferURL array."""
        cfg = render_config("US", 1080)
        assert cfg["PropagationChannelId"] == _TEST_PROPAGATION_CHANNEL_ID
        assert cfg["SponsorId"] == _TEST_SPONSOR_ID
        assert (
            cfg["RemoteServerListSignaturePublicKey"]
            == _TEST_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
        )
        # The env var is WRAPPED: 1-element TransferURL array carrying the
        # raw URL + OnlyAfterAttempts=0 + SkipVerify=False.
        urls = cfg["RemoteServerListURLs"]
        assert isinstance(urls, list)
        assert len(urls) == 1
        entry = urls[0]
        assert entry["URL"] == _TEST_REMOTE_SERVER_LIST_URL
        assert entry["OnlyAfterAttempts"] == 0
        assert entry["SkipVerify"] is False

    def test_sponsor_id_is_nonempty_string(self):
        # Hotfix #13 (Bug #1 v2): SponsorId must be a non-empty string
        # (Config.Commit rejects the empty value with "sponsor ID is
        # missing from the configuration file"). Hotfix #14 keeps that
        # invariant but now sources the value from the operator's env.
        cfg = render_config("US", 1080)
        assert isinstance(cfg["SponsorId"], str) and cfg["SponsorId"]

    def test_egress_region_uppercased_and_port_int(self):
        cfg = render_config("de", 11080)
        assert cfg["EgressRegion"] == "DE"
        assert cfg["LocalSocksProxyPort"] == 11080
        assert isinstance(cfg["LocalSocksProxyPort"], int)

    def test_disable_local_http_proxy_true(self):
        # Spec: tunnels only expose SOCKS5; HTTP proxy is disabled.
        assert render_config("US", 1080)["DisableLocalHTTPProxy"] is True

    @pytest.mark.parametrize(
        ("code", "socks_port"),
        [
            ("US", 80),  # port below 1024
            ("US", 70000),  # port above 65535
            ("US1", 1080),  # non-alpha code
            ("U", 1080),  # too short
            ("USA", 1080),  # too long
            ("", 1080),  # empty
        ],
    )
    def test_invalid_inputs_raise_value_error(self, code, socks_port):
        with pytest.raises(ValueError):
            render_config(code, socks_port)

    def test_remote_server_list_urls_is_plural_transfer_url_array(self):
        # Phase 24 (was Hotfix #12 Bug #1): render_config emits the PLURAL
        # `RemoteServerListURLs` field as a list of TransferURL dicts (NOT a
        # singular lowercase-final-"l" string). The autouse fixture populates
        # the singular `PSIPHON_REMOTE_SERVER_LIST_URL` env var, which
        # `_resolve_upstream_credentials` wraps into a 1-elem array.
        # psiphon-tunnel-core's promoteLegacyTransferURL branch is NOT
        # triggered (the plural array is non-nil), and the legacy singular
        # field is NOT emitted anymore.
        cfg = render_config("US", 1080)
        assert "RemoteServerListUrl" not in cfg  # singular field GONE
        urls = cfg["RemoteServerListURLs"]
        assert isinstance(urls, list)
        assert len(urls) == 1
        assert urls[0]["URL"] == _TEST_REMOTE_SERVER_LIST_URL
        assert isinstance(urls[0]["OnlyAfterAttempts"], int)
        assert isinstance(urls[0]["SkipVerify"], bool)


# --------------------------------------------------------------------------- #
# render_config — Phase 24 (post-Hotfix-#14 cleanup) credential placeholder   #
# rejection (operator-supplied BAD overrides only)                            #
# --------------------------------------------------------------------------- #
class TestPsiphonCredentialErrorRegressions:
    """Phase 24 (post-Hotfix-#14 cleanup): the four Psiphon-Inc upstream
    bootstrap constants are BAKED IN as `_PUBLIC_*` defaults inside
    panel/psiphon/__init__.py (extracted from the public Psiphon-3 client
    APK). Per-country tunnels establish out-of-the-box with NO env vars
    required. The four `PSIPHON_*` env vars are now OPTIONAL OVERRIDES —
    a commercial sponsor can substitute its own PropChannel / SponsorId /
    signed server-list URL / sig-pubkey. render_config fast-fails with
    PsiphonCredentialError ONLY when the operator EXPLICITLY sets an env
    override that looks like the externally-known placeholder form (all-F's,
    all-0's, "..." stub, non-base64 sig-pubkey, non-https URL), instead of
    silently producing a config that psiphon-tunnel-core will then 5-minute
    EstablishTunnelTimeout on.
    """

    @pytest.mark.parametrize(
        ("envname", "bad_value", "expected_reason_fragment"),
        [
            # The upstream psiphon.config.sample literal "..." form.
            (
                "PSIPHON_PROPAGATION_CHANNEL_ID",
                "...",
                'config.sample stub "..."',
            ),
            # All-F's placeholder for PropagationChannelId.
            (
                "PSIPHON_PROPAGATION_CHANNEL_ID",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "all-FF placeholder",
            ),
            # All-0's placeholder for SponsorId.
            (
                "PSIPHON_SPONSOR_ID",
                "0000000000000000",
                "all-zero placeholder",
            ),
            # The FABRICATED 64-hex sig-pubkey the panel shipped pre-Hotfix-14.
            (
                "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
                "62BFA6DFD5C8C6E2E8F5B9E3C1F9F8A5D6E2B6C9A0F1D2E3B4C5D6F7E8A9B0C",
                "FABRICATED placeholder shipped pre-Hotfix-14",
            ),
            # Non-base64 sig-pubkey (contains '@' — fails the base64 regex).
            # Phase 24 rewording: dropped the "ed25519" qualifier because the
            # public-client RemoteServerListSignaturePublicKey is RSA-2048 SPKI.
            (
                "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
                "AAA@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "is not a valid base64-encoded public key",
            ),
            # Non-http(s):// RemoteServerListUrl.
            (
                "PSIPHON_REMOTE_SERVER_LIST_URL",
                "ftp://example.invalid/psiphon-list",
                "is not an http(s):// URL",
            ),
        ],
    )
    def test_render_config_rejects_placeholder_upstream_credential(
        self,
        monkeypatch: pytest.MonkeyPatch,
        envname: str,
        bad_value: str,
        expected_reason_fragment: str,
    ) -> None:
        """Phase 24 (was Hotfix #14): the panel fast-fails with
        PsiphonCredentialError — carrying an operator-actionable message —
        when ANY of the four upstream credentials is provided via an env
        override that LOOKS LIKE the externally-known placeholder form.
        The autouse fixture set real-shape values for all four; we override
        the one we're testing with a placeholder, then assert the error
        MESSAGE names the env var. NOTE: Phase 24 changed the contract — a
        missing env var NO LONGER raises (the baked-in `_PUBLIC_*` default
        is used). Only the empty-string-fallback path of the parametrize was
        REMOVED in Phase 24 — placeholder-shaped overrides still raise."""
        monkeypatch.setenv(envname, bad_value)
        with pytest.raises(PsiphonCredentialError) as excinfo:
            render_config("US", 1080)
        # Substring match (NOT regex) so the fragments can carry regex-meta
        # chars like the literal "http(s)://" or the all-F's grouping without
        # us having to escape every paren / dot.
        assert expected_reason_fragment in str(excinfo.value), (
            f"expected credential-error fragment {expected_reason_fragment!r} "
            f"in error message; got: {excinfo.value}"
        )
        # Sanity: the operator-actionable suffix must also be present so the
        # operator can actually act on the rejection.
        assert "/opt/psiphon-3x-ui/panel.env" in str(excinfo.value)

    def test_render_config_error_message_is_operator_actionable(self, monkeypatch):
        """The fast-fail message must name the env var + panel.env path +
        the restart command, so the operator knows exactly what to do. NOTE
        Phase 24: an EMPTY Sponsor used to raise; now it falls through to
        the baked-in default (no error). We set Sponsor to the placeholder
        form ("0000...") so the rejector still fires."""
        monkeypatch.setenv("PSIPHON_SPONSOR_ID", "0000000000000000")
        with pytest.raises(PsiphonCredentialError) as excinfo:
            render_config("US", 1080)
        msg = str(excinfo.value)
        assert "PSIPHON_SPONSOR_ID" in msg
        assert "/opt/psiphon-3x-ui/panel.env" in msg
        assert "systemctl restart psiphon-3x-ui" in msg
        assert "docs/TROUBLESHOOTING.md" in msg

    def test_render_config_uses_baked_in_default_when_env_unset(self, monkeypatch):
        """Phase 24 INVERTED the empty-env-var contract: deleting
        PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY (the realistic
        installer-skipped-prompt case) NO LONGER raises — the panel uses the
        baked-in `_PUBLIC_*` default and renders successfully. Pre-Phase-24
        (Hotfix #14) the panel fast-failed here; that was the root cause of
        user-reported Issues 2/3/4 (wizard/dashboard enable blocked)."""
        monkeypatch.delenv("PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY", raising=False)
        # Should NOT raise — the baked-in `_PUBLIC_*` default kicks in.
        cfg = render_config("US", 1080)
        # The baked-in default for the sig-pubkey is the RSA-2048 SPKI (~716 chars).
        from panel.psiphon import _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
        assert (
            cfg["RemoteServerListSignaturePublicKey"]
            == _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
        )

    def test_psiphon_credential_error_is_runtime_error_subclass(self):
        """PsiphonCredentialError is caught by the panel's general exception
        handlers because it subclasses RuntimeError (NOT a custom error code)."""
        assert issubclass(PsiphonCredentialError, RuntimeError)

    def test_legacy_stub_constants_document_the_placeholders_we_reject(self):
        """Source-compat aliases keep the legacy constant NAMES importable (so
        test_hardening.py static-grep tests + importers don't break), but
        their VALUES must remain the literal placeholder forms the panel
        rejects. This locks in the placeholder identity for forward-compatibility:
        if anyone is tempted to set the legacy constant = a real value, this
        test will fail loudly. NOTE Phase 24: these legacy `_LEGACY_STUB_*`
        constants are KEPT for source-compat with the placeholder-rejector
        test cases + the TestHotfix14 static-grep tests; they no longer feed
        into render_config (the `_PUBLIC_*` defaults do)."""
        from panel.psiphon import (  # noqa: PLC0415
            PSIPHON_PROPAGATION_CHANNEL_ID,
            PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
            PSIPHON_SPONSOR_ID,
        )

        assert PSIPHON_PROPAGATION_CHANNEL_ID == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        assert PSIPHON_SPONSOR_ID == "0000000000000000"
        assert PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY == (
            "62BFA6DFD5C8C6E2E8F5B9E3C1F9F8A5D6E2B6C9A0F1D2E3B4C5D6F7E8A9B0C"
        )


# --------------------------------------------------------------------------- #
# Phase 24 — TestPublicBootstrapDefaults                                       #
# --------------------------------------------------------------------------- #
class TestPublicBootstrapDefaults:
    """Phase 24 (post-Hotfix-#14 cleanup): the public-bootstrap Psiphon-3
    constants extracted from the public client APK are baked into
    panel/psiphon/__init__.py as `_PUBLIC_*`. These tests assert:

      1. The 7 `_PUBLIC_*` constant values match the public APK dump exactly.
      2. render_config() with all PSIPHON_* env vars UNSET round-trips the
         `_PUBLIC_*` constants into the output dict.
      3. The plural `RemoteServerListURLs` array (with no env override) carries
         the 4-mirror default, each wrapped as a TransferURL dict.
      4. The non-env-overridable fields (`ServerEntrySignaturePublicKey`,
         `ExchangeObfuscationKey`, `ObfuscatedServerListRootURLs`) round-trip
         the baked-in defaults even when the operator tries to override them
         (the env var is IGNORED for non-overridable fields).
    """

    @pytest.fixture(autouse=True)
    def _unset_all_psiphon_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Override the module-level autouse fixture that sets fake-but-real-shape
        env values — we want NO env vars set so the `_PUBLIC_*` defaults are
        actually exercised (the module-level autouse would mask them)."""
        for var in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            monkeypatch.delenv(var, raising=False)

    def test_public_bootstrap_constants_match_apk_dump(self):
        """The 7 `_PUBLIC_*` constants must EXACTLY match the values extracted
        from the public Psiphon-3 Android APK dump. If the panel is rebuilt
        against a future Psiphon-3 client release these lock-in tests will
        catch drift."""
        from panel.psiphon import (  # noqa: PLC0415
            _PUBLIC_EXCHANGE_OBFUSCATION_KEY,
            _PUBLIC_OBFUSCATED_SERVER_LIST_ROOT_URLS,
            _PUBLIC_PROPAGATION_CHANNEL_ID,
            _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
            _PUBLIC_REMOTE_SERVER_LIST_URLS,
            _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY,
            _PUBLIC_SPONSOR_ID,
        )

        assert _PUBLIC_PROPAGATION_CHANNEL_ID == "92AACC5BABE0944C"
        assert _PUBLIC_SPONSOR_ID == "92AACC5BABE0944C"

        # 4 mirror URLs for the plain server list (compressed).
        assert _PUBLIC_REMOTE_SERVER_LIST_URLS == (
            "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed",
            "https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/server_list_compressed",
            "https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/server_list_compressed",
            "https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/server_list_compressed",
        )
        # 4 mirror URLs for the obfuscated server-list root (same 4 hosts, /osl path).
        assert _PUBLIC_OBFUSCATED_SERVER_LIST_ROOT_URLS == (
            "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/osl",
            "https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/osl",
            "https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/osl",
            "https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/osl",
        )

        # RemoteServerListSignaturePublicKey is RSA-2048 SPKI base64 (~716 chars),
        # NOT Ed25519 (the old Hotfix-#14 comment was wrong). It ends in
        # "rsCAQM=" after the +agEAQi60pXn7+rsCAQM= suffix — match last 20 chars
        # to avoid bloating the test file with the full string, while still
        # catching a real drift.
        assert _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY.startswith("MIICIDAN")
        assert _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY.endswith("rsCAQM=")
        assert len(_PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY) > 700

        # ServerEntrySignaturePublicKey IS Ed25519 (~44 chars base64).
        assert (
            _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY
            == "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA="
        )
        # ExchangeObfuscationKey is the ~44-char handshake obfuscation seed.
        assert (
            _PUBLIC_EXCHANGE_OBFUSCATION_KEY
            == "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU="
        )

    def test_render_config_no_env_uses_public_bootstrap_defaults(self):
        """With every PSIPHON_* env var UNSET, render_config() must produce a
        config carrying the baked-in `_PUBLIC_*` constants (NOT a
        PsiphonCredentialError). This is the post-Phase-24 happy path —
        the realistic installer-no-credentials-prompt case."""
        cfg = render_config("US", 1080)
        from panel.psiphon import (  # noqa: PLC0415
            _PUBLIC_EXCHANGE_OBFUSCATION_KEY,
            _PUBLIC_PROPAGATION_CHANNEL_ID,
            _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY,
            _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY,
            _PUBLIC_SPONSOR_ID,
        )

        assert cfg["PropagationChannelId"] == _PUBLIC_PROPAGATION_CHANNEL_ID
        assert cfg["SponsorId"] == _PUBLIC_SPONSOR_ID
        assert (
            cfg["RemoteServerListSignaturePublicKey"]
            == _PUBLIC_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
        )
        assert cfg["ServerEntrySignaturePublicKey"] == _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY
        assert cfg["ExchangeObfuscationKey"] == _PUBLIC_EXCHANGE_OBFUSCATION_KEY

    def test_render_config_no_env_emits_4_mirror_remote_server_list_urls(self):
        """With no PSIPHON_REMOTE_SERVER_LIST_URL env override, render_config()
        must emit the baked-in 4-mirror `RemoteServerListURLs` TransferURL
        array (NOT a 1-element array). Each entry carries the raw URL +
        OnlyAfterAttempts=0 + SkipVerify=False."""
        cfg = render_config("US", 1080)
        urls = cfg["RemoteServerListURLs"]
        assert isinstance(urls, list)
        assert len(urls) == 4
        from panel.psiphon import _PUBLIC_REMOTE_SERVER_LIST_URLS  # noqa: PLC0415
        for entry, raw_url in zip(urls, _PUBLIC_REMOTE_SERVER_LIST_URLS, strict=True):
            assert isinstance(entry, dict)
            assert entry["URL"] == raw_url
            assert entry["OnlyAfterAttempts"] == 0
            assert entry["SkipVerify"] is False

    def test_non_overridable_fields_ignore_env_var(self, monkeypatch):
        """ServerEntrySignaturePublicKey, ExchangeObfuscationKey, and
        ObfuscatedServerListRootURLs are NOT env-overridable — the panel
        always ships the baked-in public-bootstrap values. Setting env
        vars `PSIPHON_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY` /
        `PSIPHON_EXCHANGE_OBFUSCATION_KEY` / etc. MUST be IGNORED by
        _resolve_upstream_credentials."""
        # Even if the operator sets these env vars, they have NO effect —
        # the panel doesn't read them.
        monkeypatch.setenv("PSIPHON_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY", "FAKE-fake-fake-fake=")
        monkeypatch.setenv("PSIPHON_EXCHANGE_OBFUSCATION_KEY", "FAKE-fake-fake-fake=")
        monkeypatch.setenv("PSIPHON_OBFUSCATED_SERVER_LIST_ROOT_URL", "https://example.invalid")
        cfg = render_config("US", 1080)
        from panel.psiphon import (  # noqa: PLC0415
            _PUBLIC_EXCHANGE_OBFUSCATION_KEY,
            _PUBLIC_OBFUSCATED_SERVER_LIST_ROOT_URLS,
            _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY,
        )
        assert cfg["ServerEntrySignaturePublicKey"] == _PUBLIC_SERVER_ENTRY_SIGNATURE_PUBLIC_KEY
        assert cfg["ExchangeObfuscationKey"] == _PUBLIC_EXCHANGE_OBFUSCATION_KEY
        # The obfuscated-roots array round-trips as TransferURL dicts wrapped over
        # the baked-in 4-mirror tuple.
        roots = cfg["ObfuscatedServerListRootURLs"]
        assert isinstance(roots, list)
        assert len(roots) == 4
        for entry, raw_url in zip(roots, _PUBLIC_OBFUSCATED_SERVER_LIST_ROOT_URLS, strict=True):
            assert entry["URL"] == raw_url
            assert entry["OnlyAfterAttempts"] == 0
            assert entry["SkipVerify"] is False


# ---------------------------------------------------------------------------
# write_config
# ---------------------------------------------------------------------------
class TestWriteConfig:
    def test_writes_parsable_json(self, tmp_path):
        path = write_config("US", 11080, config_dir=tmp_path)
        assert path == tmp_path / "US.json"
        assert path.is_file()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["EgressRegion"] == "US"
        assert data["LocalSocksProxyPort"] == 11080

    def test_country_code_uppercased_in_filename(self, tmp_path):
        path = write_config("de", 11081, config_dir=tmp_path)
        assert path.name == "DE.json"

    def test_creates_config_dir_if_missing(self, tmp_path):
        nested = tmp_path / "deeper" / "and_deeper"
        path = write_config("JP", 11082, config_dir=nested)
        assert path.is_file()
        assert path == nested / "JP.json"

    def test_overwrites_existing_file(self, tmp_path):
        write_config("US", 11083, config_dir=tmp_path)
        # Second write with a different port must replace the file's content.
        path = write_config("US", 11084, config_dir=tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["LocalSocksProxyPort"] == 11084


# ---------------------------------------------------------------------------
# _unit_name
# ---------------------------------------------------------------------------
def test_unit_name_format():
    assert _unit_name("US") == "psiphon-tunnel@US.service"
    assert _unit_name(" de ") == "psiphon-tunnel@DE.service"


def test_unit_name_rejects_invalid_codes():
    for bad in ("", "U", "USA", "1A"):
        with pytest.raises(ValueError):
            _unit_name(bad)


# ---------------------------------------------------------------------------
# systemctl wrappers — drive `subprocess.run` via monkeypatch.
# ---------------------------------------------------------------------------
class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_systemctl(
    monkeypatch, *, returncode: int = 0, stdout: str = "", stderr: str = ""
) -> list[list[str]]:
    """Patch ``subprocess.run`` to capture the argv and return a fake proc.

    Returns the list of argv lists captured so tests can assert the exact
    systemctl invocation.
    """
    calls: list[list[str]] = []

    def _fake_run(argv, **kwargs):  # noqa: ANN001  test-only stub
        calls.append(list(argv))
        return _FakeProc(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(subprocess, "run", _fake_run)
    return calls


class TestStartStopRestart:
    def test_start_invokes_systemctl_start_with_unit_name(self, monkeypatch):
        calls = _patch_systemctl(monkeypatch, returncode=0)
        start_unit("US")
        assert calls == [["systemctl", "start", "psiphon-tunnel@US.service"]]

    def test_stop_invokes_systemctl_stop(self, monkeypatch):
        calls = _patch_systemctl(monkeypatch, returncode=0)
        stop_unit("DE")
        assert calls == [["systemctl", "stop", "psiphon-tunnel@DE.service"]]

    def test_restart_invokes_systemctl_restart(self, monkeypatch):
        calls = _patch_systemctl(monkeypatch, returncode=0)
        restart_unit("JP")
        assert calls == [["systemctl", "restart", "psiphon-tunnel@JP.service"]]

    def test_nonzero_exit_raises_psiphon_unit_error(self, monkeypatch):
        _patch_systemctl(monkeypatch, returncode=1, stderr="unit not loaded")
        with pytest.raises(PsiphonUnitError, match="exit 1"):
            start_unit("US")

    def test_systemctl_missing_returns_psiphon_unit_error(self, monkeypatch):
        def _raise_filenotfound(*a, **kw):  # noqa: ANN001  test stub
            raise FileNotFoundError("systemctl")

        monkeypatch.setattr(subprocess, "run", _raise_filenotfound)
        with pytest.raises(PsiphonUnitError, match="systemctl not found"):
            start_unit("US")

    def test_timeout_raises_psiphon_unit_error(self, monkeypatch):
        def _raise_timeout(*a, **kw):  # noqa: ANN001  test stub
            raise subprocess.TimeoutExpired(cmd="systemctl", timeout=15)

        monkeypatch.setattr(subprocess, "run", _raise_timeout)
        with pytest.raises(PsiphonUnitError, match="timed out"):
            stop_unit("DE")


class TestIsActive:
    def test_active_unit_returns_true(self, monkeypatch):
        _patch_systemctl(monkeypatch, returncode=0, stdout="active\n")
        assert is_unit_active("US") is True

    def test_inactive_returns_false_without_raising(self, monkeypatch):
        # `systemctl is-active` returns 3 when the unit is inactive — our
        # is_unit_active must swallow that and return False.
        _patch_systemctl(monkeypatch, returncode=3, stdout="inactive\n")
        assert is_unit_active("DE") is False

    def test_failed_unit_returns_false(self, monkeypatch):
        _patch_systemctl(monkeypatch, returncode=3, stdout="failed\n")
        assert is_unit_active("JP") is False


# ---------------------------------------------------------------------------
# health_probe — inject a fake socket via `_sock_factory`.
# ---------------------------------------------------------------------------
class _FakeSocket:
    """Minimal `socket.socket()`-shaped stub for SOCKS5 health-probe tests."""

    def __init__(
        self,
        *,
        recv_payload: bytes = b"\x05\x00",
        connect_raises: type[Exception] | None = None,
        sendall_raises: type[Exception] | None = None,
        recv_raises: type[Exception] | None = None,
    ) -> None:
        self._recv_payload = recv_payload
        self._connect_raises = connect_raises
        self._sendall_raises = sendall_raises
        self._recv_raises = recv_raises
        self.closed = False
        self.connect_calls: list[tuple[str, int]] = []
        self.sendall_calls: list[bytes] = []
        self.timeout: float | None = None

    def settimeout(self, t: float) -> None:
        self.timeout = t

    def connect(self, addr: tuple[str, int]) -> None:
        if self._connect_raises is not None:
            raise self._connect_raises(f"connect refused: {addr}")
        self.connect_calls.append(addr)

    def sendall(self, data: bytes) -> None:
        if self._sendall_raises is not None:
            raise self._sendall_raises("sendall failed")
        self.sendall_calls.append(data)

    def recv(self, n: int) -> bytes:
        if self._recv_raises is not None:
            raise self._recv_raises("recv failed")
        return self._recv_payload[:n]

    def close(self) -> None:
        self.closed = True


class TestHealthProbe:
    def test_healthy_describes_selected_method(self):
        sock = _FakeSocket(recv_payload=b"\x05\x00")
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result is not None
        assert result.healthy is True
        assert "method 0x0" in result.detail.lower()

    def test_sends_socks5_greeting(self):
        sock = _FakeSocket(recv_payload=b"\x05\x00")
        health_probe(11080, _sock_factory=lambda: sock)
        assert sock.sendall_calls == [bytes([0x05, 0x01, 0x00])]
        assert sock.connect_calls == [("127.0.0.1", 11080)]

    def test_connect_refused_is_unhealthy(self):
        sock = _FakeSocket(connect_raises=ConnectionRefusedError)
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "connect" in result.detail.lower()
        assert sock.closed is True

    def test_sendall_failure_is_unhealthy(self):
        sock = _FakeSocket(sendall_raises=OSError)
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "send" in result.detail.lower()

    def test_recv_failure_is_unhealthy(self):
        sock = _FakeSocket(recv_raises=OSError)
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "recv" in result.detail.lower()

    def test_short_greeting_is_unhealthy(self):
        sock = _FakeSocket(recv_payload=b"\x05")  # only 1 byte back
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "short" in result.detail.lower()

    def test_wrong_socks_version_unhealthy(self):
        # VER byte != 0x05 → not SOCKS5.
        sock = _FakeSocket(recv_payload=b"\x04\x00")
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "version" in result.detail.lower()

    def test_no_acceptable_methods_unhealthy(self):
        # selected method == 0xFF → listener rejected everything we offered.
        sock = _FakeSocket(recv_payload=b"\x05\xff")
        result = health_probe(11080, _sock_factory=lambda: sock)
        assert result.healthy is False
        assert "refused" in result.detail.lower()

    def test_invalid_port_returns_unhealthy_without_opening_socket(self):
        # Port outside [1024, 65535] short-circuits before opening a socket.
        opened = {"yes": False}

        def _factory():  # noqa: ANN202
            opened["yes"] = True
            return _FakeSocket()

        result = health_probe(80, _sock_factory=_factory)  # 80 < 1024
        assert result.healthy is False
        assert "out of range" in result.detail.lower()
        assert opened["yes"] is False, "factory must not be called for invalid ports"

    def test_socket_closed_even_on_failure(self):
        # The finally-branch's contextlib.suppress must close the socket.
        sock = _FakeSocket(connect_raises=ConnectionRefusedError)
        health_probe(11080, _sock_factory=lambda: sock)
        assert sock.closed is True


# ---------------------------------------------------------------------------
# Extra coverage: HealthProbeResult dataclass shape (frozen + default detail).
# ---------------------------------------------------------------------------
def test_health_probe_result_is_frozen():
    r = HealthProbeResult(healthy=True, detail="ok")
    assert r.healthy is True
    assert r.detail == "ok"
    with pytest.raises(FrozenInstanceError):
        r.healthy = False  # type: ignore[misc]


def test_health_probe_result_default_detail_empty():
    r = HealthProbeResult(healthy=False)
    assert r.detail == ""
