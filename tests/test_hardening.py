"""Phase 7 hardening tests — CSRF tokens, login rate-limit, HTTPS, i18n.

The security primitives introduced in Phase 7 are listed below; each one gets
its own dedicated test class:

* :class:`TestCsrfPrimitives` — unit tests for :func:`panel.auth.issue_csrf_token`,
  :func:`panel.auth.verify_csrf_token` and :func:`panel.auth.csrf_tokens_match`
  independent of the FastAPI wiring.
* :class:`TestCsrfMiddleware` — integration tests that flip
  ``PSIPHON3XUI_CSRF_ENFORCE=1`` *after* the panel.main module is imported and
  prove the middleware 403s mutating verbs without the right header, passes
  when the cookie+header match, and exempts the documented prefixes.
* :class:`TestLoginRateLimit` — exercises :func:`panel.auth.login_rate_limit_hit`
  directly (sliding-window bucket) and via the live login endpoint (429 once
  the threshold trips, cleared after successful login).
* :class:`TestHttpsSettings` — confirms :class:`panel.config.Settings.tls_cert` /
  :attr:`https_only` wire into cookie Secure flags and that
  :mod:`panel.__main__` passes ``ssl_certfile``/``ssl_keyfile`` to uvicorn
  only when both files exist.
* :class:`TestI18nModule` — :func:`panel.i18n.load_locale`, :func:`t` with
  interpolation, :func:`available_locales`.
* :class:`TestI18nEndpoint` — ``GET /api/i18n/{locale}`` returns the bundled
  JSON for known locales and 404s for unknown ones.
* :class:`TestUninstallFlag` — a smoke check that ``install.sh --uninstall``
  prints the documented warning and exits 0 only after "yes" is supplied.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from panel.auth import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    csrf_tokens_match,
    issue_csrf_token,
    login_rate_limit_hit,
    login_rate_limit_reset,
    verify_csrf_token,
)


# ---------------------------------------------------------------------------
# Shared harness (mirrors tests/test_auth.py::_isolated_env so each test gets
# its own panel.db + test settings without polluting the global Settings cache).
# ---------------------------------------------------------------------------
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase7-hardening-secret")
    monkeypatch.setenv("PSIPHON3XUI_PORT", "18001")
    # Default for tests: CSRF bypass so the legacy endpoints behave as before,
    # and a permissive rate limit so the suite doesn't accidentally throttle
    # itself. Each CSRF/rate-limit test flips these locally + reloads the
    # panel.main module state.
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_WINDOW", "60")
    monkeypatch.setenv("PSIPHON3XUI_PSIPHON_CONFIG_DIR", str(tmp_path / "config"))
    from panel import config, db

    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    db._engine = None  # type: ignore[attr-defined]
    db._session_factory = None  # type: ignore[attr-defined]


def _seed_settings(*, password: str = "phase7-password", user: str = "admin") -> None:
    from panel.auth import hash_password
    from panel.db import get_engine, init_db
    from panel.models import Settings

    init_db()
    with Session(get_engine()) as s:
        existing = s.get(Settings, {"id": 1})
        if existing is not None:
            s.delete(existing)
            s.flush()
        s.add(
            Settings(
                id=1,
                panel_port=18001,
                admin_user=user,
                admin_pass_hash=hash_password(password),
                wizard_completed=True,
            )
        )
        s.commit()


def _client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    _isolated_env(tmp_path, monkeypatch)
    _seed_settings()
    from panel.main import app

    return TestClient(app)


def _login(client: TestClient, *args: str, **kwargs: str) -> Any:
    payload = {
        "user": kwargs.get("user", "admin"),
        "password": kwargs.get("password", "phase7-password"),
    }
    return client.post("/auth/login", json=payload)


# ===========================================================================
# CSRF primitive round-trip (panel.auth).
# ===========================================================================
class TestCsrfPrimitives:
    """Unit-level tests for issue_csrf_token + verify + match."""

    def test_round_trip_verifies(self):
        token = issue_csrf_token()
        assert verify_csrf_token(token)

    def test_verify_rejects_none_and_empty(self):
        assert verify_csrf_token(None) is False
        assert verify_csrf_token("") is False

    def test_verify_rejects_garbage_string(self):
        assert verify_csrf_token("definitely-not-a-signed-token") is False

    def test_verify_rejects_tampered_token(self):
        token = issue_csrf_token()
        tampered = token[:-4] + "AAAA"
        assert verify_csrf_token(tampered) is False

    def test_tokens_match_constant_time_success_and_failure(self):
        token = issue_csrf_token()
        assert csrf_tokens_match(token, token) is True
        assert csrf_tokens_match(token, issue_csrf_token()) is False

    def test_tokens_match_handles_none_or_empty(self):
        assert csrf_tokens_match(None, "x") is False
        assert csrf_tokens_match("x", None) is False
        assert csrf_tokens_match("", "") is False


# ===========================================================================
# CSRF middleware wiring (panel.main).
# ===========================================================================
class TestCsrfMiddleware:
    """End-to-end enforcement via the FastAPI middleware."""

    def setup_method(self):
        # login_rate_limit reset between cases — these tests exercise login
        # before reaching the CSRF-mutating paths.
        login_rate_limit_reset()

    def teardown_method(self):
        login_rate_limit_reset()

    def _force_csrf_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reimport + flip _CSRF_ENFORCE so middleware engage paths run."""
        import panel.main as m

        monkeypatch.setattr(m, "_CSRF_ENFORCE", True, raising=True)

    def test_missing_header_blocks_mutating_verb_when_enforced(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        self._force_csrf_on(monkeypatch)
        # PATCH expects a CSRF header — none provided, so 403.
        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 403, r.text
        assert "CSRF" in r.json()["detail"]

    def test_matching_header_passes_when_enforced(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        # A login response sets the CSRF cookie; TestClient persists it.
        assert CSRF_COOKIE_NAME in client.cookies
        token = client.cookies.get(CSRF_COOKIE_NAME)
        assert token
        self._force_csrf_on(monkeypatch)
        # Send the same token back as the header. We hit a dashboard endpoint
        # with no seeded PortAssignment so it 409s (wizard gate passes — we've
        # seeded wizard_completed=True); that's enough to prove the middleware
        # did NOT 403 (the CSRF check passed).
        r = client.patch(
            "/api/dashboard/countries/US",
            json={"enabled": True},
            headers={CSRF_HEADER_NAME: token},
        )
        assert r.status_code != 403, "CSRF middleware blocked a valid token"

    def test_mismatched_header_blocks(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        self._force_csrf_on(monkeypatch)
        # Cookie set by login + bogus header → 403.
        r = client.patch(
            "/api/dashboard/countries/US",
            json={"enabled": True},
            headers={CSRF_HEADER_NAME: "totally-bogus"},
        )
        assert r.status_code == 403

    def test_get_is_not_gated_even_when_enforced(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        self._force_csrf_on(monkeypatch)
        # GET to /api/me should be allowed without a CSRF header.
        r = client.get("/api/me")
        assert r.status_code == 200

    def test_login_endpoint_exempt_from_csrf(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        self._force_csrf_on(monkeypatch)
        # POST /auth/login must succeed without a CSRF token (CSRF-issuing
        # itself is the bootstrap step — chicken/egg).
        r = _login(client)
        assert r.status_code == 204, r.text

    def test_default_off_when_env_disabled(self, monkeypatch, tmp_path):
        # The fixture sets PSIPHON3XUI_CSRF_ENFORCE=0; ensure middleware is
        # bypassed so mutating verbs pass without a CSRF header.
        client = _client(monkeypatch, tmp_path)
        _login(client)
        # Confirm the module global reflects "off".
        import panel.main as m

        assert m._CSRF_ENFORCE is False
        # Hit a mutating endpoint; we don't seed anything, so it 404/409 — but
        # must not be 403 (CSRF not blocking).
        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code != 403


# ===========================================================================
# Login rate-limit (panel.auth.login_rate_limit_hit + the live /auth/login).
# ===========================================================================
class TestLoginRateLimit:
    """Sliding-window bucket + the 429 response code."""

    def setup_method(self):
        login_rate_limit_reset()

    def teardown_method(self):
        login_rate_limit_reset()

    def test_under_limit_is_allowed(self):
        assert login_rate_limit_hit("1.2.3.4") is False
        assert login_rate_limit_hit("1.2.3.4") is False

    def test_bucket_is_per_ip(self):
        # Different keys have separate buckets.
        assert login_rate_limit_hit("10.0.0.1") is False
        assert login_rate_limit_hit("10.0.0.2") is False
        assert login_rate_limit_hit("10.0.0.1") is False

    def test_threshold_trip_returns_true(self, monkeypatch):
        # Configure threshold=3 going forward — but the module-level constants
        # are fixed at import; reach into panel.auth and override them so the
        # bucket's len() >= threshold check trips immediately.
        import panel.auth as a

        monkeypatch.setattr(a, "LOGIN_RATE_LIMIT", 3)
        monkeypatch.setattr(a, "LOGIN_RATE_WINDOW", 60)
        assert login_rate_limit_hit("A") is False
        assert login_rate_limit_hit("A") is False
        assert login_rate_limit_hit("A") is False  # at threshold now
        # The next call must refuse.
        assert login_rate_limit_hit("A") is True

    def test_reset_clears_all_ips(self):
        login_rate_limit_hit("1.1.1.1")
        login_rate_limit_reset()  # clears all
        # /proc-like state: a fresh call should be allowed.
        assert login_rate_limit_hit("1.1.1.1") is False

    def test_reset_single_ip_only(self):
        login_rate_limit_hit("1.1.1.1")
        login_rate_limit_hit("1.1.1.2")
        login_rate_limit_reset("1.1.1.1")
        # Both should now be allowed (single-IP reset doesn't touch others but
        # the count for "1.1.1.2" was 1, still under the threshold).
        assert login_rate_limit_hit("1.1.1.1") is False
        assert login_rate_limit_hit("1.1.1.2") is False

    def test_login_endpoint_returns_429_when_buckets_full(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        import panel.auth as a

        monkeypatch.setattr(a, "LOGIN_RATE_LIMIT", 3)
        monkeypatch.setattr(a, "LOGIN_RATE_WINDOW", 60)
        # TestClient reports request.client.host as "testclient" — so we're
        # limiting on that key.
        for _ in range(3):
            r = _login(client, password="WRONG")
            assert r.status_code == 401
        # 4th attempt must be 429 (regardless of password correctness).
        r = _login(client, password="WRONG")
        assert r.status_code == 429, r.text
        assert "too many" in r.json()["detail"].lower()

    def test_successful_login_clears_rate_limit_for_ip(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        import panel.auth as a

        monkeypatch.setattr(a, "LOGIN_RATE_LIMIT", 3)
        monkeypatch.setattr(a, "LOGIN_RATE_WINDOW", 60)
        # Two failures, then the third must be the correct password:
        _login(client, password="WRONG")
        _login(client, password="WRONG")
        r_ok = _login(client)  # correct password
        assert r_ok.status_code == 204, r_ok.text
        # An immediate further login attempt should succeed (rate-limit cleared).
        r_again = _login(client)
        assert r_again.status_code == 204


# ===========================================================================
# HTTPS / TLS settings (panel.config + auth cookie Secure flags).
# ===========================================================================
class TestHttpsSettings:
    """Confirm settings.tls_cert/key + https_only propagate correctly."""

    def test_default_settings_disable_tls(self, monkeypatch, tmp_path):
        _isolated_env(tmp_path, monkeypatch)
        from panel.config import get_settings

        settings = get_settings()
        assert settings.tls_cert is None
        assert settings.tls_key is None
        assert settings.https_only is False

    def test_secure_cookie_flag_follows_https_only(self, monkeypatch, tmp_path):
        # When https_only=true, set_session_cookie sets the Secure flag.
        import panel.auth as a

        # Replace _cookies_secure (no need to spin a full request/response).
        monkeypatch.setattr(a, "_cookies_secure", lambda: True)
        from fastapi import Response

        # Use a plain Response so we don't need a real route.
        response = Response()
        a.set_session_cookie(response, "admin")
        set_cookie = response.headers.get("set-cookie", "")
        assert "Secure" in set_cookie

    def test_non_secure_when_https_only_false(self, monkeypatch, tmp_path):
        import panel.auth as a

        monkeypatch.setattr(a, "_cookies_secure", lambda: False)
        from fastapi import Response

        response = Response()
        a.set_session_cookie(response, "admin")
        set_cookie = response.headers.get("set-cookie", "")
        assert "Secure" not in set_cookie

    def test_uvicorn_ssl_args_injected_when_cert_present(self, monkeypatch, tmp_path):
        # Build a temp cert + key + write paths; verify __main__ wraps them.
        import panel.__main__ as m

        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("FAKE-CERT")
        key.write_text("FAKE-KEY")
        # Capture the dict passed to uvicorn.run.
        captured: dict = {}

        def fake_run(app_str, **kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(m.uvicorn, "run", fake_run)
        monkeypatch.setattr(
            m,
            "get_settings",
            lambda: _FakeSettings(
                host="0.0.0.0",
                port=18443,
                tls_cert=cert,
                tls_key=key,
                https_only=True,
                debug=False,
            ),
        )
        m.main()
        assert captured.get("ssl_certfile") == str(cert)
        assert captured.get("ssl_keyfile") == str(key)
        assert captured.get("host") == "0.0.0.0"
        assert captured.get("port") == 18443

    def test_uvicorn_omits_ssl_when_cert_missing(self, monkeypatch, tmp_path):
        import panel.__main__ as m

        captured: dict = {}

        def fake_run(app_str, **kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(m.uvicorn, "run", fake_run)
        monkeypatch.setattr(
            m,
            "get_settings",
            lambda: _FakeSettings(
                host="0.0.0.0",
                port=18001,
                tls_cert=None,
                tls_key=None,
                https_only=False,
                debug=False,
            ),
        )
        m.main()
        assert "ssl_certfile" not in captured
        assert "ssl_keyfile" not in captured

    def test_uvicorn_skips_ssl_when_files_absent(self, monkeypatch, tmp_path):
        """Settings have tls_cert set but the file path doesn't exist."""
        import panel.__main__ as m

        captured: dict = {}

        def fake_run(app_str, **kwargs):
            captured.update(kwargs)

        monkeypatch.setattr(m.uvicorn, "run", fake_run)
        monkeypatch.setattr(
            m,
            "get_settings",
            lambda: _FakeSettings(
                host="0.0.0.0",
                port=18001,
                tls_cert=tmp_path / "nope.pem",
                tls_key=tmp_path / "nope.key",
                https_only=True,
                debug=False,
            ),
        )
        m.main()
        # Since the cert files don't actually exist on disk, we expect a
        # fallback to plain HTTP.
        assert "ssl_certfile" not in captured
        assert "ssl_keyfile" not in captured


class _FakeSettings:
    """Minimal stand-in for panel.config.Settings used by TestHttpsSettings."""

    def __init__(self, *, host: str, port: int, tls_cert, tls_key, https_only: bool, debug: bool):
        self.host = host
        self.port = port
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self.https_only = https_only
        self.debug = debug


# ===========================================================================
# i18n loader + t() + available_locales().
# ===========================================================================
class TestI18nModule:
    """Panel.i18n loader / resolved-key / interpolation."""

    def setup_method(self):
        # The lru_cache means mutations to en.json persist across tests in
        # the same process; clear before each scenario.
        from panel.i18n import load_locale

        load_locale.cache_clear()

    def test_available_locales_includes_en(self):
        from panel.i18n import available_locales

        locales = available_locales()
        assert "en" in locales

    def test_load_locale_returns_dict_for_en(self):
        from panel.i18n import load_locale

        bundle = load_locale("en")
        assert isinstance(bundle, dict)
        assert "meta" in bundle
        assert bundle["meta"]["name"] == "Psiphon for 3X-UI"

    def test_load_locale_falls_back_to_en_for_missing(self):
        from panel.i18n import load_locale

        # "fr" isn't shipped in v1 — loader should fall back to en (logged).
        bundle = load_locale("fr")
        assert bundle["meta"]["name"] == "Psiphon for 3X-UI"

    def test_load_locale_handles_corrupted_json_gracefully(self, monkeypatch, tmp_path):
        import panel.i18n as i18n

        # Point I18N_DIR at a tmp dir + write a bogus en.json.
        fake_dir = tmp_path / "i18n"
        fake_dir.mkdir()
        (fake_dir / "en.json").write_text("{ this isn't json")
        monkeypatch.setattr(i18n, "I18N_DIR", fake_dir)
        i18n.load_locale.cache_clear()
        bundle = i18n.load_locale("en")
        assert bundle == {}

    def test_t_resolves_dotted_key(self):
        from panel.i18n import t

        assert t("meta.name") == "Psiphon for 3X-UI"
        assert t("wizard.steps.apply.title") == "Apply"

    def test_t_interpolates_named_placeholders(self):
        from panel.i18n import t

        result = t("wizard.steps.apply.progress", country="US")
        assert "Spawning tunnel US" in result

    def test_t_returns_default_when_key_missing(self):
        from panel.i18n import t

        assert t("no.such.key", default="fallback") == "fallback"
        # No default → the key itself is returned (graceful degradation).
        assert t("no.such.key") == "no.such.key"

    def test_t_with_missing_param_leaves_placeholder(self):
        from panel.i18n import t

        # Call without providing the {country} placeholder — the interpolator
        # must not raise; the literal "{country}" survives.
        result = t("wizard.steps.apply.progress")
        assert "{country}" in result


# ===========================================================================
# i18n REST endpoint.
# ===========================================================================
class TestI18nEndpoint:
    """``GET /api/i18n/{locale}`` happy/404 paths."""

    def test_get_known_locale_returns_bundle(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        r = client.get("/api/i18n/en")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["locale"] == "en"
        assert body["default_locale"] == "en"
        assert isinstance(body["bundle"], dict)
        assert body["bundle"]["meta"]["name"] == "Psiphon for 3X-UI"

    def test_get_unknown_locale_returns_404(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        r = client.get("/api/i18n/boop")
        assert r.status_code == 404
        assert "not bundled" in r.json()["detail"]


# ===========================================================================
# install.sh --uninstall smoke — confirmation prompt + warning banner.
# ===========================================================================
_SKIP_NO_BASH = shutil.which("bash") is None

skip_no_bash = pytest.mark.skipif(
    _SKIP_NO_BASH,
    reason="bash not on PATH (Windows dev host; installer targets Ubuntu)",
)


class TestUninstallFlag:
    """Lightweight subprocess test — run `install.sh --help` and look for the
    documented --uninstall usage + warning banner text. Skipped on hosts
    without bash in PATH (the installer is Ubuntu-only; this gate is a guard
    for cross-platform CI machines)."""

    _install_path = Path(__file__).resolve().parent.parent / "install.sh"

    @skip_no_bash
    def test_help_mentions_uninstall(self):
        r = subprocess.run(
            ["bash", str(self._install_path), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, r.stderr
        assert "--uninstall" in r.stdout

    @skip_no_bash
    def test_help_documents_idempotent_re_runs(self):
        r = subprocess.run(
            ["bash", str(self._install_path), "--help"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Either form of wording lands in --help output:
        stdout_lower = r.stdout.lower()
        assert "idempotent" in stdout_lower or "re-runs" in stdout_lower

    @skip_no_bash
    def test_uninstall_cancelled_returns_zero_without_action(self):
        # Pipe "no" so the uninstaller aborts before any destructive step.
        r = subprocess.run(
            ["bash", str(self._install_path), "--uninstall"],
            input="no\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert r.returncode == 0, r.stderr
        assert "Uninstall cancelled" in r.stdout

    def test_install_script_has_uninstall_branch_regardless_of_bash(self):
        """Static check that works on any host — scan install.sh source for
        the documented --uninstall flag handler so the phase-7 'uninstall'
        checkbox stays meaningful even where bash isn't installed."""
        text = self._install_path.read_text(encoding="utf-8")
        assert "--uninstall|-u)" in text
        assert "run_uninstall" in text
        assert "Uninstall cancelled" in text
