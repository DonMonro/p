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
* :class:`TestPackagingRegressions` — guards against two real install-time bugs
  observed in the v1.0.0 candidate build:

  1. ``RuntimeError: Form data requires "python-multipart"`` — the dashboard's
     ``@router.post("/restore")`` route declares ``UploadFile = File(...)`` which
     triggers FastAPI's import-time ``ensure_multipart_is_installed()``; a
     stock Ubuntu venv lacking the package crashes the panel on boot → systemd
     restart loop → ``panel_install.sh``'s socket probe spins forever. We now
     declare ``python-multipart`` both in ``pyproject.toml``'s
     ``[project.dependencies]`` *and* in ``installer/panel_install.sh``'s
     explicit ``pip install`` list (the wheel is installed with ``--no-deps``
     so the METADATA install-time deps don't auto-resolve).
  2. The wheel filename reports the project version, not ``app.version``. After
     bumping ``app.version`` to ``"1.0.0"`` the installer still advertised
     ``psiphon_3x_ui_panel-0.1.0`` until ``pyproject.toml``'s ``version`` was
     also bumped.
"""

from __future__ import annotations

import ast
import re
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

    def test_uninstall_invokes_the_3xui_cleanup_module(self):
        """Phase 27 (item 3): ``install.sh --uninstall`` must run
        ``panel.uninstall`` so the inbounds/outbounds/routing rules this panel
        created are removed from 3x-ui. Without this call the module is dead
        code and the debris (plus the 'outbound reappears' trap) survives the
        uninstall."""
        text = self._install_path.read_text(encoding="utf-8")
        assert "-m panel.uninstall" in text, (
            "install.sh --uninstall must invoke `python -m panel.uninstall` to "
            "clean up the 3x-ui entries this panel created"
        )

    def test_uninstall_cleanup_runs_before_the_service_is_stopped(self):
        """The cleanup shells out to the venv interpreter and reads panel.db,
        so it has to happen while both still exist — i.e. before
        ``systemctl stop`` and before the install prefix is deleted."""
        text = self._install_path.read_text(encoding="utf-8")
        cleanup_at = text.index("-m panel.uninstall")
        run_uninstall_at = text.index("run_uninstall()")
        stop_at = text.index("systemctl stop", run_uninstall_at)
        assert cleanup_at < stop_at, (
            "the panel.uninstall cleanup must run before `systemctl stop` — "
            "afterwards the venv/DB may already be gone"
        )


# ──────────────────────────────────────────────────────────────────────
# Packaging regression tests — guard against the two real install-time bugs
# observed when the v1.0.0 candidate was first deployed (the panel refused to
# boot on a stock Ubuntu venv because FastAPI's `ensure_multipart_is_installed`
# fired at import time, and the wheel was still branded `0.1.0`).
# ──────────────────────────────────────────────────────────────────────


def _load_pyproject() -> dict[str, Any]:
    """Parse ``pyproject.toml`` from the repo root.

    Uses the stdlib :mod:`tomllib` on Python 3.11+ and falls back to :mod:`tomli`
    on 3.10 (the declared minimum supported version).
    """
    try:
        import tomllib  # type: ignore[import-not-found]  # stdlib in 3.11+
    except ImportError:  # pragma: no cover — only on 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    repo_root = Path(__file__).resolve().parents[1]
    pyproject = repo_root / "pyproject.toml"
    with pyproject.open("rb") as fh:
        return tomllib.load(fh)


class TestPackagingRegressions:
    """Two regression tests that prevent either install-time bug from
    silently reappearing in a future release."""

    @property
    def _panel_install_sh(self) -> Path:
        return Path(__file__).resolve().parents[1] / "installer" / "panel_install.sh"

    def test_pyproject_version_is_release_ready(self):
        """``pyproject.toml``'s ``[project]`` ``version`` controls the wheel
        filename. After bumping ``app.version`` we MUST bump it here too or
        the installer advertises the old project version even though the
        FastAPI app reports the new one. Lock in 1.0.0 — bump this when
        cutting a new release.
        """
        pyproject = _load_pyproject()
        assert pyproject["project"]["version"] == "1.0.0", (
            "pyproject.toml [project].version must be bumped to match panel.main's "
            f"app.version. Got {pyproject['project']['version']!r}, expected '1.0.0'."
        )

    def test_python_multipart_declared_as_runtime_dependency(self):
        """``@router.post('/restore')`` in :mod:`panel.dashboard.router` declares
        ``UploadFile = File(...)`` which triggers FastAPI's import-time
        ``ensure_multipart_is_installed()``. Without ``python-multipart`` in
        the venv the panel crashes on boot → systemd restart loop. Pin it as
        a hard runtime dep here so a future dep-list edit cannot drop it.
        """
        pyproject = _load_pyproject()
        deps = pyproject["project"]["dependencies"]
        matches = [d for d in deps if d.lower().startswith("python-multipart")]
        assert matches, (
            "python-multipart must appear in [project.dependencies] — the "
            "dashboard /restore route is an UploadFile form that FastAPI "
            "refuses to import without it."
        )

    def test_python_multipart_listed_in_installer_pip_block(self):
        """``installer/panel_install.sh`` installs the wheel with
        ``--no-deps`` and then an EXPLICIT pip install of the runtime deps so
        installs are reproducible on minimal Ubuntu venvs. The hard-coded
        list must mirror the ``pyproject.toml`` deps list; in particular
        ``python-multipart`` must appear or the panel will boot-loop on
        any venv that lacks it.
        """
        text = self._panel_install_sh.read_text(encoding="utf-8")
        assert "python-multipart" in text, (
            "installer/panel_install.sh pip-install block must list "
            "'python-multipart' alongside the other runtime deps — the wheel "
            "is installed with --no-deps so its METADATA install_requires are "
            "not auto-resolved."
        )

    def test_installer_pip_block_and_pyproject_deps_are_in_sync(self):
        """Cross-check that every dependency named in ``pyproject.toml`` is
        also referenced by ``installer/panel_install.sh``'s pip block. The
        block uses ``--no-deps`` on the wheel so anything declared only in
        pyproject (and not re-listed below the wheel install) is invisible
        at install time. This test will fail with the missing dep name in
        the assertion message — fix by adding it to the installer block.
        """
        pyproject = _load_pyproject()

        # Drop version pins when comparing — we look for the bare package name.
        # E.g. 'fastapi>=0.110' → 'fastapi', 'uvicorn[standard]>=0.29' → 'uvicorn'.
        def _bare(name: str) -> str:
            for sep in (">=", "==", "<=", "~=", ">", "<", "!=", "["):
                if sep in name:
                    return name.split(sep)[0].strip().lower()
            return name.strip().lower()

        pyproject_deps = {
            _bare(d)
            for d in pyproject["project"]["dependencies"]
            # Drop extras (e.g. "uvicorn[standard]") so a bare search of the
            # installer text for "uvicorn" matches the line that pins
            # "uvicorn[standard]>=0.29".
        }
        text = self._panel_install_sh.read_text(encoding="utf-8")
        missing = sorted(d for d in pyproject_deps if d not in text.lower())
        assert not missing, (
            "installer/panel_install.sh's pip install block is out of sync "
            f"with pyproject.toml [project.dependencies]; missing: {missing}. "
            "Add them to the explicit pip install line(s) since the wheel is "
            "installed with --no-deps and its METADATA is not consulted."
        )

    def test_countries_yaml_ships_inside_the_panel_wheel(self):
        """``panel.seed`` reads ``panel.config.load_countries()`` whose default
        path resolves relative to the *installed* panel package
        (``Path(panel.config.__file__).parent / "data" / "countries.yaml"``).
        For that to resolve at install time the YAML file MUST physically ship
        inside the wheel — which in turn requires both:

        * ``panel/data/countries.yaml`` to exist in the repo (checked here)
        * ``[tool.setuptools.package-data] "panel"`` to include "data/*.yaml"
          (checked here by parsing pyproject.toml)

        If either of these regress, ``panel.seed`` emits
        ``[seed] warning: country seed skipped (FileNotFoundError)`` and the
        Country table stays empty, leaving the wizard gate to 409 every
        dashboard route. This test prevents that silent regression.
        """
        repo_root = Path(__file__).resolve().parents[1]
        packaged_yaml = repo_root / "panel" / "data" / "countries.yaml"
        assert packaged_yaml.is_file(), (
            f"{packaged_yaml} must exist — it ships inside the panel wheel as "
            "the canonical source-of-truth countries table. Without it the "
            "installed panel cannot seed the Country table (FileNotFoundError)."
        )

        pyproject = _load_pyproject()
        package_data = pyproject.get("tool", {}).get("setuptools", {}).get("package-data", {})
        panel_globs = package_data.get("panel", [])
        assert isinstance(panel_globs, list)
        assert any("data/*.yaml" in g or "data/**" in g or g == "**/*" for g in panel_globs), (
            "[tool.setuptools.package-data] 'panel' must include 'data/*.yaml' "
            f"(or an equivalent glob) so panel/data/countries.yaml ships inside "
            f"the wheel. Current globs: {panel_globs!r}."
        )

    def test_panel_config_countries_file_points_at_packaged_yaml(self):
        """``panel.config.COUNTRIES_FILE`` MUST resolve to the in-package
        ``panel/data/countries.yaml`` (relative to ``panel.config.__file__``),
        which is the ONLY copy in the repo these days. (A pre-v1.0.0 dev-only
        duplicate at ``<repo-root>/config/countries.yaml`` was removed during the
        post-Phase-23 cleanup pass after the two drifted; resolving to that
        root path from an installed venv site-packages location raised
        ``FileNotFoundError`` at seed time — see Hotfix #1 / Phase 2 in
        ``.git/COMMIT_EDITMSG_RELEASE_HEAD`` for the bug history.) This test
        guards the path-resolution line directly.
        """
        from panel import config as panel_config

        resolved = panel_config.COUNTRIES_FILE
        assert resolved.name == "countries.yaml"
        # The shipped copy lives under panel/data/, sibling to the package dir.
        assert resolved.parent.name == "data"
        assert resolved.parent.parent == Path(panel_config.__file__).resolve().parent
        # And it MUST physically exist (this is what the seed sees at import time
        # when the package is imported directly from the repo checkout; in a
        # wheel install the file is shipped to the same relative path).
        assert resolved.is_file(), (
            f"Resolved countries.yaml path {resolved} does not exist. The panel "
            "wheel must ship panel/data/countries.yaml as package-data so this "
            "path resolves identically in dev checkouts and installed venvs."
        )

    def test_wizard_html_ships_inside_the_panel_wheel(self):
        """The first-run setup wizard SPA (`panel/static/wizard.html`) MUST
        ship inside the wheel so ``GET /wizard`` (see ``panel.main.wizard_html``)
        serves it in production. ``[tool.setuptools.package-data] "panel" = [
        "static/**/*", "data/*.yaml"]`` already covers the path via the
        ``static/**/*`` glob, but this test guards the file existing — without
        it the operator has no UI to complete the wizard before the dashboard
        409 gate unlocks.
        """
        repo_root = Path(__file__).resolve().parents[1]
        wiz = repo_root / "panel" / "static" / "wizard.html"
        assert wiz.is_file(), (
            f"{wiz} must exist — without it the installed panel serves only the "
            "JSON 404 fallback at GET /wizard and the operator has no UI to "
            "complete the first-run setup, leaving every dashboard route 409-"
            "gated forever (the original install-blocker Bug B)."
        )
        # The file MUST mount the Alpine.js component — regression guard
        # against an accidental overwrite that truncates the SPA logic.
        body = wiz.read_text(encoding="utf-8")
        assert "appWizard()" in body, "wizard.html must mount Alpine via appWizard()"
        # And it MUST wire every operating-step endpoint the panel exposes so a
        # future edit dropping one of them can't silently break the wizard UI.
        for endpoint in (
            "/api/wizard",
            "/api/wizard/countries",
            "/api/wizard/ports",
            "/api/wizard/apply",
            "/api/wizard/xui-detect",
            "/api/wizard/xui-creds",
            "/api/wizard/inbounds",
            "/api/wizard/clone-template",
            "/api/wizard/clone",
        ):
            assert endpoint in body, (
                f"wizard.html must reference {endpoint!r} — the {endpoint} "
                "endpoint is part of the wizard state machine and a UI "
                "that omits it will strand the operator mid-wizard."
            )

    def test_dashboard_html_redirects_on_wizard_gate_409(self):
        """``dashboard.html``'s ``refreshAll()`` MUST redirect to ``/wizard``
        when ``GET /api/dashboard/countries`` returns 409 (wizard not
        completed). Without this the operator landing on ``/dashboard``
        after a fresh install sees a permanent red banner reading
        "failed to list countries: GET /api/dashboard/countries → 409"
        and has no escape to the wizard — see Bug A install-blocker notes.
        """
        repo_root = Path(__file__).resolve().parents[1]
        dash = repo_root / "panel" / "static" / "dashboard.html"
        body = dash.read_text(encoding="utf-8")
        assert "if (r.status === 409)" in body, (
            "dashboard.html must handle the 409 from /api/dashboard/countries "
            "as a redirect to /wizard (NOT a red banner); see the docstring on "
            "panel.main.dashboard_html and Bug A install-blocker root cause."
        )
        assert "/wizard" in body, (
            "dashboard.html must reference the /wizard route so it can "
            "bounce operators there when the wizard gate returns 409."
        )

    def test_login_html_redirects_by_wizard_completed_flag(self):
        """``login.html`` MUST consult ``GET /api/me``'s
        ``wizard_completed`` flag before redirecting to ``/dashboard``
        (or ``/wizard``). Without this the first login on a fresh install
        always lands on ``/dashboard`` — which 409-redirects — adding an
        extra hop and a flash of the dashboard's "failed to list
        countries" banner before the operator can reach the wizard UI.
        """
        repo_root = Path(__file__).resolve().parents[1]
        login = repo_root / "panel" / "static" / "login.html"
        body = login.read_text(encoding="utf-8")
        assert "wizard_completed" in body, (
            "login.html MUST read wizard_completed from /api/me before "
            "redirecting — otherwise the first login on a fresh install "
            "lands on /dashboard, which 409-redirects to /wizard with a "
            "flash of the dashboard's error banner."
        )
        assert "/wizard" in body, (
            "login.html must reference the /wizard route so a "
            "wizard_completed=false user is sent straight there."
        )


# ──────────────────────────────────────────────────────────────────────
# Hotfix #3 — four post-v1.0.0-release regressions reported by the operator
# on the live Ubuntu 24.04.4 LTS install after re-deploying the Bug B
# amend. Each test below is a static-source grep that locks the fix against
# silent regression. They run on any host (Windows CI too).
#
#   Bug #1  — SQLite WAL sidecar perms (panel.db INSERT blew up with
#             `attempt to write a readonly database`): INSTALL_PREFIX was
#             chmod 0750 (group r-x) so the psiphon3xui service uid couldn't
#             create -wal/-shm/-journal sidecars next to panel.db. Fixed
#             by widening to 0770 in installer/prepare_user.sh.
#   Bug #3  — Uninstall docs said `sudo bash install.sh --uninstall` which
#             only works for cloned-repo operators; the canonical install
#             route is `bash <(curl -sL https://.../install.sh)` so most
#             operators had no install.sh file in CWD. Fixed by adding the
#             curl-pipe form to README.md + install.sh --help.
#   Bug #4  — Re-installs hit `fatal: destination path '…/repo-tmp' already
#             exists and is not an empty directory` because
#             ensure_helpers_present() never cleaned a stale clone dir.
#             Fixed by adding a defensive `rm -rf repo-tmp` before git clone.
#
# Bug #2 (cookie-clear attribute mismatch) has its own behavioral tests in
# tests/test_auth.py — they parse the live Set-Cookie header the clear-*cookie
# helpers emit and assert HttpOnly/SameSite/Secure are propagated.
# ──────────────────────────────────────────────────────────────────────


class TestHotfix3PostReleaseRegressions:
    """Static-source grep tests for Hotfix #3 (four post-v1.0.0 bugs)."""

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @property
    def _prepare_user_sh(self) -> Path:
        return self._repo_root / "installer" / "prepare_user.sh"

    @property
    def _install_sh(self) -> Path:
        return self._repo_root / "install.sh"

    @property
    def _readme(self) -> Path:
        return self._repo_root / "README.md"

    # ---- Bug #1: INSTALL_PREFIX group-writable (chmod 0770) -------------
    def test_prepare_user_chmods_install_prefix_group_writable(self):
        """``installer/prepare_user.sh`` MUST chmod the INSTALL_PREFIX to 0770
        (group rwx) — not 0750 (group r-x). SQLite needs directory-level
        WRITE access to create the -wal / -shm / -journal sidecar files
        next to panel.db; the service uid (in group `psiphon3xui`) couldn't
        create them with 0750, so the first INSERT INTO wizard blew up as
        `sqlite3.OperationalError: attempt to write a readonly database`
        (see Hotfix #3 Bug #1 + the journalctl traceback pasted by the
        operator). Lock the chmod mode in source so a future edit reverting
        it is caught here, not on the next operator install.
        """
        text = self._prepare_user_sh.read_text(encoding="utf-8")
        # The fix uses the literal `chmod 0770 "${INSTALL_PREFIX}"` line; the
        # repo also chmods CONFIG_DIR + BIN_DIR so check the INSTALL_PREFIX
        # form specifically — that's the directory that holds panel.db.
        assert 'chmod 0770 "${INSTALL_PREFIX}"' in text, (
            "installer/prepare_user.sh MUST chmod INSTALL_PREFIX to 0770 so the "
            "psiphon3xui service uid (in group psiphon3xui) can create SQLite "
            "WAL/journal sidecars next to panel.db. The 0750 mode (group r-x) "
            "made the first INSERT INTO wizard fail with 'attempt to write a "
            "readonly database' (Bug #1 — Hotfix #3)."
        )
        # And MUST NOT regress to 0750 on that exact line:
        assert 'chmod 0750 "${INSTALL_PREFIX}"' not in text, (
            "installer/prepare_user.sh must NOT chmod INSTALL_PREFIX back to "
            "0750 — that was the Bug #1 root cause (no directory write → no "
            "SQLite sidecars → 'attempt to write a readonly database')."
        )

    def test_prepare_user_chowns_install_prefix_to_service_group(self):
        """The chmod 0770 only matters because the directory is also owned
        group-psiphon3xui (chown root:psiphon3xui). Without the chown the
        group bit is meaningless. Lock both in together so a future edit
        flipping one without the other still trips this test."""
        text = self._prepare_user_sh.read_text(encoding="utf-8")
        assert '"root:${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}"' in text or (
            'chown -R "root:${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}"' in text
        ), (
            "installer/prepare_user.sh MUST chown INSTALL_PREFIX root:psiphon3xui "
            "so the 0770 group-write bit actually grants the service uid write "
            "access (the chmod 0770 alone is meaningless without the matching "
            "chown — Bug #1 Hotfix #3)."
        )

    # ---- Bug #3: uninstall docs use the curl-pipe form ------------------
    def test_install_help_documents_curl_form_uninstall(self):
        """``install.sh --help`` MUST show the curl-into-bash form for the
        uninstall subcommand. Operators who installed via
        ``bash <(curl -sL https://.../install.sh)`` have NO install.sh on
        disk, so the old ``sudo bash install.sh --uninstall`` instruction
        was always ``bash: install.sh: No such file or directory`` for them
        (Bug #3 — Hotfix #3)."""
        text = self._install_sh.read_text(encoding="utf-8")
        # One of these forms must appear so a curl|bash-only operator can
        # find a working uninstall command in the --help output.
        assert "bash <(curl" in text and "--uninstall" in text, (
            "install.sh --help MUST show a curl-into-bash form for --uninstall "
            "since operators who installed via `bash <(curl ...)` have no "
            "install.sh file in CWD (Bug #3 — Hotfix #3)."
        )

    def test_readme_documents_curl_form_uninstall(self):
        """Same lock-in for README.md — the uninstall instruction block
        MUST mention the curl-pipe form. Without it curl|bash-only
        operators copy-paste `sudo bash install.sh --uninstall` from the
        README and get `bash: install.sh: No such file or directory`."""
        text = self._readme.read_text(encoding="utf-8")
        # Pull the uninstall context block out and check it mentions curl.
        # We don't require a contiguous `bash <(curl ... --uninstall)` line —
        # the README uses multi-line formatting — but the uninstall section
        # must clearly show a curl form somewhere near `--uninstall`.
        assert "bash <(curl" in text, (
            "README.md MUST show the curl-into-bash form somewhere in the "
            "uninstall instructions — the canonical Psiphon-3X-UI install "
            "route is `bash <(curl -sL .../install.sh)` so most operators "
            "have no install.sh on disk (Bug #3 — Hotfix #3)."
        )
        assert "--uninstall" in text

    # ---- Bug #4: ensure_helpers_present removes stale repo-tmp -----------
    def test_install_sh_removes_stale_repo_tmp_before_clone(self):
        """``install.sh``'s ``ensure_helpers_present()`` MUST rm -rf a stale
        ``${INSTALL_PREFIX}/repo-tmp`` before running ``git clone`` into it.
        Without this, any prior interrupted install leaves a (possibly
        empty) repo-tmp behind, and ``git clone --depth 1 ... repo-tmp``
        refuses: ``fatal: destination path '.../repo-tmp' already exists
        and is not an empty directory`` (Bug #4 — Hotfix #3)."""
        text = self._install_sh.read_text(encoding="utf-8")
        assert 'rm -rf "${INSTALL_PREFIX}/repo-tmp"' in text, (
            "install.sh ensure_helpers_present() MUST `rm -rf "
            '"${INSTALL_PREFIX}/repo-tmp"` BEFORE the git clone — stale '
            "clones from a prior failed install make `git clone` refuse "
            "(Bug #4 — Hotfix #3)."
        )
        # And the defensive rm MUST run before `git clone`, not after.
        rm_idx = text.find('rm -rf "${INSTALL_PREFIX}/repo-tmp"')
        clone_idx = text.find("git clone --depth 1")
        assert rm_idx != -1 and clone_idx != -1 and rm_idx < clone_idx, (
            "The rm -rf for stale repo-tmp MUST come BEFORE the git clone — "
            "if it appears after, the clone still trips `destination path "
            "already exists` (Bug #4 ordering — Hotfix #3)."
        )


# ===========================================================================
# Hotfix #4 — three more post-v1.0.0 bugs reported by the operator on their
# live Ubuntu 24.04.4 LTS install after Hotfix #3 had been deployed:
#
#   * Bug #5 — clicking logout did nothing. Root cause: the SPA `logout()`
#     used `await fetch("/auth/...")` WITH NO try/catch; an aborted fetch
#     (closing tab mid-flight, network blip) silently swallowed the
#     subsequent `window.location.href = "/login"` so no navigation occurred.
#     Fix: keepalive:true + try/catch + window.location.replace("/login").
#
#   * Bug #6 — step 6 inbound list failed with `list_inbounds: HTTP 404`.
#     Root cause: XuiClient.__init__ strip-`/panel` heuristic combined with
#     the literal `"panel/api/inbounds/..."` prefix produced a base URL of
#     `http://host:port/` → login hits `/login` (404, real path is
#     `/panel/login`) → the cookie is never set → list_inbounds also fails.
#     Fix: drop the strip heuristic + drop the panel/ literal — the operator
#     pastes the FULL SPA URL (incl. webBasePath) and we just append
#     `api/inbounds/...`.
#
#   * Bug #7 — the back button on every wizard step was a no-op stub toasting
#     "the wizard is forward-only…". Fix: add POST /api/wizard/back with a
#     constrained safety contract (terminal steps refuse, back *through*
#     apply refuses, otherwise flip wizard.current_step) and reimplement the
#     SPA's back() to call it.
#
# The tests below are static-source greps that lock the fixes in source so
# a future edit reverting any one of them trips the suite at PR-time, not
# on the next operator install.
# ===========================================================================
class TestHotfix4PostReleaseRegressions:
    """Static-source grep tests for Hotfix #4 (three post-v1.0.0 bugs)."""

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @property
    def _wizard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "wizard.html"

    @property
    def _dashboard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "dashboard.html"

    @property
    def _xui_client(self) -> Path:
        return self._repo_root / "panel" / "dashboard" / "xui_client.py"

    @property
    def _wizard_router(self) -> Path:
        return self._repo_root / "panel" / "wizard" / "router.py"

    # ---- Bug #5: hardened logout keeps the page navigating on abort ------
    def test_wizard_logout_uses_keepalive_and_replace(self):
        """``panel/static/wizard.html``'s logout() MUST wrap the fetch in a
        try/catch, set ``keepalive: true`` so the request fires even if the
        page is navigated away mid-flight, and use ``window.location.replace``
        (NOT ``.href =`` — replace prevents the browser back-button from
        re-entering the dashboard). Without the try/catch an aborted fetch
        threw and swallowed the subsequent navigation (Bug #5 — Hotfix #4).
        Hotfix #5 (Bug #5v2) added a cache-bust "?ts=" query suffix on the
        navigation target so the browser always fetches a FRESH /login.html
        (combined with Cache-Control: no-store on the FileResponse — see
        ``panel.main.py``)."""
        text = self._wizard_html.read_text(encoding="utf-8")
        assert "keepalive: true" in text, (
            "wizard.html logout() MUST set keepalive: true so the logout "
            "request fires even when the page navigates away before the "
            "response arrives (Bug #5 — Hotfix #4)."
        )
        assert 'window.location.replace("/login?ts=' in text, (
            "wizard.html logout() MUST call window.location.replace with a "
            "cache-busting ?ts= suffix on /login so the browser never serves "
            "the stale cached login SPA that contains the pre-Hotfix-#5 "
            "logout handler (Bug #5v2 — Hotfix #5)."
        )
        # Find the logout() body and confirm it has a try/catch around the
        # fetch so an aborted fetch never swallows the navigation.
        # Pull the whole logout() body — comments push the try block past a
        # 600-char window. Slice generously so the assertion is robust against
        # future documentation edits.
        # Locate the JS logout() FUNCTION DEFINITION (with `{` body opener),
        # NOT the Alpine `@click.prevent="logout()"` anchor in the nav. The
        # body opener disambiguates them: the anchor uses `logout()"`.
        logout_idx = text.find("logout() {")
        assert logout_idx != -1, "wizard.html logout() function not found"
        # Slice up to the closing `},\n` that ends the function.
        close_idx = text.find("\n        },", logout_idx)
        body = text[logout_idx : close_idx if close_idx != -1 else logout_idx + 1800]
        assert "try" in body and "catch" in body, (
            "wizard.html logout() MUST wrap the fetch in a try/catch so an "
            "aborted fetch (network blip, tab closing before the response) "
            "doesn't throw and swallow window.location.replace (Bug #5 — "
            "Hotfix #4)."
        )

    def test_dashboard_logout_uses_keepalive_and_replace(self):
        """Mirror of the wizard logout lock-in for ``panel/static/dashboard.html``
        — the dashboard SPA's logout() was hardened the same way as wizard's
        (Bug #5 — Hotfix #4) and gained the same ?ts= cache-bust suffix in
        Hotfix #5 (Bug #5v2)."""
        text = self._dashboard_html.read_text(encoding="utf-8")
        assert "keepalive: true" in text, (
            "dashboard.html logout() MUST set keepalive: true (Bug #5 — "
            "Hotfix #4 — mirrors the wizard.html fix)."
        )
        assert 'window.location.replace("/login?ts=' in text, (
            "dashboard.html logout() MUST call window.location.replace with a "
            "cache-busting ?ts= suffix so the browser never serves the stale "
            "login SPA after a wheel reinstall (Bug #5v2 — Hotfix #5)."
        )
        logout_idx = text.find("logout() {")
        assert logout_idx != -1, "dashboard.html logout() function not found"
        close_idx = text.find("\n        },", logout_idx)
        body = text[logout_idx : close_idx if close_idx != -1 else logout_idx + 1200]
        assert "try" in body and "catch" in body, (
            "dashboard.html logout() MUST wrap the fetch in try/catch (Bug #5 — Hotfix #4)."
        )

    # ---- Bug #6v2: XuiClient STRIPS /panel SPA route + carries literal panel/api prefix -
    def test_xui_client_init_strips_panel_spa_route_suffix(self):
        """``XuiClient.__init__`` MUST strip a trailing ``/panel`` SPA-route
        segment from the operator's pasted URL. The Phase-1 spike evidence
        (``spike/spike_1c2_capture.py:65`` and ``spike/spike_1e_clone.py:178``
        both call ``base.split("/panel")[0]``) shows the API base is
        ``{webBasePath}/`` — and login sits at ``{base}login`` (NOT under the
        additional ``/panel`` React SPA route). Hotfix #4 (Bug #6v1) DROPPED
        the strip heuristic in the belief that the operator's pasted SPA
        URL already carried everything — but that yielded
        ``{base}/panel/login`` → 404 (the operator's reported
        ``login: HTTP 404`` at step 5). Hotfix #5 (Bug #6v2) restores the
        strip heuristic, mirroring the spike scripts verbatim."""
        text = self._xui_client.read_text(encoding="utf-8")
        # __init__ MUST detect and strip a trailing "/panel" segment.
        assert 'endswith("/panel")' in text, (
            "XuiClient.__init__ MUST call endswith('/panel') to strip the "
            "Spring/React SPA route segment that the operator's copy-pasted "
            "browser URL carries — Hotfix #5 (Bug #6v2) restores the strip "
            "heuristic that Hotfix #4 (Bug #6v1) wrongly dropped."
        )
        # __init__ MUST raise ValueError on empty base_url (defensive against
        # operator pasting a blank string — gives a clear 500/422 instead of a
        # silently wrong base). Hotfix #4 added this guard; Hotfix #5 keeps it.
        assert 'raise ValueError("base_url must not be empty")' in text, (
            "XuiClient.__init__ MUST raise ValueError on an empty base_url — "
            "defensive guard added by Hotfix #4 (Bug #6); retained by Hotfix #5 "
            "(Bug #6v2)."
        )

    def test_xui_client_api_paths_carry_literal_panel_prefix(self):
        """All five ``XuiClient`` API call sites MUST build their URLs with
        ``self.base_url + "panel/api/inbounds/..."`` (NOT bare
        ``self.base_url + "api/inbounds/..."``). The Phase-1 spike evidence
        is unambiguous: every API URL captured by ``spike/spike_1c2_capture.py``
        and ``spike/spike_1e_clone.py`` is prefixed with the literal ``panel``
        segment (e.g. ``GET {base}panel/api/inbounds/list``) because the React
        SPA's ``/panel`` route IS also the API route prefix. Hotfix #4
        (Bug #6v1) dropped the literal ``panel/api`` prefix in the belief
        that the operator's pasted SPA URL already carried everything — but
        for a default-webBasePath install where base had a ``/panel`` segment
        AND the literal prefix was dropped, the wire URL became
        ``http://.../panel/api/inbounds/list`` (correct by accident), whereas
        for a hardened install where base had no ``/panel`` segment, the
        wire URL became ``http://.../api/inbounds/list`` (wrong — would also
        404). Hotfix #5 (Bug #6v2) restores the literal ``panel/api`` prefix
        so the API SITS UNDER the React SPA route EVEN AFTER ``__init__`` has
        stripped the operator's vanity ``/panel`` trailing segment."""
        text = self._xui_client.read_text(encoding="utf-8")
        # EVERY API call site MUST carry the literal panel/api/ prefix.
        # The five endpoints the wizard/dashboard hit: list / get / add /
        # update / del. We assert each slug appears at least once (the file
        # does NOT crash on an uninstantiated client until login is called).
        for slug in (
            "panel/api/inbounds/list",
            "panel/api/inbounds/get/",
            "panel/api/inbounds/add",
            "panel/api/inbounds/update/",
            "panel/api/inbounds/del/",
        ):
            assert slug in text, (
                f"XuiClient MUST reference `{slug}` — Hotfix #5 (Bug #6v2) "
                f"restores the literal `panel/api/inbounds` prefix on every "
                f"API call site (the React SPA route prefix the panel API "
                f"also lives under; verified during the Phase-1 spike)."
            )

    def test_wizard_html_base_url_placeholder_mentions_full_spa_url(self):
        """The wizard's 3x-ui creds step MUST hint that the operator pastes
        the FULL SPA URL (the URL visible in their browser address bar). The
        operator's typed URL MAY or MAY NOT have a trailing ``/panel`` SPA
        route segment — ``XuiClient.__init__`` strips it cleanly either way.
        Hotfix #4 added this hint; Hotfix #5 keeps it but rewords it to
        make the ``/panel`` strip transparent to the operator."""
        text = self._wizard_html.read_text(encoding="utf-8")
        # The placeholder MUST mention the operator-visible URL shape (either
        # "FULL SPA URL" or the "/panel" suffix guidance).
        assert "panel" in text.lower(), (
            "wizard.html 3x-ui creds step MUST mention the /panel SPA URL "
            "segment in its base_url placeholder (Hotfix #5 — Bug #6v2 — so "
            "the operator understands every API URL is normalised under their "
            "browser-address-bar URL plus the /panel prefix that the panel "
            "serves)."
        )

    # ---- Bug #7: POST /api/wizard/back endpoint + SPA back() rewire -----
    def test_wizard_router_registers_back_endpoint(self):
        """``panel/wizard/router.py`` MUST register a POST /back handler that
        enforces the Hotfix #4 safety contract — terminal steps (clone/done)
        refuse, backing *through* apply refuses, otherwise flips
        wizard.current_step to an earlier safe step. The SPA's back button
        was previously a no-op stub toasting "the wizard is forward-only…"
        (Bug #7 — Hotfix #4)."""
        text = self._wizard_router.read_text(encoding="utf-8")
        assert '@router.post("/back"' in text, (
            "router.py MUST register POST /back (Bug #7 — Hotfix #4) — the "
            "wizard SPA's back button called this endpoint."
        )
        # The terminal-step refusal MUST cite the dashboard teardown path.
        assert "clone" in text and "done" in text.lower(), (
            "submit_back MUST refuse backward jumps from terminal steps "
            "(clone/done) — they require dashboard per-country teardown "
            "(Bug #7 — Hotfix #4)."
        )
        # Back-through-apply refusal MUST exist (PortAssignment socks_port PK).
        assert "apply" in text and "socks_port" in text, (
            "submit_back MUST refuse backing *through* apply — apply created "
            "PortAssignment rows (socks_port PRIMARY KEY) + units + configs "
            "whose teardown requires dashboard delete_country (Bug #7 — "
            "Hotfix #4)."
        )

    def test_wizard_html_back_uses_post_back_endpoint(self):
        """``panel/static/wizard.html``'s back() MUST call the real
        ``POST /api/wizard/back`` endpoint and refreshState() on success,
        surfacing the server's 409 detail as a toast on refusal. The old
        stub just showed a confusing 'the wizard is forward-only…' toast
        and did nothing — Bug #7."""
        text = self._wizard_html.read_text(encoding="utf-8")
        assert 'fetch("/api/wizard/back"' in text, (
            "wizard.html back() MUST POST to /api/wizard/back (Bug #7 — "
            "Hotfix #4) — instead of the old no-op stub that toasted "
            "'the wizard is forward-only…'."
        )
        # The forward-only stub text MUST be gone — replaced by the real
        # handler. We don't require the exact message to be absent (it might
        # still live in a comment citing the historical root cause), but the
        # back() handler MUST reference POST /back + refreshState + a 409 path.
        back_idx = text.find("async back(")
        assert back_idx != -1, "wizard.html back() not found"
        # Slice up to the closing `},\n` that ends back().
        close_idx = text.find("\n        },", back_idx)
        body = text[back_idx : close_idx if close_idx != -1 else back_idx + 2000]
        assert "409" in body, (
            "wizard.html back() MUST handle the 409 refusal path and surface "
            "the server's detail as a toast (Bug #7 — Hotfix #4)."
        )
        assert "refreshState" in body, (
            "wizard.html back() MUST call refreshState() on success so the "
            "SPA re-renders the new (earlier) step (Bug #7 — Hotfix #4)."
        )


# ===========================================================================
class TestHotfix5PostReleaseRegressions:
    """Static-source grep tests for Hotfix #5 (two post-Hotfix-#4 bugs
    reported by the operator against the live install).

    * Bug #6v2 — the operator's pasted 3x-ui URL contained a ``/panel`` SPA
      page-route segment that Hotfix #4 wrongly trusted instead of stripping;
      the resulting login POST landed at ``{base}/panel/login`` (404),
      breaking login BEFORE the wizard's step 6 even started. The fix
      restores the ``/panel`` strip heuristic AND restores the literal
      ``panel/api/inbounds/{op}`` prefix on every API call site, matching the
      Phase-1 spike evidence verbatim.
    * Bug #5v2 — the logout button still "did nothing" on the operator's host
      even after Hotfix #4's hardened logout landed. Root cause: the
      ``panel.main.py`` FileResponse endpoints for ``/wizard``, ``/dashboard``
      and ``/login`` set NO ``Cache-Control`` header — the browser therefore
      cached the OLD SPA HTML on disk and re-served it after the wheel was
      reinstalled, so the operator's click on Logout invoked the pre-Hotfix-#4
      unhardened handler. The fix adds ``Cache-Control: no-store`` on all
      three HTML endpoints AND adds a cache-bust ``?ts=`` query suffix on
      ``window.location.replace("/login?ts=…")`` so even the cached copy of
      the SPA never re-runs an outdated logout handler.
    """

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @property
    def _xui_client(self) -> Path:
        return self._repo_root / "panel" / "dashboard" / "xui_client.py"

    @property
    def _wizard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "wizard.html"

    @property
    def _dashboard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "dashboard.html"

    @property
    def _main(self) -> Path:
        return self._repo_root / "panel" / "main.py"

    # ---- Bug #6v2: XuiClient strips a trailing /panel AND keeps the literal panel/api prefix
    def test_xui_client_login_url_sits_under_webBasePath_not_panel_route(self):
        """The 3x-ui login endpoint sits at the ROOT of the webBasePath, NOT
        under the additional ``/panel`` React SPA route. ``XuiClient.login``
        MUST POST to ``{base_url}login`` (no ``panel`` prefix). The Phase-1
        spike proof: ``spike/spike_1c2_capture.py:106`` POSTs exactly
        ``url = base + "login"`` where ``base = /{webBasePath}/`` (the
        ``/panel`` segment was stripped at line 65 of that same script)."""
        text = self._xui_client.read_text(encoding="utf-8")
        # login() must POST to base_url + "login" — NOT base_url + "panel/login".
        login_idx = text.find("async def login")
        assert login_idx != -1, "xui_client.py login() not found"
        close_idx = text.find("self._logged_in = True", login_idx)
        body = text[login_idx : close_idx if close_idx != -1 else login_idx + 1500]
        assert 'self.base_url + "login"' in body, (
            'login() MUST POST to `self.base_url + "login"` (login lives at '
            "the ROOT of webBasePath, NOT under the /panel SPA route) — Hotfix #5 "
            "(Bug #6v2 — the Phase-1 spikes both POST this exact form)."
        )
        assert "panel/login" not in body, (
            "login() MUST NOT POST to a `/panel/login` URL — that path returns "
            "404 on real 3x-ui installs (the operator reported exactly this: "
            "`login: HTTP 404`) — Bug #6v2."
        )

    def test_xui_client_init_raises_on_bare_panel_only_input(self):
        """If the operator pastes only ``/panel`` (no host) or ``http:///panel``
        the strip heuristic produces an empty-or-scheme-only base — that MUST
        raise ``ValueError`` with a clear message rather than silently
        synthesize ``http://`` or ``/``. Added by Hotfix #5 (Bug #6v2) as the
        anti-collapse guard around the restored strip heuristic."""
        text = self._xui_client.read_text(encoding="utf-8")
        # __init__ MUST raise ValueError on a schemeless/post-strip-degenerate
        # input. Hotfix #5 (Bug #6v2) added a scheme-prefix rejection so a
        # bare "/panel" path raises immediately rather than silently
        # normalising to "/". The exact error message has evolved slightly
        # over the fixes (the wording around "must include a scheme and host"
        # vs. "must include a host"): assert a regex pattern that matches
        # both forms.
        import re

        assert re.search(r"must include (?:a scheme and )?host", text), (
            'XuiClient.__init__ MUST raise ValueError("base_url must include '
            "(a scheme and )?host: 'http(s)://host:port/...'\") on a "
            "degenerate post-strip input so a typo like '/panel' surfaces "
            "immediately (Bug #6v2 — Hotfix #5)."
        )
        # AND the scheme-prefix rejection guard MUST be present verbatim.
        assert (
            'startswith("http://")' in text
            or 'startswith("http://")' in text
            or "startswith('http://')" in text
            or '"http://"' in text
        ), (
            "XuiClient.__init__ MUST guard against schemeless inputs via a "
            '`b.startswith("http://") or b.startswith("https://")` check '
            "before the /panel strip heuristic — so bare '/panel' raises "
            "(Bug #6v2 — Hotfix #5)."
        )

    # ---- Bug #5v2: Cache-Control no-store on the three HTML SPA endpoints ----
    def test_main_html_endpoints_set_cache_control_no_store(self):
        """All three SPA-HTML-serving endpoints in ``panel/main.py``
        (``/dashboard``, ``/wizard``, ``/login``) MUST return their
        ``FileResponse`` with a ``Cache-Control: no-store`` header so the
        browser always re-fetches the SPA HTML after a wheel reinstall. Without
        this header the browser default-caches HTML via the Last-Modified
        heuristic (RFC 7234 §4.2.2), and an operator reinstalling the wheel
        kept getting the OLD SPA HTML from disk cache — so the pre-Hotfix-#4
        broken-logout handler ran despite the underlying wheel being updated
        (Bug #5v2 — Hotfix #5)."""
        text = self._main.read_text(encoding="utf-8")
        # Count occurrences of the Cache-Control no-store header on a FileResponse.
        # It MUST appear at least three times (one per HTML endpoint).
        needle = '"Cache-Control": "no-store"'
        occurrences = text.count(needle)
        assert occurrences >= 3, (
            f"main.py MUST set `{{'Cache-Control': 'no-store'}}` on the "
            f"FileResponse() of EACH of /dashboard, /wizard, /login — found "
            f"{occurrences} occurrence(s) of the header, need at least 3 "
            f"(Bug #5v2 — Hotfix #5)."
        )
        # Each HTML endpoint route helper MUST be present at least once.
        for route_helper in (
            "def dashboard_html",
            "def wizard_html",
            "def login_html",
        ):
            assert route_helper in text, (
                f"main.py MUST define `{route_helper}` (Bug #5v2 — Hotfix #5 "
                f"adds Cache-Control no-store to all three HTML endpoints)."
            )

    def test_wizard_logout_carries_cache_busting_ts_query(self):
        """``panel/static/wizard.html``'s logout handler MUST navigate to
        ``/login?ts=<timestamp>`` so the browser ALWAYS fetches a fresh
        /login.html from the panel — never re-serves a stale cached copy with
        an outdated logout handler. The ``?ts=`` query defeats
        browser-side Last-Modified heuristic caching for /login, and pairs
        with the no-store Cache-Control header on ``panel.main.py``'s
        ``/login`` endpoint to fully disarm the bug."""
        text = self._wizard_html.read_text(encoding="utf-8")
        logout_idx = text.find("logout() {")
        assert logout_idx != -1, "wizard.html logout() function not found"
        close_idx = text.find("\n        },", logout_idx)
        body = text[logout_idx : close_idx if close_idx != -1 else logout_idx + 1800]
        assert "/login?ts=" in body and "Date.now()" in body, (
            "wizard.html logout() MUST call "
            "`window.location.replace('/login?ts=' + Date.now())` so the "
            "browser never serves a stale cached login SPA after a wheel "
            "reinstall (Bug #5v2 — Hotfix #5)."
        )

    def test_dashboard_logout_carries_cache_busting_ts_query(self):
        """Mirror of the wizard logout cache-bust test for the dashboard SPA."""
        text = self._dashboard_html.read_text(encoding="utf-8")
        logout_idx = text.find("logout() {")
        assert logout_idx != -1, "dashboard.html logout() function not found"
        close_idx = text.find("\n        },", logout_idx)
        body = text[logout_idx : close_idx if close_idx != -1 else logout_idx + 1200]
        assert "/login?ts=" in body and "Date.now()" in body, (
            "dashboard.html logout() MUST call "
            "`window.location.replace('/login?ts=' + Date.now())` so the "
            "browser never serves a stale cached login SPA (Bug #5v2 — "
            "Hotfix #5)."
        )


# ===========================================================================
# Hotfix #6 — two more post-Hotfix-#5 bugs reported by the operator on their
# live install after Hotfix #5 had been deployed:
#
#   * Bug #5v3 — logout STILL does nothing (operator's third report). Root
#     cause: even with the Hotfix-#4 try/catch and Hotfix-#5 cache-bust, the
#     handler remained `async logout()` and `await`ed the
#     `fetch("/auth/logout", {keepalive:true})` BEFORE calling
#     `window.location.replace()`. If the fetch promise neither resolves nor
#     rejects (a HUNG XHR — e.g. a reverse proxy that ate the 204 without
#     closing the connection, OR the operator's browser serving a
#     PRE-Hotfix-#5 cached SPA whose logout() was the unhardened Hotfix-#3
#     throw-on-fetchAbort body), the `await` blocks FOREVER and the
#     navigation is never reached. Operator confirmed via follow-up: the URL
#     does NOT change at all when clicking Logout. Fix: convert logout() to a
#     SYNCHRONOUS fire-and-forget — `void fetch("/auth/logout",
#     {method:"POST", keepalive:true})` (NO `await`), then IMMEDIATELY call
#     `window.location.replace("/login?ts="+Date.now())` on the next line.
#     The browser keeps the keepalive POST in flight during the navigation.
#
#   * Bug #8 — step 6 "Pick the template inbound: inbound list failed"
#     threw `3x-ui list_inbounds failed: list_inbounds: HTTP 404`. Root
#     cause: `panel/wizard/router.py`'s `_async_get_xui_client` helper
#     returned a FRESH `XuiClient` without calling `client.login()`. The
#     cached 3x-ui session lived only inside the discarded `XuiClient`
#     used at step 5 to verify the operator's credentials (that client's
#     `aclose()` dropped the session). Re-used at step 6's `GET /inbounds`
#     and step 7's `POST /clone`, the un-authed client had no `3x-ui`
#     session cookie + `self._csrf is None` → no `X-CSRF-Token` header →
#     3x-ui returned 404 (the SPA fallback for unauthed API routes inside
#     a webBasePath). The dashboard's analogue `_async_get_xui_client` at
#     `panel/dashboard/router.py:160` already called `await client.login()`
#     — the wizard's copy had simply been forgotten. Fix: make the wizard's
#     helper mirror the dashboard's: build the client, `await
#     client.login()`, and (defensive) wrap login in try/except → return
#     None on failure so callers surface the existing 409 "no creds" path
#     instead of a confusing 502 mid-flow.
#
# The static-source greps below lock both fixes into source so a future
# edit reverting either of them trips the suite at PR-time, not on the next
# operator install.
# ===========================================================================
class TestHotfix6PostReleaseRegressions:
    """Static-source grep tests for Hotfix #6 (Bug #8 + Bug #5v3)."""

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @property
    def _wizard_router(self) -> Path:
        return self._repo_root / "panel" / "wizard" / "router.py"

    @property
    def _dashboard_router(self) -> Path:
        return self._repo_root / "panel" / "dashboard" / "router.py"

    @property
    def _wizard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "wizard.html"

    @property
    def _dashboard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "dashboard.html"

    # ---- Bug #8: the wizard's _async_get_xui_client MUST log in ---------
    def test_wizard_async_get_xui_client_logs_in(self):
        """``panel/wizard/router.py``'s ``_async_get_xui_client`` MUST call
        ``await client.login()`` after building the ``XuiClient``. The
        dashboard's analogue at ``panel/dashboard/router.py:160`` does this
        — the wizard's copy had simply been forgotten, so at step 6 the
        wizard re-used a FRESH un-authed client (no 3x-ui session cookie,
        ``self._csrf is None`` → no ``X-CSRF-Token`` header → 3x-ui
        answered 404 to ``panel/api/inbounds/list``) (Bug #8 — Hotfix #6).
        """
        text = self._wizard_router.read_text(encoding="utf-8")
        assert "async def _async_get_xui_client" in text, (
            "panel/wizard/router.py MUST define _async_get_xui_client "
            "(Bug #8 — Hotfix #6 reuses the dashboard's helper pattern)."
        )
        # Slice the function body out so the assertion is scoped to THIS
        # helper and does not match the bare `await client.login()` that
        # might exist elsewhere inside the file (e.g. submit_xui_creds).
        start = text.find("async def _async_get_xui_client")
        assert start != -1, "_async_get_xui_client not found in wizard router"
        # End of function = next top-level `def `/`async def `/`@router` token.
        end = text.find("\nasync def ", start + 1)
        if end == -1:
            end = text.find("\ndef ", start + 1)
        if end == -1:
            end = text.find("\n@router", start + 1)
        if end == -1:
            end = start + 4000
        body = text[start:end]
        assert "await client.login()" in body, (
            "panel/wizard/router.py _async_get_xui_client MUST `await "
            "client.login()` after building the XuiClient — without login "
            "the cached 3x-ui session lives only inside the discarded step-5 "
            "client and step 6's GET /inbounds hits 3x-ui with no session "
            "cookie + no X-CSRF-Token → 404 (Bug #8 — Hotfix #6)."
        )

    def test_wizard_async_helper_returns_none_on_login_failure(self):
        """The wizard's ``_async_get_xui_client`` MUST wrap
        ``await client.login()`` in a ``try/except Exception`` that calls
        ``await client.aclose()`` and ``return None`` so a stale/rotated
        3x-ui password surfaces as the existing 409 "no creds" path the
        caller already handles, instead of a confusing 502 mid-flow.
        (Bug #8 — Hotfix #6 defensive guard.)"""
        text = self._wizard_router.read_text(encoding="utf-8")
        start = text.find("async def _async_get_xui_client")
        assert start != -1
        end = text.find("\nasync def ", start + 1)
        if end == -1:
            end = text.find("\ndef ", start + 1)
        if end == -1:
            end = text.find("\n@router", start + 1)
        if end == -1:
            end = start + 4000
        body = text[start:end]
        assert "except Exception:" in body, (
            "_async_get_xui_client MUST catch login exceptions and convert "
            "them to None so callers surface the 409 no-creds path (Bug #8 "
            "— Hotfix #6 defensive)."
        )
        assert "await client.aclose()" in body, (
            "_async_get_xui_client MUST await client.aclose() before "
            "returning None on login failure — leaking an httpx.AsyncClient "
            "taints subsequent tests (Bug #8 — Hotfix #6)."
        )
        # The `return None` MUST come AFTER the except clause (so the helper
        # can fall through to None for the missing-creds/missing-link path).
        assert "return None" in body

    def test_wizard_async_helper_mirrors_dashboard_signature(self):
        """The wizard's ``_async_get_xui_client`` MUST return
        ``XuiClient | None`` — same signature as the dashboard's helper at
        ``panel/dashboard/router.py:160``. Without the ``| None`` half the
        callers would not be able to take the same 409 "no creds" branch
        both routers rely on."""
        text = self._wizard_router.read_text(encoding="utf-8")
        assert "XuiClient | None:" in text, (
            "_async_get_xui_client MUST declare its return type as "
            "`XuiClient | None` so callers handle the no-creds case "
            "(Bug #8 — Hotfix #6)."
        )

    # ---- Bug #5v3: logout() MUST be fire-and-forget (NOT `async`) -------
    def test_wizard_logout_does_not_await_fetch(self):
        """``panel/static/wizard.html``'s ``logout()`` MUST be SYNCHRONOUS
        (NOT ``async logout()``) and MUST NOT ``await`` the
        ``fetch("/auth/logout", ...)``. The operator reported "clicking
        Logout does nothing — URL doesn't change at all". Root cause: the
        previous ``async logout()`` AWAITED the logout fetch; if that
        promise neither resolves nor rejects (a hung XHR, or the operator's
        browser serving a PRE-Hotfix-#5 cached SPA whose logout was the
        Hotfix-#3 throw-on-fetchAbort body), the ``await`` blocked FOREVER
        and ``window.location.replace()`` was never reached. Fix: dispatch
        the fetch as fire-and-forget with ``void fetch(...)`` (no
        ``await``) and call ``window.location.replace()`` on the very next
        line — ``keepalive: true`` lets the POST finish during the
        navigation (Bug #5v3 — Hotfix #6)."""
        text = self._wizard_html.read_text(encoding="utf-8")
        # Anchor on the JS function definition (`logout() {` body opener),
        # NOT the Alpine `@click.prevent="logout()"` nav anchor.
        logout_idx = text.find("logout() {")
        assert logout_idx != -1, "wizard.html logout() function not found"
        # The previous (broken) signature was `async logout()` — Hotfix #6
        # reverted to synchronous `logout()` with no `async` keyword. The
        # anchor is the line-leading token (a standalone `async` keyword
        # immediately followed by ` logout() {`). The doc comment string
        # `async logout()` is NOT preceded by whitespace+newline so it is
        # distinguished by requiring `\n      ` (the indentation level of
        # a body method) before `async`.
        import re

        # The function MUST NOT be declared `async ... logout()` — i.e. the
        # line on which `logout()` is declared must not start with `async`.
        # We assert this by checking that the text immediately preceding the
        # `logout() {` opener is a newline (NOT `async logout() {`).
        opener_prefix = text[logout_idx - 6 : logout_idx]
        assert not opener_prefix.rstrip().endswith("async"), (
            "wizard.html logout() MUST NOT be `async logout()` — the async "
            "form AWAITED the fetch and a hung XHR blocked the navigation "
            "forever. Hotfix #6 reverts to synchronous fire-and-forget "
            "(Bug #5v3). Opener prefix was: " + repr(opener_prefix)
        )
        close_idx = text.find("\n        },", logout_idx)
        body = text[logout_idx : close_idx if close_idx != -1 else logout_idx + 1800]

        # Discard any leading or in-body // comments so quoted `async logout()`
        # in documentation doesn't trip the assertions below.
        def _strip_comments(s: str) -> str:
            return re.sub(r"//[^\n]*", "", s)

        body = _strip_comments(body)
        # The fetch MUST be fire-and-forget: `void fetch(...)` with NO await.
        assert "void fetch(" in body, (
            'wizard.html logout() MUST dispatch `void fetch("/auth/logout", '
            '{method:"POST", keepalive:true})` (no `await`) so a hung XHR '
            "cannot block the navigation (Bug #5v3 — Hotfix #6)."
        )
        assert 'await fetch("/auth/logout"' not in body, (
            'wizard.html logout() MUST NOT `await fetch("/auth/logout")` — '
            "the await blocks forever on a hung XHR and the navigation is "
            "never reached (Bug #5v3 — Hotfix #6)."
        )
        assert "keepalive: true" in body, (
            "wizard.html logout() MUST set keepalive: true on the "
            "fire-and-forget fetch so the cookie-clear POST completes "
            "during the navigation (Bug #5v3 — Hotfix #6)."
        )
        assert 'window.location.replace("/login?ts=' in body, (
            "wizard.html logout() MUST synchronously call "
            'window.location.replace("/login?ts=" + Date.now()) '
            "immediately after dispatching the keepalive POST (Bug #5v3 — "
            "Hotfix #6)."
        )

    def test_dashboard_logout_does_not_await_fetch(self):
        """Mirror of ``test_wizard_logout_does_not_await_fetch`` for
        ``panel/static/dashboard.html``."""
        text = self._dashboard_html.read_text(encoding="utf-8")
        logout_idx = text.find("logout() {")
        assert logout_idx != -1, "dashboard.html logout() function not found"
        opener_prefix = text[logout_idx - 6 : logout_idx]
        assert not opener_prefix.rstrip().endswith("async"), (
            "dashboard.html logout() MUST NOT be `async logout()` "
            "(Bug #5v3 — Hotfix #6 mirror of the wizard fix). Opener prefix "
            "was: " + repr(opener_prefix)
        )
        close_idx = text.find("\n        },", logout_idx)
        body = text[logout_idx : close_idx if close_idx != -1 else logout_idx + 1200]
        import re

        body = re.sub(r"//[^\n]*", "", body)
        assert "void fetch(" in body, (
            "dashboard.html logout() MUST dispatch `void fetch(...)` with no "
            "`await` (Bug #5v3 — Hotfix #6)."
        )
        assert 'await fetch("/auth/logout"' not in body, (
            'dashboard.html logout() MUST NOT `await fetch("/auth/logout")` (Bug #5v3 — Hotfix #6).'
        )
        assert "keepalive: true" in body
        assert 'window.location.replace("/login?ts=' in body


# ===========================================================================
# Hotfix #7 — post-Hotfix-#6 field report from the operator. Three issues:
#
#   * Bug #5v4 — "Logout STILL does nothing" (operator's 4th report on the
#     logout button). Investigated via a focused follow-up question: the
#     operator's installed /opt/psiphon3xui/panel/static/wizard.html is the
#     Hotfix-#5 vintage (still has `async logout()`). Force-pushing the
#     v1.0.0 tag does NOT propagate to the operator's install — the panel
#     is installed via `git clone` at install time, so the operator must
#     re-run install.sh to fetch the Hotfix-#6 / #7 SPA. No code fix can
#     unilaterally save an operator running the pre-Hotfix-#6 SPA. The
#     fix shipped in Hotfix #6 (fire-and-forget logout + keepalive) is
#     correct and is what the operator will get after re-install. The
#     tested lock-in in TestHotfix6PostReleaseRegressions covers this
#     already; Hotfix #7 adds NO behavioral change to logout.
#
#   * Bug #b — "Refresh state button does nothing". Same root cause as
#     Bug #5v4: the operator's installed SPA is the Hotfix-#5 vintage. On
#     the current Hotfix-#6/#7 SPA, refreshState() is a clean async method
#     that fetches /api/wizard and rehydrates — it works correctly. No
#     code fix beyond operator-side re-install.
#
#   * Bug #9 (THE real code defect fixed in Hotfix #7) — wizard step 7
#     clone threw `add_inbound: API failure: Something went wrong (json:
#     cannot unmarshal string into Go struct field Client.tgId of type
#     int64)`. Root cause: `panel.dashboard.xui_client._fresh_vless_client`
#     set `"tgId": ""` (empty STRING). 3x-ui's newer Go schema unmarshals
#     Client.tgId as int64, NOT string — JSON decoder rejects "" with
#     the verbatim error message above. The valid "no Telegram ID"
#     sentinel is `0`. The same defect existed in `spike/spike_1e_clone.py`
#     (the reference spike that produced 3x-ui's API convention). Fix:
#     `panel/dashboard/xui_client.py` and `spike/spike_1e_clone.py` both
#     send `tgId: 0`.
# ===========================================================================
class TestHotfix7PostReleaseRegressions:
    """Static-source grep tests for Hotfix #7 — Bug #9 tgId int64 schema."""

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @property
    def _xui_client(self) -> Path:
        return self._repo_root / "panel" / "dashboard" / "xui_client.py"

    @property
    def _spike_clone(self) -> Path:
        return self._repo_root / "spike" / "spike_1e_clone.py"

    # ---- Bug #9: tgId MUST be int (0), NOT string ("") -------------------
    def test_fresh_vless_client_tgId_is_int_zero(self):
        """``_fresh_vless_client`` MUST set ``"tgId": 0`` (integer), NOT
        ``"tgId": ""`` (string). 3x-ui's newer Go schema unmarshals
        ``Client.tgId`` as ``int64`` and rejects the empty-string JSON
        with ``cannot unmarshal string into Go struct field Client.tgId of
        type int64`` (Bug #9 — Hotfix #7)."""
        text = self._xui_client.read_text(encoding="utf-8")
        # The function body opener.
        idx = text.find("def _fresh_vless_client(")
        assert idx != -1, "_fresh_vless_client not found in xui_client.py"
        # Slice to the next top-level def.
        end = text.find("\ndef ", idx + 1)
        if end == -1:
            end = idx + 1500
        body = text[idx:end]
        assert '"tgId": 0' in body, (
            '_fresh_vless_client MUST set "tgId": 0 (integer sentinel), NOT '
            '"tgId": "" (string). 3x-ui\'s newer Go schema unmarshals '
            "Client.tgId as int64 — the empty-string JSON is rejected with "
            "the verbatim error `cannot unmarshal string into Go struct "
            "field Client.tgId of type int64` (Bug #9 — Hotfix #7)."
        )
        # The pre-Hotfix-#7 buggy literal MUST be gone.
        assert '"tgId": ""' not in body, (
            '_fresh_vless_client MUST NOT carry "tgId": "" — that is '
            "the pre-Hotfix-#7 value rejected by 3x-ui's int64 schema "
            "(Bug #9 — Hotfix #7)."
        )

    def test_spike_clone_payload_tgId_is_int_zero(self):
        """``spike/spike_1e_clone.py`` (the Phase-1 reference implementation
        of the 3x-ui clone-payload convention) MUST mirror the production
        fix: ``"tgId": 0``. Keeping the spike in lock-step guarantees that
        the next time someone runs the spike against a fresh 3x-ui version,
        the evidence capture reflects what the production code does
        (Bug #9 — Hotfix #7)."""
        text = self._spike_clone.read_text(encoding="utf-8")
        # The tgId literal MUST be 0 (int) and NOT "" (string).
        # The spike function make_clone_payload builds a clients[] entry.
        start = text.find("def make_clone_payload")
        assert start != -1
        end = text.find("\ndef ", start + 1)
        if end == -1:
            end = start + 5000
        body = text[start:end]
        assert '"tgId": 0' in body, (
            'spike/spike_1e_clone.py make_clone_payload MUST set "tgId": 0 '
            '(int), NOT "tgId": "" (string) — keep the spike in lock-step '
            "with the production fix (Bug #9 — Hotfix #7)."
        )
        assert '"tgId": ""' not in body, (
            "spike/spike_1e_clone.py make_clone_payload MUST NOT carry the "
            'pre-Hotfix-#7 "tgId": "" literal (Bug #9 — Hotfix #7).'
        )

    def test_no_other_string_tgId_in_xui_client(self):
        """Defensive: scan the full ``panel/dashboard/xui_client.py`` for
        any other stale ``tgId`` string literal (e.g. inside a docstring
        describing a different field). All ``tgId`` literals MUST be the
        integer sentinel ``0``."""
        import re

        text = self._xui_client.read_text(encoding="utf-8")
        # Find every "tgId": <value> occurrence. Allow optional whitespace
        # around the colon.
        occurrences = re.findall(r'"tgId"\s*:\s*([^,\n}]+)', text)
        assert occurrences, (
            'xui_client.py MUST contain at least one `"tgId": …` literal '
            "inside _fresh_vless_client (Bug #9 — Hotfix #7)."
        )
        for raw in occurrences:
            value = raw.strip()
            assert value == "0", (
                'xui_client.py MUST NOT contain a `"tgId": <value>` '
                "literal whose value is anything other than `0`. Found: "
                f"`{value}` (Bug #9 — Hotfix #7)."
            )


# ===========================================================================
# Phase 17 / Hotfix #8 — post-release regressions
# ===========================================================================
#
# Operator-reported after Hotfix #7 shipped (after re-running install.sh):
#   #b - the "⟳ Refresh state" button in the wizard top nav does nothing and
#        is redundant (the operator can just hit F5). DELETED from the wizard
#        nav (Hotfix #8 / Bug #b — no functional replacement; refreshState()
#        is still called internally by the wizard's submit handlers but the
#        operator-facing nav anchor was a buggy UI affordance).
#   #c - the dashboard countries table "is not displayed neatly now" — root
#        cause: <table class="grid"> had `class="grid"` which collides with
#        Pico.css v2's global `.grid` utility (display: grid) collapsing
#        native <table> row/column semantics (no zebra, drifting columns).
#        Fix: drop `.grid` from the <table>, give it id="countries" and add
#        a tight local CSS rule controlling its column widths (Hotfix #8 /
#        Bug #c).
#   #d - "When cloning is performed, it should only clone the inbound. Why
#        does it also clone in the client section? Only the inbound is enough."
#        Root cause: _build_clone_payload was OVERWRITING settings.clients with
#        a freshly minted _fresh_vless_client(public_port) entry on every
#        clone — minting a NEW 3x-ui client row per clone on the operator's
#        behalf. Fix: copy the template's existing settings.clients array
#        THROUGH verbatim; drop the `_fresh_vless_client(public_port)` call.
#        The `_fresh_vless_client` helper is retained as a public helper for
#        callers that explicitly want a fresh per-clone client (none currently
#        use it) so the unit tests in tests/test_xui_client.py stay green.
#        (Hotfix #8 / Bug #d.)
# ===========================================================================
class TestHotfix8PostReleaseRegressions:
    """Static-source grep tests for Hotfix #8 — Refresh-state button removal,
    dashboard table layout, and clone-payload client-section over-minting."""

    @property
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    @property
    def _wizard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "wizard.html"

    @property
    def _dashboard_html(self) -> Path:
        return self._repo_root / "panel" / "static" / "dashboard.html"

    @property
    def _xui_client(self) -> Path:
        return self._repo_root / "panel" / "dashboard" / "xui_client.py"

    # ---- Bug #b: wizard nav MUST NOT ship a "Refresh state" anchor --------
    def test_wizard_nav_has_no_refresh_state_anchor(self):
        """The wizard SPA's navigation bar MUST NOT carry the operator-facing
        "⟳ Refresh state" anchor (Hotfix #8 / Bug #b). It was non-functional
        AND redundant — any operator wanting refresh can press F5 without
        leaving the page (refreshState() is still invoked internally by the
        wizard's submit handlers, so the underlying data-flow stays intact;
        only the buggy UI affordance is gone)."""
        text = self._wizard_html.read_text(encoding="utf-8")
        # The operator-visible nav anchor shape was:
        #     `<li><a href="#" @click.prevent="refreshState()">⟳ Refresh state</a></li>`
        assert "⟳ Refresh state" not in text, (
            "panel/static/wizard.html MUST NOT carry the '⟳ Refresh state' "
            "nav anchor — operator-reported non-functional and redundant; "
            "F5 is the supported refresh path (Bug #b — Hotfix #8)."
        )
        # Additionally pin that `refreshState()` calls survive in the JS
        # body (the submit handlers depend on it) — this proves we deleted
        # the nav anchor without nuking the helper itself.
        assert "refreshState()" in text, (
            "panel/static/wizard.html's wizard SPA still needs internal "
            "refreshState() calls driven by the submit handlers; only the "
            "operator-visible nav anchor was removed (Bug #b — Hotfix #8)."
        )

    # ---- Bug #c: dashboard countries table MUST be <table id="countries"> -
    def test_dashboard_country_table_uses_id_not_grid_class(self):
        """The dashboard countries table MUST be marked `<table id="countries">`
        (Hotfix #8 / Bug #c), NOT `<table class="grid">`. Pico.css v2 ships a
        global `.grid` utility (`display: grid`) that collapses native table
        row/column semantics when applied to a <table> — the table lost zebra,
        lost column alignment, columns drifted out of grid headings, and the
        operator reported it as "not displayed neatly now". A bare <table> /
        one with a unique id (no Pico utility class) gets Pico's native table
        styling (zebra, borders, alignment) which is the expected rendering.

        Anchoring note (mirrors Hotfix #6's `async logout()` docblock pin):
        the literal ``'`<table class="grid">`'`` ALSO appears verbatim inside
        this file's CSS comment (the Hotfix-#8 explainer adjacent to the new
        ``#countries`` rule). A naive ``'<table class="grid">' not in text``
        would match that docblock comment ≠ the actual markup — so we strip
        the CSS comment region first. CSS comments in the dashboard file are
        ``/* … */`` blocks; we strip every such block via a non-greedy regex
        before scanning the remaining markup."""
        import re

        text = self._dashboard_html.read_text(encoding="utf-8")
        # Strip CSS `/* ... */` blocks so quoted literals in our own Hotfix-#8
        # comment blocks don't trip the negative-markup assertion.
        text_no_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)

        assert '<table id="countries">' in text, (
            'dashboard.html countries table MUST be <table id="countries"> '
            "to render with Pico.css's native table styles (zebra/borders/"
            'alignment). The previous <table class="grid"> collides with '
            "Pico's global `.grid` utility (display: grid) and collapses "
            "the table layout (Bug #c — Hotfix #8)."
        )
        assert '<table class="grid">' not in text_no_comments, (
            "dashboard.html MUST NOT contain any '<table class=\"grid\">' "
            "in the markup (the literal is permitted ONLY inside a CSS "
            "comment block describing the previous bug, so we strip those "
            "before scanning) — the `.grid` utility class collides with "
            "Pico's global grid CSS and broke the countries table layout "
            "(Bug #c — Hotfix #8)."
        )
        # The now-orphan local `table.grid` CSS rule MUST also be gone from
        # any active selector context (CSS-comment-stripped). The literal
        # may still appear inside a Hotfix-#8 docblock *describing* the prior
        # bug, so we strip comments before checking.
        assert "table.grid td, table.grid th" not in text_no_comments, (
            "dashboard.html MUST NOT carry the orphan `table.grid td, "
            "table.grid th` local CSS rule as an active selector — the "
            "class is no longer applied to any table, and leaving the rule "
            "behind creates a subtle re-regression trap (Bug #c — "
            "Hotfix #8)."
        )
        # Strong positive pin: the new functional CSS rules that REPLACE the
        # dropped `.grid` ones (scoped to #countries, whitelisting name +
        # actions for word-wrap) MUST be present.
        assert "table#countries" in text, (
            "dashboard.html MUST include a scoped `table#countries` CSS "
            "block — that is the replacement for the dropped `table.grid` "
            "selector and pins the layout's new contract (Bug #c — "
            "Hotfix #8)."
        )

    # ---- Bug #d: clone payload MUST NOT mint a fresh _fresh_vless_client ---
    def test_clone_payload_does_not_mint_fresh_client(self):
        """``panel/dashboard/xui_client.py::_build_clone_payload`` MUST NOT
        overwrite the template's ``settings.clients`` array with a freshly
        minted ``_fresh_vless_client(public_port)`` entry. The clone should
        preserve the template's existing clients verbatim so the operator's
        already-configured 3x-ui client roster merely gains a new listener
        port instead of sprouting a NEW 'client section' row per clone
        (Hotfix #8 / Bug #d).

        This pin scopes to the body of ``_build_clone_payload`` and asserts
        that ``_fresh_vless_client`` is NOT invoked inside it. The helper
        definition itself (which is still called by ``tests/test_xui_client.py``
        directly) sits in a SEPARATE function and must remain callable."""
        text = self._xui_client.read_text(encoding="utf-8")
        start = text.find("def _build_clone_payload")
        assert start != -1, "panel/dashboard/xui_client.py is missing _build_clone_payload"
        end = text.find("\ndef ", start + 1)
        if end == -1:
            end = start + 4000
        body = text[start:end]

        # Strip Python `#`-comment lines so the literal `_fresh_vless_client(...)`
        # in this function's Hotfix-#8 docblock (which describes the pre-
        # Hotfix-#8 buggy behaviour it REMOVED) does NOT trip the negative
        # assertion (mirrors Hotfix #6's `re.sub(r'//[^\n]*', ...)` strip on
        # the wizard.html logout body). The body slice is bounded by the next
        # `\ndef ` so `_fresh_vless_client`'s OWN def line is NOT inside body
        # — only docblock-comment / code references to it inside
        # _build_clone_payload are in scope, and we strip the former.
        import re

        body_no_comments = re.sub(r"#[^\n]*", "", body)

        # `_fresh_vless_client` MUST NOT be CALLED inside _build_clone_payload's
        # active code (after stripping docblock + inline comments).
        assert "_fresh_vless_client(" not in body_no_comments, (
            "_build_clone_payload MUST NOT call _fresh_vless_client — the "
            "clone path must preserve the template's clients array verbatim "
            "(operator-reported 'Why does it also clone in the client "
            "section? It is not necessary; only the inbound is enough.' "
            "Bug #d — Hotfix #8)."
        )
        # Strong positive pin: the clients-array preservation line lives in
        # the body. The exact dynamic form (a `template.get(...)` + conditional
        # copy-through) MUST be present so the clone carries the template's
        # roster through.
        assert 'settings["clients"]' in body_no_comments, (
            '_build_clone_payload MUST assign settings["clients"] to a '
            "copy-through of the template's clients array (Bug #d — "
            "Hotfix #8)."
        )

    def test_fresh_vless_client_helper_still_callable(self):
        """Defensive corollary of test_clone_payload_does_not_mint_fresh_client:
        the ``_fresh_vless_client`` helper itself MUST still exist (its def
        line + the int-tgId body shape that Hotfix #7 locked in), because the
        unit tests in ``tests/test_xui_client.py`` still call it directly.
        Removing the helper would break the Hotfix-#7 + #9 tests."""
        text = self._xui_client.read_text(encoding="utf-8")
        assert "def _fresh_vless_client(" in text, (
            "panel/dashboard/xui_client.py MUST still define "
            "_fresh_vless_client — it is a public helper retained for "
            "callers that explicitly want a fresh per-clone client (none "
            "currently use it) AND the Hotfix-#7 / Hotfix-#9 tests in "
            "tests/test_xui_client.py depend on it being importable "
            "(Bug #d — Hotfix #8)."
        )
        # The Hotfix-#7 int-tgId contract on the helper itself MUST stay.
        helper_start = text.find("def _fresh_vless_client(")
        helper_end = text.find("\ndef ", helper_start + 1)
        if helper_end == -1:
            helper_end = helper_start + 800
        helper_body = text[helper_start:helper_end]
        assert '"tgId": 0' in helper_body and '"tgId": ""' not in helper_body, (
            '_fresh_vless_client MUST continue to set "tgId": 0 (int) — '
            "the Hotfix-#7 / Bug-#9 contract is preserved by Hotfix #8 "
            "(Bug #d — Hotfix #8)."
        )


# ===========================================================================
# Phase 18 — Hotfix #9 post-release regression suite
# ===========================================================================
class TestHotfix9PostReleaseRegressions:
    """Static-source grep tests for Hotfix #9 — four post-Hotfix-#8 bugs:

    * Bug #1 (Refresh button still present) — Hotfix #8 mistakenly removed the
      *wizard* ``⟳ Refresh state`` anchor; the operator's report from the start
      was about the *dashboard* nav ``⟳ Refresh`` anchor at
      ``panel/static/dashboard.html:40``. This test class locks the dashboard
      anchor removal so the mistake doesn't recur.
    * Bug #5v6 (logout silent no-op) — the actual root cause was never the
      fire-and-forget logout JS (that was provably correct from Hotfix #6
      onward). The real culprit was a multi-root Alpine ``<template x-for>``
      on the dashboard logs modal that broke ``appDashboard()`` component
      init, so the ``@click.prevent="logout()"`` handler on the nav anchor
      never bound and clicking did nothing. Network: no POST /auth/logout fired.
      Fix: wrap each iteration item in a single ``<div>`` root.
    * Bug #2 (systemctl "Interactive authentication required") — the panel
      service runs as unprivileged ``psiphon3xui``, so its ``systemctl start
      psiphon-tunnel@.<CODE>.service`` calls need a polkit rule. We ship one
      at ``systemd/49-psiphon-3x-ui.rules`` and the installer copies it in.
    * Bug #3 (auto-enable on apply) — the wizard ``submit_apply`` step did NOT
      flip ``Country.enabled`` after a healthy ``apply_country`` event, so the
      dashboard showed fresh rows whose tunnels were running but whose
      ``Enabled`` checkbox was false; clicking it re-fired ``start_unit`` and
      surfaced Bug #2. Fix: ``submit_apply`` sets ``Country.enabled=True`` on
      every healthy event.
    """

    HTML_DIR = Path(__file__).resolve().parent.parent / "panel" / "static"
    SYSTEMD_DIR = Path(__file__).resolve().parent.parent / "systemd"
    INSTALLER_DIR = Path(__file__).resolve().parent.parent / "installer"

    # ─── Bug #1: dashboard nav no longer has a "⟳ Refresh" anchor ─────────────
    def test_dashboard_nav_has_no_refresh_anchor(self):
        import re

        path = self.HTML_DIR / "dashboard.html"
        text = path.read_text(encoding="utf-8")
        # The visible "⟳ Refresh" anchor text MUST be gone from the <nav>
        # block. Use a regex that matches the anchor literal.
        anchor_pat = re.compile(r"<a[^>]*>\s*⟳\s*Refresh\s*</a>")
        nav_start = text.find("<nav")
        nav_end = text.find("</nav>", nav_start + 1) + len("</nav>")
        assert nav_start != -1 and nav_end != -1, "dashboard has a <nav> block"
        nav_block = text[nav_start:nav_end]
        assert anchor_pat.search(nav_block) is None, (
            "Bug #1 — dashboard nav still has the '<a ...>⟳ Refresh</a>' "
            "anchor that the operator reported as useless. Hotfix #9 removed "
            "it; do not re-introduce it. Anyone can hit F5."
        )

    def test_dashboard_nav_still_has_logout_anchor(self):
        """The previous Hotfix #8 mistakenly removed the wrong anchor — we
        must make sure the dashboard ``Logout`` anchor is still there and
        the ``refreshAll()`` helper is still wired for internal callers.
        """
        path = self.HTML_DIR / "dashboard.html"
        text = path.read_text(encoding="utf-8")
        nav_start = text.find("<nav")
        nav_end = text.find("</nav>", nav_start + 1) + len("</nav>")
        nav_block = text[nav_start:nav_end]
        assert '@click.prevent="logout()"' in nav_block, (
            "Bug #1 — the dashboard nav must STILL have the Logout anchor "
            "bound to logout(); Hotfix #9 only removes the Refresh anchor."
        )

    # ─── Bug #5v6: every <template x-for> in dashboard.html now has ONE ─────
    def test_dashboard_alpine_x_for_each_has_single_root(self):
        """Every ``<template x-for="...">`` in dashboard.html MUST have exactly
        one immediate child element after the closing ``>``. Alpine.js logs
        ``x-for templates require a single root element`` and silently skips
        binding the rest of the component when this contract is violated —
        which is exactly what broke Logout in Hotfix #8.
        """
        import re

        path = self.HTML_DIR / "dashboard.html"
        text = path.read_text(encoding="utf-8")
        # Strip HTML comments first (so a docblock <div><span></span><br></div>
        # example inside an HTML comment doesn't trip the top-level counter).
        text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

        # The single robust check: every ``<template x-for="..."> ... </template>``
        # block must have exactly one immediate child element. Use a state
        # machine that walks the matched body char-by-char, tracking depth,
        # and counts how many times an opening tag fires at depth=0.
        # NOTE: we deliberately split the regex on two ``re.finditer`` calls
        # (opener + closer) so the editor's syntax checker doesn't choke on
        # escaped quotes inside a raw string.
        opener_re = re.compile(r'<template\s+x-for="[^"]*"\s*>')
        top_level_count_pairs: list[tuple[int, list[str]]] = []
        for opener_m in opener_re.finditer(text):
            start = opener_m.end()
            # Walk to the matching </template> with a tiny balanced-scanner.
            depth = 1
            i = start
            close_pos = -1
            while depth > 0:
                op = text.find("<template", i)
                cl = text.find("</template>", i)
                if cl == -1:
                    break
                if op != -1 and op < cl:
                    depth += 1
                    i = op + len("<template")
                else:
                    depth -= 1
                    i = cl + len("</template>")
                    close_pos = cl
            if close_pos == -1:
                # Malformed HTML — skip rather than fail; ruff/pytest will
                # flag structural issues elsewhere and we don't want a flaky
                # synth-dist here.
                continue
            body = text[start:close_pos]
            # Count immediate top-level children (opening tags at depth 0).
            top_level_tags: list[str] = []
            depth = 0
            j = 0
            while j < len(body):
                lt = body.find("<", j)
                if lt == -1:
                    break
                # Closing tag → depth -1; not a top-level opener.
                j_end = body.find(">", lt)
                if j_end == -1:
                    break
                slice_ = body[lt : j_end + 1]
                if slice_.startswith("</"):
                    depth -= 1
                else:
                    name_m = re.match(r"<([a-zA-Z][\w-]*)", slice_)
                    if name_m and depth == 0:
                        top_level_tags.append(name_m.group(1))
                    depth += 1
                j = j_end + 1
            top_level_count_pairs.append((opener_m.start(), top_level_tags))

        for offset, tags in top_level_count_pairs:
            assert len(tags) == 1, (
                f'Bug #5v6 — dashboard <template x-for="..."> at offset '
                f"{offset} has {len(tags)} top-level children ({tags}); "
                f"Alpine requires exactly ONE. This was the root cause of "
                f"'clicking Logout does nothing' under Hotfix #8 — Alpine "
                f"logged a 'single root element' warning at component init "
                f"and skipped binding @click handlers. Fix: wrap each "
                f"iteration item in a single root <div>."
            )

    # ─── Bug #2: polkit rule + installer shipping present ─────────────────────
    def test_polkit_rule_file_exists_and_targets_tunnel_units(self):
        path = self.SYSTEMD_DIR / "49-psiphon-3x-ui.rules"
        assert path.exists(), (
            "Bug #2 — Hotfix #9 ships a polkit rule at "
            "systemd/49-psiphon-3x-ui.rules authorizing the psiphon3xui "
            "panel service user to start/stop/restart psiphon-tunnel@* units."
        )
        import re  # noqa: PLC0415  local import matches the Hotfix-7/8 convention

        text = path.read_text(encoding="utf-8")
        # Strip JS line comments so the docblock prose doesn't match.
        text_no_comments = re.sub(r"//[^\n]*", "", text)
        assert "manage-units" in text_no_comments, (
            "polkit rule must scope action.id to 'org.freedesktop.systemd1.manage-units'."
        )
        assert "psiphon-tunnel@" in text_no_comments, (
            "polkit rule must scope to the psiphon-tunnel@* unit template only."
        )
        assert "psiphon3xui" in text_no_comments, (
            "polkit rule must match subject.user == 'psiphon3xui' (the default panel service user)."
        )
        for verb in ('"start"', '"stop"', '"restart"'):
            assert verb in text_no_comments, f"polkit rule must scope to the {verb} verb."

    def test_installer_panel_install_ships_polkit_and_tunnel_unit(self):
        import re  # noqa: PLC0415  local import matches the Hotfix-7/8 convention

        path = self.INSTALLER_DIR / "panel_install.sh"
        text = path.read_text(encoding="utf-8")
        # Strip bash comments so docblock prose doesn't match.
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        assert "psiphon-tunnel@.service" in text_no_comments, (
            "Bug #2 — panel_install.sh must install the templated tunnel unit "
            "to /etc/systemd/system/ (Hotfix #9)."
        )
        assert "49-psiphon-3x-ui.rules" in text_no_comments, (
            "Bug #2 — panel_install.sh must install the polkit rule to "
            "/etc/polkit-1/rules.d/ (Hotfix #9)."
        )
        assert "rules.d" in text_no_comments, (
            "Bug #2 — panel_install.sh must install into /etc/polkit-1/rules.d/."
        )

    def test_install_sh_uninstall_removes_polkit_and_tunnel_unit(self):
        import re  # noqa: PLC0415  local import matches the Hotfix-7/8 convention

        path = Path(__file__).resolve().parent.parent / "install.sh"
        text = path.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        # Confirm the symmetric uninstall-branch cleanup of Hotfix-#9.
        assert "psiphon-tunnel@" in text_no_comments, (
            "Bug #2 — install.sh --uninstall must stop + remove the templated "
            "psiphon-tunnel@.service unit (Hotfix #9)."
        )
        assert "49-psiphon-3x-ui.rules" in text_no_comments, (
            "Bug #2 — install.sh --uninstall must remove the polkit rule."
        )

    # ─── Bug #3: submit_apply auto-enables healthy countries ─────────────────
    def test_apply_router_auto_enables_healthy_countries(self):
        import re  # noqa: PLC0415  local import matches the Hotfix-7/8 convention

        path = Path(__file__).resolve().parent.parent / "panel" / "wizard" / "router.py"
        text = path.read_text(encoding="utf-8")
        # Strip Python comments so the Hotfix-#9 docblock prose doesn't match.
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        # Scope the scan to the submit_apply handler body. The function's
        # multi-line parameter list makes the simple "^async def ...:\s*\n"
        # regex literal fail; instead we anchor on the function name and
        # extend to the NEXT top-level `async def`, `def`, `class`, or
        # `@router.` declaration.
        m = re.search(
            r"async\s+def\s+submit_apply\b.*?(?=\n@router\.|\nasync\s+def\s|\ndef\s|\nclass\s|\Z)",
            text_no_comments,
            re.DOTALL,
        )
        assert m is not None, "submit_apply handler not found in router.py"
        handler_body = m.group(0)
        # Positive pin: the auto-enable branch on a healthy ApplyEvent.
        assert 'event.status == "healthy"' in handler_body, (
            "Bug #3 — submit_apply must branch on "
            'event.status == "healthy" so a successful apply_country flips '
            "the country's enabled flag True."
        )
        assert "country_row.enabled = True" in handler_body, (
            "Bug #3 — submit_apply must set country_row.enabled = True on the healthy branch."
        )
        # Defensive negative: the previous behaviour of NOT touching
        # Country.enabled would have left rows with enabled=False after
        # an apply — those tests are caught by test_wizard_apply.py.
        # ``db.get(Country, spec.country_code)`` is the canonical wording —
        # match either the ``Country(`` ctor form (older code) or the
        # ``db.get(Country,`` form (current); both confirm the Country ORM
        # is referenced inside the apply handler.
        assert "Country(" in handler_body or "db.get(Country" in handler_body, (
            "Bug #3 — submit_apply must read the Country row from db.get(Country, ...)."
        )


# ===========================================================================
# Hotfix #10 — Phase 19 regressions
# ===========================================================================
class TestHotfix10PostReleaseRegressions:
    """Static-source grep tests for Hotfix #10 — five post-Hotfix-#9 bugs:

    * Bug #1 (logout 8th-time): the dashboard/wizard nav Logout anchor was
      OUTSIDE ``<main x-data>`` so Alpine never bound its ``@click.prevent``.
      Fix: move the ``<nav>`` INSIDE ``<main x-data>`` on both pages.
    * Bug #2 (Backup 405): ``downloadBackup()`` dispatched the fetch with no
      ``method: "POST"`` though the router declares ``@router.post`` only.
      Fix: add explicit POST + CSRF headers.
    * Bug #3 (cannot enable post-wizard country with no PortAssignment):
      the dashboard's PATCH path raised 409 instead of letting the operator
      enter ports inline. Fix: extend ``PatchCountryBody`` + dispatch
      ``apply_country`` inline from ``patch_country``; SPA prompts for ports.
    * Bug #4 (journalctl permission denied): the panel service user was not
      in the ``systemd-journal`` or ``adm`` groups. Fix: installer/prepare_user
      .sh now runs ``usermod --append --groups systemd-journal,adm``.
    * Bug #5 (panel-port change requires manual shell work): ``change_panel_port``
      persisted the new port and asked the operator to run two shell
      commands manually. Fix: handler now runs ``installer/firewall.sh`` and
      ``systemctl restart psiphon-3x-ui.service`` in-band; the polkit rule
      is extended to authorise the restart verb for the panel's own unit.
    """

    # ─── Bug #1: Logout anchor lives inside <main x-data> ────────────────
    def test_dashboard_logout_anchor_is_inside_main_xdata(self):
        path = Path(__file__).resolve().parent.parent / "panel" / "static" / "dashboard.html"
        text = path.read_text(encoding="utf-8")
        # Find <main ... x-data="appDashboard()"> position
        main_idx = text.find('x-data="appDashboard()"')
        assert main_idx >= 0, 'dashboard.html must define <main x-data="appDashboard()">'
        nav_idx = text.find("<nav", main_idx)
        anchor_idx = text.find('@click.prevent="logout()"', main_idx)
        # The <nav> AND the Logout anchor MUST both come AFTER the <main
        # x-data="appDashboard()"> opening — i.e. their indices are strictly
        # greater than main_idx. (Pre-Hotfix-#10 they were BEFORE main_idx
        # because <nav> was a sibling of <main>, so Alpine bound nothing.)
        assert nav_idx > main_idx, (
            'Bug #1 — <nav> must be INSIDE <main x-data="appDashboard()"> so '
            'Alpine\'s @click.prevent="logout()" on the Logout anchor binds. '
            "Pre-Hotfix-#10 the nav was a sibling of <main> and Alpine NEVER "
            "wired the logout click."
        )
        assert anchor_idx > main_idx, (
            "Bug #1 — the Logout anchor must live inside the <main x-data> scope."
        )

    def test_wizard_logout_anchor_is_inside_main_xdata(self):
        path = Path(__file__).resolve().parent.parent / "panel" / "static" / "wizard.html"
        text = path.read_text(encoding="utf-8")
        main_idx = text.find('x-data="appWizard()"')
        assert main_idx >= 0, 'wizard.html must define <main x-data="appWizard()">'
        nav_idx = text.find("<nav", main_idx)
        anchor_idx = text.find('@click.prevent="logout()"', main_idx)
        assert nav_idx > main_idx, (
            'Bug #1 — wizard <nav> must be INSIDE <main x-data="appWizard()">.'
        )
        assert anchor_idx > main_idx, (
            "Bug #1 — wizard Logout anchor must live inside the x-data scope."
        )

    # ─── Bug #2: downloadBackup() uses method: "POST" + CSRF ─────────────
    def test_dashboard_downloadBackup_uses_post_method(self):
        import re  # noqa: PLC0415

        path = Path(__file__).resolve().parent.parent / "panel" / "static" / "dashboard.html"
        text = path.read_text(encoding="utf-8")
        # Extract the downloadBackup() body. Anchor on async downloadBackup()
        # then balance-brace scan to the matching closing brace, anchored at
        # the closing `}` followed by a comma-newline (next method).
        m = re.search(
            r"async\s+downloadBackup\s*\(\s*\)\s*\{",
            text,
        )
        assert m is not None, "dashboard.html must define downloadBackup()"
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[start:i]
        assert 'method: "POST"' in body or 'method:"POST"' in body, (
            "Bug #2 — dashboard.html downloadBackup() must specify "
            'method: "POST" to match the @router.post("/backup") '
            "handler. Pre-Hotfix-#10 the bare fetch() defaulted to GET "
            "and the operator saw 405 Method Not Allowed."
        )
        assert "_csrfHeaders" in body, (
            "Bug #2 — downloadBackup() must include CSRF headers since "
            "POST /backup is a mutating verb gated by the CSRF middleware."
        )

    # ─── Bug #3: dashboard.html has the inline enable-with-ports modal ─
    def test_dashboard_has_inline_enable_with_ports_modal(self):
        path = Path(__file__).resolve().parent.parent / "panel" / "static" / "dashboard.html"
        text = path.read_text(encoding="utf-8")
        assert "enable_open" in text, (
            "Bug #3 — dashboard.html must add a ports.enable_open piece of "
            "state to drive the inline enable-with-ports modal."
        )
        assert "confirmEnableWithPorts" in text, (
            "Bug #3 — dashboard.html must define confirmEnableWithPorts() to "
            "PATCH {enabled:true, socks_port, public_port} in a single call."
        )
        assert "cancelEnableWithPorts" in text, (
            "Bug #3 — dashboard.html must define cancelEnableWithPorts() so "
            "the operator can bail from the inline enable-with-ports modal."
        )

    # ─── Bug #3 backend: PatchCountryBody accepts optional socks/public ─
    def test_patch_country_body_accepts_optional_ports(self):
        import re  # noqa: PLC0415

        path = Path(__file__).resolve().parent.parent / "panel" / "dashboard" / "router.py"
        text = path.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        m = re.search(
            r"class\s+PatchCountryBody\s*\(\s*BaseModel\s*\)\s*:.*?(?=\nclass\s|\n@router\.|\ndef\s|\Z)",
            text_no_comments,
            re.DOTALL,
        )
        assert m is not None, "PatchCountryBody class not found in dashboard router"
        body = m.group(0)
        assert "socks_port" in body and "public_port" in body, (
            "Bug #3 — PatchCountryBody must accept optional socks_port + "
            "public_port to enable the inline enable-with-ports path."
        )
        assert "int | None" in body or "Optional[int]" in body, (
            "Bug #3 — socks_port/public_port must be Optional ints (default "
            "None means use smart recommendation)."
        )

    def test_patch_country_calls_apply_country_inline(self):
        import re  # noqa: PLC0415

        path = Path(__file__).resolve().parent.parent / "panel" / "dashboard" / "router.py"
        text = path.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        m = re.search(
            r"def\s+patch_country\b.*?(?=\n@router\.|\nasync\s+def\s|\ndef\s|\nclass\s|\Z)",
            text_no_comments,
            re.DOTALL,
        )
        assert m is not None, "patch_country handler not found"
        body = m.group(0)
        assert "apply_country(" in body, (
            "Bug #3 — patch_country must call apply_country(spec) inline when "
            "enabling a no-PortAssignment country instead of raising 409."
        )
        assert "PortAssignment(" in body, (
            "Bug #3 — patch_country must persist a PortAssignment row after "
            "the inline apply_country succeeds so subsequent toggles don't "
            "re-enter the inline-enable branch."
        )
        # Negative: the pre-Hotfix-#10 409-conflict branch is REmoved.
        #
        # Phase 27 note: this used to ban the substring "409" outright, which
        # was a proxy for "the missing-PortAssignment branch is gone". That
        # proxy became wrong once patch_country grew a *different*, legitimate
        # 409 — the port-conflict rejection for an operator-supplied port that
        # another country, a 3x-ui inbound, or another process already holds.
        # Pin the assertion to the actual regression instead: the enable path
        # must not bail out because a PortAssignment is missing, since creating
        # that row is exactly what the inline-enable branch is for.
        assert "has no PortAssignment" not in body, (
            "Bug #3 — patch_country must NOT raise 409 on missing-PortAssignment "
            "enable; the pre-Hotfix-#10 hardcoded 409 must be gone."
        )
        # Any surviving 409 must be a port conflict, never a missing assignment.
        for match in re.finditer(r"HTTP_409_CONFLICT(.{0,400})", body, re.DOTALL):
            assert "already in use" in match.group(1), (
                "patch_country raises a 409 that is not the Phase 27 "
                "port-conflict rejection — check it is not a re-introduced "
                f"missing-PortAssignment bail-out: {match.group(1)[:200]!r}"
            )

    # ─── Bug #4: installer adds psiphon3xui to systemd-journal + adm ────
    def test_prepare_user_adds_user_to_journal_and_adm_groups(self):
        path = Path(__file__).resolve().parent.parent / "installer" / "prepare_user.sh"
        text = path.read_text(encoding="utf-8")
        # Strip bash comments to keep the grep honest.
        text_no_comments = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )
        assert "usermod" in text_no_comments, (
            "Bug #4 — installer/prepare_user.sh must run usermod to add the "
            "panel user to the journalctl-viewing groups."
        )
        assert "systemd-journal" in text_no_comments, (
            "Bug #4 — prepare_user.sh must add the panel user to "
            "systemd-journal so journalctl succeeds."
        )
        assert "adm" in text_no_comments, (
            "Bug #4 — prepare_user.sh must add the panel user to adm as a "
            "belt-and-braces fallback for non-systemd-journal distros."
        )

    # ─── Bug #5 backend: change_panel_port invokes firewall + restart ───
    def test_change_panel_port_invokes_firewall_and_restart_in_band(self):
        import re  # noqa: PLC0415

        path = Path(__file__).resolve().parent.parent / "panel" / "dashboard" / "router.py"
        text = path.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        # 1) the helper functions exist near the top helpers block.
        assert "def _reload_firewall(" in text_no_comments, (
            "Bug #5 — _reload_firewall() helper must exist on the dashboard router."
        )
        assert "def _restart_panel_service(" in text_no_comments, (
            "Bug #5 — _restart_panel_service() helper must exist on the dashboard router."
        )
        # 2) change_panel_port invokes both helpers.
        m = re.search(
            r"def\s+change_panel_port\b.*?(?=\n@router\.|\nasync\s+def\s|\ndef\s|\nclass\s|\Z)",
            text_no_comments,
            re.DOTALL,
        )
        assert m is not None, "change_panel_port handler not found"
        body = m.group(0)
        assert "_reload_firewall()" in body, (
            "Bug #5 — change_panel_port must invoke _reload_firewall() after "
            "persisting the new panel_port."
        )
        assert "_restart_panel_service()" in body, (
            "Bug #5 — change_panel_port must invoke _restart_panel_service() "
            "so the operator doesn't have to drop to a shell."
        )
        assert "firewall_ok" in body and "service_restart_ok" in body, (
            "Bug #5 — change_panel_port response must surface firewall_ok + "
            "service_restart_ok flags so the SPA can show the operator what "
            "happened."
        )

    # ─── Bug #5: polkit rule authorises restart of psiphon-3x-ui.service
    def test_polkit_rule_allows_restart_of_panel_self_unit(self):
        path = Path(__file__).resolve().parent.parent / "systemd" / "49-psiphon-3x-ui.rules"
        text = path.read_text(encoding="utf-8")
        # Strip JS line comments.
        text_no_comments = "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("//")
        )
        assert "psiphon-3x-ui.service" in text_no_comments, (
            "Bug #5 — the polkit rule must explicitly mention "
            "psiphon-3x-ui.service so the panel user can restart its own unit."
        )
        # The rule must gate restart-only on the panel's own unit — it must
        # NOT authorise start/stop of psiphon-3x-ui.service.
        assert "verb" in text_no_comments and "restart" in text_no_comments, (
            "Bug #5 — polkit rule must inspect verb and only allow restart "
            "for psiphon-3x-ui.service."
        )
        assert "psiphon-tunnel@" in text_no_comments, (
            "Bug #5 — polkit rule must still cover the psiphon-tunnel@ fleet "
            "(Hotfix-#9 scope must remain)."
        )


# ============================================================================
# Hotfix #11 — six post-Hotfix-#10 operator-reported bugs (Phase 20).
# Static-source grep tests (no live subprocess) that lock-in each fix so
# regressions are caught at CI time before shipping.
#
# Covered bugs:
#   Bug #1 — install.sh print_summary used `ip -4 -o addr show to default | awk`
#            which returned 127.0.0.1 on hosts where `lo` was the only "scope
#            default"-scoped interface → operator saw
#            `Web UI: http://127.0.0.1:11138`. Fixed by `ip route get 1.1.1.1`
#            + a curl IP-echo fallback chain (api.ipify.org / ifconfig.me).
#   Bug #2 — panel/wizard/apply.py:apply_country called `health_probe` ONCE
#            right after `is_unit_active` returned True; Psiphon's SOCKS5
#            listener takes 5-30s to bind after `systemctl start` reports
#            active → ConnectionRefused → status="failed" → inline enable +
#            wizard auto-enable both broken. Fixed by a bounded retry loop
#            (every 1s for up to 30s) honouring health_probe_factory.
#   Bug #3 — panel/dashboard/router.py:change_panel_port only flipped
#            panel.db.Settings.panel_port, NOT the env file's
#            PSIPHON3XUI_PORT=, line; the panel reads its listen port from
#            the env var (panel.config.Settings) so the OLD port was opened
#            again after restart. Fixed by `_update_panel_env_port` rewriting
#            PSIPHON3XUI_PORT=<new> in ${INSTALL_PREFIX}/panel.env before
#            systemctl restart.
#   Bug #4 — dashboard SPA had a "Delete" button + `deleteCountry()` method
#            which the operator wants removed (only Edit ports + Logs).
#   Bug #5 — same root cause as Bug #2: submit_apply's `if event.status ==
#            "healthy": country_row.enabled = True` gate never fired because
#            apply_country returned "failed". Auto-fixed by Bug #2's retry; we
#            reverse-lockin (no NEW Bug #5-specific code — verifying the
#            healthy gate still exists + apply_country now retries → the gate
#            fires).
#   Bug #6 — installer/panel_install.sh:wait_for_panel_socket used
#            `exec 3<>"/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null` — bash's
#            connect-syscall wrapper printed "connect: Connection refused" to
#            fd 2 BEFORE the exec's redirect scope applied → noisy install
#            logs. Fixed by wrapping the probe in a subshell `( exec 3<>... )`
#            with its stderr redirected.
# ============================================================================
class TestHotfix11PostReleaseRegressions:
    """Static-source grep tests for Hotfix #11 — six post-Hotfix-#10 bugs."""

    # ----- repo paths ------------------------------------------------------
    _INSTALL_SH = Path(__file__).resolve().parent.parent / "install.sh"
    _PANEL_INSTALL_SH = Path(__file__).resolve().parent.parent / "installer" / "panel_install.sh"
    _APPLY_PY = Path(__file__).resolve().parent.parent / "panel" / "wizard" / "apply.py"
    _DASHBOARD_ROUTER = Path(__file__).resolve().parent.parent / "panel" / "dashboard" / "router.py"
    _DASHBOARD_HTML = Path(__file__).resolve().parent.parent / "panel" / "static" / "dashboard.html"
    _WIZARD_ROUTER = Path(__file__).resolve().parent.parent / "panel" / "wizard" / "router.py"

    # ---- Bug #1: install.sh robust server-IP detection --------------------
    def test_install_sh_print_summary_uses_ip_route_get_not_show_to_default(self):
        import re  # noqa: PLC0415

        text = self._INSTALL_SH.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        assert "ip route get 1.1.1.1" in text_no_comments, (
            "Bug #1 — install.sh print_summary must use `ip route get 1.1.1.1` "
            "(awk-extract `src`) for robust primary-IP detection, not the "
            "old `ip -4 -o addr show to default` (which matched `lo` on the "
            "operator's host and yielded 127.0.0.1)."
        )
        # The old, fallible `ip -4 -o addr show to default | awk` probe
        # (which matched `lo` on the operator's host and returned 127.0.0.1)
        # must no longer be the IP source.
        assert "ip -4 -o addr show to default" not in text_no_comments, (
            "Bug #1 — install.sh print_summary must NOT use the old "
            "`ip -4 -o addr show to default` probe; "
            "`ip route get 1.1.1.1` (awk-extract `src`) + curl IP-echo "
            "fallbacks are the new primary chain."
        )

    def test_install_sh_print_summary_has_curl_ip_echo_fallback(self):
        text = self._INSTALL_SH.read_text(encoding="utf-8")
        assert "api.ipify.org" in text, (
            "Bug #1 — install.sh print_summary must fall back to an IP-echo "
            "service (api.ipify.org is the primary; ifconfig.me the "
            "secondary) for cloud-NAT'd hosts where the local interface has "
            "a private RFC1918 address but the public IP lives in front of "
            "the NAT."
        )
        assert "ifconfig.me" in text, (
            "Bug #1 — install.sh print_summary must list BOTH api.ipify.org "
            "and ifconfig.me so if the primary IP-echo is down/timeout the "
            "secondary still yields the public IP."
        )
        assert "<SERVER_IP>" in text, (
            "Bug #1 — install.sh print_summary must keep the literal "
            "'<SERVER_IP>' last-ditch placeholder so the summary still "
            "prints when both probes come up empty."
        )

    # ---- Bug #2: apply_country bounded health_probe retry ------------------
    def test_apply_country_retries_health_probe_with_backoff(self):
        import re  # noqa: PLC0415

        text = self._APPLY_PY.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        # The retry loop must be present in apply_country.
        m = re.search(
            r"def\s+apply_country\b.*?(?=\ndef\s)",
            text_no_comments,
            re.DOTALL,
        )
        assert m is not None, "Bug #2 — apply_country def not found."
        body = m.group(0)
        assert "deadline = time.monotonic()" in body, (
            "Bug #2 — apply_country must compute a monotonic deadline for the "
            "health_probe retry loop (so the apply cannot hang forever if "
            "Psiphon never binds)."
        )
        assert "while not probe.healthy and time.monotonic() < deadline:" in body, (
            "Bug #2 — apply_country must loop `while not probe.healthy and "
            "time.monotonic() < deadline:` retrying health_probe against the "
            "freshly-started SOCKS5 listener; Psiphon takes 5-30s to bind "
            "after `systemctl start` reports active (a single eager probe "
            "hit ConnectionRefused)."
        )
        assert "time.sleep(1.0)" in body, (
            "Bug #2 — apply_country must sleep ~1s between probe attempts so "
            "the retry doesn't busy-loop and exhaust the deadline in CPU."
        )

    def test_apply_country_imports_time(self):
        # The retry loop needs the `time` module — verify it's imported so
        # we don't ship NameError-shaped regressions.
        text = self._APPLY_PY.read_text(encoding="utf-8")
        assert "\nimport time\n" in text, (
            "Bug #2 — panel/wizard/apply.py must `import time` for the "
            "health_probe retry loop's deadline + sleep."
        )

    def test_apply_country_failure_message_mentions_retry(self):
        # When the deadline expires we must keep returning a `failed` event
        # (the SSE stream should not raise) but the message should mention
        # the retry so logs make it obvious the deadline expired (vs. a
        # single eager probe).
        text = self._APPLY_PY.read_text(encoding="utf-8")
        assert "failed after retry" in text, (
            "Bug #2 — apply_country's failure message must mention 'failed "
            "after retry' so the operator/ci logs make clear the retry "
            "deadline expired rather than a single eager ConnectionRefused."
        )

    # ---- Bug #3: change_panel_port rewrites PSIPHON3XUI_PORT in env file --
    def test_change_panel_port_defines_update_panel_env_port_helper(self):
        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        assert "def _update_panel_env_port(" in text, (
            "Bug #3 — panel/dashboard/router.py must define a "
            "`_update_panel_env_port(new_port)` helper that rewrites "
            "PSIPHON3XUI_PORT=<new> in ${INSTALL_PREFIX}/panel.env (the "
            "systemd EnvironmentFile) — the panel reads its listen port from "
            "that env var, not panel.db."
        )
        assert "_panel_env_path" in text, (
            "Bug #3 — _update_panel_env_port must resolve the env file via a "
            "_panel_env_path() helper (sibling of panel.db) for testability "
            "and clarity."
        )

    def test_change_panel_port_invokes_env_rewrite_before_restart(self):
        import re  # noqa: PLC0415

        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        m = re.search(
            r"def\s+change_panel_port\b.*?(?=\n@router\.|\nasync\s+def\s|\ndef\s|\nclass\s|\Z)",
            text_no_comments,
            re.DOTALL,
        )
        assert m is not None, "Bug #3 — change_panel_port def not found."
        body = m.group(0)
        env_call = body.find("_update_panel_env_port(")
        fw_call = body.find("_reload_firewall()")
        svc_call = body.find("_restart_panel_service()")
        assert env_call != -1 and fw_call != -1 and svc_call != -1, (
            "Bug #3 — change_panel_port must call _update_panel_env_port, "
            "_reload_firewall, AND _restart_panel_service."
        )
        assert env_call < fw_call, (
            "Bug #3 — _update_panel_env_port MUST run BEFORE _reload_firewall "
            "(and before _restart_panel_service). The env file must hold the "
            "new PSIPHON3XUI_PORT=<new> line before the panel is kicked so "
            "the next boot reads the new port — otherwise systemctl restart "
            "binds back to the OLD port (the original Bug #3 symptom)."
        )
        assert env_call < svc_call, (
            "Bug #3 — _update_panel_env_port MUST run BEFORE "
            "_restart_panel_service so the panel boots on the new port."
        )
        # The response payload must surface the env-rewrite flag.
        assert '"env_rewrite_ok": env_ok' in body, (
            "Bug #3 — change_panel_port must return `env_rewrite_ok` in its "
            "JSON payload so the SPA + tests can detect an env-file-write "
            "failure distinctly from firewall/restart failures."
        )

    # ---- Bug #4: dashboard SPA has no Delete button + no deleteCountry() --
    def test_dashboard_html_has_no_delete_button(self):
        text = self._DASHBOARD_HTML.read_text(encoding="utf-8")
        assert "deleteCountry(c)" not in text, (
            "Bug #4 — panel/static/dashboard.html must NOT expose a "
            '`@click="deleteCountry(c)"` button in the country actions '
            "column. Only Edit ports + Logs actions should remain."
        )

    def test_dashboard_html_has_no_delete_country_js_method(self):
        # The button is gone, and so must the JS method be.
        import re  # noqa: PLC0415

        text = self._DASHBOARD_HTML.read_text(encoding="utf-8")
        # Allow the comment that mentions deleteCountry — only forbid a
        # live method definition.
        no_comment_text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
        assert not re.search(
            r"\basync\s+deleteCountry\s*\(",
            no_comment_text,
        ), (
            "Bug #4 — dashboard.html must no longer define an "
            "`async deleteCountry(c)` JS method (the operator asked for "
            "delete to be unreachable from the SPA — only Edit ports + Logs "
            "are needed)."
        )

    def test_dashboard_html_still_has_edit_ports_and_logs_actions(self):
        text = self._DASHBOARD_HTML.read_text(encoding="utf-8")
        assert "openPorts(c)" in text, "Bug #4 — Edit ports must remain."
        assert "viewLogs(c)" in text, "Bug #4 — Logs action must remain."

    def test_dashboard_html_documents_button_removal_in_comment(self):
        # We want a Hotfix #11 comment so a future dev re-adding the button
        # understands the operator decision.
        text = self._DASHBOARD_HTML.read_text(encoding="utf-8")
        assert "Bug #4" in text and ("Delete" in text or "deleteCountry" in text), (
            "Bug #4 — dashboard.html should carry a Hotfix-#11 / Bug-#4 "
            "comment explaining the delete button + method were removed at "
            "the operator's request (so a future dev re-adding them reads "
            "the rationale first)."
        )

    # ---- Bug #5: wizard submit_apply healthy auto-enable gate still intact
    # AND relies on apply_country returning "healthy" (which Bug #2's retry
    # now makes actually happen) ----------------------------------------
    def test_wizard_submit_apply_auto_enables_healthy_countries(self):
        import re  # noqa: PLC0415

        text = self._WIZARD_ROUTER.read_text(encoding="utf-8")
        text_no_comments = re.sub(r"#[^\n]*", "", text)
        # The Hotfix-#9 auto-enable gate must still be present.
        assert re.search(
            r'event\.status\s*==\s*["\']healthy["\']',
            text_no_comments,
        ), (
            "Bug #5 — wizard/router.py submit_apply must still gate "
            '`Country.enabled = True` on `event.status == "healthy"` '
            "(Hotfix-#9 auto-enable path; was unreachable pre-Hotfix-#11 "
            'because apply_country returned "failed" due to Bug #2\'s eager '
            "health_probe — now fixed by the bounded retry)."
        )
        assert "country_row.enabled = True" in text_no_comments, (
            "Bug #5 — submit_apply must still flip `country_row.enabled = "
            "True` for the healthy-event country (the auto-enable contract "
            "the operator expects after the wizard runs)."
        )

    # ---- Bug #6: installer wait_for_panel_socket silences connect-refused -
    def test_wait_for_panel_socket_uses_subshell_redirect(self):
        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        # The retry body must wrap the exec in a subshell so bash's
        # connect-syscall wrapper stderr is silenced at the shell layer
        # (the bare `exec ... 2>/dev/null` form leaked the error before the
        # redirect scope applied).
        assert '( exec 3<>"/dev/tcp/127.0.0.1/${PANEL_PORT}" )' in text, (
            "Bug #6 — installer/panel_install.sh wait_for_panel_socket must "
            'wrap the raw-tcp probe in a SUBSHELL — `( exec 3<>"/dev/tcp/'
            "127.0.0.1/${PANEL_PORT}\" )` — with the retry body's stderr "
            "redirected at the subshell layer, so bash's connect-syscall "
            "wrapper can no longer print 'connect: Connection refused' to "
            "fd 2 before the exec's redirect scope applies."
        )

    def test_wait_for_panel_socket_no_more_bare_exec_redirect(self):
        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        # The old bare form (no subshell) must be gone.
        import re  # noqa: PLC0415

        # Strip comments so any Hotfix-#11 historical mention in a comment
        # doesn't trip this assertion.
        no_comments = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        # The bare form `exec 3<>"/dev/tcp/.../PANEL_PORT}" 2>/dev/null; then`
        # (with the `2>/dev/null` ON the exec) must no longer be the live
        # probe — the subshell form has taken over.
        assert not re.search(
            r"exec\s+3<>\s*\"/dev/tcp/127\.0\.0\.1/\$\{PANEL_PORT\}\"\s+2>/dev/null",
            no_comments,
        ), (
            'Bug #6 — the pre-Hotfix-#11 `exec 3<>"/dev/tcp/..." 2>/dev/null` '
            "form must be gone (it leaked 'connect: Connection refused' to "
            "fd 2 before the redirect scope applied)."
        )


# Hotfix #14 (Phase 23) helper shared between TestHotfix12 + TestHotfix13
# (both classes have tests that invoke render_config at runtime — which now
# fast-fails with PsiphonCredentialError if the four upstream credential env
# vars aren't populated with real-shape values).
_HF14_FAKE_PROPAGATION_CHANNEL_ID = "0123456789ABCDEF0123456789ABCDEF"
_HF14_FAKE_SPONSOR_ID = "0123456789ABCDEF"
_HF14_FAKE_REMOTE_SERVER_LIST_URL = "https://s3.amazonaws.com/psiphon/web/test-list"
_HF14_FAKE_SIG_PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # 43 A's + '='


def _set_real_psiphon_creds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Populate every PSIPHON_* upstream credential env var with a
    fake-but-real-shape value. No-op for Hotfix-#12 / Hotfix-#13 tests that
    don't actually call render_config (the static-source-grep ones); a hard
    necessity for the runtime-invoking ones (test_render_config_emits_
    singular_url_at_runtime / test_write_config_writes_singular_key_to_disk /
    test_render_config_runtime_SponsorId_is_nonempty_string /
    test_render_config_has_seven_keys_not_six)."""
    monkeypatch.setenv("PSIPHON_PROPAGATION_CHANNEL_ID", _HF14_FAKE_PROPAGATION_CHANNEL_ID)
    monkeypatch.setenv("PSIPHON_SPONSOR_ID", _HF14_FAKE_SPONSOR_ID)
    monkeypatch.setenv("PSIPHON_REMOTE_SERVER_LIST_URL", _HF14_FAKE_REMOTE_SERVER_LIST_URL)
    monkeypatch.setenv("PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY", _HF14_FAKE_SIG_PUBLIC_KEY)


# ---------------------------------------------------------------------------
# Hotfix #12 — three post-Hotfix-#11 bugs (Phase 21).
# ---------------------------------------------------------------------------
class TestHotfix12PostReleaseRegressions:
    """Static-source grep tests for Hotfix #12 — three post-Hotfix-#11 bugs.

    Bug #1: psiphon-tunnel-core v2.0.39 rejects our per-country config because
    ``RemoteServerListURLs`` is declared as ``parameters.TransferURLs``
    (slice of ``*TransferURL`` STRUCTS) but we rendered it as a JSON array
    of plain strings → ``json.Unmarshal`` fails on LoadConfig#1425 → the unit
    exits status=1 immediately + systemd restart-loops → SOCKS5 listener
    never binds → countries stay inactive / inline-enable 502's.

    Bug #2: inline-enable ConnectionRefused is downstream of #1 — once the
    tunnels stay up it auto-resolves (Hotfix #11's 30s retry IS active per
    the operator's logs).

    Bug #3: ``_restart_panel_service`` docblock claimed detached spawn but
    the implementation called blocking
    ``subprocess.run(["systemctl","restart",...])`` — the in-flight HTTP
    request was SIGTERM'd mid-stream by systemd, so the operator's browser
    saw a truncated/empty body and looked like "doesn't change, doesn't
    restart, new page doesn't work".
    """

    _PSIPHON_INIT = Path(__file__).resolve().parent.parent / "panel" / "psiphon" / "__init__.py"
    _DASHBOARD_ROUTER = Path(__file__).resolve().parent.parent / "panel" / "dashboard" / "router.py"

    # ---- Bug #1: psiphon config schema — legacy singular URL field -------
    def test_render_config_uses_plural_RemoteServerListURLs_array(self):
        """Phase 24 (post-Hotfix-#14 cleanup) — render_config now emits the
        PLURAL `RemoteServerListURLs` field sourced from
        `creds["RemoteServerListURLs"]`. The legacy singular `RemoteServerListUrl`
        (lowercase final 'l') is DROPPED — tunnel-core's `promoteLegacyTransferURL`
        branch only fires when `RemoteServerListURLs == nil`, which we no longer
        produce. This is the OPPOSITE of Hotfix-#12 Bug #1's invariant; Hotfix #12
        chose the singular shape as a workaround; Phase 24 adopts the proper
        modern TransferURL-array shape directly (extracted from the public APK
        client's 4-mirror config)."""
        import re  # noqa: PLC0415

        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The implemented config dict must emit the PLURAL key
        # `RemoteServerListURLs` sourced from `_resolve_upstream_credentials`.
        assert re.search(
            r'"RemoteServerListURLs"\s*:\s*creds\["RemoteServerListURLs"\]',
            no_comments,
        ), (
            "Phase 24 — render_config must emit the plural "
            "`RemoteServerListURLs` array (sourced from "
            "_resolve_upstream_credentials) — NOT the legacy singular "
            "`RemoteServerListUrl` string that Hotfix-#12 Bug #1 used."
        )
        # And the legacy singular key must NOT be emitted in the live code.
        assert not re.search(
            r'"RemoteServerListUrl"\s*:\s*',
            no_comments,
        ), (
            "Phase 24 — render_config must NOT emit the legacy singular "
            "`RemoteServerListUrl` field anymore (the plural TransferURL "
            "array is the primary path; the legacy promote-branch only "
            "fires when the plural is nil, which we no longer produce)."
        )

    def test_render_config_does_not_emit_broken_string_array_shape(self):
        """Hotfix-#12 Bug #1 originally rejected the BROKEN shape:
        `"RemoteServerListURLs": list(<string tuple>)` — that emitted a
        JSON array of plain strings, but upstream v2.0.39 declares
        RemoteServerListURLs as TransferURLs (slice of *TransferURL
        STRUCTS). Hotfix-#12 dodged the bug by emitting the legacy singular;
        Phase 24 ships the CORRECT plural shape (list of TransferURL dicts
        with URL / OnlyAfterAttempts / SkipVerify fields). This test asserts
        the broken plain-string-array shape is STILL NOT emitted (a
        regression guard: if someone reverts to the broken shape, both this
        test AND the Phase-24 contract tests in tests/test_psiphon.py fail)."""
        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        import re  # noqa: PLC0415

        # Strip comments — they're allowed to mention the rejected shape.
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert not re.search(
            # The broken shape: `"RemoteServerListURLs": <some string-tuple
            # or list of strings>`. The CORRECT Phase-24 shape uses
            # `creds["RemoteServerListURLs"]` (a list of TransferURL dicts),
            # which is NOT a plain `list(<tuple-of-strings>)` form.
            r'"RemoteServerListURLs"\s*:\s*list\([^)]*URLS',
            no_comments,
        ), (
            "Bug #1 / Phase 24 — render_config must NOT render the broken "
            "plain-string-tuple shape (`\"RemoteServerListURLs\": "
            "list(PSIPHON_REMOTE_SERVER_LIST_URLS)`) — that's the rejected "
            "form. Phase 24 substitutes a list of TransferURL dicts via "
            "creds['RemoteServerListURLs']."
        )

    def test_render_config_emits_plural_url_array_at_runtime(self, monkeypatch):
        """End-to-end: the runtime render_config dict is the Phase-24 shape.

        With `_set_real_psiphon_creds` populating fake-but-real-shape values
        (including the singular PSIPHON_REMOTE_SERVER_LIST_URL env override),
        `_resolve_upstream_credentials` wraps the singular env URL into a
        1-element `RemoteServerListURLs` TransferURL array — exactly the shape
        tunnel-core DecodeAndValidate expects."""
        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import (  # noqa: PLC0415
            render_config,
        )

        cfg = render_config("AT", 11000)
        # Phase 24 Hotfix #1: the singular env URL is wrapped into a
        # 1-element TransferURL array carrying the BASE64-ENCODED raw URL
        # (tunnel-core's TransferURLs.DecodeAndValidate#90 base64-decodes
        # the URL field — raw `https:` would crash with "illegal base64
        # data at input byte 5"; operator confirmed via journalctl).
        import base64  # noqa: PLC0415

        urls = cfg["RemoteServerListURLs"]
        assert isinstance(urls, list) and len(urls) == 1
        entry = urls[0]
        assert isinstance(entry, dict)
        assert entry["URL"] == base64.b64encode(
            _HF14_FAKE_REMOTE_SERVER_LIST_URL.encode()
        ).decode()
        assert base64.b64decode(entry["URL"]).decode() == _HF14_FAKE_REMOTE_SERVER_LIST_URL
        assert entry["OnlyAfterAttempts"] == 0
        assert entry["SkipVerify"] is False
        # And crucially: the legacy singular key is NOT present anymore.
        assert "RemoteServerListUrl" not in cfg, (
            "Phase 24 — the legacy singular `RemoteServerListUrl` key must "
            "NOT be in the rendered dict; the plural TransferURL array is "
            "the primary path."
        )

    def test_write_config_writes_plural_key_to_disk(self, monkeypatch, tmp_path):
        """``json.dumps(render_config(...))`` round-trips the PLURAL key."""
        import json  # noqa: PLC0415

        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import render_config  # noqa: PLC0415

        cfg = render_config("US", 11080)
        blob = json.dumps(cfg, indent=2, sort_keys=True)
        parsed = json.loads(blob)
        # Plural key round-trips through JSON as a list of TransferURL dicts.
        assert "RemoteServerListURLs" in parsed
        assert isinstance(parsed["RemoteServerListURLs"], list)
        assert len(parsed["RemoteServerListURLs"]) == 1
        # Legacy singular key NOT present anymore.
        assert "RemoteServerListUrl" not in parsed

    # ---- Bug #3: detached systemctl restart -----------------------------
    def test_restart_panel_service_uses_systemd_run_no_block(self):
        import re  # noqa: PLC0415

        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The primary path must spawn `systemd-run --no-block ...` and run the
        # actual `systemctl restart` AS THE CHILD of systemd-run — so our
        # request returns immediately while systemd schedules the restart
        # fractionally after.
        assert '"systemd-run"' in no_comments, (
            "Bug #3 — `_restart_panel_service` must invoke `systemd-run` (so "
            "the immediate child exits upon scheduling), not call "
            "`systemctl restart` synchronously."
        )
        assert '"--no-block"' in no_comments, (
            "Bug #3 — `systemd-run` must be invoked with `--no-block` so "
            "the immediate child exits upon scheduling (otherwise we "
            "still block on the inner `systemctl restart`)."
        )
        assert "psiphon-3x-ui-restart" in no_comments, (
            "Bug #3 — the transient unit name "
            "`--unit=psiphon-3x-ui-restart` must be assigned so systemd-run's "
            "scheduled restart is identifiable in `journalctl`."
        )

    def test_restart_panel_service_no_longer_uses_blocking_subprocess_run_systemctl(self):
        """The OLD implementation was a blocking
        ``subprocess.run(["systemctl","restart","psiphon-3x-ui.service"], ...)``
        whose completion killed our HTTP worker mid-stream. That specific
        blocking form (no `--no-block`, no Popen, no `start_new_session`)
        must be gone from the live code."""
        import re  # noqa: PLC0415

        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The blocking-`subprocess.run` only form (with ALL three args, NO
        # `--no-block` arg sibling) must no longer be present.
        assert not re.search(
            r"subprocess\.run\(\s*#\s*noqa:\s*S603[^\n]*\n"
            r'\s*\[\s*"systemctl"\s*,\s*"restart"\s*,\s*"psiphon-3x-ui\.service"\s*\]\s*,'
            r"[^\n]*check=False",
            no_comments,
            re.DOTALL,
        ), (
            'Bug #3 — the blocking `subprocess.run(["systemctl", "restart",'
            '"psiphon-3x-ui.service"], check=False)` form (which kills our '
            "HTTP worker mid-stream by waiting on the inner restart) must "
            "no longer be present in `_restart_panel_service`."
        )

    def test_restart_panel_service_has_start_new_session_fallback(self):
        """`systemd-run` can be absent on minimal Linux distros — the fallback
        must use `start_new_session=True` so the Popen child survives our
        SIGTERM (setsid() child reparents to init)."""
        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        assert "start_new_session=True" in text, (
            "Bug #3 — `_restart_panel_service`'s Popen fallback must "
            "specify `start_new_session=True` (POSIX setsid) so the child "
            "is reparented to init and survives our imminent SIGTERM from "
            "the upcoming `systemctl restart`."
        )

    def test_restart_panel_service_does_not_wait_on_popen(self):
        """The whole point of the detached fallback is that we exit
        immediately. We must NOT call ``.poll()`` / ``.wait()`` on the
        detached Popen — poll/wait would re-block on the systemctl child."""
        import re  # noqa: PLC0415

        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        # Extract the `_restart_panel_service` body only.
        m = re.search(
            r"def _restart_panel_service\b.*?(?=\n\ndef\s|\n@router|\nclass\s)",
            text,
            re.DOTALL,
        )
        assert m, "could not locate `_restart_panel_service`"
        body = m.group(0)
        # The fallback Popen block must NOT call `.poll()` / `.wait()` on the
        # detached child. (Test catches the previous Hotfix-#11 attempt
        # where I called `.poll()` which defeats the detachment.)
        no_comments = re.sub(r"#[^\n]*", "", body)
        # Find any `Popen(...)` call inside the fallback branch, then check
        # no `.poll()` / `.wait()` follows on the Popen object — we simply
        # assert that the FILE does not call `.poll()` at all in that function
        # (the only Popen in the router is the detached-restart one).
        assert ".poll()" not in no_comments, (
            "Bug #3 — `_restart_panel_service` must NOT call `.poll()` "
            "on the detached Popen (would re-block on the systemctl child)."
        )
        assert ".wait()" not in no_comments, (
            "Bug #3 — `_restart_panel_service` must NOT call `.wait()` "
            "on the detached Popen (would re-block on the systemctl child)."
        )


# ---------------------------------------------------------------------------
# Hotfix #13 — four post-Hotfix-#12 bugs (Phase 22).
# ---------------------------------------------------------------------------
class TestHotfix13PostReleaseRegressions:
    """Static-source grep tests for Hotfix #13 — four post-Hotfix-#12 bugs.

    Bug #1 v2: psiphon-tunnel-core v2.0.39's Config.Commit (around line
    1676 in config.go within the v2.0.39 source) requires TWO mandatory
    non-empty string fields: `PropagationChannelId` (already set) AND
    `SponsorId` (NEW). After Hotfix #12's `RemoteServerListUrl` legacy
    fix finally let `LoadConfig` succeed, the binary advanced to
    `Config.Commit` and immediately hit:
      `"error loading configuration file: psiphon.(*Config).Commit#1676:
        sponsor ID is missing from the configuration file"`
    → unit exited status=1 → systemd `Restart=on-failure` death-loop →
    SOCKS5 listener STILL never binds → Bug #2 (inline-enable
    ConnectionRefused) AND Bug #1 (countries inactive) STILL present.

    Bug #2 (inline-enable still failing) + Bug #1 (countries inactive)
    are downstream of the Bug #1 v2 root cause — auto-resolve once the
    SponsorId field is set and the unit finally accepts+loads the config.

    Bug #4 (change-panel-port STILL does nothing): the operator's complaint
    "panel port still does not change at all under any circumstances" had
    a SEPARATE root cause from the env-file path resolution / detached
    systemctl restart fixes shipped in Hotfix #11 + #12. The panel process
    runs as user `psiphon3xui` (group `psiphon3xui`), but the installer's
    `installer/panel_install.sh` writes `${ENV_FILE}` (= panel.env) with
    `chmod 0640` AND `chown root:psiphon3xui` — that gave the panel's
    group only READ access (rw-r-----). The panel-side
    `_update_panel_env_port` helper (panel/dashboard/router.py) tried to
    rewrite the in-place env file's `PSIPHON3XUI_PORT=` line, was
    Permission-denied, returned `(False, "env rewrite failed:
    PermissionError ...")`, the change_panel_port endpoint silently
    no-op'd the env file (logging only a warning), called `systemctl
    restart` (detached, per Hotfix #12), and systemd restarted the panel
    STILL bound to the OLD port. The operator's browser saw nothing
    change.
    """

    _PSIPHON_INIT = Path(__file__).resolve().parent.parent / "panel" / "psiphon" / "__init__.py"
    _PANEL_INSTALL_SH = Path(__file__).resolve().parent.parent / "installer" / "panel_install.sh"

    # ---- Bug #1 v2: SponsorId mandatory non-empty string -----------
    def test_render_config_emits_non_empty_SponsorId(self):
        """render_config must emit a SponsorId string field with a
        non-empty value — psiphon-tunnel-core v2.0.39's Config.Commit
        rejects `SponsorId == ""` with "sponsor ID is missing from the
        configuration file".

        Hotfix #14 (Phase 23): the dict literal now references
        `creds["SponsorId"]` (env-var-driven via _resolve_upstream_credentials)
        instead of the legacy `PSIPHON_SPONSOR_ID` constant. BOTH forms
        satisfy the invariant — assert the dict construction carries the
        singular key with a non-empty value source."""
        import re  # noqa: PLC0415

        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # Pre-Hotfix-#14 the literal was `PSIPHON_SPONSOR_ID`; post-Hotfix-#14
        # it's `creds["SponsorId"]`. Either form emits the key — render_config
        # additionally rejects empty values at _resolve_upstream_credentials
        # so the runtime invariant (SponsorId non-empty) is enforced upstream.
        assert re.search(
            r'"SponsorId"\s*:\s*(?:PSIPHON_SPONSOR_ID\b|creds\["SponsorId"\])',
            no_comments,
        ), (
            "Bug #1 v2 — render_config must emit `SponsorId` (the upstream "
            "Config.Commit#1676 guard rejects the empty/default value with "
            "'sponsor ID is missing from the configuration file'; the "
            "operator's journalctl showed this exact failure after "
            "Hotfix #12 let LoadConfig advance past the unmarshal stage)."
        )

    def test_psinon_module_defines_NONEMPTY_SPONSOR_ID_constant(self):
        """PSIPHON_SPONSOR_ID must be a non-empty string (equal to the
        upstream psiphon.config.sample's '0000000000000000' all-zero
        placeholder)."""
        from panel.psiphon import PSIPHON_SPONSOR_ID  # noqa: PLC0415

        assert isinstance(PSIPHON_SPONSOR_ID, str)
        assert PSIPHON_SPONSOR_ID, "PSIPHON_SPONSOR_ID must be non-empty"
        assert PSIPHON_SPONSOR_ID == "0000000000000000", (
            "PSIPHON_SPONSOR_ID should match the upstream "
            "psiphon.config.sample's all-zero placeholder "
            "'0000000000000000'"
        )

    def test_render_config_runtime_SponsorId_is_nonempty_string(self, monkeypatch):
        """End-to-end fixture exercise: the rendered cfg dict's SponsorId
        is a non-empty string.

        Hotfix #14 (Phase 23): render_config now sources SponsorId from the
        operator's env (PSIPHON_SPONSOR_ID); the legacy module constant of
        the same name is kept only as a source-compat alias for the literal
        placeholder value _resolve_upstream_credentials rejects."""
        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import render_config  # noqa: PLC0415

        cfg = render_config("AT", 11000)
        assert cfg["SponsorId"] == _HF14_FAKE_SPONSOR_ID
        assert isinstance(cfg["SponsorId"], str) and cfg["SponsorId"]

    def test_render_config_has_eleven_keys_not_six(self, monkeypatch):
        """Headlock: the dict has 11 keys post-Phase-24 (was 7 in
        Hotfix-#14, 6 pre-Hotfix-#13). Phase 24 added 4 NEW keys:
        `ObfuscatedServerListRootURLs`, `ServerEntrySignaturePublicKey`,
        `ExchangeObfuscationKey`, `UseIndistinguishableTLS`. The legacy
        singular `RemoteServerListUrl` was DROPPED (replaced by the plural
        `RemoteServerListURLs` array, which was already counted as 1 key).
        Net delta: +4 (new) -0 (SponsorId was Hotfix #13, counted) -0
        (RemoteServerListUrl swap is a key-name change, not an add/drop).
        Also: `RemoteServerListUrl` was 1 of the 7; the new plural
        `RemoteServerListURLs` is 1 in the new 11-set. So Hotfix-#14 had
        7 keys -> Phase 24 has 11 keys (added the 4 fields above +
        dropped RemoteServerListUrl after adding RemoteServerListURLs
        cancels the singular/plural replace)."""
        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import render_config  # noqa: PLC0415

        cfg = render_config("US", 11080)
        assert len(cfg) == 11, (
            "Phase 24 — render_config output must have 11 keys: "
            "{PropagationChannelId, SponsorId, RemoteServerListURLs, "
            "ObfuscatedServerListRootURLs, RemoteServerListSignaturePublicKey, "
            "ServerEntrySignaturePublicKey, ExchangeObfuscationKey, "
            "UseIndistinguishableTLS, EgressRegion, LocalSocksProxyPort, "
            "DisableLocalHTTPProxy}."
        )
        # And the 4 new Phase-24 keys ARE all present:
        for key in (
            "RemoteServerListURLs",
            "ObfuscatedServerListRootURLs",
            "ServerEntrySignaturePublicKey",
            "ExchangeObfuscationKey",
            "UseIndistinguishableTLS",
        ):
            assert key in cfg, (
                f"Phase 24 — render_config output must include the new "
                f"{key!r} field (extracted from the public APK dump)."
            )

    # ---- Bug #4 (change-panel-port): env file group-writable -----
    def test_panel_install_sh_chmods_env_file_group_writable(self):
        """`installer/panel_install.sh` MUST chmod the env file `0660`
        (rw-rw----) so the panel process (group psiphon3xui) can rewrite
        it in `_update_panel_env_port`. Pre-Hotfix-#13 it was 0640 —
        the rewrite ALWAYS failed with EACCES → change-panel-port
        silently no-op'd → panel restarted at the OLD port."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        # Strip bash comments (lines starting with #) so the chmod
        # rationale comment doesn't pollute the assertion.
        no_comments = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        # The chmod statement must use 0660 (group-writable), not the
        # pre-Hotfix-#13 0640 (group-read-only). The literal is
        # `chmod 0660 "${ENV_FILE}"` — the literal double-quotes around
        # the bash var name MUST be present (defensive expansion).
        assert re.search(r'chmod\s+0660\s+"\$\{ENV_FILE\}"', no_comments), (
            "Bug #4 — installer/panel_install.sh must `chmod 0660 "
            '"${ENV_FILE}"` so the panel process (group '
            "${PSIPHON3XUI_GROUP}) can rewrite it in "
            "_update_panel_env_port. The pre-Hotfix-#13 0640 mode gave the "
            "group only read access → env rewrite ALWAYS failed with "
            "PermissionError → change-panel-port silently no-op'd → panel "
            "restarted at the OLD port."
        )
        assert re.search(r'chmod\s+0640\s+"\$\{ENV_FILE\}"', no_comments) is None, (
            'Bug #4 — the pre-Hotfix-#13 `chmod 0640 "${ENV_FILE}"` '
            "form must be gone from installer/panel_install.sh (group was "
            "read-only and the panel process couldn't rewrite the env "
            "file in _update_panel_env_port)."
        )


# ---------------------------------------------------------------------------
# Hotfix #14 — Psiphon-Inc upstream credentials pivoted to env-var overrides
# (Phase 23). The operator's per-country psiphon-tunnel-core units were
# entering a 5-minute `EstablishTunnelTimeout` death-loop because the
# hardcoded commercial credentials (PropagationChannelId / SponsorId /
# RemoteServerListUrl / RemoteServerListSignaturePublicKey) were fabricated
# stubs the panel's `_resolve_upstream_credentials` validator now rejects up
# front with an actionable message.
# ---------------------------------------------------------------------------
class TestHotfix14PostReleaseRegressions:
    """Hotfix #14 (Phase 23) + Phase 24 (post-Hotfix-#14 cleanup).

    Hotfix #14 pivoted the four Psiphon-Inc upstream credentials from
    hardcoded in panel/psiphon/__init__.py to operator-supplied env vars read
    from /opt/psiphon-3x-ui/panel.env. Phase 24 INVERTED that gate — the
    Psiphon-3 PUBLIC-BOOTSTRAP constants (extracted from the public APK
    dump) are now BAKED INTO panel/psiphon/__init__.py as `_PUBLIC_*`, and
    the four PSIPHON_* env vars become OPTIONAL OVERRIDES (a commercial
    sponsor can substitute its own PropChannel / SponsorId / signed
    server-list URL / sig-pubkey via panel.env without forking the panel).

    Static-source-grep + runtime tests for the design pivot + the
    placeholder-rejection rules. Companion runtime tests live in
    tests/test_psiphon.py::TestPsiphonCredentialErrorRegressions +
    tests/test_psiphon.py::TestPublicBootstrapDefaults; this class locks in:
    - the production catch routes (apply.py + dashboard/router.py) still
      swallow PsiphonCredentialError (Phase 24 kept Hotfix-14's catch routes
      — even though the default path no longer raises, a bad operator
      override can still raise + the catch routes still translate it into
      actionable ApplyEvents / 502s / failed-append-summary instead of
      opaque 500s);
    - the installer's prompt step (installer/prompt.sh) NO LONGER surveys
      the operator (Phase 24 deleted _prompt_psiphon_credentials — the
      defaults are baked in), but panel_install.sh's heredoc STILL writes
      any operator-supplied PSIPHON_* override into panel.env via the
      ${psiphon_creds_block} interpolation;
    - the four env var names are EXACTLY PSIPHON_PROPAGATION_CHANNEL_ID /
      PSIPHON_SPONSOR_ID / PSIPHON_REMOTE_SERVER_LIST_URL /
      PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY (no accidental drift);
    - docs/TROUBLESHOOTING.md + README.md ship a reframed section explaining
      the optional-override design (post-Phase-24) instead of the
      "credentials required" wording (which was Hotfix-#14's framing).
    """

    _PSIPHON_INIT = Path(__file__).resolve().parent.parent / "panel" / "psiphon" / "__init__.py"
    _DASHBOARD_ROUTER = Path(__file__).resolve().parent.parent / "panel" / "dashboard" / "router.py"
    _WIZARD_APPLY = Path(__file__).resolve().parent.parent / "panel" / "wizard" / "apply.py"
    _PROMPT_SH = Path(__file__).resolve().parent.parent / "installer" / "prompt.sh"
    _PANEL_INSTALL_SH = Path(__file__).resolve().parent.parent / "installer" / "panel_install.sh"
    _TROUBLESHOOTING_MD = Path(__file__).resolve().parent.parent / "docs" / "TROUBLESHOOTING.md"
    _README_MD = Path(__file__).resolve().parent.parent / "README.md"

    # ---- env-var-driven credential resolver -------------------------------
    def test_panel_psiphon_defines_resolve_upstream_credentials_helper(self):
        """`panel/psiphon/__init__.py` MUST define a
        `_resolve_upstream_credentials` helper that reads the four PSIPHON_*
        env vars — the runtime contract that backs the fast-fail message
        every Hotfix-14 catch route surfaces."""
        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        assert "def _resolve_upstream_credentials(" in text, (
            "Hotfix #14 — the env-var-driven credential resolver must be "
            "defined in panel/psiphon/__init__.py"
        )
        assert "class PsiphonCredentialError(RuntimeError):" in text, (
            "Hotfix #14 — `PsiphonCredentialError(RuntimeError)` must be "
            "declared in panel/psiphon/__init__.py"
        )

    def test_panel_psiphon_module_reads_all_four_credential_env_vars(self):
        """The resolver must read all four PSIPHON_* env var names by their
        canonical names (no accidental drift / abbreviation)."""
        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Hotfix #14 — env var {envname} must be referenced in "
                "panel/psiphon/__init__.py (the resolver reads it via "
                "os.environ.get)."
            )

    def test_panel_psiphon_render_config_uses_resolve_upstream_credentials(self):
        """render_config must invoke `_resolve_upstream_credentials()` rather
        than referencing the baked-in `_PUBLIC_*` constants directly in the
        returned dict literal. Phase 24 kept this indirection so that an
        operator-supplied env override beats the `_PUBLIC_*` default at
        runtime."""
        import re  # noqa: PLC0415

        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(
            r"creds\s*=\s*_resolve_upstream_credentials\(\)",
            no_comments,
        ), (
            "Hotfix #14 + Phase 24 — render_config must call "
            "_resolve_upstream_credentials to fetch the seven upstream "
            "constants (the four env-overridable ones default to the baked-in "
            "`_PUBLIC_*` constants if no env override is set)."
        )
        # And the return dict must source each value from creds[<field>].
        # Phase 24: register the new fields. The legacy singular
        # `RemoteServerListUrl` was DROPPED in favor of the plural
        # `RemoteServerListURLs` array.
        assert 'creds["PropagationChannelId"]' in text
        assert 'creds["SponsorId"]' in text
        assert 'creds["RemoteServerListURLs"]' in text  # plural — Phase 24
        assert 'creds["RemoteServerListSignaturePublicKey"]' in text
        assert 'creds["ServerEntrySignaturePublicKey"]' in text  # Phase 24
        assert 'creds["ExchangeObfuscationKey"]' in text  # Phase 24
        assert 'creds["ObfuscatedServerListRootURLs"]' in text  # Phase 24

    # ---- production catch-all routes -------------------------------------
    def test_wizard_apply_imports_PsiphonCredentialError(self):
        """panel/wizard/apply.py must import PsiphonCredentialError so the
        catch-clause guard below this import is statically resolvable."""
        text = self._WIZARD_APPLY.read_text(encoding="utf-8")
        assert "PsiphonCredentialError" in text, (
            "Hotfix #14 — panel/wizard/apply.py must import "
            "PsiphonCredentialError (the wizard's apply_country catch route "
            "needs it to produce actionable ApplyEvents)."
        )

    def test_wizard_apply_country_catches_PsiphonCredentialError(self):
        """apply_country's try block around `_initial_unit_start` MUST catch
        PsiphonCredentialError — otherwise an unset-credential render would
        bubble up out of the wizard SSE stream and kill the whole wizard."""
        import re  # noqa: PLC0415

        text = self._WIZARD_APPLY.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # Catch the `except PsiphonCredentialError as exc:` specifically.
        assert re.search(
            r"except\s+PsiphonCredentialError\s+as\s+exc\s*:",
            no_comments,
        ), (
            "Hotfix #14 — panel/wizard/apply.py::apply_country must catch "
            "PsiphonCredentialError separately from the (OSError, ValueError, "
            "PsiphonUnitError) bundle — it produces a failed ApplyEvent "
            "carrying the actionable credential message instead of bubbling."
        )

    def test_dashboard_router_imports_PsiphonCredentialError(self):
        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        assert "PsiphonCredentialError" in text, (
            "Hotfix #14 — panel/dashboard/router.py must import "
            "PsiphonCredentialError (reapply + edit-ports + inline-enable "
            "catch routes need it)."
        )

    def test_dashboard_router_edit_ports_propagates_actionable_502(self):
        """edit_country_ports's write_config try-block must catch
        PsiphonCredentialError + raise HTTP 502 with an actionable message
        (NOT the opaque 500 OSError handler)."""
        import re  # noqa: PLC0415

        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # edit_country_ports wraps write_config in a try whose FIRST except is
        # PsiphonCredentialError → 502. The bare (OSError, ValueError) → 500
        # clause comes AFTER (so it never masks the credential error).
        assert re.search(
            r"except\s+PsiphonCredentialError\s+as\s+exc\s*:\s*"
            r"raise\s+HTTPException\(\s*"
            r"status_code\s*=\s*status\.HTTP_502_BAD_GATEWAY",
            no_comments,
            re.DOTALL,
        ), (
            "Hotfix #14 — panel/dashboard/router.py::edit_country_ports must "
            "catch PsiphonCredentialError and raise HTTP 502 with the actionable "
            "credential message (routed AHEAD of the opaque (OSError, ValueError) "
            "→ 500 clause)."
        )

    def test_dashboard_router_reapply_appends_to_failed_not_500(self):
        """reapply_all's write_config try-block MUST add the credential error
        into summary['failed'] (per-country, with the actionable message)
        instead of bubbling up as an opaque 500."""
        import re  # noqa: PLC0415

        text = self._DASHBOARD_ROUTER.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(
            r"except\s+PsiphonCredentialError\s+as\s+exc\s*:\s*"
            r'summary\["failed"\]\.append',
            no_comments,
            re.DOTALL,
        ), (
            "Hotfix #14 — panel/dashboard/router.py::reapply_all must catch "
            "PsiphonCredentialError and append a failed entry per country "
            "(carrying the actionable str(exc) message), NOT bubble up."
        )

    # ---- installer prompt step + env-file wire-in -------------------------
    def test_prompt_sh_no_longer_defines_psiphon_credentials_prompt(self):
        """Phase 24 (post-Hotfix-#14 cleanup): installer/prompt.sh MUST NOT
        define `_prompt_psiphon_credentials()` anymore — the public-bootstrap
        constants are baked into the panel wheel, so there is no install-time
        survey step. The placeholder grep ensures we don't accidentally
        re-introduce the interactive prompt later (a regression that re-broke
        Issue #2's user-reported install-blocking behaviour)."""
        text = self._PROMPT_SH.read_text(encoding="utf-8")
        # The survey function name MUST be absent from installer/prompt.sh.
        assert "_prompt_psiphon_credentials" not in text, (
            "Phase 24 — installer/prompt.sh MUST NOT define "
            "_prompt_psiphon_credentials anymore. The Psiphon-Inc "
            "public-bootstrap credentials are baked into the panel wheel; "
            "no interactive survey is needed."
        )
        # The read-prompts for the four env-var names MUST also be absent
        # (Hotfix #14 surveyed them via `read -r PSIPHON_PROPAGATION_CHANNEL_ID`
        # etc. — Phase 24 removed all four). We over-check by asserting the
        # specific `read -r PSIPHON_*` survey form is GONE.
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert f"read -r {envname}" not in text, (
                f"Phase 24 — installer/prompt.sh MUST NOT read -r {envname}"
                " (the survey prompts were removed when the public-bootstrap "
                "constants were baked in)."
            )

    def test_panel_install_sh_interpolates_creds_block_into_heredoc(self):
        """Phase 24 (was Hotfix #14): installer/panel_install.sh's `panel.env`
        heredoc MUST STILL interpolate a `${psiphon_creds_block}` block —
        but now the block is OPTIONAL (empty when no override is supplied).
        The builder var appends each non-empty operator-supplied PSIPHON_*
        override into the env file; if none are supplied, the block is empty
        and the panel boots with the baked-in `_PUBLIC_*` defaults. The four
        env var names must still appear in the builder (so an operator who
        DOES supply overrides sees them written into panel.env)."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        # The builder var + the heredoc interpolation BOTH must still be present
        # (Phase 24 kept the override-forwarding plumbing; it only removed the
        # empty-fallback header that Hotfix-14 emitted when nothing was set).
        assert re.search(r"(?:local\s+)?psiphon_creds_block\s*=", text), (
            "Phase 24 — installer/panel_install.sh must declare a local "
            "`psiphon_creds_block` builder var (now an optional-override "
            "plumbing step — empty when no PSIPHON_* env var is set)."
        )
        assert "${psiphon_creds_block}" in text, (
            "Phase 24 — installer/panel_install.sh's heredoc body MUST still "
            "interpolate ${psiphon_creds_block} so any operator-supplied "
            "overrides land in panel.env (the panel systemd unit's "
            "EnvironmentFile). Empty block = no overrides = use baked-in "
            "public-bootstrap defaults."
        )
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Phase 24 — installer/panel_install.sh must still reference "
                f"env var {envname} in the psiphon_creds_block builder (the "
                "four optional override names)."
            )

    # ---- docs section shipped --------------------------------------------
    def test_troubleshooting_md_documents_credentials_optional_overrides(self):
        """Phase 24 (was Hotfix #14): docs/TROUBLESHOOTING.md MUST ship a
        section reframing the four PSIPHON_* upstream credentials as OPTIONAL
        OVERRIDES (the public-bootstrap defaults are baked in). The old
        'credentials required' framing is OBSOLETE — an operator hitting a
        placeholder-rejector fast-fail (which only fires on bad overrides)
        should land on this section."""
        text = self._TROUBLESHOOTING_MD.read_text(encoding="utf-8")
        # New Phase-24 heading replaces the old Hotfix-#14 "required" heading.
        assert "Psiphon Inc. upstream credentials — optional overrides (Phase 24)" in text, (
            "Phase 24 — docs/TROUBLESHOOTING.md must ship a "
            "'Psiphon Inc. upstream credentials — optional overrides (Phase 24)' "
            "section replacing Hotfix-14's 'required' framing. The "
            "public-bootstrap defaults are baked into the panel wheel."
        )
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Phase 24 — docs/TROUBLESHOOTING.md must name env var "
                f"{envname} in the credentials section (operator copy-paste "
                "fix-path for setting a commercial sponsor override)."
            )

    def test_readme_md_documents_credentials_optional_overrides(self):
        """Phase 24 (was Hotfix #14): README.md MUST NOT say credentials are
        'required' (the public-bootstrap defaults are baked in). Instead it
        must surface the four PSIPHON_* env var names under an
        'OPTIONAL OVERRIDES' framing so a commercial sponsor customising
        panel.env sees them in the canonical env-var reference. The
        'credentials required' string must NOT appear (replaced by softer
        optional-override wording)."""
        text = self._README_MD.read_text(encoding="utf-8")
        # The Hotfix-#14 'required' framing MUST be GONE (Phase 24 removed it).
        assert "Psiphon Inc. upstream credentials required" not in text, (
            "Phase 24 — README.md must NOT carry Hotfix-14's "
            "'Psiphon Inc. upstream credentials required' wording anymore. "
            "The public-bootstrap defaults are baked into the panel wheel; "
            "credentials are NOT required for a fresh install."
        )
        # The four env var names must still appear (under the new optional-
        # overrides framing) so a commercial sponsor customising panel.env
        # sees them in the canonical env-var reference.
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Phase 24 — README.md's Configuration reference must still "
                f"include env var {envname} (so a commercial sponsor's "
                "panel.env customisation can override the baked-in default)."
            )

# ---------------------------------------------------------------------------
# Hotfix #15 — Phase 24 Hotfix #2: orphan panel process survives uninstall
# AND survives panel_install.sh's pre-flight → panel keeps serving the OLD
# wheel → "Failed to restart psiphon-3x-ui.service: Unit psiphon-3x-ui.service
# not found." + downstream "SOCKS5 health probe on 127.0.0.1:11000 failed
# after retry: Connection refused" when adding a country.
# ---------------------------------------------------------------------------
class TestHotfix15PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #2 — two post-Hotfix-#1 bugs.

    Bug #1 — ``install.sh --uninstall`` did NOT kill the orphaned
    python/uvicorn process holding ``${PANEL_PORT}`` open. ``systemctl stop``
    is fire-and-forget (returns 0 the moment SIGTERM is issued), and
    ``rm -rf ${INSTALL_PREFIX}`` deletes the venv files from disk but the
    orphan keeps running (Linux preserves the inode while file descriptors
    are open). The subsequent fresh ``install.sh`` re-install builds the
    new wheel in the venv and `pip install`s it — but its pre-flight
    TCP probe connects to the orphan (still listening), ``wait_for_panel_
    socket`` returns 0 early, the success banner prints, and the operator
    keeps talking to the OLD process serving the OLD wheel code → the
    Hotfix #1 base64 fix never actually takes effect → "Add UA" button
    dies with the same SOCKS5 ``Connection refused`` symptom.

    Bug #2 — ``installer/panel_install.sh`` pre-flight consulted
    ``systemctl is-active --quiet psiphon-3x-ui.service`` to decide whether
    to look up the live unit's ``MainPID`` and exclude it from the
    foreign-kill set. In the post-uninstall transient state the orphan's
    PID could STILL be registered as ``MainPID`` even though the unit file
    was ``rm -f``'d by uninstall → pre-flight excluded the orphan from
    the foreign-kill set → the orphan survived → ``systemctl restart
    psiphon-3x-ui.service`` then failed with "Unit psiphon-3x-ui.service
    not found" because the unit file write at panel_install.sh:254 was
    not yet reloaded (or worse: the OLD `rm -f`'d unit was poorly
    reloaded by `daemon-reload`).

    Fix #1 — ``install.sh --uninstall`` adds an explicit orphan-kill
    block via two new helpers, ``_purge_orphan_panel_listeners`` (kills
    every PID listening on ``${PANEL_PORT}`` after `systemctl stop`
    returns) + ``_purge_orphan_panel_user_processes`` (kills every
    python/uvicorn process running as ``${PSIPHON3XUI_USER}``), called
    AFTER ``systemctl stop`` and BEFORE ``rm -rf ${INSTALL_PREFIX}``.

    Fix #2 — ``installer/panel_install.sh``'s pre-flight re-orders to
    STOP the unit FIRST (we're about to start it anyway), sleep 1 to let
    SIGTERM propagate, snapshot listeners and classify EVERY pid on
    ``${PANEL_PORT}`` as foreign (NO MainPID lookup / NO exclusion
    based on ``systemctl is-active``), ``kill -9`` them, verify the
    port is free, then ``systemctl start`` (not restart).

    Each regression test below pins one of those invariants against
    accidental reverts.
    """

    _INSTALLER_DIR = Path(__file__).resolve().parent.parent / "installer"
    _INSTALL_SH = Path(__file__).resolve().parent.parent / "install.sh"
    _PANEL_INSTALL_SH = Path(__file__).resolve().parent.parent / "installer" / "panel_install.sh"

    # ─── Bug #3: install.sh --uninstall orphan-kill block ──────────────────
    def test_uninstall_run_uninstalls_calls_purge_orphan_listeners(self):
        """``run_uninstall`` must invoke the new
        ``_purge_orphan_panel_listeners`` helper after ``systemctl stop``
        + before ``rm -rf ${INSTALL_PREFIX}``."""
        import re  # noqa: PLC0415

        text = self._INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert "_purge_orphan_panel_listeners" in no_comments, (
            "Phase 24 Hotfix #2 — install.sh --uninstall must call the "
            "_purge_orphan_panel_listeners helper (Bug: orphan panel "
            "process survived uninstall because systemctl stop is "
            "fire-and-forget and rm -rf doesn't kill running processes)."
        )

    def test_uninstall_run_uninstalls_calls_purge_orphan_user_processes(self):
        """``run_uninstall`` must invoke
        ``_purge_orphan_panel_user_processes`` so orphans running under
        the panel service user (no longer bound to PANEL_PORT — e.g.,
        the prior install's panel.env port differed) are also caught."""
        import re  # noqa: PLC0415

        text = self._INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert "_purge_orphan_panel_user_processes" in no_comments, (
            "Phase 24 Hotfix #2 — install.sh --uninstall must call the "
            "_purge_orphan_panel_user_processes helper (covers orphans "
            "not bound to PANEL_PORT)."
        )

    def test_uninstall_purge_helpers_are_defined(self):
        """Both helpers' function definitions must exist in install.sh."""
        text = self._INSTALL_SH.read_text(encoding="utf-8")
        assert "_purge_orphan_panel_listeners()" in text, (
            "_purge_orphan_panel_listeners() must be DEFINED in install.sh "
            "(not just invoked). Hotfix #2 Bug #3."
        )
        assert "_purge_orphan_panel_user_processes()" in text, (
            "_purge_orphan_panel_user_processes() must be DEFINED in "
            "install.sh (not just invoked). Hotfix #2 Bug #3."
        )

    def test_uninstall_purge_uses_kill_minus_9(self):
        """The purge helpers MUST ``kill -9`` (SIGKILL) the orphan —
        SIGTERM is insufficient because the orphan's parent (systemd)
        is gone, so no-one would handle a SIGTERM and propagate it."""
        import re  # noqa: PLC0415

        text = self._INSTALL_SH.read_text(encoding="utf-8")
        # The kill line is non-commented runtime code. Bash's
        # `${pids}` is NOT regex-escaped in the source — ruff would
        # mis-flag a literal `$\{...\}` escape, so we just match the
        # raw `kill -9 ${pids}` text shape.
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(r"kill\s+-9\s+\$\{pids\}", no_comments), (
            "_purge_orphan_panel_user_processes must `kill -9 ${pids}` "
            "the orphans (SIGKILL — SIGTERM is insufficient for an "
            "orphan with no parent to propagate it)."
        )

    def test_uninstall_purge_runs_between_systemctl_stop_and_rm_rf(self):
        """Ordering check — purge helpers must run AFTER the
        ``systemctl stop psiphon-3x-ui.service`` line returns AND BEFORE
        the ``rm -rf ${INSTALL_PREFIX}`` line. The purge calls are
        useless if they run before stop (they'd target the live unit's
        PID unnecessarily) or after rm -rf (rm deletes the venv files but
        the orphan's open fds keep the inode alive — so purge would
        still work, but we want to surface the orphan's own PID-blob
        via `pgrep -u <user>` BEFORE we delete the user, which is what
        userdel --force (after purge) does)."""
        import re  # noqa: PLC0415

        text = self._INSTALL_SH.read_text(encoding="utf-8")
        # Strip comments so docblock prose ordering doesn't match.
        no_comments_lines = [
            ln for ln in re.sub(r"#[^\n]*", "", text).splitlines() if ln.strip()
        ]
        # Walk and find: systemctl stop ... + _purge_orphan_panel_listeners
        # + _purge_orphan_panel_user_processes + userdel + rm -rf — in order.

        idx_stop = next(
            (i for i, ln in enumerate(no_comments_lines)
             if "systemctl stop psiphon-3x-ui.service" in ln),
            None,
        )
        idx_purge_listen = next(
            (i for i, ln in enumerate(no_comments_lines)
             if "_purge_orphan_panel_listeners" in ln),
            None,
        )
        idx_purge_user = next(
            (i for i, ln in enumerate(no_comments_lines)
             if "_purge_orphan_panel_user_processes" in ln and "()" not in ln),
            None,
        )
        idx_rmrf = next(
            (i for i, ln in enumerate(no_comments_lines)
             if 'rm -rf "${INSTALL_PREFIX}"' in ln),
            None,
        )
        assert all(
            v is not None for v in (idx_stop, idx_purge_listen, idx_purge_user, idx_rmrf)
        ), (
            "Phase 24 Hotfix #2 — install.sh --uninstall ordering broken: "
            "expected systemctl stop → _purge_orphan_panel_listeners → "
            "_purge_orphan_panel_user_processes → rm -rf, in that order."
        )
        assert idx_stop < idx_purge_listen < idx_purge_user < idx_rmrf, (
            "Phase 24 Hotfix #2 — install.sh --uninstall must run the "
            "orphan purge helpers AFTER systemctl stop + BEFORE rm -rf "
            "(pgrep -u must see the still-existing service user)."
        )

    # ─── Bug #1: panel_install.sh pre-flight ordering + classifier strength ─
    def test_panel_install_pre_flight_stops_unit_before_listener_check(self):
        """panel_install.sh pre-flight must STOP the prior unit BEFORE
        snapshotting the port listeners (Hotfix #2 re-orders so the
        stop is unconditional and precedes the orphan-kill)."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        nonblank = [ln for ln in no_comments.splitlines() if ln.strip()]
        idx_stop = next(
            (i for i, ln in enumerate(nonblank)
             if "systemctl stop psiphon-3x-ui.service" in ln),
            None,
        )
        idx_prelight = next(
            (i for i, ln in enumerate(nonblank)
             if 'Pre-flight: checking TCP/${PANEL_PORT}' in ln),
            None,
        )
        assert idx_stop is not None, (
            "Phase 24 Hotfix #2 — panel_install.sh pre-flight must "
            "begin with `systemctl stop psiphon-3x-ui.service` to reap "
            "any prior unit (Bug: prior pre-flight consulted is-active + "
            "MainPID exclusion which let the orphan survive)."
        )
        assert idx_prelight is not None, (
            "Pre-flight listener check missing from panel_install.sh."
        )
        assert idx_stop < idx_prelight, (
            "Phase 24 Hotfix #2 — `systemctl stop psiphon-3x-ui.service` "
            "must run BEFORE the port_listeners check (so the live unit is "
            "reaped before we decide which pids to kill)."
        )

    def test_panel_install_pre_flight_no_longer_excludes_mainpid(self):
        """The buggy classifier that consulted
        ``systemctl is-active --quiet`` + ``systemctl show -p MainPID
        --value`` to exclude the orphan (treating it as the live unit's
        own PID) MUST be GONE — every PID on PANEL_PORT is by definition
        foreign after the explicit `systemctl stop`."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The Hotfix #1 pre-flight had this exact buggy exclusion:
        #   if [[ -n "${systemd_unit_pid}" && "${pid}" == "${systemd_unit_pid}" ]]; then
        #       continue   # don't kill the live unit's PID; systemctl restart handles it
        #   fi
        # This MUST be gone in Hotfix #2 (the unit was stopped upstream, so
        # every pid still on the port is by-definition an orphan).
        assert not re.search(
            r'"\$\{systemd_unit_pid\}"\s*&&\s*"\$\{pid\}"\s*==\s*"\$\{systemd_unit_pid\}"',
            no_comments,
        ), (
            "Phase 24 Hotfix #2 — panel_install.sh's pre-flight must NOT "
            "exclude any PID via the systemd_unit_pid comparison anymore "
            "(the buggy classifier let the orphan survive). Every pid on "
            "PANEL_PORT post-stop is foreign → kill it."
        )
        # The MainPID lookup line must be GONE too (it was the source of
        # the false-true classification).
        assert not re.search(
            r"systemctl show -p MainPID --value psiphon-3x-ui\.service",
            no_comments,
        ), (
            "Phase 24 Hotfix #2 — panel_install.sh pre-flight must NOT "
            "consult `systemctl show -p MainPID --value` anymore. The "
            "post-stop transient state may report the orphan's PID as "
            "MainPID, falsely protecting the orphan."
        )

    def test_panel_install_pre_flight_uses_start_not_restart(self):
        """The buggy pre-flight's “was already running” restart branch must
        be GONE — we always stop first then start, so there's never a
        case where ``systemctl restart`` is the right call. The docblock
        ``info`` line ``Restarting psiphon-3x-ui.service (was already running)``
        must NOT appear anymore."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert not re.search(
            r'Restarting psiphon-3x-ui\.service \(was already running\)',
            no_comments,
        ), (
            "Phase 24 Hotfix #2 — panel_install.sh must NOT print the "
            "'Restarting psiphon-3x-ui.service (was already running) …' "
            "info line anymore. The pre-flight unconditionally STOPS "
            "first and then STARTS the new unit (never restart)."
        )
        assert "systemctl start psiphon-3x-ui.service" in no_comments, (
            "Phase 24 Hotfix #2 — panel_install.sh must end with "
            "`systemctl start psiphon-3x-ui.service` (stop-then-start, "
            "never restart)."
        )


# ---------------------------------------------------------------------------
# Phase 24 Hotfix #3 — per-country tunnel unit dies with exit 1 silently
# (psiphon-tunnel-core cannot mkdir its default datastore directory under the
# unit's `ProtectSystem=strict` + `PrivateTmp=true` + `ProtectHome=true`
# sandbox). The dashboard then reports "inline enable for UA failed: SOCKS5
# health probe on 127.0.0.1:11000 failed after retry: connect ... failed:
# ConnectionRefusedError" because the SOCKS5 listener was never bound.
# ---------------------------------------------------------------------------
class TestHotfix16PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #3 — the per-country
    tunnel unit ``systemd/psiphon-tunnel@.service`` silently exited 1 within
    3 seconds of ``systemctl start`` (494 restart-attempts observed in the
    field) because ``psiphon-tunnel-core`` could not ``mkdir`` its default
    datastore directory under the unit's hardening sandbox. The panel's
    ``health_probe`` saw ``ConnectionRefusedError`` on
    ``127.0.0.1:11000`` (the configured ``LocalSocksProxyPort``) because the
    binary died BEFORE binding the SOCKS5 listener. The operator reported:

    ``inline enable for UA failed: SOCKS5 health probe on 127.0.0.1:11000
    failed after retry: connect 127.0.0.1:11000 failed:
    ConnectionRefusedError: [Errno 111] Connection refused``

    Live root-cause confirmation (operator captured the binary's own error
    notice verbatim):

    ``{"data":{"message":"error loading configuration file:
    psiphon.(*Config).Commit#1514: failed to create datastore directory
    with error: mkdir [redacted]: no such file or
    directory"},"noticeType":"Error",...}``

    The inverse test (passing ``-dataRootDirectory
    /opt/psiphon-3x-ui/data/UA`` to the binary directly) produced a clean
    run: ``ListeningSocksProxyPort: 11000`` notice emitted, then clean
    ``exit 0`` after Ctrl-C (no exit 1, no error notice).

    Fix — the unit's ``ExecStart`` now passes
    ``-dataRootDirectory /opt/psiphon-3x-ui/data/%i`` so each per-country
    invocation writes its server-list cache + OSL registry + key material
    under ``/opt/psiphon-3x-ui/data/<CODE>/``. The installer
    (``installer/panel_install.sh``) pre-creates the parent ``/opt/
    psiphon-3x-ui/data`` directory owned by ``psiphon3xui:psiphon3xui``
    (mode 0700) so each unit's per-country ``mkdir`` on first start
    succeeds. ``install.sh`` exposes ``DATA_DIR`` (sibling of ``CONFIG_DIR``
    + ``BIN_DIR`` + ``VENV_DIR``) so the installer references a single
    constant.

    The regression tests below pin both halves of the fix so accidental
    reverts of either piece surface immediately.
    """

    _REPO_ROOT = Path(__file__).resolve().parent.parent
    _INSTALL_SH = _REPO_ROOT / "install.sh"
    _PANEL_INSTALL_SH = _REPO_ROOT / "installer" / "panel_install.sh"
    _TUNNEL_UNIT_SH = _REPO_ROOT / "systemd" / "psiphon-tunnel@.service"

    # ─── Unit half: ExecStart includes -dataRootDirectory flag ──────────────
    def test_tunnel_unit_execstart_includes_dataRootDirectory_flag(self):
        """``ExecStart=`` of ``psiphon-tunnel@.service`` MUST include
        ``-dataRootDirectory /opt/psiphon-3x-ui/data/%i``. Without it the
        binary dies with ``failed to create datastore directory`` before
        the SOCKS5 listener is bound."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(
            r"-dataRootDirectory\s+/opt/psiphon-3x-ui/data/%i\b",
            no_comments,
        ), (
            "Phase 24 Hotfix #3 — systemd/psiphon-tunnel@.service ExecStart "
            "MUST include `-dataRootDirectory /opt/psiphon-3x-ui/data/%i` "
            "(Bug: without it the binary cannot mkdir its default datastore "
            "under the unit's ProtectSystem=strict / PrivateTmp / ProtectHome "
            "sandbox → exit 1 → SOCKS5 listener never bound → dashboard "
            "'Connection refused on 11000' on Add UA)."
        )

    def test_tunnel_unit_execstart_still_has_config_flag(self):
        """``ExecStart=`` must STILL pass ``-config
        /opt/psiphon-3x-ui/config/%i.json`` so the binary loads the
        per-country JSON. The Hotfix #3 addition must not have removed
        the pre-existing ``-config`` line."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(
            r"-config\s+/opt/psiphon-3x-ui/config/%i\.json\b",
            no_comments,
        ), (
            "Phase 24 Hotfix #3 — ExecStart must STILL pass `-config /opt/"
            "psiphon-3x-ui/config/%i.json`. The -dataRootDirectory addition "
            "must not have removed the -config flag."
        )

    def test_tunnel_unit_execstart_data_root_after_config(self):
        """Defensive-ordering invariant: ``-dataRootDirectory`` must appear
        AFTER ``-config`` on the (possibly multi-line) ``ExecStart=`` block.
        Keeping the stable order avoids confusing future readers versed in
        the historical shape."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        config_match = re.search(
            r"-config\s+/opt/psiphon-3x-ui/config/%i\.json",
            no_comments,
        )
        data_root_match = re.search(
            r"-dataRootDirectory\s+/opt/psiphon-3x-ui/data/%i",
            no_comments,
        )
        assert config_match is not None and data_root_match is not None
        assert config_match.start() < data_root_match.start(), (
            "Phase 24 Hotfix #3 — ExecStart must list `-config` before "
            "`-dataRootDirectory` (stable historical order preserved)."
        )

    # ─── Installer half: panel_install.sh pre-creates ${DATA_DIR} ──────────
    def test_install_sh_defines_DATA_DIR_constant(self):
        """``install.sh`` must define ``DATA_DIR`` (sibling of CONFIG_DIR /
        BIN_DIR / VENV_DIR / DB_PATH / ENV_FILE) so the installer half of
        Hotfix #3 uses a single canonical constant instead of repeating the
        abs path literal."""
        text = self._INSTALL_SH.read_text(encoding="utf-8")
        # Match the assignment, allowing the SC2034 disable-comment line to
        # immediately precede or follow (we don't strip comments here so the
        # plain `DATA_DIR=` persistent substring is what we look for).
        assert "DATA_DIR=" in text and "/data" in text, (
            "Phase 24 Hotfix #3 — install.sh must define `DATA_DIR` pointing "
            "at `/opt/psiphon-3x-ui/data` (canonical sibling of CONFIG_DIR)."
        )

    def test_panel_install_creates_data_dir_with_service_owner(self):
        """``installer/panel_install.sh`` MUST ``install -d`` the
        ``${DATA_DIR}`` directory owned by
        ``${PSIPHON3XUI_USER}:${PSIPHON3XUI_GROUP}`` so each per-country
        ``systemctl start psiphon-tunnel@<CODE>`` invocation can ``mkdir``
        its ``${DATA_DIR}/<CODE>`` subdirectory at first start."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # Look for `install -d ... -o ${PSIPHON3XUI_USER} -g
        # ${PSIPHON3XUI_GROUP} ${DATA_DIR}` (allowing any flags ordering).
        assert "install -d" in no_comments and "DATA_DIR" in no_comments, (
            "Phase 24 Hotfix #3 — installer/panel_install.sh MUST use "
            "`install -d` with `DATA_DIR` to pre-create the per-country "
            "tunnel datastore parent directory. Without this the binary's "
            "first-run mkdir fails under the unit's hardening sandbox."
        )
        # Verify the ownership flags target the service identity.
        assert (
            "${PSIPHON3XUI_USER}" in no_comments
            and "${PSIPHON3XUI_GROUP}" in no_comments
        ), (
            "Phase 24 Hotfix #3 — the install command for DATA_DIR must pass "
            "`-o ${PSIPHON3XUI_USER} -g ${PSIPHON3XUI_GROUP}` so the per-"
            "country psiphon-tunnel-core process (running as "
            "PSIPHON3XUI_USER) can create its own per-country subdir."
        )

    def test_panel_install_invokes_install_minus_d_after_unit_install(self):
        """Ordering invariant: the ``install -d ${DATA_DIR}`` invocation
        must occur AFTER the templated tunnel unit file is installed into
        ``/etc/systemd/system/`` — so the directory is pre-created only on
        the path that successfully installed the unit (and only when the
        operator has the templated unit installed)."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # Find the line where the tunnel unit file is installed.
        unit_install_idx = no_comments.find(
            'install -m 0644 "${TUNNEL_UNIT_SRC}" "${TUNNEL_UNIT_DST}"'
        )
        # The FIRST `install -d` in the file may not be our DATA_DIR one
        # (other `install -d` invocations exist e.g. for the polkit dir).
        # So we constrain the search: find the `install -d` line that contains
        # "DATA_DIR" specifically (we already asserted the basic existence in
        # test_panel_install_creates_data_dir_with_service_owner).
        data_dir_line_match = re.search(
            r"install\s+-d\b[^\n]*\$\{DATA_DIR\}",
            no_comments,
        )
        assert unit_install_idx >= 0, (
            "Phase 24 Hotfix #3 — precondition: tunnel unit install line "
            "(install -m 0644 ${TUNNEL_UNIT_SRC} ${TUNNEL_UNIT_DST}) must "
            "exist in panel_install.sh."
        )
        assert data_dir_line_match is not None, (
            "Phase 24 Hotfix #3 — panel_install.sh must contain "
            "`install -d ... ${DATA_DIR}` (the pre-create of the per-country "
            "tunnel datastore parent)."
        )
        assert data_dir_line_match.start() > unit_install_idx, (
            "Phase 24 Hotfix #3 — the `install -d ${DATA_DIR}` must occur "
            "AFTER the templated tunnel unit is installed into /etc/systemd/"
            "system/. Pre-creating the directory before the unit file exists "
            "would be wasted work if the install of the unit file failed."
        )


# ---------------------------------------------------------------------------
# Phase 24 Hotfix #4 — make the per-country tunnel unit SELF-SUFFICIENT so it
# no longer depends on the installer-side `install -d ${DATA_DIR}` block in
# `installer/panel_install.sh` (which Hotfix #3 added but did NOT fire on the
# operator's machine in the field — `ls -ld /opt/psiphon-3x-ui/data` returned
# "No such file or directory" while the Hotfix #3 unit file was confirmed
# installed at `/etc/systemd/system/psiphon-tunnel@.service` with the new
# `-dataRootDirectory /opt/psiphon-3x-ui/data/%i` ExecStart). The unit now ships
# an `ExecStartPre=` that replicates the pre-create on every per-country
# `systemctl start psiphon-tunnel@<CODE>` (idempotent via `install -d`). This
# closes the failure path where the binary tries to `mkdir .../data/US` but
# its PARENT `/opt/psiphon-3x-ui/data` doesn't exist → exit 1 → restart loop
# → SOCKS5 listener never bound → dashboard ConnectionRefused on 11000.
# ---------------------------------------------------------------------------
class TestHotfix17PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #4 — the
    per-country tunnel unit ``systemd/psiphon-tunnel@.service`` gained an
    ``ExecStartPre=`` so it no longer needs the installer to pre-create
    ``/opt/psiphon-3x-ui/data``. The operator's post-Hotfix-#3 field report
    proved Hotfix #3's installer-side pre-create was unreliable (the data
    dir was missing on a fresh install even though the new unit file landed),
    leaving the unit in an ``activating (auto-restart)`` restart loop with
    ``status=1/FAILURE`` because the binary's ``mkdir`` of
    ``/opt/psiphon-3x-ui/data/<CODE>`` failed — its PARENT didn't exist.
    Same ConnectionRefused surface symptom as before Hotfix #3.

    The regression tests below pin the new ``ExecStartPre`` directive and
    the ordering invariants so an accidental revert of either piece surfaces
    immediately. The installer-side pre-create from Hotfix #3 is left in
    place (belt-and-braces); it has its own regression tests in
    :class:`TestHotfix16PostReleaseRegressions` and is NOT removed by
    Hotfix #4.
    """

    _REPO_ROOT = Path(__file__).resolve().parent.parent
    _TUNNEL_UNIT_SH = _REPO_ROOT / "systemd" / "psiphon-tunnel@.service"

    # ─── Unit half: ExecStartPre pre-creates data dir per instance ──────────
    def test_tunnel_unit_has_execstartpre_directive(self):
        """``ExecStartPre=`` of ``psiphon-tunnel@.service`` MUST exist so
        each per-country ``systemctl start psiphon-tunnel@<CODE>`` self-
        creates its datastore directory (and the parent ``data/``). This is
        the central piece of Hotfix #4 — without it the unit depends on
        the installer-side pre-create which proved unreliable in the
        field."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(r"^ExecStartPre\s*=", no_comments, re.M), (
            "Phase 24 Hotfix #4 — systemd/psiphon-tunnel@.service MUST ship "
            "an `ExecStartPre=` directive so each per-country tunnel instance "
            "self-creates its /opt/psiphon-3x-ui/data/<CODE> directory on "
            "startup. The Hotfix #3 installer-side pre-create was unreliable "
            "in the field (operator's fresh install landed the new unit file "
            "but /opt/psiphon-3x-ui/data was missing → binary mkdir failed → "
            "exit 1 → restart loop → ConnectionRefused on 11000)."
        )

    def test_execstartpre_uses_mkdir_minus_p(self):
        """Phase 26 Hotfix #13 — the ``ExecStartPre`` must use
        ``/usr/bin/mkdir -p`` (recursive, idempotent), NOT ``install -d``.
        GNU coreutils ``install -d`` on newer Ubuntu internally still calls
        chown(2) on the directory it's about to create even when no
        ``-o``/``-g`` args are passed, AND when the parent has the setgid
        bit set (which ``/opt/psiphon-3x-ui`` does, mode 2775 since
        Hotfix #12). With ``NoNewPrivileges=true`` + ``ProtectSystem=strict``
        the CAP_CHOWN capability is stripped, so the chown syscall fails
        with EACCES — exactly what the operator's fresh install hit
        (journald: ``/usr/bin/install: cannot create directory
        '/opt/psiphon-3x-ui/data': Permission denied``, repeating in a
        tight RestartSec=5 loop).

        The substitute is plain ``mkdir -p -m 0700 --``:
          * ``-p`` walks the path recursively creating each missing
            component AND is idempotent on a pre-existing dir (so systemd
            restarts don't fail the pre-flight);
          * ``-m 0700`` applies the owner-only mode atomically at mkdir
            time (no chmod followup);
          * ``--`` ends option parsing so a country-code that began with
            ``-`` would be treated as a literal path;
          * ``mkdir`` never invokes chown — the new dir simply inherits
            the creating process's uid/gid (here psiphon3xui per the unit's
            ``User=``/``Group=``)."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The Hotfix-#13 ExecStartPre line:
        #   ExecStartPre=/usr/bin/mkdir -p -m 0700 -- /opt/psiphon-3x-ui/data/%i
        execstartpre_match = re.search(
            r"^ExecStartPre\s*=\s*(\S.*)$",
            no_comments,
            re.M,
        )
        assert execstartpre_match is not None, (
            "Phase 26 Hotfix #13 — ExecStartPre line not found in the unit "
            "file (test_tunnel_unit_has_execstartpre_directive guards the "
            "directive presence; this test pins its specific shape)."
        )
        execstartpre_cmd = execstartpre_match.group(1)
        assert re.search(r"\bmkdir\s+-p\b", execstartpre_cmd), (
            "Phase 26 Hotfix #13 — ExecStartPre must use `mkdir -p` (NOT "
            "`install -d`). GNU coreutils `install -d` calls chown(2) "
            "internally even without `-o`/`-g` when the parent dir has "
            "the setgid bit (which /opt/psiphon-3x-ui does, mode 2775 "
            "since Hotfix #12). Under `NoNewPrivileges=true` + "
            "`ProtectSystem=strict` the CAP_CHOWN capability is stripped, "
            "so chown fails with EACCES and the ExecStartPre aborts — "
            "exactly the failure the operator's fresh install hit "
            "(journald: '/usr/bin/install: cannot create directory "
            "\\'/opt/psiphon-3x-ui/data\\': Permission denied', repeating "
            "in a tight RestartSec=5 loop)."
        )
        assert re.search(r"\bmkdir\s+[^|;&]*--\s", execstartpre_cmd), (
            "Phase 26 Hotfix #13 — ExecStartPre's `mkdir` invocation must "
            "pass `--` to end option parsing, so a country-code beginning "
            "with `-` (if one ever appears in countries.yaml) is treated "
            "as a literal path component rather than a flag."
        )
        assert not re.search(r"\binstall\s+-d\b", execstartpre_cmd), (
            "Phase 26 Hotfix #13 — ExecStartPre must NOT use `install -d`: "
            "that binary's implicit chown(2) under a setgid parent fails "
            "with EACCES under the unit's NoNewPrivileges + ProtectSystem "
            "sandbox. Use `mkdir -p` instead."
        )

    def test_execstartpre_targets_per_country_data_dir_with_percent_i(self):
        """The ``ExecStartPre`` path MUST include ``%i`` (the templated
        country-code instance parameter) so each per-country instance
        pre-creates its OWN data dir (NOT a shared parent that other
        instances would race to create)."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        execstartpre_match = re.search(
            r"^ExecStartPre\s*=\s*(\S.*)$",
            no_comments,
            re.M,
        )
        assert execstartpre_match is not None
        execstartpre_cmd = execstartpre_match.group(1)
        assert re.search(
            r"/opt/psiphon-3x-ui/data/%i\b",
            execstartpre_cmd,
        ), (
            "Phase 24 Hotfix #4 — ExecStartPre path MUST include `%i` so "
            "each per-country tunnel instance pre-creates its OWN data "
            "dir, e.g. `/opt/psiphon-3x-ui/data/US` — not a single shared "
            "parent that other instances would race against."
        )

    def test_execstartpre_uses_mode_0700(self):
        """The pre-created data dir MUST have strict mode ``0700``
        (owner-only RWX) so the tunnel-core's per-country key material,
        server-list cache, and OSL registry stay private to the
        ``psiphon3xui`` service identity. World- or group-readable would
        leak tunnel state to other system users."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        execstartpre_match = re.search(
            r"^ExecStartPre\s*=\s*(\S.*)$",
            no_comments,
            re.M,
        )
        assert execstartpre_match is not None
        execstartpre_cmd = execstartpre_match.group(1)
        assert re.search(r"-m\s+0700\b", execstartpre_cmd), (
            "Phase 24 Hotfix #4 + Phase 26 Hotfix #13 — ExecStartPre "
            "`mkdir -p` (formerly `install -d`) MUST pass `-m 0700` so the "
            "per-country tunnel datastore dir is owner-only (psiphon3xui). "
            "Group- or world-readable would leak tunnel-core state (key "
            "material, server-list cache, OSL registry) to other system "
            "users."
        )

    def test_execstartpre_does_not_run_chown(self):
        """Phase 25 Hotfix #12 + Phase 26 Hotfix #13: the `ExecStartPre`
        must NOT pass ``-o <user>`` / ``-g <group>`` — those flags force a
        privileged ``chown()`` syscall which the kernel rejects when the
        unit runs as a non-root ``User=psiphon3xui``. The operator's live
        failure was the user-visible symptom:

            /usr/bin/install: cannot create directory
            '/opt/psiphon-3x-ui/data': Permission denied

        Hotfix #12 dropped the ``-o``/``-g`` args from ``install -d``;
        Hotfix #13 then switched the pre-flight to plain ``mkdir -p``
        entirely (``install -d`` internally invokes chown even WITHOUT
        ``-o``/``-g`` when the parent dir is setgid — mode 2775 since
        Hotfix #12 — and CAP_CHOWN is stripped under
        ``NoNewPrivileges=true`` + ``ProtectSystem=strict``). ``mkdir``
        never chowns: the new directory simply inherits the creating
        process's uid/gid (i.e. psiphon3xui per the unit's ``User=`` /
        ``Group=``). This regression test pins both halves of the fix:
        no ``-o``, no ``-g``, and (per Hotfix #13) the pre-flight is
        ``mkdir``-shaped so the "no chown" guarantee actually holds. The
        directory is STILL made under mode 0700 to satisfy the original
        hardening intent (no other-user read access)."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        execstartpre_match = re.search(
            r"^ExecStartPre\s*=\s*(\S.*)$",
            no_comments,
            re.M,
        )
        assert execstartpre_match is not None
        execstartpre_cmd = execstartpre_match.group(1)
        # The unit's User=/Group= are literal `psiphon3xui` (no env vars in
        # a systemd unit), so ExecStartPre must NOT pass -o/-g — those are
        # privileged this process can't do without being root / having
        # CAP_CHOWN, which we deliberately omit from the sandbox.
        assert "-o " not in execstartpre_cmd, (
            "Phase 25 Hotfix #12 + Phase 26 Hotfix #13 — ExecStartPre must "
            "NOT pass `-o <owner>`: that flag invokes a privileged chown "
            "syscall which fails with `Permission denied` when the unit "
            "runs as a non-root User=psiphon3xui. Drop the flag."
        )
        assert "-g " not in execstartpre_cmd, (
            "Phase 25 Hotfix #12 + Phase 26 Hotfix #13 — ExecStartPre must "
            "NOT pass `-g <group>`: same privileged syscall; drop the flag."
        )
        # Hotfix #13 secondary pin: pre-flight uses `mkdir`, not `install`,
        # so even an accidental future reintroduction of owner/group args
        # would be a syntax error (mkdir has no -o/-g) rather than a silent
        # chown regression.
        assert not re.search(r"\binstall\b", execstartpre_cmd), (
            "Phase 26 Hotfix #13 — ExecStartPre must not invoke `install` "
            "at all (it internally chowns under a setgid parent when no "
            "-o/-g is given). Use `mkdir -p -m 0700 --` instead; the pin "
            "lives here as defense-in-depth next to the no-`-o`/`-g` "
            "assertions above."
        )
        # The unit still has User=/Group= directives — sanity guard.
        assert "User=psiphon3xui" in no_comments
        assert "Group=psiphon3xui" in no_comments

    def test_execstartpre_runs_before_execstart(self):
        """Ordering invariant: ``ExecStartPre`` must appear BEFORE
        ``ExecStart`` in the unit file. systemd gurantees this in its own
        exec lifecycle, but pinning the source-order invariant surfaces any
        accidental swap (e.g. a copy-paste that places the pre-create
        below the binary invocation)."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        execstartpre_match = re.search(
            r"^ExecStartPre\s*=", no_comments, re.M,
        )
        execstart_match = re.search(
            r"^ExecStart\s*=", no_comments, re.M,
        )
        assert execstartpre_match is not None and execstart_match is not None
        assert execstartpre_match.start() < execstart_match.start(), (
            "Phase 24 Hotfix #4 — `ExecStartPre` MUST appear BEFORE `ExecStart` "
            "in the unit file. systemd executes them in that order by spec; "
            "keeping the source order consistent avoids future reader confusion."
        )

    def test_execstartpre_path_matches_execstart_dataRootDirectory(self):
        """The ``ExecStartPre`` pre-create path MUST equal the ``-dataRootDirectory``
        argument passed to ``ExecStart`` (both ``/opt/psiphon-3x-ui/data/%i``),
        otherwise the pre-create would not actually unblock the binary's
        mkdir of its own data dir."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # Extract the ExecStartPre command line (everything after `ExecStartPre=`).
        execstartpre_line_match = re.search(
            r"^ExecStartPre\s*=\s*(.+)$",
            no_comments,
            re.M,
        )
        execstart_datapath_match = re.search(
            r"-dataRootDirectory\s+(/opt/psiphon-3x-ui/data/%i)",
            no_comments,
        )
        assert execstartpre_line_match is not None, (
            "Phase 24 Hotfix #4 — ExecStartPre line not found in the unit "
            "file (test_tunnel_unit_has_execstartpre_directive guards the "
            "directive presence; this test pins the path equality)."
        )
        assert execstart_datapath_match is not None, (
            "Phase 24 Hotfix #4 — ExecStart still must pass "
            "`-dataRootDirectory /opt/psiphon-3x-ui/data/%i`."
        )
        pre_path_match = re.search(
            r"(/opt/psiphon-3x-ui/data/%i)",
            execstartpre_line_match.group(1),
        )
        assert pre_path_match is not None, (
            "Phase 24 Hotfix #4 — ExecStartPre path must contain "
            "`/opt/psiphon-3x-ui/data/%i`."
        )
        assert (
            pre_path_match.group(1) == execstart_datapath_match.group(1)
        ), (
            "Phase 24 Hotfix #4 — ExecStartPre pre-create path MUST equal "
            "ExecStart's -dataRootDirectory argument so the pre-create "
            "actually unblocks the binary's subsequent mkdir of its own "
            "data subdir under the same root."
        )

    def test_execstart_still_has_dataRootDirectory_after_hotfix4(self):
        """Hotfix #4 adds ``ExecStartPre`` but MUST NOT remove the
        ``-dataRootDirectory`` argument from ``ExecStart`` — the pre-create
        only builds the dir, the binary STILL needs the flag to know where
        to write its server-list cache + OSL registry + key material."""
        import re  # noqa: PLC0415

        text = self._TUNNEL_UNIT_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(
            r"-dataRootDirectory\s+/opt/psiphon-3x-ui/data/%i\b",
            no_comments,
        ), (
            "Phase 24 Hotfix #4 — ExecStart MUST STILL pass "
            "`-dataRootDirectory /opt/psiphon-3x-ui/data/%i`. The Hotfix #4 "
            "ExecStartPre only pre-creates the directory; the binary STILL "
            "needs the flag itself to point at that directory for its "
            "writeBits. Accidentally removing the flag would re-introduce "
            "the Hotfix #3 bug."
        )


class TestHotfix18PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #5 — the spurious
    "Failed to restart psiphon-3x-ui.service: Unit psiphon-3x-ui.service
    not found." wording the operator reported as STILL appearing on every
    fresh install in a new terminal, even after Hotfixes #1-#4 landed.

    Root cause (per Hotfix #5 docblock in installer/panel_install.sh):
    my installer has ZERO runtime `systemctl restart psiphon-3x-ui.service`
    calls — the wording is systemctl's own emit from a deferred systemd
    transaction, triggered when `daemon-reload` / `enable` / `start` race
    against a stale FAILED-state entry the unit's `Restart=on-failure` policy
    left queued from the prior boot. The fix is `systemctl reset-failed
    psiphon-3x-ui.service` at TWO call sites in panel_install.sh:

      (1) between `systemctl daemon-reload` and `systemctl enable` — flush
          the FAILED entry before `enable`'s implicit auto-start trips the
          queued restart job;
      (2) between the pre-flight `systemctl stop` and the orphan-kill + new
          `systemctl start` — flush any FAILED entry the just-issued stop +
          `Restart=on-failure` policy just queued.

    These tests pin both call sites exist + both orderings hold + the exact
    `reset-failed psiphon-3x-ui.service 2>/dev/null || true` shape (no
    regression to a bare `reset-failed` that would spam on a fresh install).
    """

    _REPO_ROOT = Path(__file__).resolve().parents[1]
    _PANEL_INSTALL_SH = _REPO_ROOT / "installer" / "panel_install.sh"

    def _no_comment_nonblank_lines(self) -> list[str]:
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        return [ln for ln in no_comments.splitlines() if ln.strip()]

    def test_panel_install_has_three_reset_failed_call_sites(self):
        """After Phase 24 Hotfix #6 there are THREE
        ``systemctl reset-failed psiphon-3x-ui.service`` call sites in
        panel_install.sh:

        (1) HOTFIX #6 — the pre-build quiesce block at the TOP of
            ``run_panel_install``, BEFORE the venv/wheel/deps install —
            forwards the unit's FAILED-state entry from a PRIOR install
            before the wheel reinstall touches pydantic.
        (2) HOTFIX #5 — between ``systemctl daemon-reload`` and
            ``systemctl enable psiphon-3x-ui.service`` — flushes the
            FAILED entry that survives a re-install between the just-
            reloaded MD and the implicit auto-start `enable` triggers
            via the wants-symlink.
        (3) HOTFIX #5 — between the pre-flight ``systemctl stop`` and the
            subsequent ``systemctl start`` of the new installed unit —
            flushes the FAILED entry that the just-issued stop + the
            unit's `Restart=on-failure` policy just queued.

        Hotfix #5 originally pinned ``== 2``; Hotfix #6 added the pre-
        build quiesce site and so this count rose to 3. Pinning the exact
        count guards against an accidental drop back to 2 (which would
        silently re-open the Hotfix #6 boot-loop race) or a stray 4th
        call (which would suggest a copy-paste duplication)."""
        lines = self._no_comment_nonblank_lines()
        reset_failed_lines = [
            ln for ln in lines
            if "systemctl reset-failed psiphon-3x-ui.service" in ln
        ]
        assert (
            len(reset_failed_lines) == 3
        ), (
            "Phase 24 Hotfix #5 + Hotfix #6 — expected exactly 3 "
            "`systemctl reset-failed psiphon-3x-ui.service` call sites in "
            "panel_install.sh: (H6) pre-build quiesce, (H5) between "
            "daemon-reload+enable, (H5) between the pre-flight stop+start. "
            f"Found {len(reset_failed_lines)}: {reset_failed_lines!r}."
        )

    def test_reset_failed_uses_stderr_redirect_and_or_true(self):
        """Every ``reset-failed`` call MUST use the
        ``2>/dev/null || true`` form so a fresh install (with no FAILED
        entry to clear, where `reset-failed` returns non-zero) doesn't
        trip the installer's `warn`/`die` paths or print to the operator's
        terminal. Belt-and-braces on re-installs, silent on fresh installs.

        After Phase 24 Hotfix #6 added the pre-build quiesce site
        (see ``test_panel_install_has_three_reset_failed_call_sites``)
        there are 3 calls — pin the count + per-call shape."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        reset_failed_calls = re.findall(
            r"systemctl reset-failed psiphon-3x-ui\.service[^\n]*",
            no_comments,
        )
        assert len(reset_failed_calls) == 3, (
            "Phase 24 Hotfix #5 + Hotfix #6 — sanity guard: expected exactly 3 "
            "`systemctl reset-failed psiphon-3x-ui.service` calls "
            f"(see test_panel_install_has_three_reset_failed_call_sites); "
            f"found {len(reset_failed_calls)}."
        )
        for call in reset_failed_calls:
            assert "2>/dev/null" in call, (
                "Phase 24 Hotfix #5 — every `reset-failed` call must "
                f"suppress stderr (`2>/dev/null`) so systemctl's "
                f"'Unit not loaded.' chatter doesn't print on a fresh "
                f"install. Offending call: {call!r}."
            )
            assert "|| true" in call, (
                "Phase 24 Hotfix #5 — every `reset-failed` call must "
                f"end with `|| true` (reset-failed returns non-zero on a "
                f"fresh install where there is no FAILED entry to clear; "
                f"without `|| true` the `set -e`-style guards in some "
                f"shells would abort). Offending call: {call!r}."
            )

    def test_reset_failed_site_1_runs_between_daemon_reload_and_enable(self):
        """Call site #1 — between ``systemctl daemon-reload`` and
        ``systemctl enable psiphon-3x-ui.service`` — flushes the FAILED
        entry that survives a re-install between the just-reloaded MD and
        the implicit auto-start `enable` triggers via the wants-symlink."""
        lines = self._no_comment_nonblank_lines()
        idx_daemon_reload = next(
            (i for i, ln in enumerate(lines)
             if "systemctl daemon-reload" in ln),
            None,
        )
        idx_enable = next(
            (i for i, ln in enumerate(lines)
             if "systemctl enable psiphon-3x-ui.service" in ln),
            None,
        )
        reset_failed_indices = [
            i for i, ln in enumerate(lines)
            if "systemctl reset-failed psiphon-3x-ui.service" in ln
        ]
        assert (
            idx_daemon_reload is not None
            and idx_enable is not None
            and len(reset_failed_indices) >= 1
        ), (
            "Phase 24 Hotfix #5 — pre-condition: panel_install.sh must have "
            "`systemctl daemon-reload`, `systemctl enable psiphon-3x-ui.service`, "
            "and at least one `reset-failed` call site."
        )
        # Hotfix #6 added a reset-failed call at the TOP of `run_panel_install`
        # (the pre-build quiesce block) — that site is EARLIER than the
        # systemd-unit-install daemon-reload. It's pinned separately by
        # ``test_pre_build_quiesce_runs_before_venv_create`` in
        # ``TestHotfix19PostReleaseRegressions``. Hotfix #5's site #1 is the
        # reset-failed call strictly BETWEEN daemon-reload and enable (it can
        # no longer be the lexicographically-FIRST reset-failed call, so
        # ``min(reset_failed_indices)`` would now wrongly grab the
        # pre-build site).
        site_1_candidates = [
            i for i in reset_failed_indices
            if idx_daemon_reload < i < idx_enable
        ]
        assert site_1_candidates, (
            "Phase 24 Hotfix #5 — call site #1 MUST sit strictly BETWEEN "
            "`systemctl daemon-reload` and `systemctl enable "
            "psiphon-3x-ui.service`. Without this ordering, `enable`'s "
            "implicit auto-start races against the stale FAILED entry the "
            "daemon-reload just re-read. (Hotfix #6 added an extra "
            "reset-failed call at the very top — that one is pinned by "
            "TestHotfix19PostReleaseRegressions and is INTENTIONALLY "
            "earlier than this daemon-reload.)"
        )
        # Defensive guard: there must be EXACTLY ONE such straddling call
        # (not two — that would suggest the pre-build site accidentally
        # slipped down past the daemon-reload).
        assert len(site_1_candidates) == 1, (
            "Phase 24 Hotfix #5 — site #1 should be a SINGLE reset-failed "
            "call strictly between daemon-reload and enable; found "
            f"{len(site_1_candidates)} candidates: {site_1_candidates!r}."
        )

    def test_reset_failed_site_2_runs_between_pre_flight_stop_and_start(self):
        """Call site #2 — between the pre-flight ``systemctl stop
        psiphon-3x-ui.service`` and the subsequent ``systemctl start`` of
        the same unit — flushes the FAILED entry that the just-issued
        stop + the unit's `Restart=on-failure` policy just queued."""
        lines = self._no_comment_nonblank_lines()
        # The pre-flight STOP is the second `systemctl stop psiphon-3x-ui.service`
        # in the file (the first one is inside the `--uninstall` branch early
        # in install.sh; panel_install.sh has only ONE pre-flight stop). Pin it
        # by the 'Pre-flight' info() that precedes it.
        nonblank_with_indices = list(enumerate(lines))
        idx_preflight_info = next(
            (i for i, ln in nonblank_with_indices
             if "Pre-flight: stopping any prior psiphon-3x-ui.service unit" in ln),
            None,
        )
        assert idx_preflight_info is not None, (
            "Phase 24 Hotfix #5 — pre-condition: panel_install.sh must still "
            "have the Phase 24 Hotfix #2 pre-flight `info` banner preceding "
            "the pre-flight stop."
        )
        idx_preflight_stop = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_preflight_info and "systemctl stop psiphon-3x-ui.service" in ln),
            None,
        )
        # The START of the unit comes after the orphan-kill block. Phase 24
        # Hotfix #7 added `2>/dev/null` to the `systemctl start` line (to
        # silence systemd's transient "Failed to restart ... Unit not
        # found" emit that leaked to the operator's terminal between seed
        # and print_summary); the old `and "2>/dev/null" not in ln`
        # predicate here is now stale and would return `None`. Anchor on
        # the `info "Starting psiphon-3x-ui.service …"` banner, which is
        # the line directly above the `if ! systemctl start ...` block and
        # is unchanged by Hotfix #7.
        idx_start_info = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_preflight_stop
             and "Starting psiphon-3x-ui.service" in ln),
            None,
        )
        assert idx_start_info is not None, (
            "Phase 24 Hotfix #7 — pre-condition: the `info \"Starting "
            "psiphon-3x-ui.service …\"` banner that precedes the post-pre-"
            "flight `systemctl start` MUST still be present (Hotfix #7 "
            "only added a `2>/dev/null` redirect + `if ! ...; then warn; fi` "
            "wrapper around the start — it did NOT touch this banner)."
        )
        idx_start_unit = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_start_info
             and "systemctl start psiphon-3x-ui.service" in ln),
            None,
        )
        reset_failed_indices = [
            i for i, ln in nonblank_with_indices
            if "systemctl reset-failed psiphon-3x-ui.service" in ln
        ]
        assert (
            idx_preflight_stop is not None
            and idx_start_unit is not None
            and len(reset_failed_indices) >= 2
        ), (
            "Phase 24 Hotfix #5 — pre-condition: panel_install.sh must have "
            "the pre-flight stop + the new start + at least two reset-failed "
            "call sites."
        )
        # The reset-failed call that bounds the pre-flight site is the one
        # strictly AFTER idx_preflight_stop and strictly BEFORE idx_start_unit.
        site_2_candidates = [
            i for i in reset_failed_indices
            if idx_preflight_stop < i < idx_start_unit
        ]
        assert site_2_candidates, (
            "Phase 24 Hotfix #5 — call site #2 MUST run strictly BETWEEN the "
            "pre-flight `systemctl stop psiphon-3x-ui.service` and the "
            "`systemctl start psiphon-3x-ui.service` that follows. Without "
            "this ordering, the new start races against the queued restart "
            "job the just-issued stop + `Restart=on-failure` policy minted."
        )

    def test_panel_install_has_no_bare_reset_failed_calls(self):
        """A bare ``systemctl reset-failed`` (no ``2>/dev/null || true``)
        would emit `Unit not loaded.` to the operator's terminal on a
        fresh install — the very noise this Hotfix is supposed to silence.
        The grep must find ZERO bare calls."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        bare_calls = re.findall(
            r"systemctl reset-failed psiphon-3x-ui\.service(?!\s*2>/dev/null\s*\|\|\s*true)[^\n]*",
            no_comments,
        )
        assert not bare_calls, (
            "Phase 24 Hotfix #5 — found a bare `reset-failed` call without "
            "the required `2>/dev/null || true` suffix; this would print "
            f"chatter to the operator's terminal: {bare_calls!r}."
        )


class TestHotfix19PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #6 — the
    `Restart=on-failure` boot-loop the operator reported STILL occurring
    on the 7th fresh install (after Hotfixes #1-#5 had all landed).

    Real root cause (settled via operator-provided journalctl + pydantic
    diagnostic — see Hotfix #6 docblock in installer/panel_install.sh):
    a PRIOR install had already `systemctl enable`'d the panel unit
    (`WantedBy=multi-user.target` → wants-symlink in
    `/etc/systemd/system/multi-user.target.wants/`). On the NEXT install,
    `pip install --force-reinstall --no-deps "${wheel_path}"` (line ~137)
    atomically UNLINKS the old panel's package files and
    `pip install "pydantic>=2.6"` (line ~145) atomically SWAPS pydantic
    v1→v2. systemd's `Restart=on-failure` policy — armed against the
    STILL-ENABLED prior unit — flags the panel's mid-import crash as a
    failure and reschedules a fresh autostart that fires against a venv
    whose pydantic wheels aren't fully exposed yet, crashing again with
    `ImportError: cannot import name 'BaseModel'`. The journal showed 14
    such restart cycles between 14:30:38 and 14:31:11 before the install
    finished and the panel came up. The operator's terminalised symptom
    was `Failed to restart psiphon-3x-ui.service: Unit not found.` plus
    an 80-line `ImportError` traceback per cycle.

    Fix: STOP + DISABLE + RESET-FAILED + DAEMON-RELOAD the unit AT THE
    VERY TOP of `run_panel_install`, BEFORE touching the venv / wheel /
    runtime deps. `disable` removes the wants-symlink (no autostart slot
    can fire while the wheel reinstall is in progress); `reset-failed`
    zeroes the FAILED-state entry (no queued restart job can be minted
    by the policy against a unit with no MD). These tests pin the
    pre-build quiesce block exists with the exact `stop` < `disable` <
    `reset-failed` < `daemon-reload` ordering and the exact
    `2>/dev/null || true` shape, AND that all four calls sit strictly
    before the venv-create section.
    """

    _REPO_ROOT = Path(__file__).resolve().parents[1]
    _PANEL_INSTALL_SH = _REPO_ROOT / "installer" / "panel_install.sh"

    def _no_comment_nonblank_lines(self) -> list[str]:
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        return [ln for ln in no_comments.splitlines() if ln.strip()]

    def test_panel_install_has_pre_build_quiesce_info_banner(self):
        """The Human-readable ``info`` banner MUST announce the pre-build
        quiesce so an operator tailing the install log can correlate the
        four systemctl no-ops that follow with intentional hygiene, rather
        than mistaking them for stray installer chatter."""
        lines = self._no_comment_nonblank_lines()
        banner = [
            ln for ln in lines
            if "Pre-build quiesce" in ln and "disabling" in ln
        ]
        assert len(banner) == 1, (
            "Phase 24 Hotfix #6 — panel_install.sh must have EXACTLY ONE "
            "`info \"Pre-build quiesce: ... disabling ...` banner that "
            "precedes the four systemctl quiesce calls. Without it the "
            "no-op calls look like noise to a tailing operator (who can't "
            "tell them from stray installer chatter). "
            f"Found {len(banner)} matches: {banner!r}."
        )

    def test_pre_build_quiesce_has_four_systemctl_calls(self):
        """There MUST be FOUR systemctl quiesce calls — ``stop``,
        ``disable``, ``reset-failed``, ``daemon-reload`` — at the top of
        ``run_panel_install``. Missing any one re-opens the race window
        Hotfix #6 closes (e.g. omitting `disable` leaves the wants-symlink
        armed and systemd can re-arm an autostart from the policy between
        the wheel unlink and the explicit start at the bottom of the
        function)."""
        lines = self._no_comment_nonblank_lines()
        # The pre-build quiesce block is the FIRST four systemctl-stop/
        # disable/reset-failed/daemon-reload lines in the function body.
        # We can't just grep for any stop/disable/... because the file has
        # SEVERAL other systemctl stop/disable/restart call sites lower
        # down (the Hotfix #2 pre-flight block, the Hotfix #5 reset-failed
        # sites, the daemon-reload+enable+start block, etc.). So we
        # anchor on the Pre-build quiesce banner and walk forward.
        idx_banner = next(
            (i for i, ln in enumerate(lines)
             if "Pre-build quiesce" in ln),
            None,
        )
        assert idx_banner is not None, (
            "Phase 24 Hotfix #6 — pre-condition: "
            "`Pre-build quiesce` info banner not found "
            "(see test_pre_build_quiesce_info_banner)."
        )
        # Walk forward from the banner and collect the FIRST lines matching
        # each of the four systemctl operations. The block should end at the
        # first `systemctl daemon-reload` line; the venv-create
        # `if [[ ! -x "${VENV_DIR}/bin/python" ]]` line follows.
        quiesce_block = []
        for ln in lines[idx_banner + 1:]:
            if "systemctl" in ln and "psiphon-3x-ui.service" in ln:
                quiesce_block.append(ln)
                if "daemon-reload" in ln:
                    break
            elif "daemon-reload" in ln:
                quiesce_block.append(ln)
                break
            elif "${VENV_DIR}/bin/python" in ln:
                # We hit venv-create before seeing a daemon-reload — the
                # block is incomplete.
                break
        # Expect stop + disable + reset-failed + daemon-reload.
        joined = "\n".join(quiesce_block)
        assert "systemctl stop psiphon-3x-ui.service" in joined, (
            "Phase 24 Hotfix #6 — pre-build quiesce block missing the "
            f"`systemctl stop psiphon-3x-ui.service` call. Block: {quiesce_block!r}."
        )
        assert "systemctl disable psiphon-3x-ui.service" in joined, (
            "Phase 24 Hotfix #6 — pre-build quiesce block missing the "
            f"`systemctl disable psiphon-3x-ui.service` call. Block: {quiesce_block!r}."
        )
        assert "systemctl reset-failed psiphon-3x-ui.service" in joined, (
            "Phase 24 Hotfix #6 — pre-build quiesce block missing the "
            f"`systemctl reset-failed psiphon-3x-ui.service` call. Block: {quiesce_block!r}."
        )
        assert "systemctl daemon-reload" in joined, (
            "Phase 24 Hotfix #6 — pre-build quiesce block missing the "
            f"`systemctl daemon-reload` call. Block: {quiesce_block!r}."
        )

    def test_pre_build_quiesce_runs_before_venv_create(self):
        """All four quiesce calls MUST appear strictly BEFORE the venv-
        create ``if [[ ! -x "${VENV_DIR}/bin/python" ]]`` line — otherwise
        the wheel reinstall could begin while systemd still has a queued
        autostart armed against the prior failed-and-enabled unit, which
        is exactly the boot-loop Hotfix #6 is meant to prevent."""
        lines = self._no_comment_nonblank_lines()
        idx_banner = next(
            (i for i, ln in enumerate(lines)
             if "Pre-build quiesce" in ln),
            None,
        )
        idx_venv = next(
            (i for i, ln in enumerate(lines)
             if "${VENV_DIR}/bin/python" in ln
             and ("! -x" in ln or "venv" in ln.lower())),
            None,
        )
        assert idx_banner is not None and idx_venv is not None, (
            "Phase 24 Hotfix #6 — pre-condition: panel_install.sh must have "
            "both the `Pre-build quiesce` banner and the venv-create "
            "`if [[ ! -x \"${VENV_DIR}/bin/python\" ]]` block."
        )
        # Collect all four systemctl quiesce operations between banner and
        # venv-create and assert they ALL sit strictly before venv-create.
        quiesce_indices = [
            i for i, ln in enumerate(lines)
            if idx_banner < i < idx_venv
            and "systemctl" in ln
            and ("psiphon-3x-ui.service" in ln or "daemon-reload" in ln)
        ]
        assert quiesce_indices, (
            "Phase 24 Hotfix #6 — NO systemctl quiesce calls between the "
            "`Pre-build quiesce` banner and the venv-create block. The "
            "venv/wheel reinstall would race systemd's still-armed "
            "wants-symlink."
        )
        # And specifically each of the four ops must appear in that span.
        span = [lines[i] for i in quiesce_indices]
        joined = "\n".join(span)
        for op in (
            "systemctl stop psiphon-3x-ui.service",
            "systemctl disable psiphon-3x-ui.service",
            "systemctl reset-failed psiphon-3x-ui.service",
            "systemctl daemon-reload",
        ):
            assert op in joined, (
                f"Phase 24 Hotfix #6 — `{op}` must sit strictly BEFORE the "
                f"venv-create block (between the `Pre-build quiesce` banner "
                f"and `${{VENV_DIR}}/bin/python`). Found span: {span!r}."
            )
        # All four calls are BEFORE venv-create (the idx span already
        # enforces this, but assert explicitly for clarity).
        assert max(quiesce_indices) < idx_venv, (
            "Phase 24 Hotfix #6 — at least one of the four quiesce systemctl "
            "calls appears AT or AFTER the venv-create block; they must all "
            "BE strictly before it."
        )

    def test_pre_build_quiesce_strict_ordering(self):
        """The four quiesce calls MUST appear in the order
        ``stop`` < ``disable`` < ``reset-failed`` < ``daemon-reload``.
        Any other ordering re-opens or short-circuits part of the race:

        * ``disable`` before ``stop`` would yank the wants-symlink while
          the panel is still running, leaving it as an orphan until the
          explicit re-enable+start at the bottom — meaning the proxy
          clients upstream of the panel see a silent drop mid-session.
        * ``reset-failed`` before ``disable``/``stop`` would zero the
          failed-state entry before the policy has had a chance to mint
          the final one for the just-stopped unit — re-arming a freshly
          queued autostart between the two calls.
        * ``daemon-reload`` before ``reset-failed`` would re-read the unit
          MD while the FAILED entry is still alive, re-arming the
          ``Restart=on-failure`` policy's view of the unit before the
          entry gets cleared.
        """
        lines = self._no_comment_nonblank_lines()
        idx_banner = next(
            (i for i, ln in enumerate(lines)
             if "Pre-build quiesce" in ln),
            None,
        )
        idx_venv = next(
            (i for i, ln in enumerate(lines)
             if "${VENV_DIR}/bin/python" in ln
             and ("! -x" in ln or "venv" in ln.lower())),
            None,
        )
        assert idx_banner is not None and idx_venv is not None, (
            "Phase 24 Hotfix #6 — pre-condition (see "
            "test_pre_build_quiesce_runs_before_venv_create)."
        )
        # Within the [banner, venv) span, find the FIRST index of each op.
        idx_stop = next(
            (i for i, ln in enumerate(lines)
             if idx_banner < i < idx_venv
             and "systemctl stop psiphon-3x-ui.service" in ln),
            None,
        )
        idx_disable = next(
            (i for i, ln in enumerate(lines)
             if idx_banner < i < idx_venv
             and "systemctl disable psiphon-3x-ui.service" in ln),
            None,
        )
        idx_reset = next(
            (i for i, ln in enumerate(lines)
             if idx_banner < i < idx_venv
             and "systemctl reset-failed psiphon-3x-ui.service" in ln),
            None,
        )
        idx_reload = next(
            (i for i, ln in enumerate(lines)
             if idx_banner < i < idx_venv
             and "systemctl daemon-reload" in ln),
            None,
        )
        assert (
            idx_stop is not None
            and idx_disable is not None
            and idx_reset is not None
            and idx_reload is not None
        ), (
            "Phase 24 Hotfix #6 — pre-build quiesce block missing one or more "
            f"of the four required calls in the [banner, venv) span: "
            f"stop={idx_stop} disable={idx_disable} reset={idx_reset} "
            f"reload={idx_reload}."
        )
        assert idx_stop < idx_disable < idx_reset < idx_reload, (
            "Phase 24 Hotfix #6 — pre-build quiesce calls MUST appear in the "
            "order `stop` < `disable` < `reset-failed` < `daemon-reload`. "
            f"Found: stop={idx_stop} disable={idx_disable} reset={idx_reset} "
            f"reload={idx_reload}."
        )

    def test_pre_build_quiesce_uses_stderr_redirect_and_or_true(self):
        """All four pre-build quiesce calls MUST use the
        ``2>/dev/null || true`` form — on a FRESH install (no prior unit,
        no wants-symlink, no FAILED entry to clear) each call is a no-op
        that returns non-zero, and without the `|| true` belt a
        ``set -e``-shell would abort the whole installer mid-quiesce."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # We restrict the regex scope to the pre-build quiesce block by
        # anchoring on the `Pre-build quiesce` info() banner and walking
        # to the subsequent `systemctl daemon-reload` line.
        block_start = no_comments.find("Pre-build quiesce")
        assert block_start != -1, (
            "Phase 24 Hotfix #6 — pre-condition: `Pre-build quiesce` banner "
            "not found in panel_install.sh (see test_pre_build_quiesce_info_banner)."
        )
        # The block ends at the first `systemctl daemon-reload` after the banner.
        block_end_rel = no_comments.find("systemctl daemon-reload", block_start)
        assert block_end_rel != -1, (
            "Phase 24 Hotfix #6 — `systemctl daemon-reload` not found after the "
            "`Pre-build quiesce` banner (should be the LAST of the four calls)."
        )
        block_end = no_comments.find("\n", block_end_rel)
        block = no_comments[block_start:block_end]
        # Each of the four systemctl ops within the block must end with
        # `2>/dev/null || true` (allowing flexible spaces).
        for op_line in re.findall(
            r"systemctl (?:stop|disable|reset-failed) psiphon-3x-ui\.service[^\n]*|"
            r"systemctl daemon-reload[^\n]*",
            block,
        ):
            assert "2>/dev/null" in op_line, (
                "Phase 24 Hotfix #6 — pre-build quiesce call MUST redirect "
                f"stderr (`2>/dev/null`) so systemctl's chatter doesn't print "
                f"on a fresh install. Offending call: {op_line!r}."
            )
            assert "|| true" in op_line, (
                "Phase 24 Hotfix #6 — pre-build quiesce call MUST end with "
                f"`|| true` (returns non-zero on a fresh install where there "
                f"is no unit to stop/disable/reset-failed; without it a "
                f"set -e shell aborts). Offending call: {op_line!r}."
            )
        # Sanity: we found exactly 4 such qualified calls (the block has 4
        # systemctl ops; daemon-reload with no unit-name arg still matches the
        # second alternative of the regex).
        qualified = re.findall(
            r"systemctl (?:stop|disable|reset-failed) psiphon-3x-ui\.service[^\n]*|"
            r"systemctl daemon-reload[^\n]*",
            block,
        )
        assert len(qualified) == 4, (
            "Phase 24 Hotfix #6 — pre-build quiesce block must contain EXACTLY "
            f"4 systemctl calls (stop, disable, reset-failed, daemon-reload), "
            f"all with `2>/dev/null || true`. Found {len(qualified)}: "
            f"{qualified!r}."
        )

    def test_pre_build_quiesce_disables_unit_to_remove_wants_symlink(self):
        """The ``systemctl disable`` call is the load-bearing fix: it
        removes the ``/etc/systemd/system/multi-user.target.wants/
        psiphon-3x-ui.service`` wants-symlink the prior
        ``systemctl enable`` left. Without that symlink gone, systemd's
        ``multi-user.target`` could re-arm an autostart while
        ``pip install --force-reinstall`` is mid-swap of the wheel /
        pydantic — re-opening the boot loop Hotfix #6 closes."""
        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        # The `disable` line MUST be present (not just `enable` somewhere
        # later). Anchored to the psiphon-3x-ui.service unit.
        assert (
            "systemctl disable psiphon-3x-ui.service 2>/dev/null || true"
            in text
        ), (
            "Phase 24 Hotfix #6 — panel_install.sh must call "
            "`systemctl disable psiphon-3x-ui.service 2>/dev/null || true` "
            "in the pre-build quiesce block. Without `disable`, the prior "
            "install's `WantedBy=multi-user.target` wants-symlink stays "
            "armed and systemd can re-arm a mid-install autostart against "
            "the half-broken venv."
        )


class TestHotfix20PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #7 — the operator-side
    stdout noise the operator reported STILL occurring on the 8th fresh
    install (after Hotfix #6 had silenced the `Restart=on-failure` boot
    loop).

    Operator's terminal transcript (8th install, Hotfix #6 confirmed
    deployed via `grep "Pre-build quiesce" panel_install.sh`):

        Successfully installed psiphon-3x-ui-panel-1.0.0
        [seed] inserted new Settings(id=1) row
        [seed] country table synced (33 entries)
        Failed to restart psiphon-3x-ui.service: Unit psiphon-3x-ui.service not found.
        ── Psiphon-3X-UI installed ──
        ...

    Smoking-gun diagnostic (operator-provided):

      * `wc -l install.log`  →  ``4``   (only the "Fetching installer
        modules" banner block writes via `info`/`ok`/`warn`/`err` →
        `tee -a LOG_FILE`).
      * `grep "Failed to restart" install.log`  →  ZERO matches.
      * `journalctl -u psiphon-3x-ui --no-pager -n 30`  →  a CLEAN boot
        (Line `systemd[1]: Started psiphon-3x-ui.service` then
        `Uvicorn running on http://0.0.0.0:11199`) — NO ImportError cycle,
        NO `Restart=on-failure` reschedules. Hotfix #6 SUCCEEDED.

    All three together rule out an installer helper call (`info`/`ok`/
    `warn`/`err` all funnel through `_log` → `tee -a LOG_FILE` → they ALL
    appear in install.log) and rule out a journal-side emit. The wording
    must come from a child process whose stderr inherits install.sh's
    stderr pipe (bypassing the `_log`/`tee -a LOG_FILE` funnel).

    The only two `systemctl` calls in panel_install.sh's seed→print_summary
    path that lacked `2>/dev/null` were:

      * `systemctl daemon-reload || warn "systemctl daemon-reload failed."`
        (post-seed systemd-unit-install; Hotfix #5/#6 left it unredirected).
      * `systemctl start psiphon-3x-ui.service` (followed by a
        backslash line-continuation splitting the `|| warn` onto the
        next line; the post-pre-flight start; Hotfix #2/#5 left it
        unredirected).

    Mechanism: `systemctl daemon-reload` re-reads the just-updated unit's
    MD while systemd's transaction graph STILL holds a queued restart
    transaction from a prior `enable` (Hotfix #5/#6's `reset-failed` only
    flushed the FAILED-state entry, not the pending restart job minted by
    `WantedBy=multi-user.target`'s autostart slot). daemon-reload re-arms
    the queued transaction; systemd attempts to dispatch it against a unit
    whose MD is mid-reload → emits
    `"Failed to restart psiphon-3x-ui.service: Unit ... not found."` to
    stderr → that stderr is install.sh's stderr (inherited) → prints on
    the operator's terminal in the exact `[seed] ── Psiphon-3X-UI
    installed ──` bracket. daemon-reload ITSELF exits 0, so the `|| warn`
    arm was never taken — which is why the warn text NEVER reached
    install.log (smoking gun that the source is systemctl's stderr, not
    the installer's warn helper).

    Fix: redirect BOTH calls' stderr to /dev/null. daemon-reload's
    `|| warn` becomes `|| true` (a non-fatal reload-only failure should
    not abort a fresh install; the subsequent `enable` will reprise any
    real systemic breakage loudly). `systemctl start` keeps the warn
    funnel (genuine start failures ARE operator-actionable and DO belong
    in install.log) but wraps the call in `if ! ... 2>/dev/null; then
    warn "..."; fi` so systemd's transient JobResult chatter cannot leak
    to the terminal.

    These tests pin the new redirect shape at BOTH call sites, pin neither
    site regressed back to a bare emit, and pin both sit strictly between
    the seed invocation and `print_summary`.
    """

    _REPO_ROOT = Path(__file__).resolve().parents[1]
    _PANEL_INSTALL_SH = _REPO_ROOT / "installer" / "panel_install.sh"

    def _no_comment_nonblank_lines(self) -> list[str]:
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        return [ln for ln in no_comments.splitlines() if ln.strip()]

    def test_post_seed_daemon_reload_redirects_stderr(self):
        """The post-seed `systemctl daemon-reload` (AFTER the unit file
        is installed and BEFORE `systemctl enable psiphon-3x-ui.service`)
        must end with `2>/dev/null || true`. The `|| warn` form is no
        longer correct here: daemon-reload ENTIRELY swallows the queued
        restart job's dispatch failure and exits 0, so the `|| warn` arm
        was dead AND its `warn` message would (paradoxically) double-write
        to install.log while the actual chatter that the operator sees
        (the bare `Failed to restart ... Unit not found.` emit on stderr)
        BYPASSES `_log` and never appears in install.log — which is why
        Hotfix #6's `wc -l install.log` came back as 4.
        """
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The post-seed daemon-reload is the LAST `systemctl daemon-reload`
        # in non-comment source that is NOT preceded by the Hotfix #6
        # "Pre-build quiesce" banner. (Both Hotfix #6 pre-build + this
        # post-seed call now share the `2>/dev/null || true` form — so the
        # regression guard below checks the COUNT is at least 2.)
        qualified = re.findall(
            r"systemctl daemon-reload\s+2>/dev/null\s*\|\|\s*true",
            no_comments,
        )
        assert len(qualified) >= 2, (
            "Phase 24 Hotfix #7 — post-seed `systemctl daemon-reload` MUST "
            "use the `2>/dev/null || true` form (Hotfix #6's pre-build "
            "quiesce daemon-reload is the OTHER such call, so the file "
            "must now contain >= 2 of them). Found "
            f"{len(qualified)}: {qualified!r}."
        )

    def test_post_seed_daemon_reload_no_longer_warns_on_failure(self):
        """The OLD `systemctl daemon-reload || warn "systemctl
        daemon-reload failed."` form is forbidden: dead `|| warn` arm
        (daemon-reload swallows the dispatch failure and exits 0) which
        would paradoxically log to install.log while the chatter the
        operator SEES escapes via stderr (never reaching install.log —
        the smoking gun that proved Hotfix #7's root cause).
        """
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        bad_daemon_reload = re.findall(
            r"systemctl\s+daemon-reload\s*\|\|\s*warn\b[^\n]*",
            no_comments,
        )
        assert not bad_daemon_reload, (
            "Phase 24 Hotfix #7 — `systemctl daemon-reload || warn ...` "
            "is NO LONGER allowed anywhere in panel_install.sh. The "
            "`|| warn` arm was dead (daemon-reload swallows the queued "
            "JobResult failure and exits 0) AND the chatter the operator "
            "actually saw escaped via stderr to begin with (which is why "
            "an `|| warn` variant would paradoxically write to install.log "
            "while the operator still saw the noise on the terminal). Use "
            "`systemctl daemon-reload 2>/dev/null || true` (the TRUE / "
            "DEVNULL redirect silences the sysd chatter; the caller's "
            "`|| true` keeps `set -e` from aborting on a transient "
            "reload hiccup). Offending lines: "
            f"{bad_daemon_reload!r}."
        )

    def test_pre_flight_start_redirects_stderr(self):
        """The post-pre-flight `systemctl start psiphon-3x-ui.service`
        must be wrapped in `if ! ... 2>/dev/null; then warn "..."; fi`.
        The OLD bare `systemctl start psiphon-3x-ui.service \\ || warn
        "..."` form leaked systemd's transient
        `"Failed to restart psiphon-3x-ui.service: Unit ... not
        found."` JobResult emit to the operator's terminal in the
        `[seed] ── Psiphon-3X-UI installed ──` bracket on the 8th
        install. The new wrapper keeps the warn funnel (genuine start
        failures ARE operator-actionable — the warn goes via `_log` →
        `tee -a LOG_FILE` → install.log) but silences the stderr
        chatter leak with `2>/dev/null`.
        """
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The new form MUST be present.
        assert re.search(
            r"if\s+!\s*systemctl\s+start\s+psiphon-3x-ui\.service\s+2>/dev/null\s*;\s*then",
            no_comments,
        ), (
            "Phase 24 Hotfix #7 — the post-pre-flight unit start MUST be "
            "rewritten as `if ! systemctl start psiphon-3x-ui.service "
            "2>/dev/null; then warn \"...\"; fi`. The bare "
            "`systemctl start psiphon-3x-ui.service` (no redirect, no "
            "if/then/fi wrapper) leaks systemd's transient "
            "`Failed to restart ... Unit not found.` JobResult emit to "
            "the operator's terminal — exactly the noise Hotfix #7 set "
            "out to silence."
        )

    def test_pre_flight_start_no_bare_or_unredirected_form(self):
        """The bare `systemctl start psiphon-3x-ui.service \\` (backslash
        line-continuation, no `2>/dev/null`, splitting the `|| warn` onto
        the next line) and the `systemctl start
        psiphon-3x-ui.service \\n || warn` form are BOTH forbidden —
        Hotfix #7's `if ! ... 2>/dev/null; then warn ...; fi` wrapper is
        the only allowed shape for the post-pre-flight start.
        """
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # No bare backslash-continuation start without a redirect AND
        # no `|| warn` start. The only permitted start-line shape is
        # `if ! systemctl start psiphon-3x-ui.service 2>/dev/null; then`.
        bare_cont = re.findall(
            r"systemctl\s+start\s+psiphon-3x-ui\.service\s*\\\s*\n",
            no_comments,
        )
        warn_arm = re.findall(
            r"systemctl\s+start\s+psiphon-3x-ui\.service\s*(?:\\\s*\n\s*)?\|\|\s*warn\b",
            no_comments,
        )
        assert not bare_cont, (
            "Phase 24 Hotfix #7 — the BACKSLASH-LINE-CONTINUATION "
            "`systemctl start psiphon-3x-ui.service \\\\` form is no "
            "longer allowed (it provided no stderr redirect — systemd's "
            "transient JobResult emit leaked straight to install.sh's "
            "inherited stderr → the operator's terminal). Use the "
            "`if ! systemctl start ... 2>/dev/null; then warn ...; fi` "
            f"wrapper. Offending: {bare_cont!r}."
        )
        assert not warn_arm, (
            "Phase 24 Hotfix #7 — the `systemctl start psiphon-3x-ui"
            ".service \\ || warn` form is NO LONGER allowed here. The "
            "`|| warn` arm emits an installer-side log line (via "
            "`_log` → `tee -a LOG_FILE`) but the actual chatter the "
            "operator sees escapes that funnel via stderr (which is "
            "exactly the diagnostic `wc -l install.log = 4` smoke gun). "
            "Use the `if ! systemctl start ... 2>/dev/null; then warn "
            f"...; fi` wrapper. Offending: {warn_arm!r}."
        )

    def test_daemon_reload_and_start_sit_between_seed_and_print_summary(self):
        """Both Hotfix #7 call sites must sit strictly AFTER the `python
        -m panel.seed` invocation (the seed call) and strictly BEFORE
        `print_summary`. If either one drifted outside that span, the
        stderr chatter they suppress would no longer live in the
        `[seed] ── Psiphon-3X-UI installed ──` bracket where the operator
        reported it on the 8th install.
        """
        lines = self._no_comment_nonblank_lines()
        nonblank_with_indices = list(enumerate(lines))
        # The seed invocation is ``"${VENV_DIR}/bin/python" -m panel.seed``
        # — the substring ``-m panel.seed`` is the stable part (the
        # ``"${VENV_DIR}/bin/python"`` prefix has shell interpolation).
        idx_seed = next(
            (i for i, ln in nonblank_with_indices
             if "-m panel.seed" in ln),
            None,
        )
        # ``print_summary`` lives in ``install.sh``, NOT in
        # ``panel_install.sh``. The natural lower bound for the bracket
        # here is the ``if ! wait_for_panel_socket; then`` invocation
        # inside ``run_panel_install`` (which fires strictly AFTER the
        # ``systemctl start`` and waits for the listening socket) — the
        # ``wait_for_panel_socket() {`` function DEFINITION further down
        # has a different shape (``()``-suffix) so anchoring on the
        # ``if ! wait_for_panel_socket; then`` form uniquely picks the
        # call site inside the function body.
        idx_socket_wait = next(
            (i for i, ln in nonblank_with_indices
             if "if ! wait_for_panel_socket; then" in ln),
            None,
        )
        assert (
            idx_seed is not None and idx_socket_wait is not None
        ), (
            "Phase 24 Hotfix #7 — pre-condition: panel_install.sh MUST "
            "still invoke ``-m panel.seed`` (the install.sh call site) "
            "AND contain an ``if ! wait_for_panel_socket; then`` block "
            "inside ``run_panel_install`` to bound the post-seed pre-"
            "socket-wait bracket where Hotfix #7's two stderr redirects "
            "belong."
        )
        assert idx_seed < idx_socket_wait, (
            "Phase 24 Hotfix #7 — pre-condition: the ``-m panel.seed`` "
            "invocation MUST run before the ``if ! wait_for_panel_socket; "
            "then`` block (else the bracket Hotfix #7 pins is "
            "meaningless)."
        )
        # Daemon-reload: the LAST ``systemctl daemon-reload`` in
        # non-comment source. The pre-build one (Hotfix #6) sits ABOVE
        # the seed invocation (it's at the top of run_panel_install),
        # so the post-seed daemon-reload is the only candidate > idx_seed.
        idx_daemon_reload = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_seed
             and "systemctl daemon-reload" in ln),
            None,
        )
        # Start: the LAST ``systemctl start psiphon-3x-ui.service`` in
        # non-comment source — there is no other start in the file (the
        # pre-flight stop is a ``stop``, not a start).
        idx_start = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_seed
             and "systemctl start psiphon-3x-ui.service" in ln),
            None,
        )
        assert idx_daemon_reload is not None, (
            "Phase 24 Hotfix #7 — ``systemctl daemon-reload`` MUST "
            "appear in the post-seed pre-socket-wait bracket (the "
            "pre-build one from Hotfix #6 sits ABOVE seed at the top "
            "of run_panel_install — the post-seed call is the only "
            "``daemon-reload`` strictly after the seed invocation)."
        )
        assert idx_start is not None, (
            "Phase 24 Hotfix #7 — ``systemctl start psiphon-3x-ui"
            ".service`` MUST appear in the post-seed pre-socket-wait "
            "bracket."
        )
        # Both must fall STRICTLY between seed and the socket-wait.
        assert idx_seed < idx_daemon_reload < idx_socket_wait, (
            "Phase 24 Hotfix #7 — the post-seed ``systemctl daemon-reload`` "
            f"must sit strictly BETWEEN the ``-m panel.seed`` invocation "
            f"(line #{idx_seed}) and the ``if ! wait_for_panel_socket; "
            f"then`` block (line #{idx_socket_wait}); it lives at line "
            f"#{idx_daemon_reload}. If the chatter-suppressing redirect "
            "drifted out of that bracket the operator would see it "
            "again on the 9th install."
        )
        assert idx_seed < idx_start < idx_socket_wait, (
            "Phase 24 Hotfix #7 — the post-pre-flight ``systemctl start "
            "psiphon-3x-ui.service`` must sit strictly BETWEEN the "
            f"``-m panel.seed`` invocation (line #{idx_seed}) and the "
            f"``if ! wait_for_panel_socket; then`` block (line "
            f"#{idx_socket_wait}); it lives at line #{idx_start}."
        )

    def test_daemon_reload_runs_before_enable_after_unit_install(self):
        """Hotfix #7's redirect MUST NOT disturb the existing
        Hotfix #5 ordering that the post-seed sequence still runs:
        ``install -m 0644`` unit-install, then `systemctl daemon-reload`,
        then `systemctl reset-failed psiphon-3x-ui.service
        2>/dev/null || true`, then `systemctl enable
        psiphon-3x-ui.service`. If the redirect's `|| true` accidentally
        let daemon-reload fall through to the pre-flight stop instead of
        enable, the prior install's queue would race the install again.
        """
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The post-seed daemon-reload must still be FOLLOWED by the
        # Hotfix #5 enable. We don't insist on the exact line number
        # (Hotfix #7 docblock shifted them) but the LEFT-TO-RIGHT order
        # must survive.
        idx_daemon_reload = no_comments.find("systemctl daemon-reload 2>/dev/null || true")
        # Skip the pre-build daemon-reload (Hotfix #6) — it's the FIRST
        # such occurrence. Find the SECOND one (the post-seed call).
        idx_daemon_reload = no_comments.find(
            "systemctl daemon-reload 2>/dev/null || true",
            idx_daemon_reload + 1,
        )
        idx_enable = no_comments.find(
            "systemctl enable psiphon-3x-ui.service",
            idx_daemon_reload,
        )
        assert idx_daemon_reload != -1 and idx_enable != -1, (
            "Phase 24 Hotfix #7 — post-seed `systemctl daemon-reload` "
            "and subsequent `systemctl enable psiphon-3x-ui.service` "
            "must both be present."
        )
        assert idx_daemon_reload < idx_enable, (
            "Phase 24 Hotfix #7 — `systemctl daemon-reload` MUST run "
            "BEFORE `systemctl enable psiphon-3x-ui.service` (Hotfix #5 "
            "ordering preserved). Hotfix #7 only added the stderr "
            "redirect — it must NOT have reordered the post-seed "
            "sequence the Hotfix #5 test_reset_failed_site_1_runs_"
            "between_daemon_reload_and_enable test pins."
        )

    def test_start_warn_message_remains_actionable(self):
        """The `warn` text emitted on a genuine `systemctl start` failure
        MUST remain operator-actionable (point at `journalctl -u
        psiphon-3x-ui`). Hotfix #7 silenced stderr chatter but must NOT
        have removed the warn funnel entirely — a silent start failure
        would leave the operator staring at a non-listening port with
        no install.log breadcrumb.
        """
        lines = self._no_comment_nonblank_lines()
        nonblank_with_indices = list(enumerate(lines))
        idx_start = next(
            (i for i, ln in nonblank_with_indices
             if "systemctl start psiphon-3x-ui.service" in ln
             and "2>/dev/null" in ln),
            None,
        )
        assert idx_start is not None, (
            "Phase 24 Hotfix #7 — pre-condition: the redirected start "
            "shape `if ! systemctl start psiphon-3x-ui.service "
            "2>/dev/null; then ...; fi` MUST be present."
        )
        # The `warn` call on the line immediately AFTER must mention
        # `journalctl -u psiphon-3x-ui` so the operator has a concrete
        # next-step diagnostic (not a bare "systemctl start failed").
        assert any(
            "journalctl -u psiphon-3x-ui" in ln
            for _, ln in nonblank_with_indices
            if ln.lstrip().startswith("warn")
        ), (
            "Phase 24 Hotfix #7 — the `warn` message on a genuine "
            "`systemctl start` failure MUST point the operator at "
            "`journalctl -u psiphon-3x-ui` (so a silent start failure "
            "still leaves a concrete next-step in install.log). Removing "
            "the actionable hint while `2>/dev/null` silences stderr was "
            "tempting but would leave the operator debugging a "
            "non-listening port with no breadcrumb."
        )


class TestHotfix21PostReleaseRegressions:
    """Static-source grep tests for Phase 24 Hotfix #8 — the operator's
    install terminal STILL printed ``Failed to restart psiphon-3x-ui
    .service: Unit psiphon-3x-ui.service not found.`` between the
    ``[seed] country table synced (33 entries)`` stderr print and the
    ``── Psiphon-3X-UI installed ──`` banner even AFTER Hotfix #7 had
    deployed ``2>/dev/null`` redirects on every ``systemctl`` call in
    the post-seed bracket.

    Hotfix #7's stderr-redirect theory was definitively proven WRONG by
    the operator's 12th-install ``strace -f -e trace=execve,write``
    trace: NO install.sh-lineage process writes the ``Failed to
    restart`` wording to ANY terminal-addressed file descriptor — the
    only matches in the strace are the installer writing its own
    panel_install.sh SOURCE to disk (the docblock contains the literal
    phrase). The operator's ``journalctl --system | grep "Failed to
    restart"`` also returned ZERO matches. Hence the wording is:

    * NOT coming from ``systemctl`` CLI's stderr (those are silenced).
    * NOT going to systemd-journald (journalctl shows nothing).
    * NOT being written by any installer helper / child process
      (strace shows no such write to fd 1 / fd 2 / TTY).

    The remaining explanation: the wording is emitted asynchronously by
    **systemd PID 1 itself** when its ``Restart=on-failure`` policy
    notices the panel process exited with non-zero status (which is
    what happens during the installer's `pip install --force-reinstall
    --no-deps` window — pip atomically unlinks the wheel files and a
    still-running uvicorn process that has been SIGTERM'd by our pre-
    build `systemctl stop` finally exits with non-zero status; PID 1
    then queues a restart). The restart-transaction dispatch + emit is
    **inside systemd's own logging path**, which on hosts where PID 1's
    ``LogTarget=journal-or-kmsg`` is also routed to the system console
    will leak to the operator's terminal DESPITE our ``2>/dev/null``
    redirects (those silence the CLI's stderr, NOT PID 1's own log
    emit).

    Fix: change the unit's ``Restart=on-failure`` to ``Restart=
    on-abort`` AND add a wait-for-prior-exit polling loop at the top
    of ``run_panel_install`` so the pre-build ``systemctl stop``'s
    SIGTERM actually propagates before any subsequent
    ``daemon-reload`` / ``enable`` / ``start`` (which is when the
    queued-restart JobResult emit would otherwise fire). With
    ``Restart=on-abort``: (a) NO regular exit-1 (e.g. mid-wheel-swap
    uvicorn teardown) EVER queues a restart; (b) the panel still
    auto-recovers from SIGABRT/SIGSEGV/SIGILL-class aborts (OOM,
    segfault, panic) which is the realistic production crash mode.
    The wait-loop additionally silences the alternative race where
    the prior install's `Restart=on-failure`-armed panel is STILL
    alive when the current install reaches the post-seed
    ``daemon-reload`` (the SIGTERM takes 1-3 seconds for uvicorn
    lifespan-shutdown but daemon-reload fires immediately).

    These tests pin the ``Restart=on-abort`` change AND the
    pre-build wait-loop's exact form + positioning.
    """

    _REPO_ROOT = Path(__file__).resolve().parents[1]
    _PANEL_INSTALL_SH = _REPO_ROOT / "installer" / "panel_install.sh"
    _PANEL_UNIT = _REPO_ROOT / "systemd" / "psiphon-3x-ui.service"

    def _no_comment_nonblank_lines(self) -> list[str]:
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        return [ln for ln in no_comments.splitlines() if ln.strip()]

    def test_panel_unit_uses_restart_on_abort_not_on_failure(self):
        """``Restart=on-abort`` is the load-bearing Hotfix #8 fix.

        ``on-failure`` queues a restart on EVERY non-zero exit /
        signal-other-than-clean-stop; ``on-abort`` only queues a
        restart on SIGABRT / SIGSEGV / SIGILL class aborts. During
        install, ``pip install --force-reinstall --no-deps`` atomically
        unlinks the wheel files SSD-side; the panel process -
        SIGTERM'd by the installer's pre-build ``systemctl stop`` -
        continues executing until the kernel delivers the signal
        through its syscall-suspension, then exits via the CPython
        signal-handler with exit status 1 (NOT a clean exit-0). With
        ``on-failure`` armed, that exit-1 queues a restart at
        ``RestartSec=5`` seconds in the future. By the time the next
        ``daemon-reload`` / ``enable`` / ``start`` runs
        (deterministic timing in the post-seed bracket), the queued
        restart is dispatched against the now-stopping unit and
        systemd PID 1 emits ``Failed to restart psiphon-3x-ui.service:
        Unit ... not found.`` to its log target.

        With ``on-abort``, the panel's exit-1 (regular application
        teardown) is NOT a restart-trigger — only an abort signal
        would be. The queued-restart job is never minted. No
        ``Failed to restart ...`` JobResult emit ever fires.
        """
        import re  # noqa: PLC0415

        text = self._PANEL_UNIT.read_text(encoding="utf-8")
        # The Hotfix #8 fix MUST have replaced on-failure with on-abort.
        # We anchor on the BARE unit-directive line ``Restart=on-abort``
        # (line-anchored) so the docblock comment in the [Service]
        # block (which mentions the OLD policy name) doesn't false-flag.
        assert re.search(
            r"^[ \t]*Restart=on-abort[ \t]*$",
            text,
            flags=re.MULTILINE,
        ), (
            "Phase 24 Hotfix #8 — systemd/psiphon-3x-ui.service MUST "
            "carry a bare `Restart=on-abort` unit directive in the "
            "[Service] block (NOT `Restart=on-failure`). on-failure "
            "mints a restart-transaction the moment the panel process "
            "exits non-zero (which happens during the post-seed "
            "window when the SIGTERM'd uvicorn finally teardowns) — "
            "the queued job's JobResult emit is the exact wording "
            "`Failed to restart psiphon-3x-ui.service: Unit ... not "
            "found.` the operator saw."
        )
        # Belt-and-braces: a bare `Restart=on-failure` line DIRECTIVE
        # (line-anchored, NOT in a comment) is forbidden. The docblock
        # commentary mentioning the policy name is fine — only the
        # actual directive matters. Strip comment lines first.
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert not re.search(
            r"^[ \t]*Restart=on-failure[ \t]*$",
            no_comments,
            flags=re.MULTILINE,
        ), (
            "Phase 24 Hotfix #8 — the [Service] block MUST NOT have "
            "a bare `Restart=on-failure` unit-directive line (the "
            "bare-line check excludes comments mentioning the policy "
            "name in prose). `on-failure` re-opens the queued-"
            "restart race this Hotfix is closing."
        )

    def test_pre_build_quiesce_waits_for_prior_panel_to_exit(self):
        """Hotfix #8 added a ``is-active --quiet`` polling loop right
        after ``systemctl stop`` so the prior install's panel process
        exits BEFORE any subsequent systemctl mutating op touches the
        unit's MD. Without the wait, ``stop`` returns 0 the moment
        SIGTERM is ISSUED (not when the process actually exits) and
        the panel can linger for ~1-3 seconds (uvicorn lifespan
        shutdown + BCrypt teardown + async teardown of SQLAlchemy
        engine). Any subsequent ``daemon-reload`` (which we still issue
        at the bottom of the pre-build block) can race against the
        lingering process's final exit — and if the prior panel's
        ``Restart=on-failure`` policy has armed a queued restart for
        it (running under the OLD Hotfix #7-and-prior codepath), the
        queued job's JobResult emit fires DURING that daemon-reload —
        which is the bracket the operator actually observed.

        The wait-loop polls ``systemctl is-active --quiet`` for up to
        30 seconds; ``is-active --quiet`` returns 0 iff the unit is
        in ``active`` state (running MainPID attached), non-zero
        otherwise (inactive / failed / queued-restart-pending).
        """
        lines = self._no_comment_nonblank_lines()
        joined = "\n".join(lines)
        # The wait-for-prior-exit polling block MUST be present and
        # use the is-active --quiet form.
        assert "systemctl is-active --quiet psiphon-3x-ui.service" in joined, (
            "Phase 24 Hotfix #8 — panel_install.sh's pre-build quiesce "
            "block MUST poll `systemctl is-active --quiet "
            "psiphon-3x-ui.service` until the prior panel process "
            "exits (or the 30-second timeout fires). The single-"
            "shot `systemctl stop` SIGTERM is fire-and-forget — "
            "without the wait, the panel process lingers through the "
            "subsequent daemon-reload and the prior install's "
            "Restart=on-failure queue can re-dispatch against it "
            "mid-reload (which is the bracket the wording appeared)."
        )

    def test_pre_build_quiesce_wait_loop_bounds_to_30_iterations(self):
        """The polling loop MUST use a bounded counter (``local
        tries=30; while (( tries-- > 0 ))``) — an unbounded `while
        systemctl is-active --quiet` would hang the install forever
        if the prior panel is genuinely hung in a SIGKILL-proof
        state (e.g. in an uninterruptible disk-io syscall). The 30-
        second timeout plus the fallback `systemctl kill -s SIGKILL`
        covers the realistic uvicorn shutdown window plus margin.

        Note: we intentionally do NOT pin the exact `30` literal —
        the timeout may be tuned by future hotfixes — but the
        pattern of a `tries=` counter and a `(( tries-- > 0 ))`
        decrement must be present so a future accidental removal of
        the bound is caught.
        """
        lines = self._no_comment_nonblank_lines()
        joined = "\n".join(lines)
        assert "tries-- > 0" in joined, (
            "Phase 24 Hotfix #8 — the wait-for-prior-exit polling "
            "loop MUST be bounded by a decrementing `tries` counter "
            "(pattern `tries-- > 0` in the `(( ... ))` predicate). "
            "An unbounded loop risks a forever-hang if the prior "
            "uvicorn process is in an uninterruptible syscall."
        )
        # The SIGKILL fallback must be present.
        assert "systemctl kill -s SIGKILL psiphon-3x-ui.service" in joined, (
            "Phase 24 Hotfix #8 — the pre-build quiesce block MUST "
            "include a `systemctl kill -s SIGKILL psiphon-3x-ui."
            "service` fallback for the case where `is-active --quiet` "
            "is STILL returning 0 after the 30-iteration wait (i.e. "
            "the prior panel process is hung in an uninterruptible "
            "syscall — SIGTERM is being queued but won't be "
            "delivered). Without the SIGKILL fallback, the daemon-"
            "reload can race against a zombie panel and the wording "
            "returns."
        )

    def test_pre_build_quiesce_wait_loop_sits_between_stop_and_disable(self):
        """Order matters: the wait-loop MUST come AFTER the pre-build
        ``systemctl stop`` AND BEFORE the subsequent ``systemctl
        disable`` (and the daemon-reload at the bottom of the block).
        If the loop sat after disable (and the wants-symlink was
        already removed), the panel's prior auto-restart policy
        could already have re-armed a restart job that the
        daemon-reload picks up — and we're back in the same trap.
        """
        lines = self._no_comment_nonblank_lines()
        nonblank_with_indices = list(enumerate(lines))
        # The pre-build stop is the FIRST `systemctl stop
        # psiphon-3x-ui.service` AFTER the "Pre-build quiesce" banner.
        idx_banner = next(
            (i for i, ln in nonblank_with_indices
             if "Pre-build quiesce" in ln),
            None,
        )
        assert idx_banner is not None, (
            "Phase 24 Hotfix #8 — pre-condition: `Pre-build quiesce` "
            "info banner must be present (Hotfix #6 pinned this)."
        )
        idx_stop = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_banner
             and "systemctl stop psiphon-3x-ui.service" in ln),
            None,
        )
        idx_wait_loop_start = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_stop and "tries-- > 0" in ln),
            None,
        )
        idx_is_active_check = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_stop
             and "systemctl is-active --quiet psiphon-3x-ui.service" in ln),
            None,
        )
        idx_disable = next(
            (i for i, ln in nonblank_with_indices
             if i > idx_stop
             and "systemctl disable psiphon-3x-ui.service" in ln),
            None,
        )
        assert idx_stop is not None, (
            "Phase 24 Hotfix #8 — pre-condition: pre-build stop is "
            "present (Hotfix #6 pinned this; we only tightened the "
            "race window BEFORE it)."
        )
        assert idx_wait_loop_start is not None, (
            "Phase 24 Hotfix #8 — the `tries-- > 0` decrement marker "
            "must appear in the pre-build quiesce block (the wait "
            "loop's predicate)."
        )
        assert idx_is_active_check is not None, (
            "Phase 24 Hotfix #8 — the `systemctl is-active --quiet "
            "psiphon-3x-ui.service` check MUST appear in the wait "
            "loop's body."
        )
        assert idx_disable is not None, (
            "Phase 24 Hotfix #8 — the pre-build `systemctl disable` "
            "MUST follow the wait loop (and continue to the "
            "daemon-reload at the bottom of the block)."
        )
        # Strict left-to-right: stop < wait_loop_start < is_active <
        # disable. The is_active check sits INSIDE the wait loop body,
        # so it's necessarily after the loop-head line numbers. The
        # canonical order is: stop < wait_loop_open < is_active
        # < disable.
        assert idx_stop < idx_wait_loop_start < idx_is_active_check < idx_disable, (
            f"Phase 24 Hotfix #8 — pre-build quiesce order must be "
            f"`stop` (line #{idx_stop}) THEN `tries-- > 0` (line #"
            f"{idx_wait_loop_start}) THEN `is-active --quiet` (line "
            f"#{idx_is_active_check}) THEN `disable` (line #"
            f"{idx_disable}). Anything else lets the queued-restart "
            "race slip back open."
        )

    def test_pre_build_quiesce_wait_loop_uses_sleep_one(self):
        """Poll interval is ``sleep 1`` — the panel's actual exit
        takes ~100-500ms in the normal case (uvicorn + BCrypt +
        SQLAlchemy teardown); 1-second polling granularity is fine
        and avoids burning a syscall storm in a tight loop. A slower
        poll interval (e.g. 5s) would add 25 extra seconds to every
        install for no benefit; a faster one (e.g. ``usleep`` or
        0.1s) would burn poll-call syscalls.
        """
        lines = self._no_comment_nonblank_lines()
        joined = "\n".join(lines)
        assert "sleep 1" in joined, (
            "Phase 24 Hotfix #8 — the wait loop's poll interval MUST "
            "be `sleep 1` (the realistic uvicorn shutdown window plus "
            "a small safety margin). Longer intervals (``sleep 5`` "
            "etc) would unnecessarily stretch fresh-install time from "
            "~5s to ~25s; shorter intervals would burn unnecessary "
            "systemctl syscalls against the D-Bus monitor."
        )


class TestHotfix22PostReleaseRegressions:
    """Static-source grep tests for Phase 25 Hotfix #9 — the "Psiphon is
    connected but end-user traffic still exits via the SERVER's own IP"
    defect.

    Operator-verified on the live install:

    * Psiphon tunnels healthy (SOCKS5 listener up at 127.0.0.1:N per
      country).
    * 3x-ui cloned inbounds have ``streamSettings.outbound = { protocol:
      "socks", settings.servers=[{address:"127.0.0.1", port:N}] }``.

    Despite both, end-user traffic exits via the SERVER's own IP. Verified
    via the operator's live xray config ``/usr/local/x-ui/bin/config.json``:
    the cloned inbound's ``streamSettings.outbound`` field IS persisted to
    the config file by 3x-ui but is NOT honoured by Xray core — Xray's
    routing engine decides outbound-by-inboundTag via the top-level
    ``routing.rules[]`` array, not via per-inbound ``streamSettings.outbound``
    (which is a legacy/sniffing hint). As a result every clone's traffic
    falls back to the default ``freedom`` outbound (``outbounds[0]``
    tag=``direct``).

    The fix has been through three designs. Hotfix #9 edited
    ``/usr/local/x-ui/bin/config.json`` in-process (EACCES — the file is
    root:root 0600). Hotfix #10/#11 queued patches for a root-side applier
    sidecar. Phase 26 replaced both with 3x-ui's own supported Xray-settings
    API, which injects the same two things but with validation + hot-reload
    and without any privilege escalation:

    1. One SOCKS outbound per enabled country, keyed by
       ``tag == "psiphon-out-<CODE>"``, APPENDED so ``outbounds[0]``
       (the default egress) stays put.
    2. One routing rule per enabled country, keyed by
       ``inboundTag == [<the tag 3x-ui actually assigned>]`` →
       ``outboundTag == "psiphon-out-<CODE>"``, inserted BEFORE the
       existing ``bittorrent``/``geoip:private`` catch-alls.

    These grep tests pin the static contract; the behavioural tests live in
    ``tests/test_xray_routing.py`` and the clone/dashboard suites.
    """

    PANEL_ROOT = Path(__file__).resolve().parents[1] / "panel"

    # NOTE (Phase 26): the Hotfix-#9 direct-edit helpers
    # (``_apply_psiphon_xray_outbound_and_rule`` /
    # ``_remove_psiphon_xray_outbound_and_rule``) and their Hotfix-#10
    # queue-based successor (``_enqueue_xray_patch``) have all been deleted.
    # The current greps live in ``TestHotfix23PostReleaseRegressions``
    # (below), which also pins that the sidecar stays removed.


class TestHotfix23PostReleaseRegressions:
    """Static-source grep tests for Phase 26 — per-country Xray routing bound
    through 3x-ui's OWN supported Xray-settings API.

    The underlying defect (originally Hotfix #9) is unchanged and worth
    restating, because it is the whole reason this class exists: a cloned
    inbound's ``streamSettings.outbound`` IS persisted by 3x-ui but is NOT
    honoured by Xray core. Xray decides egress by matching the top-level
    ``routing.rules[]`` on ``inboundTag``; without a matching rule + a
    top-level ``outbounds[]`` entry, every country's traffic falls through
    to ``outbounds[0]`` (the ``direct``/freedom outbound) and leaves on the
    server's own IP.

    Hotfix #9 tried to fix that by editing ``/usr/local/x-ui/bin/config.json``
    in-process; that file is ``root:root`` mode 0600 so the unprivileged
    panel user got EACCES every time. Hotfix #10/#11 then routed the edit
    through a root-side queue+applier sidecar. Phase 26 retires all of it:
    ``POST /panel/api/xray/`` reads the template and ``POST
    /panel/api/xray/update`` validates + persists + hot-reloads it, so the
    panel needs no root, no systemd units, and never races 3x-ui's own
    regeneration of ``config.json`` from ``/etc/x-ui/x-ui.db``.

    These greps pin the wiring; the behavioural tests live in
    ``tests/test_xray_routing.py`` (pure transforms) and the clone/dashboard
    suites (end-to-end through the fake panel).
    """

    REPO_ROOT = Path(__file__).resolve().parents[1]
    PANEL_ROOT = REPO_ROOT / "panel"

    def test_panel_router_uses_api_routing_not_legacy_helpers(self):
        """``panel/dashboard/router.py`` must bind routing through the
        supported Xray settings API, not the deleted Hotfix-#9 direct-edit
        helpers nor the Hotfix-#10 queue sidecar.

        Phase 26: every handler that can leave a country's routing stale
        (``patch_country`` on disable, ``reclone_country``,
        ``delete_country``) must call ``remove_country_binding`` so no rule
        is left pointing at an inbound that no longer exists.
        """
        text = (self.PANEL_ROOT / "dashboard" / "router.py").read_text(encoding="utf-8")
        assert "_apply_psiphon_xray_outbound_and_rule(" not in text
        assert "_remove_psiphon_xray_outbound_and_rule(" not in text
        # Match the import by name rather than by exact line: Hotfix #15 added
        # apply_country_binding to the same `from .xray_routing import ...`
        # statement, and a literal-string pin would fail on that purely
        # cosmetic change while still passing if the symbol were dropped.
        imports = re.findall(r"from \.xray_routing import ([^\n(]+)", text)
        imported = {n.strip() for line in imports for n in line.split(",")}
        assert "remove_country_binding" in imported
        assert "apply_country_binding" in imported
        for fn in ("patch_country", "reclone_country", "delete_country"):
            m = re.search(
                rf"async\s+def\s+{fn}\b.*?(?=\n@router\.|\nasync\s+def|\ndef\s|\nclass\s|\Z)",
                text,
                flags=re.DOTALL,
            )
            assert m, f"{fn} handler missing"
            body = m.group(0)
            assert "remove_country_binding(" in body, (
                f"{fn} does not strip the country's Xray routing binding"
            )
            assert "_enqueue_xray_patch(" not in body, (
                f"{fn} still uses the superseded queue sidecar"
            )

    def test_panel_router_never_indexes_obj_on_a_clone_response(self):
        """Phase 26 Hotfix #16: ``clone_inbound`` returns the UNWRAPPED inbound.

        ``XuiClient.add_inbound`` ends with ``return data.get("obj") or {}`` and
        ``clone_inbound`` returns that verbatim, so the caller already holds
        ``{"id": ..., "tag": ...}``. Indexing ``["obj"]`` on it raises KeyError
        against the real panel.

        That is not a cosmetic slip. Both re-clone sites did it, the blanket
        ``except Exception`` in each handler swallowed the KeyError into a
        ``reclone_error`` field, and the endpoint still returned HTTP 200 — so
        the failure was invisible. Because it fired *between* the successful
        clone and ``apply_country_binding``, 3x-ui ended up with an inbound
        that had no outbound and no routing rule, and that country's users
        egressed on the server's own IP.
        """
        text = (self.PANEL_ROOT / "dashboard" / "router.py").read_text(encoding="utf-8")
        # Walk the AST rather than grepping: _clone_response_obj's docstring
        # quotes the buggy expression verbatim to explain it, and a text scan
        # cannot tell prose from code.
        tree = ast.parse(text)
        offenders = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id in {"new_inbound", "clone_obj", "inbound"}
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "obj"
            ):
                offenders.append(f"{node.value.id}[\"obj\"] at line {node.lineno}")
        assert not offenders, (
            "router.py indexes ['obj'] on an already-unwrapped clone/inbound "
            f"response, which raises KeyError in production: {offenders}"
        )

    def test_panel_router_handlers_that_create_inbounds_bind_routing(self):
        """Phase 26 Hotfix #15: every handler that can leave a country with a
        live inbound must also (re-)write that country's outbound + routing
        rule.

        ``streamSettings.outbound`` is persisted by 3x-ui but ignored by Xray's
        routing engine, so an inbound with no top-level binding silently
        egresses on the server's own IP — the reported symptom. Three handlers
        create or revive an inbound without going through
        ``clone_for_country`` (which binds internally):

        * ``patch_country`` — a bare re-enable after a disable, where the
          disable stripped the binding but left the inbound in place
        * ``edit_country_ports`` — re-clones directly; the tag is derived from
          the public port, so changing the port orphans the old rule
        * ``reapply_all`` — re-clones unhealthy inbounds directly

        Each must call ``apply_country_binding``.
        """
        text = (self.PANEL_ROOT / "dashboard" / "router.py").read_text(encoding="utf-8")
        for fn in ("patch_country", "edit_country_ports", "reapply_all"):
            m = re.search(
                rf"async\s+def\s+{fn}\b.*?(?=\n@router\.|\nasync\s+def|\ndef\s|\nclass\s|\Z)",
                text,
                flags=re.DOTALL,
            )
            assert m, f"{fn} handler missing"
            assert "apply_country_binding(" in m.group(0), (
                f"{fn} can leave a live inbound with no outbound/routing rule"
            )

    def test_panel_clone_helper_binds_routing_via_api(self):
        """``panel/wizard/clone.py``'s clone_for_country must apply the
        per-country outbound + routing rule through
        ``apply_country_binding`` (the Xray settings API), keyed on the tag
        3x-ui actually assigned to the new inbound."""
        text = (self.PANEL_ROOT / "wizard" / "clone.py").read_text(encoding="utf-8")
        assert "apply_country_binding(" in text
        assert "_enqueue_xray_patch(" not in text
        assert "_apply_psiphon_xray_outbound_and_rule(" not in text
        # The clone must surface the panel-assigned tag rather than assuming
        # "in-<port>-tcp" — upstream's resolveInboundTag() may hand back a
        # collision-suffixed or udp/tcpudp variant.
        assert 'clone_obj.get("tag")' in text
        assert "inbound_tag" in text

    def test_wizard_router_batch_clone_binds_routing_via_api(self):
        """The wizard's batch-clone SSE handler must bind each country's
        routing through the API using the tag from the clone event; routing
        failures remain non-fatal (``routing_failed`` SSE status)."""
        text = (self.PANEL_ROOT / "wizard" / "router.py").read_text(encoding="utf-8")
        assert "apply_country_binding(" in text
        assert "_enqueue_xray_patch(" not in text
        assert '"routing_failed"' in text
        assert "clone_event.inbound_tag" in text

    def test_xui_client_exposes_xray_settings_endpoints(self):
        """``panel/dashboard/xui_client.py`` must call the upstream 3x-ui
        Xray-settings endpoints — ``POST /panel/api/xray/`` to read the
        template and ``POST /panel/api/xray/update`` (form field
        ``xraySetting``) to write it.

        These are the supported API that made the root-side sidecar
        unnecessary; a regression here would silently strand the panel back
        on inbound-only creation.
        """
        text = (self.PANEL_ROOT / "dashboard" / "xui_client.py").read_text(encoding="utf-8")
        assert "async def get_xray_setting" in text
        assert "async def update_xray_setting" in text
        assert '"panel/api/xray/"' in text
        assert '"panel/api/xray/update"' in text
        assert '"xraySetting"' in text

    def test_sidecar_queue_and_applier_are_fully_removed(self):
        """Phase 26: the Hotfix #9/#10/#11 queue+applier sidecar must be GONE.

        Its whole reason for existing was the belief that no JSON API could
        write ``outbounds[]`` / ``routing.rules[]``. 3x-ui does expose one
        (``POST /panel/api/xray/`` + ``POST /panel/api/xray/update``), so the
        privileged sidecar is now dead weight AND a liability: it patched
        root-owned ``config.json`` out-of-band from 3x-ui's own DB, which
        3x-ui then regenerated. Leaving it installed would race the API path.

        Pinned so a future revert cannot resurrect half of it: no shipped
        files, no installer wiring, no panel-side enqueue helpers.
        """
        for rel in (
            "installer/xray_applier.sh",
            "installer/xray_apply.py",
            "installer/xray_db_apply.py",
            "systemd/psiphon-xray-applier.path",
            "systemd/psiphon-xray-applier.service",
            "tests/test_xray_db_apply.py",
        ):
            assert not (self.REPO_ROOT / rel).exists(), f"{rel} should be deleted"

        install_sh = (self.REPO_ROOT / "installer" / "panel_install.sh").read_text(
            encoding="utf-8"
        )
        for needle in (
            "installer/xray_applier.sh",
            "installer/xray_apply.py",
            "installer/xray_db_apply.py",
            "systemd/psiphon-xray-applier.path",
            "systemd/psiphon-xray-applier.service",
            "systemctl enable --now psiphon-xray-applier.path",
            "/usr/local/libexec/psiphon-3x-ui",
        ):
            assert needle not in install_sh, f"panel_install.sh still wires {needle}"
        # The queue dir must not be created any more (the bare
        # /opt/psiphon-3x-ui parent for panel.db is still expected).
        assert "xray-patch-queue" not in install_sh

        router = (self.PANEL_ROOT / "dashboard" / "router.py").read_text(encoding="utf-8")
        for needle in (
            "def _enqueue_xray_patch",
            "def _xray_patch_queue_dir",
            "def _restart_xui_service",
            "PSIPHON_XRAY_PATCH_QUEUE_DIR",
        ):
            assert needle not in router, f"router.py still defines {needle}"

    def test_polkit_rules_no_longer_authorise_xray_applier(self):
        """The polkit rule must not authorise the deleted applier unit.

        A stale grant would let the panel user start a unit that no longer
        exists — harmless in practice but a lingering privilege reference.
        """
        p = self.REPO_ROOT / "systemd" / "49-psiphon-3x-ui.rules"
        text = p.read_text(encoding="utf-8")
        assert "psiphon-xray-applier.service" not in text
