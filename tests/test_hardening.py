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
        assert "HTTP_409_CONFLICT" not in body or "409" not in body, (
            "Bug #3 — patch_country must NOT raise 409 on missing-PortAssignment "
            "enable; the pre-Hotfix-#10 hardcoded 409 must be gone."
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
    def test_render_config_uses_legacy_singular_RemoteServerListUrl(self):
        import re  # noqa: PLC0415

        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        # The implemented config dict must emit the LEGACY singular key
        # `RemoteServerListUrl` (lowercase final 'l') — auto-promoted by the
        # binary's `promoteLegacyTransferURL` (config.go:202568 +
        # LoadConfig#82242). Pre-Hotfix-#14 the dict literal referenced the
        # module-level PSIPHON_REMOTE_SERVER_LIST_URLS[0] constant directly;
        # Hotfix #14 pivoted the upstream credentials to env-var overrides
        # so the literal now reads `creds["RemoteServerListUrl"]`. Either
        # form satisfies the invariant — assert the singular key IS
        # emitted by the return-dict construction.
        assert re.search(
            r'"RemoteServerListUrl"\s*:\s*'
            r'(?:PSIPHON_REMOTE_SERVER_LIST_URLS\[0\]|creds\["RemoteServerListUrl"\])',
            no_comments,
        ), (
            "Bug #1 — render_config must emit the legacy singular "
            "`RemoteServerListUrl` string field (lowercase final 'l'), "
            "auto-promoted by the binary's "
            "`promoteLegacyTransferURL` (config.go:202568 + LoadConfig#82242)."
        )

    def test_render_config_does_not_emit_plural_RemoteServerListURLs(self):
        """The plural-string-array shape is the rejected one — must not."""
        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        # The broken shape was the dict literal `"RemoteServerListURLs": ...`
        # (plural `URLs`, capital). The fix swaps to `"RemoteServerListUrl":`
        # (singular `Url`). Both keys appear in the docblock, but the literal
        # dict assignments must only carry the singular.
        import re  # noqa: PLC0415

        # Strip comments — they're allowed to mention either spelling (the
        # docblock explains the schema upgrade). Tests only concern the live
        # code.
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert not re.search(
            r'"RemoteServerListURLs"\s*:\s*list\(',
            no_comments,
        ), (
            "Bug #1 — render_config must NOT render the broken plural "
            '`"RemoteServerListURLs": list(PSIPHON_REMOTE_SERVER_LIST_URLS)` '
            "(rejected by upstream v2.0.39 — TransferURLs expects "
            "`[]*TransferURL`-struct entries, not `[]string`)."
        )

    def test_render_config_emits_singular_url_at_runtime(self, monkeypatch):
        """End-to-end: the runtime render_config dict IS the new shape.

        Hotfix #14 (Phase 23): render_config now sources the upstream
        credentials from env (it fast-fails with PsiphonCredentialError if
        any are missing/placeholder). _set_real_psiphon_creds populates
        fake-but-real-shape values so the test exercises the happy path."""
        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import (  # noqa: PLC0415
            render_config,
        )

        cfg = render_config("AT", 11000)
        # Singular field present + correctly valued. The value is whatever
        # the operator supplied via PSIPHON_REMOTE_SERVER_LIST_URL (the panel
        # no longer caries a hardcoded well-known URL — Hotfix #14).
        assert isinstance(cfg["RemoteServerListUrl"], str) and cfg["RemoteServerListUrl"]
        # And crucially: the plural form is NOT present.
        assert "RemoteServerListURLs" not in cfg, (
            "Bug #1 — the plural `RemoteServerListURLs` key must NOT be "
            "in the rendered dict; the binary's legacy-promote branch only "
            "fires when `RemoteServerListURLs == nil`, which requires "
            "omitting the plural key entirely."
        )

    def test_write_config_writes_singular_key_to_disk(self, monkeypatch, tmp_path):
        """``json.dumps(render_config(...))`` round-trips the singular key."""
        import json  # noqa: PLC0415

        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import render_config  # noqa: PLC0415

        cfg = render_config("US", 11080)
        blob = json.dumps(cfg, indent=2, sort_keys=True)
        parsed = json.loads(blob)
        assert "RemoteServerListUrl" in parsed
        assert "RemoteServerListURLs" not in parsed

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

    def test_render_config_has_seven_keys_not_six(self, monkeypatch):
        """Headlock: the dict has 7 keys (was 6 pre-Hotfix-#13) — the
        new SponsorId slot.

        Hotfix #14 (Phase 23): render_config now fast-fails with
        PsiphonCredentialError if PSIPHON_* env vars aren't set, so we
        _set_real_psiphon_creds to exercise the happy 7-key path."""
        _set_real_psiphon_creds(monkeypatch)
        from panel.psiphon import render_config  # noqa: PLC0415

        cfg = render_config("US", 11080)
        assert len(cfg) == 7, (
            "Hotfix #13 — render_config output must have 7 keys after "
            "the SponsorId addition (was 6 pre-Hotfix-#13)."
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
    """Hotfix #14 (Phase 23) — pivots the four Psiphon-Inc upstream
    credentials from hardcoded in panel/psiphon/__init__.py to
    operator-supplied env vars read from /opt/psiphon-3x-ui/panel.env.

    Static-source-grep + runtime tests for the design pivot + the
    placeholder-rejection rules. Companion runtime tests live in
    tests/test_psiphon.py::TestPsiphonCredentialErrorRegressions; this class
    locks in:
    - the production catch routes (apply.py + dashboard/router.py) all
      swallow PsiphonCredentialError (NOT bubble up as opaque 500s);
    - the installer's prompt step (installer/prompt.sh) + panel_install.sh
      heredoc (installer/panel_install.sh) carry the four credential env
      var names so a fresh install from v1.0.0 sources sets them up;
    - the four credential env var names are exactly PSIPHON_PROPAGATION_
      CHANNEL_ID / PSIPHON_SPONSOR_ID / PSIPHON_REMOTE_SERVER_LIST_URL /
      PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY (no accidental drift);
    - docs/TROUBLESHOOTING.md + README.md ship a section explaining the
      requirement.
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
        than referencing the legacy hardcoded constants directly in the
        returned dict literal."""
        import re  # noqa: PLC0415

        text = self._PSIPHON_INIT.read_text(encoding="utf-8")
        no_comments = re.sub(r"#[^\n]*", "", text)
        assert re.search(
            r"creds\s*=\s*_resolve_upstream_credentials\(\)",
            no_comments,
        ), (
            "Hotfix #14 — render_config must call _resolve_upstream_credentials "
            "to fetch the four upstream constants, NOT reference the legacy "
            "module constants directly."
        )
        # And the return dict must source each value from creds[<field>].
        assert 'creds["PropagationChannelId"]' in text
        assert 'creds["SponsorId"]' in text
        assert 'creds["RemoteServerListUrl"]' in text
        assert 'creds["RemoteServerListSignaturePublicKey"]' in text

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
    def test_prompt_sh_defines_psiphon_credentials_prompt(self):
        """installer/prompt.sh MUST define `_prompt_psiphon_credentials()`
        that surveys the operator for the four credentials on a TTY."""
        text = self._PROMPT_SH.read_text(encoding="utf-8")
        assert "_prompt_psiphon_credentials" in text, (
            "Hotfix #14 — installer/prompt.sh must define "
            "_prompt_psiphon_credentials (the installer interactive prompt "
            "step that surveys the operator for the four Psiphon-Inc creds)."
        )
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Hotfix #14 — installer/prompt.sh must reference env var "
                f"{envname} (so it `read -r <NAME>`'d into the same name the "
                "_resolve_upstream_credentials resolver will look for)."
            )

    def test_panel_install_sh_interpolates_creds_block_into_heredoc(self):
        """installer/panel_install.sh's `panel.env` heredoc MUST interpolate
        a `${psiphon_creds_block}` block that emits each non-empty
        credential env var into the file the panel systemd unit loads."""
        import re  # noqa: PLC0415

        text = self._PANEL_INSTALL_SH.read_text(encoding="utf-8")
        # The builder var + the heredoc interpolation BOTH must be present.
        assert re.search(r"(?:local\s+)?psiphon_creds_block\s*=", text), (
            "Hotfix #14 — installer/panel_install.sh must declare a local "
            "`psiphon_creds_block` builder var that the heredoc interpolates."
        )
        assert "${psiphon_creds_block}" in text, (
            "Hotfix #14 — installer/panel_install.sh's heredoc body MUST "
            "interpolate ${psiphon_creds_block} so the four credentials end "
            "up in the written panel.env file (the panel systemd unit "
            "EnvironmentFile loads)."
        )
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Hotfix #14 — installer/panel_install.sh must reference env "
                f"var {envname} in the psiphon_creds_block builder."
            )

    # ---- docs section shipped --------------------------------------------
    def test_troubleshooting_md_documents_credentials_requirement(self):
        """docs/TROUBLESHOOTING.md MUST ship a section about the Psiphon Inc.
        commercial-credential requirement — so an operator hitting the
        fast-fail messages has a doc page to follow."""
        text = self._TROUBLESHOOTING_MD.read_text(encoding="utf-8")
        assert "Psiphon Inc. upstream credentials required (Hotfix #14)" in text, (
            "Hotfix #14 — docs/TROUBLESHOOTING.md must ship a "
            "'## Psiphon Inc. upstream credentials required' section "
            "documenting where to obtain the colossid four credentials + "
            "how to set them in panel.env."
        )
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Hotfix #14 — docs/TROUBLESHOOTING.md must name env var "
                f"{envname} in the credentials section (operator copy-paste "
                "fix-path)."
            )

    def test_readme_md_warns_operator_about_credentials_requirement(self):
        """README.md must surface the credentials requirement near the
        install one-liner so a fresh operator doesn't install + run with
        empty/stub values only to hit the fast-fail later."""
        text = self._README_MD.read_text(encoding="utf-8")
        assert "Psiphon Inc. upstream credentials required" in text
        # The README's Configuration reference table must include the four
        # credential env var names so an operator customising panel.env sees
        # them in the canonical env-var reference.
        for envname in (
            "PSIPHON_PROPAGATION_CHANNEL_ID",
            "PSIPHON_SPONSOR_ID",
            "PSIPHON_REMOTE_SERVER_LIST_URL",
            "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        ):
            assert envname in text, (
                f"Hotfix #14 — README.md's Configuration reference must "
                f"include env var {envname} (so a fresh operator's "
                "panel.env customisation covers all four)."
            )
