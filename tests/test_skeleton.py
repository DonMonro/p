"""Smoke tests for the Phase-0 skeleton.

Run with::

    pytest panel/tests/test_skeleton.py

These verify the things that must work before the Phase 1 spike starts:
* The FastAPI app boots and answers /api/health.
* ``config/countries.yaml`` parses cleanly and exposes a non-empty country list.
* bcrypt hashing and the signed-session round-trip work.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from panel.auth import (
    generate_password,
    hash_password,
    sign_session,
    verify_password,
    verify_session,
)


def _fixture_countries_path() -> Path:
    # tests/ sits directly in the repo root, so one level up.
    return Path(__file__).resolve().parents[1] / "config" / "countries.yaml"


def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    """Point the panel at a throwaway SQLite + isolated session secret."""
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "test-secret")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")
    # Drop cached settings + countries so env changes take effect.
    from panel import config

    config.get_settings.cache_clear()
    config.load_countries.cache_clear()


def test_countries_yaml_is_valid(tmp_path, monkeypatch):
    raw = yaml.safe_load(_fixture_countries_path().read_text(encoding="utf-8"))
    assert raw["version"] >= 1
    assert isinstance(raw["countries"], list) and raw["countries"]
    # Every entry has the required fields and a 2-letter uppercase code.
    for c in raw["countries"]:
        assert set(c) >= {"code", "name", "flag", "region"}
        assert c["code"].isalpha() and c["code"].isupper() and len(c["code"]) == 2
    # Defaults ranges are sane public SOCKS/port pools.
    s = raw["defaults"]["socks_port_range"]
    p = raw["defaults"]["public_port_range"]
    assert s["start"] < s["end"] < 65536
    assert p["start"] < p["end"] < 65536


def test_health_endpoint(tmp_path, monkeypatch):
    _isolated_env(tmp_path, monkeypatch)
    from panel.main import app

    client = TestClient(app)
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_list_countries_endpoint(tmp_path, monkeypatch):
    _isolated_env(tmp_path, monkeypatch)
    from panel.main import app

    client = TestClient(app)
    r = client.get("/api/countries")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 30  # current Psiphon set is ~32; allow drift
    assert any(c["code"] == "US" for c in body["countries"])
    assert any(c["code"] == "DE" for c in body["countries"])


def test_countries_endpoint_count_matches_yaml(tmp_path, monkeypatch):
    raw = yaml.safe_load(_fixture_countries_path().read_text(encoding="utf-8"))
    _isolated_env(tmp_path, monkeypatch)
    from panel.main import app

    client = TestClient(app)
    body = client.get("/api/countries").json()
    assert body["count"] == len(raw["countries"])


def test_wizard_html_endpoint_serves_the_spa_shell(tmp_path, monkeypatch):
    """``GET /wizard`` returns the first-run setup-wizard SPA shell.

    The route is intentionally not authenticated (mirrors ``/login`` and
    ``/dashboard``); the SPA itself redirects to ``/login`` when its first
    call to ``GET /api/wizard`` returns 401. The served file MUST be HTML
    and MUST contain the ``appWizard()`` Alpine.js anchor so the page
    actually mounts (regression guard for a future accidental overwrite).
    """
    _isolated_env(tmp_path, monkeypatch)
    from panel.main import app

    client = TestClient(app)
    r = client.get("/wizard", follow_redirects=False)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    # Anchor that the GET /wizard handler actually served the bundled file
    # rather than the JSON 404 fallback (wizard SPA shell not bundled).
    assert "appWizard()" in body, "wizard.html must mount Alpine.x via appWizard()"
    # The page must talk to every operating-step endpoint the panel exposes.
    for endpoint in ("/api/wizard", "/api/wizard/countries", "/api/wizard/ports",
                     "/api/wizard/apply", "/api/wizard/xui-detect",
                     "/api/wizard/xui-creds", "/api/wizard/inbounds",
                     "/api/wizard/clone-template", "/api/wizard/clone",
                     "/api/countries"):
        assert endpoint in body, (
            f"wizard.html SPA must reference {endpoint!r} — the {endpoint} "
            "endpoint is part of the wizard state machine and the UI should "
            "either drive it (POST), read it (GET), or hand off to it."
        )


def test_root_redirects_to_login(tmp_path, monkeypatch):
    """The bare ``/`` URL yields 302 → ``/login`` so an operator opening
    the panel URL in a browser lands on the auth form rather than on
    FastAPI's info JSON."""
    _isolated_env(tmp_path, monkeypatch)
    from panel.main import app

    client = TestClient(app)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/login"


def test_auth_primitives_round_trip(monkeypatch):
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "test-secret")
    from panel import config

    config.get_settings.cache_clear()

    pw = generate_password(20)
    assert len(pw) == 20
    h = hash_password(pw)
    assert h != pw and verify_password(pw, h) is True
    assert verify_password("wrong", h) is False

    token = sign_session({"user": "admin"})
    assert verify_session(token) == {"user": "admin"}
    assert verify_session("garbage") is None
