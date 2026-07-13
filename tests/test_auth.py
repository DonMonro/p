"""Authentication + /api/me endpoint tests (Phase 3 — step 1 of the panel
core).

Covers:

* `POST /auth/login` — happy / bad-password / unknown-user / no-Settings-row
* `GET /api/me` — unauthenticated 401 vs authenticated 200 with the expected
  ``{user, wizard_completed}`` body
* `POST /auth/logout` — idempotent, clears the cookie
* cookie invalidation (tampered cookie → 401)
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from panel.auth import hash_password, sign_session


def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    """Point the panel at a throwaway SQLite + isolated session secret.

    Also flushes the cached modules so env changes win for the next import /
    engine creation.
    """
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase3-test-secret")
    monkeypatch.setenv("PSIPHON3XUI_PORT", "18001")  # used by /api/wizard/ports later
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")  # Phase 7: default off for tests
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")  # don't throttle tests

    from panel import config, db

    config.get_settings.cache_clear()
    # Drop the cached engine + session factory so the next request rebuilds
    # them against the new (per-test) db_path.
    db._engine = None  # noqa: SLF001
    db._session_factory = None  # noqa: SLF001


def _seed_settings(
    *,
    admin_user: str = "admin",
    admin_pass: str = "correct-horse-battery-staple",
    wizard_completed: bool = False,
) -> None:
    """Insert (or replace) the singleton Settings row in the test panel.db.

    Assumes :func:`_isolated_env` has already cleared the cached engine so
    `get_engine()` reflects the new test db_path.
    """
    from sqlalchemy.orm import Session

    from panel.db import get_engine, init_db
    from panel.models import Settings

    init_db()  # safe to call repeatedly — create_all is idempotent
    engine = get_engine()
    with Session(engine) as s:
        existing = s.get(Settings, {"id": 1})
        if existing is not None:
            s.delete(existing)
            s.flush()
        s.add(
            Settings(
                id=1,
                panel_port=18001,
                admin_user=admin_user,
                admin_pass_hash=hash_password(admin_pass),
                wizard_completed=wizard_completed,
            )
        )
        s.commit()


def _client(monkeypatch, tmp_path) -> TestClient:
    _isolated_env(tmp_path, monkeypatch)
    _seed_settings()
    from panel.main import app

    return TestClient(app)


# ------------------------------------------------------------------ login
def test_login_success_sets_cookie(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.post(
        "/auth/login", json={"user": "admin", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 204, r.text
    # TestClient surfaces Set-Cookie via .cookies
    assert "psiphon3xui_session" in client.cookies
    # The cookie must be a non-empty opaque string
    assert client.cookies["psiphon3xui_session"]


def test_login_wrong_password_returns_401(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.post("/auth/login", json={"user": "admin", "password": "WRONG"})
    assert r.status_code == 401
    assert "psiphon3xui_session" not in client.cookies


def test_login_unknown_user_returns_401(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.post("/auth/login", json={"user": "nobody", "password": "irrelevant"})
    assert r.status_code == 401


def test_login_no_settings_row_returns_503(tmp_path, monkeypatch):
    """If installer hasn't seeded panel.db, login can't even attempt."""
    _isolated_env(tmp_path, monkeypatch)
    from panel.db import init_db
    from panel.main import app

    init_db()  # creates tables but NOT the Settings(id=1) row
    client = TestClient(app)
    r = client.post("/auth/login", json={"user": "admin", "password": "anything"})
    assert r.status_code == 503


# --------------------------------------------------------------- api/me
def test_api_me_unauthenticated_returns_401(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.get("/api/me")
    assert r.status_code == 401


def test_api_me_authenticated_returns_user_and_wizard_state(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    client.post("/auth/login", json={"user": "admin", "password": "correct-horse-battery-staple"})
    r = client.get("/api/me")
    assert r.status_code == 200
    body = r.json()
    assert body["user"] == "admin"
    assert body["wizard_completed"] is False


def test_api_me_reflects_wizard_completed_flag(tmp_path, monkeypatch):
    # Re-seed with wizard_completed=true and re-query /api/me.
    _isolated_env(tmp_path, monkeypatch)
    _seed_settings(wizard_completed=True)
    from panel.main import app

    client = TestClient(app)
    client.post("/auth/login", json={"user": "admin", "password": "correct-horse-battery-staple"})
    r = client.get("/api/me")
    assert r.status_code == 200
    assert r.json()["wizard_completed"] is True


# -------------------------------------------------------------- logout
def test_logout_clears_cookie(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    client.post("/auth/login", json={"user": "admin", "password": "correct-horse-battery-staple"})
    assert "psiphon3xui_session" in client.cookies
    r = client.post("/auth/logout")
    assert r.status_code == 204
    # After logout, /api/me must reject.
    assert client.get("/api/me").status_code == 401


# ------------------------------------------------------------- tampering
def test_tampered_cookie_returns_401(tmp_path, monkeypatch):
    """A syntactically valid but tampered cookie must be rejected."""
    _isolated_env(tmp_path, monkeypatch)
    _seed_settings()
    from panel.main import app

    client = TestClient(app)
    # Sign a cookie with a different secret, then force it through.
    # (sign_session under the test secret — vs. a cookie we tamper with by
    #  flipping leading characters.)
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "WRONG-SECRET")
    from panel import config

    config.get_settings.cache_clear()
    forged = sign_session({"sub": "admin"})
    # Now flip the panel's actual secret back to the test one and inject the
    # forged cookie as if a client constructed one out-of-band:
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase3-test-secret")
    config.get_settings.cache_clear()
    client.cookies.set("psiphon3xui_session", forged, domain="testserver")
    assert client.get("/api/me").status_code == 401
