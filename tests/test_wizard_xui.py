"""Phase 4 wizard xui-creds / inbounds / clone-template tests (step 4l).

Covers the three handlers added to ``panel/wizard/router.py``::

* ``POST /api/wizard/xui-creds``     — login attempt + cache encrypted creds
                                         (success, login failure, unreachable,
                                          state-machine 409, 401 unauth).
* ``GET  /api/wizard/inbounds``       — list simplified ``[{id, remark, port,
                                         protocol, tag}]`` from the cached
                                         3x-ui session (happy, no-cache,
                                         failure 502, state-machine 409, 401).
* ``POST /api/wizard/clone-template`` — store chosen template inbound id,
                                         advance the wizard to ``clone`` (happy,
                                         state-machine 409, 422 bad body,
                                         401 unauth).

The 3x-ui panel surface is mocked via :class:`FakeXuiClient` injected in place
of ``panel.wizard.router.XuiClient`` (no real network calls).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from panel.auth import decrypt_creds, hash_password
from panel.dashboard.xui_client import InboundSummary, XuiClientError


# ===========================================================================
# Shared harness
# ===========================================================================
def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase4-xui-secret")
    monkeypatch.setenv("PSIPHON3XUI_PORT", "18001")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")

    from panel import config, db

    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    db._engine = None  # noqa: SLF001
    db._session_factory = None  # noqa: SLF001


def _seed_settings() -> None:
    from sqlalchemy.orm import Session

    from panel.db import get_engine, init_db
    from panel.models import Settings

    init_db()
    with Session(get_engine()) as s:
        if s.get(Settings, {"id": 1}) is not None:
            s.delete(s.get(Settings, {"id": 1}))
            s.flush()
        s.add(
            Settings(
                id=1,
                panel_port=18001,
                admin_user="admin",
                admin_pass_hash=hash_password("correct-horse-battery-staple"),
                wizard_completed=False,
            )
        )
        s.commit()


def _client(monkeypatch, tmp_path) -> TestClient:
    _isolated_env(tmp_path, monkeypatch)
    _seed_settings()
    from panel.main import app

    return TestClient(app)


def _login(client: TestClient) -> None:
    r = client.post(
        "/auth/login",
        json={"user": "admin", "password": "correct-horse-battery-staple"},
    )
    assert r.status_code == 204, r.text


def _set_wizard_step(client: TestClient, step: str, *, step_data: dict | None = None) -> None:
    """Force-set the wizard row's current_step + optional step_data via direct DB."""
    import json

    from sqlalchemy.orm import Session

    from panel.db import get_engine, init_db
    from panel.models import Wizard

    init_db()
    with Session(get_engine()) as s:
        w = s.get(Wizard, {"id": 1})
        if w is None:
            w = Wizard(id=1, current_step=step, step_data=json.dumps(step_data or {}))
            s.add(w)
        else:
            w.current_step = step
            if step_data is not None:
                w.step_data = json.dumps(step_data)
        s.commit()


# ---------------------------------------------------------------------------
# FakeXuiClient — replaces panel.wizard.router.XuiClient for handler tests.
# ---------------------------------------------------------------------------
class FakeXuiClient:
    """Test stand-in for :class:`panel.dashboard.xui_client.XuiClient`.

    The router constructs ``XuiClient(base_url, username, password)`` directly,
    so this must match the constructor signature. Behaviour is configured at
    class level (so the router's ``XuiClient(...)`` call returns this type).
    """

    login_raises: type[Exception] | None = None
    login_raises_msg: str = "fake login failure"
    list_summaries_result: list[InboundSummary] | None = None
    list_summaries_raises: type[Exception] | None = None
    list_summaries_raises_msg: str = "fake list_inbounds failure"
    constructed: list[tuple[str, str, str]] = []
    closed: bool = False

    def __init__(self, base_url: str, username: str, password: str, **kwargs) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        FakeXuiClient.constructed.append((base_url, username, password))

    async def login(self) -> None:
        if FakeXuiClient.login_raises is not None:
            raise FakeXuiClient.login_raises(FakeXuiClient.login_raises_msg)

    async def list_inbound_summaries(self) -> list[InboundSummary]:
        if FakeXuiClient.list_summaries_raises is not None:
            raise FakeXuiClient.list_summaries_raises(FakeXuiClient.list_summaries_raises_msg)
        return FakeXuiClient.list_summaries_result or []

    async def aclose(self) -> None:
        FakeXuiClient.closed = True


@pytest.fixture(autouse=True)
def _patch_xui_client(monkeypatch):
    """Substitute ``FakeXuiClient`` for the router-level ``XuiClient`` import.

    Resets the class-level state in between tests so each starts from a clean
    baseline.
    """
    FakeXuiClient.login_raises = None
    FakeXuiClient.login_raises_msg = ""
    FakeXuiClient.list_summaries_result = None
    FakeXuiClient.list_summaries_raises = None
    FakeXuiClient.list_summaries_raises_msg = ""
    FakeXuiClient.constructed = []
    FakeXuiClient.closed = False
    from panel.wizard import router as router_mod

    monkeypatch.setattr(router_mod, "XuiClient", FakeXuiClient)
    yield


def _seed_xui_link(
    *,
    base_url: str = "http://127.0.0.1:2053/",
    username: str = "admin",
    password: str = "panel-pass",
) -> None:
    """Persist a XuiLink row backed by an ``encrypt_creds`` password blob."""
    from sqlalchemy.orm import Session

    from panel.auth import encrypt_creds
    from panel.db import get_engine, init_db
    from panel.models import XuiLink

    init_db()
    token = encrypt_creds({"password": password})
    with Session(get_engine()) as s:
        existing = s.get(XuiLink, {"id": 1})
        if existing is not None:
            s.delete(existing)
            s.flush()
        s.add(
            XuiLink(
                id=1,
                base_url=base_url,
                username=username,
                password_enc=token,
            )
        )
        s.commit()


# ===========================================================================
# POST /api/wizard/xui-creds
# ===========================================================================
class TestXuiCreds:
    def test_happy_login_advances_wizard_and_caches_creds(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "xui_creds")

        r = client.post(
            "/api/wizard/xui-creds",
            json={
                "base_url": "http://127.0.0.1:2053/",
                "username": "admin",
                "password": "panel-pass",
            },
        )
        assert r.status_code == 200, r.text
        state = r.json()
        assert state["current_step"] == "template"

        # XuiLink(id=1) was created with encrypted password.
        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import XuiLink

        with Session(get_engine()) as s:
            link = s.get(XuiLink, {"id": 1})
            assert link is not None
            assert link.base_url == "http://127.0.0.1:2053/"
            assert link.username == "admin"
        # The password_enc round-trips to the original password.
        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import XuiLink

        with Session(get_engine()) as s:
            link = s.get(XuiLink, {"id": 1})
            creds = decrypt_creds(link.password_enc)
            assert creds == {"password": "panel-pass"}

        # FakeXuiClient was constructed with the supplied credentials.
        assert FakeXuiClient.constructed == [("http://127.0.0.1:2053/", "admin", "panel-pass")]
        assert FakeXuiClient.closed is True

    def test_login_failure_xui_client_error_returns_400(self, monkeypatch, tmp_path):
        FakeXuiClient.login_raises = XuiClientError
        FakeXuiClient.login_raises_msg = "invalid username / password"
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "xui_creds")

        r = client.post(
            "/api/wizard/xui-creds",
            json={"base_url": "http://x/", "username": "admin", "password": "x"},
        )
        assert r.status_code == 400
        assert "3x-ui login failed" in r.json()["detail"]

    def test_unreachable_returns_502(self, monkeypatch, tmp_path):
        FakeXuiClient.login_raises = ConnectionError
        FakeXuiClient.login_raises_msg = "connection refused"
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "xui_creds")

        r = client.post(
            "/api/wizard/xui-creds",
            json={"base_url": "http://127.0.0.1:9999/", "username": "a", "password": "b"},
        )
        assert r.status_code == 502
        assert "3x-ui unreachable" in r.json()["detail"]

    def test_state_machine_409_when_on_wrong_step(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "countries")

        r = client.post(
            "/api/wizard/xui-creds",
            json={"base_url": "http://x/", "username": "a", "password": "b"},
        )
        assert r.status_code == 409
        assert "wizard is on step 'countries'" in r.json()["detail"]

    def test_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _set_wizard_step(client, "xui_creds")

        r = client.post(
            "/api/wizard/xui-creds",
            json={"base_url": "http://x/", "username": "a", "password": "b"},
        )
        assert r.status_code == 401

    def test_missing_field_returns_422(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "xui_creds")

        # Forget `password` — FastAPI/pydantic must reject with 422.
        r = client.post(
            "/api/wizard/xui-creds",
            json={"base_url": "http://x/", "username": "a"},
        )
        assert r.status_code == 422


# ===========================================================================
# GET /api/wizard/inbounds
# ===========================================================================
class TestInbounds:
    def test_happy_returns_simplified_projection(self, monkeypatch, tmp_path):
        FakeXuiClient.list_summaries_result = [
            InboundSummary(id=1, port=443, protocol="vless", remark="VM01", tag="in-1"),
            InboundSummary(id=2, port=444, protocol="vless", remark="VM02", tag="in-2"),
        ]
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "template")  # past xui_creds
        _seed_xui_link()

        r = client.get("/api/wizard/inbounds")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["count"] == 2
        assert {ib["id"] for ib in data["inbounds"]} == {1, 2}
        first = data["inbounds"][0]
        assert set(first) == {"id", "port", "protocol", "remark", "tag"}

    def test_no_cached_creds_returns_409(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "template")

        r = client.get("/api/wizard/inbounds")
        assert r.status_code == 409
        assert "no 3x-ui credentials stored" in r.json()["detail"]

    def test_wizard_on_step_before_xui_creds_returns_409(self, monkeypatch, tmp_path):
        # /inbounds must not be queryable before the creds step has been done
        # — otherwise the wizard could be confused into thinking creds exist
        # when they don't.
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "apply")  # earlier than xui_creds

        r = client.get("/api/wizard/inbounds")
        assert r.status_code == 409
        assert "POST /api/wizard/xui-creds first" in r.json()["detail"]

    def test_list_inbounds_failure_returns_502(self, monkeypatch, tmp_path):
        FakeXuiClient.list_summaries_raises = XuiClientError
        FakeXuiClient.list_summaries_raises_msg = "session expired"
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "template")
        _seed_xui_link()

        r = client.get("/api/wizard/inbounds")
        assert r.status_code == 502
        assert "list_inbounds failed" in r.json()["detail"]

    def test_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _set_wizard_step(client, "template")

        r = client.get("/api/wizard/inbounds")
        assert r.status_code == 401


# ===========================================================================
# POST /api/wizard/clone-template
# ===========================================================================
class TestCloneTemplate:
    def test_happy_advances_wizard_to_clone_and_stores_template_id(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "template")

        r = client.post("/api/wizard/clone-template", json={"template_inbound_id": 17})
        assert r.status_code == 200, r.text
        state = r.json()
        assert state["current_step"] == "clone"
        assert state["step_data"]["template"]["template_inbound_id"] == 17

    def test_state_machine_409_when_on_wrong_step(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "xui_creds")  # not 'template' yet

        r = client.post("/api/wizard/clone-template", json={"template_inbound_id": 1})
        assert r.status_code == 409
        assert "wizard is on step 'xui_creds'" in r.json()["detail"]

    def test_invalid_template_id_returns_422(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "template")

        # template_inbound_id must be ≥ 1 — 0 is rejected by Field(ge=1).
        r = client.post("/api/wizard/clone-template", json={"template_inbound_id": 0})
        assert r.status_code == 422

    def test_missing_field_returns_422(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "template")

        r = client.post("/api/wizard/clone-template", json={})
        assert r.status_code == 422

    def test_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _set_wizard_step(client, "template")

        r = client.post("/api/wizard/clone-template", json={"template_inbound_id": 1})
        assert r.status_code == 401
