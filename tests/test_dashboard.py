"""Phase 6 management dashboard tests.

Covers ``panel/dashboard/router.py`` mounted at ``/api/dashboard``. The
dashboard surface is gated on ``Settings.wizard_completed == True``;
each test flushes the wizard state to that finished state via the shared
``_mark_wizard_completed`` helper.

External services (`systemctl`, `journalctl`, the 3x-ui API) are
sandboxed — ``_patch_systemd`` swaps ``panel.dashboard.router``'s
``start_unit``/``stop_unit``/``restart_unit``/``is_unit_active`` calls
with recording fakes, ``_patch_journalctl`` swaps
``_journalctl_lines`` with a deterministic stub, and ``FakeXuiClient``
replaces the router-level ``XuiClient`` for the 3x-ui clone/delete paths.
"""

from __future__ import annotations

import copy
import io
import json
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from panel.auth import encrypt_creds, hash_password
from panel.db import get_engine, init_db
from panel.models import (
    CloneRecord,
    Country,
    PortAssignment,
    Settings,
    Wizard,
    XuiLink,
)


# ---------------------------------------------------------------------------
# Shared harness (mirrors tests/test_wizard_xui.py).
# ---------------------------------------------------------------------------
def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase6-dashboard-secret")
    monkeypatch.setenv("PSIPHON3XUI_PORT", "18001")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")
    # Psiphon config dir lives inside the test tmp_path so backup/restore
    # tests don't trample the operator's real /opt tree.
    monkeypatch.setenv("PSIPHON3XUI_PSIPHON_CONFIG_DIR", str(tmp_path / "config"))

    from panel import config, db

    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    db._engine = None  # noqa: SLF001
    db._session_factory = None  # noqa: SLF001


def _seed_settings(*, wizard_completed: bool = True) -> None:
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
                admin_user="admin",
                admin_pass_hash=hash_password("correct-horse-battery-staple"),
                wizard_completed=wizard_completed,
            )
        )
        # Force the Wizard row into the "done" terminal step (the dashboard
        # surface ignores current_step once wizard_completed is set, but other
        # invariants expect it).
        w = s.get(Wizard, {"id": 1})
        if w is None:
            w = Wizard(id=1, current_step="done", step_data="{}")
            s.add(w)
        else:
            w.current_step = "done"
            w.step_data = "{}"
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


def _seed_country(
    *,
    code: str = "US",
    name: str = "United States",
    flag: str = "🇺🇸",
    region: str = "Americas",
    enabled: bool = False,
) -> None:
    init_db()
    with Session(get_engine()) as s:
        s.add(Country(code=code, name=name, flag_emoji=flag, region=region, enabled=enabled))
        s.commit()


def _seed_assignment(*, code: str, socks_port: int, public_port: int) -> None:
    init_db()
    with Session(get_engine()) as s:
        s.add(
            PortAssignment(
                socks_port=socks_port,
                public_port=public_port,
                country_code=code,
            )
        )
        s.commit()


def _seed_clone(
    *, country_code: str, inbound_id: int, socks_port: int, public_port: int, healthy: bool = True
) -> None:
    init_db()
    with Session(get_engine()) as s:
        s.add(
            CloneRecord(
                inbound_id=inbound_id,
                country_code=country_code,
                public_port=public_port,
                socks_port=socks_port,
                healthy=healthy,
            )
        )
        s.commit()


def _seed_xui_link(*, password: str = "xui-pass") -> None:
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
                base_url="http://127.0.0.1:2053",
                username="xui-admin",
                password_enc=token,
            )
        )
        s.commit()


def _set_wizard_step_data(step_data: dict) -> None:
    """Overwrite the singleton Wizard row's step_data JSON."""
    init_db()
    with Session(get_engine()) as s:
        w = s.get(Wizard, {"id": 1})
        assert w is not None
        w.step_data = json.dumps(step_data)
        s.commit()


# ---------------------------------------------------------------------------
# Systemd recording fakes.
# ---------------------------------------------------------------------------
class _SystemdFake:
    """Replaces start/stop/restart/is_active with recording sinks.

    Resets between tests via the autouse fixture in :func:`_patch_systemd`.
    """

    started: list[str] = []
    stopped: list[str] = []
    restarted: list[str] = []
    active_result: dict[str, bool] = {}
    start_raises: type[Exception] | None = None
    stop_raises: type[Exception] | None = None
    restart_raises: type[Exception] | None = None

    @classmethod
    def reset(cls) -> None:
        cls.started = []
        cls.stopped = []
        cls.restarted = []
        cls.active_result = {}
        cls.start_raises = None
        cls.stop_raises = None
        cls.restart_raises = None

    @classmethod
    def start_unit(cls, code: str) -> None:
        if cls.start_raises is not None:
            raise cls.start_raises(f"start_unit({code}) fake-failed")
        cls.started.append(code)

    @classmethod
    def stop_unit(cls, code: str) -> None:
        if cls.stop_raises is not None:
            raise cls.stop_raises(f"stop_unit({code}) fake-failed")
        cls.stopped.append(code)

    @classmethod
    def restart_unit(cls, code: str) -> None:
        if cls.restart_raises is not None:
            raise cls.restart_raises(f"restart_unit({code}) fake-failed")
        cls.restarted.append(code)

    @classmethod
    def is_unit_active(cls, code: str) -> bool:
        return cls.active_result.get(code, False)


@pytest.fixture(autouse=True)
def _patch_systemd(monkeypatch):
    """Install the recording fake + clear it before each test."""
    _SystemdFake.reset()
    from panel.dashboard import router as dashboard_router

    monkeypatch.setattr(dashboard_router, "start_unit", _SystemdFake.start_unit)
    monkeypatch.setattr(dashboard_router, "stop_unit", _SystemdFake.stop_unit)
    monkeypatch.setattr(dashboard_router, "restart_unit", _SystemdFake.restart_unit)
    monkeypatch.setattr(dashboard_router, "is_unit_active", _SystemdFake.is_unit_active)
    # Disable write_config's real disk writes by pointing the config dir at
    # the per-test tmp_path (set via env in _isolated_env).
    #
    # Hotfix #14 (Phase 23): the dashboard endpoints exercise real write_config
    # -> render_config -> _resolve_upstream_credentials(). Inject fake-but-
    # real-shape PSIPHON_* env vars so the credential fast-fail does not turn
    # every TestEditPorts / TestReapply assertion into a 502/failed entry.
    monkeypatch.setenv("PSIPHON_PROPAGATION_CHANNEL_ID", "0123456789ABCDEF0123456789ABCDEF")
    monkeypatch.setenv("PSIPHON_SPONSOR_ID", "0123456789ABCDEF")
    monkeypatch.setenv(
        "PSIPHON_REMOTE_SERVER_LIST_URL",
        "https://s3.amazonaws.com/psiphon/web/test-mirror",
    )
    monkeypatch.setenv(
        "PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    yield


@pytest.fixture(autouse=True)
def _patch_journalctl(monkeypatch):
    """Stub journalctl so the logs endpoint doesn't shell out."""
    from panel.dashboard import router as dashboard_router

    journal_lines: dict[str, list[str]] = {}
    raises_msg: str | None = None

    def _fake(unit: str, lines: int) -> list[str]:
        if raises_msg is not None:
            raise RuntimeError(raises_msg)
        return journal_lines.get(unit, [f"no entries for {unit}"])[: int(lines)]

    monkeypatch.setattr(dashboard_router, "_journalctl_lines", _fake)

    class _Journal:
        lines = journal_lines
        raises = raises_msg

    # Expose mutable state for tests via the function attrs (simpler than a
    # global dataclass).
    def _set_lines(unit: str, lines: list[str]) -> None:
        journal_lines[unit] = list(lines)

    def _set_raises(msg: str | None) -> None:
        nonlocal raises_msg
        raises_msg = msg

    dashboard_router._journalctl_lines.set_lines = _set_lines  # type: ignore[attr-defined]
    dashboard_router._journalctl_lines.set_raises = _set_raises  # type: ignore[attr-defined]
    yield


# ---------------------------------------------------------------------------
# FakeXuiClient — replaces panel.dashboard.router.XuiClient.
# ---------------------------------------------------------------------------
def _stock_xray_template() -> dict:
    """A minimal stand-in for 3x-ui's default ``xrayTemplateConfig``.

    Carries the two pieces the routing binder cares about: a ``direct``
    freedom outbound that MUST stay at index 0 (Xray's default egress), and
    the stock trailing catch-all rules a per-country rule must be inserted
    *before*.
    """
    return {
        "log": {"loglevel": "warning"},
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
            ],
        },
    }


class FakeXuiClient:
    """Test stand-in for :class:`panel.dashboard.xui_client.XuiClient`.

    Class-level state mirrors the test_wizard_xui.py pattern (reset per test
    via the autouse fixture). The router constructs ``XuiClient(base_url,
    username, password)`` directly; tests configure behaviour via the class
    knobs then monkeypatch ``router.XuiClient = FakeXuiClient``.
    """

    login_raises: type[Exception] | None = None
    delete_inbound_raises: dict[int, type[Exception] | Exception] | None = None
    delete_inbound_calls: list[int] = []
    clone_inbound_result: dict | None = None
    clone_inbound_raises: type[Exception] | Exception | None = None
    clone_inbound_calls: list[tuple[int, dict, int, int]] = []
    get_inbound_result: dict | None = None
    get_inbound_raises: type[Exception] | Exception | None = None
    get_inbound_calls: list[int] = []

    # Phase 27 (item 2): ports already held by 3x-ui inbounds, which
    # _gather_claimed_ports must treat as unavailable.
    list_inbounds_result: list[dict] | None = None
    list_inbounds_raises: type[Exception] | Exception | None = None

    # Phase 26: the in-memory Xray template the routing binder reads/writes
    # via get_xray_setting / update_xray_setting. Replaces the Hotfix #10
    # queue-file stubbing — routing now goes through the panel's own API.
    xray_template: dict | None = None
    xray_updates: list[str] = []
    xray_get_raises: type[Exception] | Exception | None = None
    xray_update_raises: type[Exception] | Exception | None = None

    def __init__(self, base_url: str, username: str, password: str, **kwargs) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password

    async def login(self) -> None:
        if self.login_raises is not None:
            raise self.login_raises("fake login failure")

    async def aclose(self) -> None:
        pass

    async def get_xray_setting(self) -> dict:
        exc = FakeXuiClient.xray_get_raises
        if exc is not None:
            raise exc if isinstance(exc, Exception) else exc("fake get_xray_setting")
        if FakeXuiClient.xray_template is None:
            FakeXuiClient.xray_template = _stock_xray_template()
        # Model the REAL contract, post-decode. Hotfix #14: upstream's
        # getXraySetting marshals its map and passes the resulting Go *string*
        # to jsonObj(), so `obj` arrives over the wire double-encoded. The real
        # XuiClient.get_xray_setting decodes that outer layer and returns the
        # inner map — in which `xraySetting` came from json.RawMessage(...) and
        # is therefore a real **dict**, not a string.
        #
        # The previous version of this fake returned
        # {"xraySetting": json.dumps(...)} — encoding an assumption instead of
        # the panel's actual behaviour. That is precisely what let the
        # double-encoding bug ship green through 469 tests. The real
        # boundary is now pinned in
        # tests/test_xui_client.py::test_get_xray_setting_decodes_double_encoded_obj.
        return {
            "xraySetting": copy.deepcopy(FakeXuiClient.xray_template),
            "inboundTags": [],
            "clientReverseTags": [],
            "outboundTestUrl": "https://www.google.com/generate_204",
        }

    async def update_xray_setting(self, xray_setting: str) -> dict:
        exc = FakeXuiClient.xray_update_raises
        if exc is not None:
            raise exc if isinstance(exc, Exception) else exc("fake update_xray_setting")
        FakeXuiClient.xray_updates.append(xray_setting)
        FakeXuiClient.xray_template = json.loads(xray_setting)
        return {"success": True}

    async def delete_inbound(self, inbound_id: int) -> dict:
        FakeXuiClient.delete_inbound_calls.append(int(inbound_id))
        exc = (self.delete_inbound_raises or {}).get(int(inbound_id))
        if exc is not None:
            raise exc if isinstance(exc, Exception) else exc("fake delete_inbound")
        return {"obj": ""}

    async def get_inbound(self, inbound_id: int) -> dict:
        """Return the inbound object, UNWRAPPED — matching the real client.

        ``XuiClient.get_inbound`` returns ``data["obj"]``, not the envelope.
        Phase 26 Hotfix #15 uses this to recover the tag 3x-ui actually
        assigned when re-binding routing on a bare re-enable.
        """
        FakeXuiClient.get_inbound_calls.append(int(inbound_id))
        exc = FakeXuiClient.get_inbound_raises
        if exc is not None:
            raise exc if isinstance(exc, Exception) else exc("fake get_inbound")
        if FakeXuiClient.get_inbound_result is not None:
            return FakeXuiClient.get_inbound_result
        return {"id": int(inbound_id), "tag": f"fake-tag-{inbound_id}", "enable": True}

    async def list_inbounds(self) -> list[dict]:
        """Return the inbounds 3x-ui currently holds.

        Phase 27 (item 2): ``_gather_claimed_ports`` calls this to reject ports
        already bound by a 3x-ui inbound — including inbounds the operator
        created by hand, which no PortAssignment row knows about.
        """
        exc = FakeXuiClient.list_inbounds_raises
        if exc is not None:
            raise exc if isinstance(exc, Exception) else exc("fake list_inbounds")
        return list(FakeXuiClient.list_inbounds_result or [])

    async def clone_inbound(
        self, *, template_id: int, country: dict, socks_port: int, public_port: int
    ) -> dict:
        FakeXuiClient.clone_inbound_calls.append(
            (int(template_id), dict(country), int(socks_port), int(public_port))
        )
        if self.clone_inbound_raises is not None:
            raise_ = self.clone_inbound_raises
            raise raise_ if isinstance(raise_, Exception) else raise_("fake clone_inbound")
        # add_inbound returns data["obj"] — the UNWRAPPED inbound object, NOT
        # the {"obj": {...}} envelope — and clone_inbound returns it verbatim.
        # Stubbing the envelope here is what hid Hotfix #16: the two re-clone
        # sites indexed resp["obj"] and only passed because the fake matched
        # the bug instead of the client. Mirrors the real shape — including
        # the `tag` field, which upstream's resolveInboundTag() always sets and
        # which the routing binder must key its rule on. Omitting it here would
        # let a caller that guesses "in-<port>-tcp" pass the test while writing
        # a rule that matches nothing in production.
        return FakeXuiClient.clone_inbound_result or {
            "id": 31001,
            "tag": "in-31001-tcp",
        }


@pytest.fixture(autouse=True)
def _patch_xui_client(monkeypatch):
    FakeXuiClient.login_raises = None
    FakeXuiClient.delete_inbound_raises = None
    FakeXuiClient.delete_inbound_calls = []
    FakeXuiClient.clone_inbound_result = None
    FakeXuiClient.clone_inbound_raises = None
    FakeXuiClient.clone_inbound_calls = []
    FakeXuiClient.get_inbound_result = None
    FakeXuiClient.get_inbound_raises = None
    FakeXuiClient.get_inbound_calls = []
    FakeXuiClient.list_inbounds_result = None
    FakeXuiClient.list_inbounds_raises = None
    FakeXuiClient.xray_template = None
    FakeXuiClient.xray_updates = []
    FakeXuiClient.xray_get_raises = None
    FakeXuiClient.xray_update_raises = None
    from panel.dashboard import router as dashboard_router

    monkeypatch.setattr(dashboard_router, "XuiClient", FakeXuiClient)
    yield


# ---------------------------------------------------------------------------
# Helper: build a dashboard-ready environment (1 country + 1 assignment).
# ---------------------------------------------------------------------------
def _seed_us_full(monkeypatch, tmp_path) -> TestClient:
    client = _client(monkeypatch, tmp_path)
    _login(client)
    _seed_country(code="US", name="United States", flag="🇺🇸", region="Americas", enabled=True)
    _seed_assignment(code="US", socks_port=11001, public_port=31001)
    _seed_clone(
        country_code="US", inbound_id=31001, socks_port=11001, public_port=31001, healthy=True
    )
    _set_wizard_step_data({"template": {"template_inbound_id": 17}})
    return client


# ===========================================================================
# 1. Wizard-completed gate
# ===========================================================================
class TestDashboardGate:
    def test_unfinished_wizard_returns_409(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        with Session(get_engine()) as s:
            row = s.get(Settings, {"id": 1})
            row.wizard_completed = False
            s.commit()
        r = client.get("/api/dashboard/countries")
        assert r.status_code == 409
        assert "wizard" in r.json()["detail"].lower()

    def test_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        # No login.
        r = client.get("/api/dashboard/countries")
        assert r.status_code == 401


# ===========================================================================
# 2. GET /api/dashboard/countries
# ===========================================================================
class TestListCountries:
    def test_empty_returns_zero_counts(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.get("/api/dashboard/countries")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 0
        assert body["enabled_count"] == 0
        assert body["active_count"] == 0
        assert body["countries"] == []

    def test_one_country_card_shape(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001, healthy=True
        )
        _SystemdFake.active_result = {"US": True}

        r = client.get("/api/dashboard/countries")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["enabled_count"] == 1
        assert body["active_count"] == 1
        card = body["countries"][0]
        assert card["code"] == "US"
        assert card["enabled"] is True
        assert card["assigned"] is True
        assert card["socks_port"] == 11001
        assert card["public_port"] == 31001
        assert card["unit_active"] is True
        assert card["inbound_id"] == 31001
        assert card["healthy"] is True

    def test_country_without_assignment_unassigned(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="DE", enabled=False)
        r = client.get("/api/dashboard/countries")
        assert r.status_code == 200
        card = r.json()["countries"][0]
        assert card["assigned"] is False
        assert card["socks_port"] is None
        assert card["public_port"] is None
        assert card["inbound_id"] is None

    def test_alphabetical_sort(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", name="Japan", flag="🇯🇵", enabled=False)
        _seed_country(code="DE", name="Germany", flag="🇩🇪", enabled=False)
        _seed_country(code="US", name="United States", flag="🇺🇸", enabled=False)
        r = client.get("/api/dashboard/countries")
        assert [c["code"] for c in r.json()["countries"]] == ["DE", "JP", "US"]


# ===========================================================================
# 3. PATCH /api/dashboard/countries/{code}
# ===========================================================================
class TestPatchCountry:
    def test_enable_starts_unit_and_flips_flag(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        assert _SystemdFake.started == ["US"]
        assert _SystemdFake.stopped == []

        # DB row actually updated.
        init_db()
        with Session(get_engine()) as s:
            assert s.get(Country, {"code": "US"}).enabled is True

    def test_disable_stops_unit(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.patch("/api/dashboard/countries/US", json={"enabled": False})
        assert r.status_code == 200
        assert _SystemdFake.stopped == ["US"]
        assert r.json()["enabled"] is False

    def test_enable_without_assignment_inline_picks_ports_and_persists(self, monkeypatch, tmp_path):
        """Hotfix #10 (Bug #3) — enabling a country that has NO PortAssignment
        no longer raises 409. The handler accepts optional socks/public ports
        (or picks smart-recommendation defaults), runs apply_country inline,
        persists a fresh PortAssignment row, and flips Country.enabled=True.
        """
        from panel.psiphon import HealthProbeResult
        from panel.wizard import apply as apply_mod

        # Sandbox apply_country: stub all 4 dependencies it calls.
        start_calls: list[str] = []
        is_active_calls: list[str] = []
        write_calls: list[tuple[str, int]] = []
        health_calls: list[int] = []

        def _fake_write(country_code, socks_port, *, config_dir=None):
            write_calls.append((country_code, socks_port))
            return Path(f"/tmp/psiphon-fake-{country_code}.json")

        def _fake_start(country_code):
            start_calls.append(country_code)

        def _fake_active(country_code):
            is_active_calls.append(country_code)
            return True

        def _fake_health(socks_port, **kwargs):  # noqa: ANN001
            health_calls.append(socks_port)
            return HealthProbeResult(healthy=True, detail="ok")

        monkeypatch.setattr(apply_mod, "write_config", _fake_write)
        monkeypatch.setattr(apply_mod, "start_unit", _fake_start)
        monkeypatch.setattr(apply_mod, "is_unit_active", _fake_active)
        monkeypatch.setattr(apply_mod, "health_probe", _fake_health)

        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        # No PortAssignment seeded — pre-Hotfix-#10 path raised 409 here.

        r = client.patch(
            "/api/dashboard/countries/US",
            json={"enabled": True, "socks_port": 11099, "public_port": 31099},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True
        assert body["socks_port"] == 11099
        assert body["public_port"] == 31099

        # Inline-enable should have run apply_country end-to-end.
        assert write_calls == [("US", 11099)]
        assert start_calls == ["US"]
        assert is_active_calls == ["US"]
        assert health_calls == [11099]

        # The new PortAssignment row should now be persisted.
        init_db()
        with Session(get_engine()) as s:
            row = s.query(PortAssignment).filter(PortAssignment.country_code == "US").one()
            assert row.socks_port == 11099
            assert row.public_port == 31099
            assert s.get(Country, {"code": "US"}).enabled is True

    def test_enable_without_assignment_failure_returns_502(self, monkeypatch, tmp_path):
        """Hotfix #10 (Bug #3) — if apply_country returns a ``failed`` event
        during inline-enable, the handler raises 502 carrying the underlying
        failure message (NOT a 409 telling the operator to revisit the wizard).
        """
        from panel.psiphon import HealthProbeResult
        from panel.wizard import apply as apply_mod

        # Force apply_country to fail at the health-probe step (progress=75).
        monkeypatch.setattr(apply_mod, "write_config", lambda *a, **k: Path("/tmp/x.json"))
        monkeypatch.setattr(apply_mod, "start_unit", lambda *a, **k: None)
        monkeypatch.setattr(apply_mod, "is_unit_active", lambda *a, **k: True)
        monkeypatch.setattr(
            apply_mod,
            "health_probe",
            lambda *a, **k: HealthProbeResult(healthy=False, detail="connection refused"),
        )

        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="DE", enabled=False)

        r = client.patch("/api/dashboard/countries/DE", json={"enabled": True})
        assert r.status_code == 502
        assert "inline enable for DE failed" in r.json()["detail"]
        assert "connection refused" in r.json()["detail"]

    def test_enable_start_unit_failure_returns_502(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        from panel.psiphon import PsiphonUnitError

        _SystemdFake.start_raises = PsiphonUnitError
        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 502
        assert "start_unit" in r.json()["detail"]

    def test_unknown_country_returns_404(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.patch("/api/dashboard/countries/ZZ", json={"enabled": True})
        assert r.status_code == 404

    def test_bad_code_format_returns_400(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.patch("/api/dashboard/countries/us1", json={"enabled": True})
        assert r.status_code == 400

    def test_disable_stop_failure_does_not_block_flag(self, monkeypatch, tmp_path):
        """A failing stop doesn't 502 (best-effort disable)."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        from panel.psiphon import PsiphonUnitError

        _SystemdFake.stop_raises = PsiphonUnitError

        r = client.patch("/api/dashboard/countries/US", json={"enabled": False})
        assert r.status_code == 200
        assert r.json()["enabled"] is False


# ---------------------------------------------------------------------------
# 3b. Feature A+C: enable-with-inbound (PATCH @enabled=true + inbound_id)
# ---------------------------------------------------------------------------
class TestPatchCountryWithInbound:
    """Phase 25 Features A+C — PATCH accepts an ``inbound_id`` and, when
    enabled=true, runs apply_country + clone_for_country and surfaces
    apply_result + clone_result in the response.
    """

    def _stub_apply(self, monkeypatch):
        """Sandbox apply_country's I/O (write_config/start/is_active/probe)."""
        from panel.psiphon import HealthProbeResult
        from panel.wizard import apply as apply_mod

        calls: dict[str, list] = {"write": [], "start": [], "active": [], "probe": []}

        def _fake_write(country_code, socks_port, *, config_dir=None):
            calls["write"].append((country_code, socks_port))
            return Path(f"/tmp/psiphon-fake-{country_code}.json")

        def _fake_start(country_code):
            calls["start"].append(country_code)

        def _fake_active(country_code):
            calls["active"].append(country_code)
            return True

        def _fake_health(socks_port, **kwargs):  # noqa: ANN001
            calls["probe"].append(socks_port)
            return HealthProbeResult(healthy=True, detail="ok")

        monkeypatch.setattr(apply_mod, "write_config", _fake_write)
        monkeypatch.setattr(apply_mod, "start_unit", _fake_start)
        monkeypatch.setattr(apply_mod, "is_unit_active", _fake_active)
        monkeypatch.setattr(apply_mod, "health_probe", _fake_health)
        return calls

    def test_enable_with_inbound_clones_and_reports(self, monkeypatch, tmp_path):
        """Enabling a country that has NO existing PortAssignment with
        ``inbound_id`` runs apply+clone; apply_result + clone_result ride the
        response. The CloneRecord row mirrors the freshly-cloned id.
        """
        self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 4242}

        r = client.patch(
            "/api/dashboard/countries/JP",
            json={"enabled": True, "inbound_id": 17},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True
        # apply ran (new PortAssignment branch always runs apply_country).
        assert body["apply_result"] is not None
        assert body["apply_result"]["status"] == "healthy"
        assert body["apply_result"]["progress"] == 100
        # clone ran.
        assert body["clone_result"] is not None
        assert body["clone_result"]["success"] is True
        assert body["clone_result"]["inbound_id"] == 4242
        assert body["clone_result"]["error"] is None
        # xui_client.clone_inbound was invoked with the template_id we sent.
        assert FakeXuiClient.clone_inbound_calls == [
            (17, {"code": "JP", "name": "United States", "flag": "🇺🇸"},
             body["socks_port"], body["public_port"])
        ]
        # DB row mirrors it.
        init_db()
        with Session(get_engine()) as s:
            clone = s.query(CloneRecord).filter(CloneRecord.country_code == "JP").first()
            assert clone is not None
            assert clone.inbound_id == 4242

    def test_enable_with_inbound_falls_back_to_smart_ports(self, monkeypatch, tmp_path):
        """socks_port/public_port omitted → smart-recommendation defaults are
        used (≥11000 / ≥11050, unified floors in Phase 27)."""
        self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        _seed_xui_link()

        r = client.patch(
            "/api/dashboard/countries/JP",
            json={"enabled": True, "inbound_id": 7},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["socks_port"] >= 11000
        assert body["public_port"] >= 11050

    def test_enable_existing_assignment_with_inbound_applies_and_clones(
        self, monkeypatch, tmp_path,
    ):
        """A country that ALREADY has a PortAssignment still runs
        apply_country + clone when enabled=true + inbound_id are sent; the
        legacy bare-toggle path (no inbound_id) does NOT call apply_country.
        """
        calls = self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 55555}

        r = client.patch(
            "/api/dashboard/countries/US",
            json={"enabled": True, "inbound_id": 3},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        # apply ran with the PERSISTED ports, not fresh ones.
        assert calls["write"] == [("US", 11001)]
        assert calls["probe"] == [11001]
        # clone ran from the picked template id.
        assert FakeXuiClient.clone_inbound_calls == [
            (3, {"code": "US", "name": "United States", "flag": "🇺🇸"}, 11001, 31001)
        ]
        assert body["apply_result"]["status"] == "healthy"
        assert body["clone_result"]["inbound_id"] == 55555

    def test_bare_toggle_without_inbound_skips_apply(self, monkeypatch, tmp_path):
        """Legacy Hotfix-#10 semantic: PATCH @enabled=true without inbound_id
        does NOT call apply_country — start_unit is enough (cheap toggle)."""
        calls = self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        # apply_country NOT in play (no inbound_id).
        assert calls["write"] == []
        assert calls["probe"] == []
        # And clone wasn't triggered either.
        assert body["apply_result"] is None
        assert body["clone_result"] is None

    def test_enable_with_inbound_clone_failure_recorded(self, monkeypatch, tmp_path):
        """If the 3x-ui clone fails mid-flow the PATCH still succeeds (the
        country IS enabled — the tunnel is up) but surfaces the error in
        clone_result.error so the SPA can render it inline.
        """
        self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        _seed_xui_link()
        from panel.dashboard.xui_client import XuiClientError

        FakeXuiClient.clone_inbound_raises = XuiClientError

        r = client.patch(
            "/api/dashboard/countries/JP",
            json={"enabled": True, "inbound_id": 17},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True
        assert body["apply_result"]["status"] == "healthy"
        assert body["clone_result"]["success"] is False
        assert "clone_inbound" in body["clone_result"]["error"]

    def test_enable_with_inbound_no_creds_recorded(self, monkeypatch, tmp_path):
        """No XuiLink row → clone_result.success == False with a clear
        error string; the country is still enabled (apply succeeded)."""
        self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        # NOTE: no _seed_xui_link call.

        r = client.patch(
            "/api/dashboard/countries/JP",
            json={"enabled": True, "inbound_id": 17},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["enabled"] is True
        assert body["clone_result"]["success"] is False
        assert "no cached 3x-ui creds" in body["clone_result"]["error"]

    def test_disable_with_inbound_ignores_inbound(self, monkeypatch, tmp_path):
        """PATCH @enabled=false ignores a stray inbound_id — disable is
        best-effort stop_unit only."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.patch(
            "/api/dashboard/countries/US",
            json={"enabled": False, "inbound_id": 17},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is False
        # No clone was triggered.
        assert body["clone_result"] is None

    def test_patch_inbound_id_validation_rejects_bool(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        r = client.patch(
            "/api/dashboard/countries/US",
            json={"enabled": True, "inbound_id": True},  # bool, not int
        )
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# 3c. Feature D: POST /api/dashboard/countries/{code}/_reclone
# ---------------------------------------------------------------------------
class TestRecloneCountry:
    """Phase 25 Feature D — swap the 3x-ui template inbound for a country."""

    def _stub_apply(self, monkeypatch):
        from panel.psiphon import HealthProbeResult
        from panel.wizard import apply as apply_mod

        monkeypatch.setattr(
            apply_mod, "write_config", lambda *a, **k: Path("/tmp/fake.json")
        )
        monkeypatch.setattr(apply_mod, "start_unit", lambda *a, **k: None)
        monkeypatch.setattr(apply_mod, "is_unit_active", lambda *a, **k: True)
        monkeypatch.setattr(
            apply_mod,
            "health_probe",
            lambda *a, **k: HealthProbeResult(healthy=True, detail="ok"),
        )

    def test_reclone_happy_path(self, monkeypatch, tmp_path):
        """Deletes the old clone, clones the new template, persists the new
        CloneRecord, applies the tunnel config, and returns the refreshed
        card + apply_result + clone_result.
        """
        self._stub_apply(monkeypatch)
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 77777}

        r = client.post(
            "/api/dashboard/countries/US/_reclone",
            json={"inbound_id": 5},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["code"] == "US"
        assert body["prior_inbound_deleted"] == 31001
        assert body["clone_result"]["success"] is True
        assert body["clone_result"]["inbound_id"] == 77777
        assert body["apply_result"]["status"] == "healthy"
        # xui_client saw delete(31001) + clone(template=5).
        assert FakeXuiClient.delete_inbound_calls == [31001]
        assert FakeXuiClient.clone_inbound_calls == [
            (5, {"code": "US", "name": "United States", "flag": "🇺🇸"}, 11001, 31001)
        ]
        # DB row holds the new inbound id.
        init_db()
        with Session(get_engine()) as s:
            clone = s.query(CloneRecord).filter(CloneRecord.country_code == "US").first()
            assert clone.inbound_id == 77777

    def test_reclone_no_prior_assignment_returns_409(self, monkeypatch, tmp_path):
        """Can't re-clone a country that has no PortAssignment (no socks_port
        to route through)."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        _seed_xui_link()

        r = client.post(
            "/api/dashboard/countries/JP/_reclone",
            json={"inbound_id": 5},
        )
        assert r.status_code == 409
        assert "PortAssignment" in r.json()["detail"]

    def test_reclone_no_creds_returns_409(self, monkeypatch, tmp_path):
        """Without a cached XuiLink row the endpoint refuses at 409 — there's
        no way to reach 3x-ui."""
        self._stub_apply(monkeypatch)
        client = _seed_us_full(monkeypatch, tmp_path)
        # NOTE: no _seed_xui_link call.

        r = client.post(
            "/api/dashboard/countries/US/_reclone",
            json={"inbound_id": 5},
        )
        assert r.status_code == 409

    def test_reclone_no_prior_clone_falls_through(self, monkeypatch, tmp_path):
        """A country with a PortAssignment but NO CloneRecord (fresh enable)
        still re-clones from the new template — no prior delete happens."""
        self._stub_apply(monkeypatch)
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 88888}

        r = client.post(
            "/api/dashboard/countries/US/_reclone",
            json={"inbound_id": 9},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["prior_inbound_deleted"] is None
        assert body["clone_result"]["inbound_id"] == 88888
        assert FakeXuiClient.delete_inbound_calls == []  # nothing to delete

    def test_reclone_clone_failure_recorded(self, monkeypatch, tmp_path):
        """A clone_inbound failure after delete is surfaced via clone_result,
        not raised — the apply step still completes."""
        self._stub_apply(monkeypatch)
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        from panel.dashboard.xui_client import XuiClientError

        FakeXuiClient.clone_inbound_raises = XuiClientError

        r = client.post(
            "/api/dashboard/countries/US/_reclone",
            json={"inbound_id": 5},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["clone_result"]["success"] is False
        assert "clone_inbound" in body["clone_result"]["error"]
        assert body["apply_result"]["status"] == "healthy"
        # Prior inbound was still deleted.
        assert FakeXuiClient.delete_inbound_calls == [31001]

    def test_reclone_unknown_country_returns_404(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/countries/ZZ/_reclone",
            json={"inbound_id": 5},
        )
        assert r.status_code == 404

    def test_reclone_inbound_id_validation(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        # Missing inbound_id → 422 body-validation error.
        r = client.post("/api/dashboard/countries/US/_reclone", json={})
        assert r.status_code == 422
        # bool rejected at the StrictInt schema level.
        r = client.post(
            "/api/dashboard/countries/US/_reclone", json={"inbound_id": True}
        )
        assert r.status_code == 422


# ===========================================================================
# 4. DELETE /api/dashboard/countries/{code}
# ===========================================================================
class TestDeleteCountry:
    def test_full_teardown_summary(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 99999}

        r = client.delete("/api/dashboard/countries/US")
        assert r.status_code == 200
        body = r.json()
        assert body["stopped_unit"] is True
        assert body["removed_clone_record"] is True
        assert body["deleted_inbound"] is True
        assert body["removed_assignment"] is True
        assert body["country_disabled"] is True

        # DB state matches.
        init_db()
        with Session(get_engine()) as s:
            assert s.query(CloneRecord).count() == 0
            assert s.query(PortAssignment).count() == 0
            country = s.get(Country, {"code": "US"})
            assert country is not None  # row preserved
            assert country.enabled is False

        assert FakeXuiClient.delete_inbound_calls == [31001]

    def test_no_clone_record_skips_xui_delete(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        # No CloneRecord seeded → step 3 skipped.
        r = client.delete("/api/dashboard/countries/US")
        assert r.status_code == 200
        assert r.json()["deleted_inbound"] is False
        assert r.json()["removed_clone_record"] is False
        assert FakeXuiClient.delete_inbound_calls == []

    def test_delete_inbound_failure_recorded_not_raised(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        from panel.dashboard.xui_client import XuiClientError

        FakeXuiClient.delete_inbound_raises = {31001: XuiClientError}
        r = client.delete("/api/dashboard/countries/US")
        assert r.status_code == 200
        body = r.json()
        assert body["deleted_inbound"] is False
        assert body["deleted_inbound_error"] is not None
        # Local teardown still proceeded:
        assert body["stopped_unit"] is True
        assert body["removed_clone_record"] is True

    def test_no_cached_creds_records_error(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        # No _seed_xui_link call => no XuiLink row.
        r = client.delete("/api/dashboard/countries/US")
        assert r.status_code == 200
        body = r.json()
        assert body["deleted_inbound"] is False
        assert body["deleted_inbound_error"] == "no cached 3x-ui creds"

    def test_stop_unit_failure_does_not_block_teardown(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        from panel.psiphon import PsiphonUnitError

        _SystemdFake.stop_raises = PsiphonUnitError

        r = client.delete("/api/dashboard/countries/US")
        assert r.status_code == 200
        body = r.json()
        assert body["stopped_unit"] is False
        assert body["removed_clone_record"] is True
        assert body["removed_assignment"] is True


# ===========================================================================
# 5. POST /api/dashboard/countries/{code}/_ports
# ===========================================================================
class TestEditPorts:
    def test_happy_rewrites_and_reclones(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 99998}

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["rewrote_config"] is True
        assert body["restarted_unit"] is True
        assert body["updated_assignment"] is True
        assert body["recloned_inbound"] is True
        assert _SystemdFake.restarted == ["US"]

        init_db()
        with Session(get_engine()) as s:
            pa = s.query(PortAssignment).filter(PortAssignment.country_code == "US").first()
            assert pa.socks_port == 12002
            assert pa.public_port == 32002
            clone = s.query(CloneRecord).filter(CloneRecord.country_code == "US").first()
            assert clone.inbound_id == 99998

        # Old inbound deleted + new clone called with new ports.
        assert FakeXuiClient.delete_inbound_calls == [31001]
        assert FakeXuiClient.clone_inbound_calls == [
            (17, {"code": "US", "name": "United States", "flag": "🇺🇸"}, 12002, 32002)
        ]

    def test_no_existing_clone_skips_reclone(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        # No CloneRecord → edit ports just rewrites config + restarts.

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 200
        assert r.json()["recloned_inbound"] is False
        assert r.json()["updated_assignment"] is True

    def test_panel_port_collision_returns_400(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 18001, "public_port": 32002},
        )
        assert r.status_code == 400
        assert "panel_port" in r.json()["detail"]

    def test_socks_equals_public_returns_400(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12345, "public_port": 12345},
        )
        assert r.status_code == 400

    def test_clash_with_other_country_returns_400(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="DE", enabled=True)
        _seed_assignment(code="DE", socks_port=12002, public_port=32002)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},  # clashes with DE
        )
        assert r.status_code == 400
        assert "DE" in r.json()["detail"]

    def test_invalid_port_returns_422(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 80, "public_port": 32002},  # socks < 1024
        )
        # pydantic Field ge=1024 enforces this at schema level → 422
        assert r.status_code == 422

    def test_restart_failure_does_not_block_assignment(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        from panel.psiphon import PsiphonUnitError

        _SystemdFake.restart_raises = PsiphonUnitError

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["restarted_unit"] is False
        assert body["restarted_unit_error"] is not None
        assert body["updated_assignment"] is True

    def test_missing_creds_reclone_recorded_not_raised(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        # No _seed_xui_link call.
        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["recloned_inbound"] is False
        assert body["reclone_error"].startswith("no cached 3x-ui creds")

    def test_unknown_country_returns_404(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/countries/ZZ/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 404


# ===========================================================================
# 5b. Phase 27 (item 2): universal pre-creation port-conflict checking
# ===========================================================================
class TestPortConflictChecking:
    """Ports must be checked against EVERY claimant before being created.

    A PortAssignment scan alone is not enough: the operator can create inbounds
    by hand in 3x-ui, and unrelated processes can hold ports on the host. The
    reported scenario is disable-one-country-then-enable-another, where the
    freed port is silently reissued to something that already owns it.
    """

    def test_edit_ports_rejects_port_held_by_a_3xui_inbound(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        # An inbound the operator made by hand — no PortAssignment row knows of it.
        FakeXuiClient.list_inbounds_result = [{"id": 55, "port": 32002}]

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 409, r.text
        assert "32002" in r.json()["detail"]

    def test_edit_ports_allows_ports_no_one_holds(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        FakeXuiClient.list_inbounds_result = [{"id": 55, "port": 40404}]

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 200, r.text

    def test_edit_ports_ignores_the_countrys_own_current_ports(self, monkeypatch, tmp_path):
        """Re-submitting a country's existing ports is a no-op, not a conflict.

        _gather_claimed_ports excludes the calling country, so US keeping its
        own socks port while moving only the public port must still succeed.
        """
        client = _seed_us_full(monkeypatch, tmp_path)  # US holds 11001 / 31001
        _seed_xui_link()

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 11001, "public_port": 32002},
        )
        assert r.status_code == 200, r.text

    def test_enable_rejects_supplied_port_held_by_a_3xui_inbound(self, monkeypatch, tmp_path):
        """The enable-with-ports modal must not create a conflicting inbound."""
        from types import SimpleNamespace

        from panel.dashboard import router as dashboard_router

        monkeypatch.setattr(
            dashboard_router,
            "apply_country",
            lambda spec: SimpleNamespace(status="healthy", message="ok"),
        )
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        _seed_xui_link()
        FakeXuiClient.list_inbounds_result = [{"id": 55, "port": 31234}]

        r = client.patch(
            "/api/dashboard/countries/JP",
            json={"enabled": True, "inbound_id": 7, "socks_port": 11234, "public_port": 31234},
        )
        assert r.status_code == 409, r.text
        assert "31234" in r.json()["detail"]

    def test_smart_pick_skips_ports_held_by_3xui_inbounds(self, monkeypatch, tmp_path):
        """The picker must walk past a 3x-ui-held port, not hand it out.

        11000 and 11050 are the unified floors, so a bare enable would pick
        exactly those. With both held by inbounds, the picker must move on.
        """
        from types import SimpleNamespace

        from panel.dashboard import router as dashboard_router

        monkeypatch.setattr(
            dashboard_router,
            "apply_country",
            lambda spec: SimpleNamespace(status="healthy", message="ok", progress=100),
        )
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="JP", enabled=False)
        _seed_xui_link()
        FakeXuiClient.list_inbounds_result = [
            {"id": 1, "port": 11000},
            {"id": 2, "port": 11050},
        ]

        r = client.patch(
            "/api/dashboard/countries/JP",
            json={"enabled": True, "inbound_id": 7},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["socks_port"] != 11000
        assert body["public_port"] != 11050
        assert body["socks_port"] >= 11000
        assert body["public_port"] >= 11050

    def test_port_probe_failure_does_not_block_creation(self, monkeypatch, tmp_path):
        """A panel that is down must not wedge port allocation.

        The 3x-ui probe is best-effort by design: the PortAssignment scan still
        runs, so we degrade to the pre-Phase-27 guarantee rather than failing shut.
        """
        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_xui_link()
        FakeXuiClient.list_inbounds_raises = RuntimeError("panel unreachable")

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 12002, "public_port": 32002},
        )
        assert r.status_code == 200, r.text


# ===========================================================================
# 6. GET /api/dashboard/tunnels/{code}/logs
# ===========================================================================
class TestTunnelLogs:
    def test_happy_returns_lines(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        from panel.dashboard import router as dashboard_router

        dashboard_router._journalctl_lines.set_lines(  # type: ignore[attr-defined]
            "psiphon-tunnel@US.service",
            ["line one", "line two"],
        )
        r = client.get("/api/dashboard/tunnels/US/logs?lines=50")
        assert r.status_code == 200
        body = r.json()
        assert body["code"] == "US"
        assert body["unit"] == "psiphon-tunnel@US.service"
        assert body["lines_requested"] == 50
        assert body["lines"] == ["line one", "line two"]

    def test_default_lines_200(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        r = client.get("/api/dashboard/tunnels/US/logs")
        assert r.status_code == 200
        assert r.json()["lines_requested"] == 200

    def test_unknown_country_404(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.get("/api/dashboard/tunnels/ZZ/logs")
        assert r.status_code == 404

    def test_lines_out_of_range_returns_400(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        r = client.get("/api/dashboard/tunnels/US/logs?lines=99999")
        assert r.status_code == 400

    def test_journalctl_failure_returns_502(self, monkeypatch, tmp_path):
        client = _seed_us_full(monkeypatch, tmp_path)
        from panel.dashboard import router as dashboard_router

        dashboard_router._journalctl_lines.set_raises("journalctl missing")  # type: ignore[attr-defined]
        r = client.get("/api/dashboard/tunnels/US/logs")
        assert r.status_code == 502
        assert "journalctl" in r.json()["detail"]


# ===========================================================================
# 7. POST /api/dashboard/reapply
# ===========================================================================
class TestReapply:
    def test_happy_all_applied(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="DE", enabled=True)
        _seed_assignment(code="DE", socks_port=11002, public_port=31002)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.post("/api/dashboard/reapply")
        assert r.status_code == 200
        body = r.json()
        assert {entry["code"] for entry in body["applied"]} == {"US", "DE"}
        assert _SystemdFake.restarted == ["DE", "US"]

    def test_restart_failure_recorded(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        from panel.psiphon import PsiphonUnitError

        _SystemdFake.restart_raises = PsiphonUnitError

        r = client.post("/api/dashboard/reapply")
        assert r.status_code == 200
        body = r.json()
        assert body["applied"] == []
        assert body["failed"] and body["failed"][0]["code"] == "US"

    def test_unhealthy_clone_triggers_reclone(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001, healthy=False
        )
        _set_wizard_step_data({"template": {"template_inbound_id": 17}})
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 31002}

        r = client.post("/api/dashboard/reapply")
        assert r.status_code == 200
        body = r.json()
        assert len(body["recloned"]) == 1
        assert body["recloned"][0]["old_inbound_id"] == 31001
        assert body["recloned"][0]["new_inbound_id"] == 31002

        init_db()
        with Session(get_engine()) as s:
            clone = s.query(CloneRecord).filter(CloneRecord.country_code == "US").first()
            assert clone.inbound_id == 31002

    def test_no_assignments_returns_empty(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post("/api/dashboard/reapply")
        assert r.status_code == 200
        assert r.json()["applied"] == []


# ===========================================================================
# 8. POST /api/dashboard/backup + /restore
# ===========================================================================
class TestBackupRestore:
    def test_backup_returns_tar_with_panel_db(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        # Seed a Country and PortAssignment row so panel.db has real content.
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        # Write a per-country config file to test it lands in the tar.
        cfg_dir = Path(tmp_path) / "config"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "US.json").write_text('{"EgressRegion": "US"}', encoding="utf-8")

        r = client.post("/api/dashboard/backup")
        assert r.status_code == 200
        assert "tar" in r.headers.get("content-disposition", "")
        body = r.content
        assert body
        # Open the tar in-memory and inspect the members.
        with tarfile.open(fileobj=io.BytesIO(body), mode="r") as tar:
            names = tar.getnames()
        assert "panel.db" in names
        assert "config/US.json" in names

    def test_restore_round_trip(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        # Build a tar with a fresh panel.db + a config file.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            db_path = Path(get_engine().url.database)
            assert db_path.is_file()
            tar.add(db_path, arcname="panel.db")
            cfg_bytes = b'{"EgressRegion": "DE"}'
            info = tarfile.TarInfo("config/DE.json")
            info.size = len(cfg_bytes)
            tar.addfile(info, io.BytesIO(cfg_bytes))
        buf.seek(0)

        r = client.post(
            "/api/dashboard/restore",
            files={"file": ("backup.tar", buf.getvalue(), "application/x-tar")},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["restored_panel_db"] is True
        assert "DE.json" in body["restored_configs"]

        # File actually written.
        cfg_path = Path(tmp_path) / "config" / "DE.json"
        assert cfg_path.is_file()
        assert json.loads(cfg_path.read_text(encoding="utf-8")) == {"EgressRegion": "DE"}

    def test_restore_empty_returns_400(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/restore",
            files={"file": ("backup.tar", b"", "application/x-tar")},
        )
        assert r.status_code == 400

    def test_restore_invalid_tar_returns_400(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/restore",
            files={"file": ("backup.tar", b"not a tar", "application/x-tar")},
        )
        assert r.status_code == 400


# ===========================================================================
# 9. POST /api/dashboard/rotate-password
# ===========================================================================
class TestRotatePassword:
    def test_happy_rotates_and_new_password_works(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/rotate-password",
            json={
                "current_password": "correct-horse-battery-staple",
                "new_password": "new-strong-password-2026",
            },
        )
        assert r.status_code == 200
        assert r.json()["rotated"] is True

        # Old password now fails; new one succeeds.
        r = client.post(
            "/auth/login",
            json={"user": "admin", "password": "correct-horse-battery-staple"},
        )
        assert r.status_code == 401
        r = client.post(
            "/auth/login",
            json={"user": "admin", "password": "new-strong-password-2026"},
        )
        assert r.status_code == 204

    def test_wrong_current_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/rotate-password",
            json={
                "current_password": " WRONG ",
                "new_password": "another-strong-pw-2026",
            },
        )
        assert r.status_code == 401

    def test_short_new_returns_422(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/rotate-password",
            json={
                "current_password": "correct-horse-battery-staple",
                "new_password": "short",
            },
        )
        assert r.status_code == 422


# ===========================================================================
# 10. POST /api/dashboard/change-panel-port
# ===========================================================================
class TestChangePanelPort:
    def test_happy_changes_panel_port(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post(
            "/api/dashboard/change-panel-port",
            json={"new_port": 19001},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["changed"] is True
        assert body["old_port"] == 18001
        assert body["new_port"] == 19001
        assert "firewall" in body["note"]

        init_db()
        with Session(get_engine()) as s:
            assert s.get(Settings, {"id": 1}).panel_port == 19001

    def test_same_port_returns_changed_false(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        r = client.post("/api/dashboard/change-panel-port", json={"new_port": 18001})
        assert r.status_code == 200
        body = r.json()
        assert body["changed"] is False
        assert body["panel_port"] == 18001

    def test_collision_with_assignment_returns_400(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        r = client.post("/api/dashboard/change-panel-port", json={"new_port": 31001})
        assert r.status_code == 400
        assert "US" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Phase 26 Hotfix #15 — routing binding on the DASHBOARD (post-wizard) paths.
# ---------------------------------------------------------------------------
def _us_rule(template: dict) -> dict | None:
    """The routing rule bound to psiphon-out-US, or None."""
    rules = template.get("routing", {}).get("rules", [])
    for r in rules:
        if isinstance(r, dict) and r.get("outboundTag") == "psiphon-out-US":
            return r
    return None


def _us_outbound(template: dict) -> dict | None:
    """The psiphon-out-US outbound entry, or None."""
    for ob in template.get("outbounds", []):
        if isinstance(ob, dict) and ob.get("tag") == "psiphon-out-US":
            return ob
    return None


class TestDashboardRoutingBinding:
    """Every dashboard surface that leaves an inbound in place must also leave
    a matching outbound + routing rule in place.

    The wizard path was fixed in Phase 26 / Hotfix #14. These cover the
    *post-wizard* panel surfaces, which is where the operator reported
    "only an inbound is created - no outbound, no route", leaving the country
    egressing on the server's own IP.
    """

    def test_reenable_after_disable_restores_outbound_and_rule(
        self, monkeypatch, tmp_path
    ):
        """THE reported bug: disable then re-enable loses the routing binding.

        The disable branch calls remove_country_binding (stripping the outbound
        + rule) but deliberately does NOT delete the inbound. The SPA's bare
        toggle sends no inbound_id once a country already has ports
        (dashboard.html::toggleEnabled), so the re-enable used to clone nothing
        and re-bind nothing - leaving exactly the reported end state.
        """
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001
        )
        _seed_xui_link()
        # 3x-ui handed this inbound a collision-suffixed tag, so a guessed
        # "in-31001-tcp" would bind a rule that matches nothing.
        FakeXuiClient.get_inbound_result = {"id": 31001, "tag": "in-31001-tcp-2"}
        # Start from a template that already carries the binding.
        FakeXuiClient.xray_template = _stock_xray_template()
        FakeXuiClient.xray_template["outbounds"].append(
            {
                "tag": "psiphon-out-US",
                "protocol": "socks",
                "settings": {
                    "servers": [{"address": "127.0.0.1", "port": 11001, "users": []}]
                },
            }
        )
        FakeXuiClient.xray_template["routing"]["rules"].insert(
            0,
            {
                "type": "field",
                "inboundTag": ["in-31001-tcp-2"],
                "outboundTag": "psiphon-out-US",
            },
        )

        # 1. Disable - strips the outbound + rule, keeps the inbound.
        r = client.patch("/api/dashboard/countries/US", json={"enabled": False})
        assert r.status_code == 200
        assert _us_outbound(FakeXuiClient.xray_template) is None
        assert _us_rule(FakeXuiClient.xray_template) is None
        assert 31001 not in FakeXuiClient.delete_inbound_calls  # inbound survives

        # 2. Re-enable with a BARE toggle (no inbound_id) - must restore both.
        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200

        ob = _us_outbound(FakeXuiClient.xray_template)
        assert ob is not None, "re-enable left the country with no outbound"
        assert ob["settings"]["servers"][0]["port"] == 11001

        rule = _us_rule(FakeXuiClient.xray_template)
        assert rule is not None, "re-enable left the country with no routing rule"
        # Bound to the tag the panel ACTUALLY holds, not a guess.
        assert rule["inboundTag"] == ["in-31001-tcp-2"]
        assert 31001 in FakeXuiClient.get_inbound_calls

        body = r.json()
        assert body["routing_result"]["applied"] is True
        assert body["routing_result"]["inbound_tag"] == "in-31001-tcp-2"

    def test_reenable_rule_precedes_catch_alls(self, monkeypatch, tmp_path):
        """The restored rule must sit above bittorrent/geoip:private.

        Xray evaluates rules top-to-bottom and stops at the first hit, so a
        rule appended after the stock catch-alls would never be reached.
        """
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001
        )
        _seed_xui_link()

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200

        rules = FakeXuiClient.xray_template["routing"]["rules"]
        assert rules[0]["outboundTag"] == "psiphon-out-US"
        assert rules[1]["protocol"] == ["bittorrent"]

    def test_reenable_keeps_direct_outbound_first(self, monkeypatch, tmp_path):
        """outbounds[0] is Xray's default egress - it must stay `direct`."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001
        )
        _seed_xui_link()

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200
        assert FakeXuiClient.xray_template["outbounds"][0]["tag"] == "direct"

    def test_reenable_without_clone_record_is_a_no_op(self, monkeypatch, tmp_path):
        """A country with no inbound has nothing to bind - must not 500."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_xui_link()

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200
        assert r.json()["enabled"] is True
        assert FakeXuiClient.xray_updates == []

    def test_reenable_routing_failure_does_not_block_enable(
        self, monkeypatch, tmp_path
    ):
        """A routing failure is reported, never fatal - the inbound already
        exists, so unwinding the enable would strand the operator."""
        from panel.dashboard.xui_client import XuiClientError

        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001
        )
        _seed_xui_link()
        FakeXuiClient.xray_get_raises = XuiClientError

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200
        assert r.json()["enabled"] is True
        assert r.json()["routing_result"]["applied"] is False
        assert r.json()["routing_result"]["error"]

    def test_reenable_falls_back_to_derived_tag_when_get_inbound_fails(
        self, monkeypatch, tmp_path
    ):
        """If the tag cannot be read, still bind rather than skipping entirely -
        a derived tag is a guess, but no rule at all is a guaranteed failure."""
        from panel.dashboard.xui_client import XuiClientError

        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001
        )
        _seed_xui_link()
        FakeXuiClient.get_inbound_raises = XuiClientError

        r = client.patch("/api/dashboard/countries/US", json={"enabled": True})
        assert r.status_code == 200
        rule = _us_rule(FakeXuiClient.xray_template)
        assert rule is not None
        assert rule["inboundTag"] == ["in-31001-tcp"]

    def test_edit_ports_rebinds_routing_to_new_tag(self, monkeypatch, tmp_path):
        """Changing the public port changes the inbound tag - the rule must
        follow, and exactly one rule must remain."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US", inbound_id=31001, socks_port=11001, public_port=31001
        )
        _set_wizard_step_data({"template": {"template_inbound_id": 17}})
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 31002, "tag": "in-31099-tcp"}
        # Pre-existing binding on the OLD port/tag.
        FakeXuiClient.xray_template = _stock_xray_template()
        FakeXuiClient.xray_template["routing"]["rules"].insert(
            0,
            {
                "type": "field",
                "inboundTag": ["in-31001-tcp"],
                "outboundTag": "psiphon-out-US",
            },
        )

        r = client.post(
            "/api/dashboard/countries/US/_ports",
            json={"socks_port": 11099, "public_port": 31099},
        )
        assert r.status_code == 200

        rule = _us_rule(FakeXuiClient.xray_template)
        assert rule is not None, "edit-ports left the country with no routing rule"
        assert rule["inboundTag"] == ["in-31099-tcp"]

        ob = _us_outbound(FakeXuiClient.xray_template)
        assert ob is not None
        assert ob["settings"]["servers"][0]["port"] == 11099

        # Exactly one rule - no stale entry pointing at the deleted inbound.
        us_rules = [
            x
            for x in FakeXuiClient.xray_template["routing"]["rules"]
            if x.get("outboundTag") == "psiphon-out-US"
        ]
        assert len(us_rules) == 1

    def test_reapply_rebinds_routing_after_reclone(self, monkeypatch, tmp_path):
        """The reapply sweep re-clones unhealthy inbounds - it must re-bind
        them too, otherwise "reapply" resurrects the inbound and leaves the
        country egressing on the server's own IP."""
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        _seed_clone(
            country_code="US",
            inbound_id=31001,
            socks_port=11001,
            public_port=31001,
            healthy=False,
        )
        _set_wizard_step_data({"template": {"template_inbound_id": 17}})
        _seed_xui_link()
        FakeXuiClient.clone_inbound_result = {"id": 31002, "tag": "in-31001-tcp-2"}

        r = client.post("/api/dashboard/reapply")
        assert r.status_code == 200
        body = r.json()
        assert len(body["recloned"]) == 1
        assert body["recloned"][0]["routing_applied"] is True
        assert body["recloned"][0]["inbound_tag"] == "in-31001-tcp-2"

        rule = _us_rule(FakeXuiClient.xray_template)
        assert rule is not None, "reapply left the country with no routing rule"
        assert rule["inboundTag"] == ["in-31001-tcp-2"]
        assert _us_outbound(FakeXuiClient.xray_template) is not None


# ===========================================================================
# 15. POST /api/dashboard/countries/{code}/_ping   (Phase 28, item 3)
# ===========================================================================
def _stub_ping(monkeypatch, results):
    """Swap router-level tunnel_ping with a recording fake.

    ``results`` maps socks_port -> TunnelPingResult. Any port not present
    yields a generic failure, so a test that pings the WRONG port fails
    loudly instead of silently passing on a default-ok stub.
    """
    from panel.dashboard import router as dashboard_router
    from panel.psiphon import TunnelPingResult

    calls: list[int] = []

    def _fake(socks_port: int, **kwargs) -> TunnelPingResult:
        calls.append(int(socks_port))
        return results.get(
            int(socks_port),
            TunnelPingResult(ok=False, detail=f"no stub for port {socks_port}"),
        )

    monkeypatch.setattr(dashboard_router, "tunnel_ping", _fake)
    return calls


class TestPingCountry:
    """The operator's question is "is THIS country connected, and how fast?".

    So the endpoint must probe the country's own SOCKS port (not a shared or
    guessed one), and must report a dead tunnel as a 200 + ``ok: false``
    rather than an HTTP error — a failed ping is a valid answer, not a
    broken request.
    """

    def test_ping_happy_returns_latency_for_that_country(self, monkeypatch, tmp_path):
        from panel.psiphon import TunnelPingResult

        client = _seed_us_full(monkeypatch, tmp_path)
        calls = _stub_ping(
            monkeypatch,
            {11001: TunnelPingResult(ok=True, latency_ms=42, detail="tunnel reached")},
        )

        r = client.post("/api/dashboard/countries/US/_ping")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert body["latency_ms"] == 42
        assert body["code"] == "US"
        # THE point of the feature: the probe went through US's own tunnel.
        assert body["socks_port"] == 11001
        assert calls == [11001]

    def test_ping_probes_each_countrys_own_socks_port(self, monkeypatch, tmp_path):
        """Two countries must not share a probe target, otherwise the badge
        would report country A's health under country B's row."""
        from panel.psiphon import TunnelPingResult

        client = _seed_us_full(monkeypatch, tmp_path)
        _seed_country(code="DE", name="Germany", flag="DE", region="Europe", enabled=True)
        _seed_assignment(code="DE", socks_port=11002, public_port=31002)
        calls = _stub_ping(
            monkeypatch,
            {
                11001: TunnelPingResult(ok=True, latency_ms=42),
                11002: TunnelPingResult(ok=True, latency_ms=98),
            },
        )

        us = client.post("/api/dashboard/countries/US/_ping").json()
        de = client.post("/api/dashboard/countries/DE/_ping").json()

        assert (us["socks_port"], us["latency_ms"]) == (11001, 42)
        assert (de["socks_port"], de["latency_ms"]) == (11002, 98)
        assert calls == [11001, 11002]

    def test_dead_tunnel_is_200_with_ok_false(self, monkeypatch, tmp_path):
        from panel.psiphon import TunnelPingResult

        client = _seed_us_full(monkeypatch, tmp_path)
        _stub_ping(
            monkeypatch,
            {
                11001: TunnelPingResult(
                    ok=False, detail="tunnel refused CONNECT: host unreachable"
                )
            },
        )

        r = client.post("/api/dashboard/countries/US/_ping")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is False
        assert body["latency_ms"] is None
        assert "host unreachable" in body["detail"]

    def test_disabled_country_returns_409(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=False)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)
        calls = _stub_ping(monkeypatch, {})

        r = client.post("/api/dashboard/countries/US/_ping")
        assert r.status_code == 409, r.text
        assert "disabled" in r.json()["detail"]
        assert calls == [], "a disabled country has no tunnel — must not be probed"

    def test_country_without_assignment_returns_409(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _seed_country(code="US", enabled=True)
        calls = _stub_ping(monkeypatch, {})

        r = client.post("/api/dashboard/countries/US/_ping")
        assert r.status_code == 409, r.text
        assert calls == []

    def test_unknown_country_returns_404(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _stub_ping(monkeypatch, {})

        r = client.post("/api/dashboard/countries/ZZ/_ping")
        assert r.status_code == 404, r.text

    def test_ping_requires_auth(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _seed_country(code="US", enabled=True)
        _seed_assignment(code="US", socks_port=11001, public_port=31001)

        r = client.post("/api/dashboard/countries/US/_ping")
        assert r.status_code in (401, 403), r.text
