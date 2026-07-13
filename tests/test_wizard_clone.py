"""Phase 5 wizard clone-step tests (step 5e).

Covers the clone engine + the wizard finalize SSE handler::

* :class:`panel.wizard.clone.CloneEvent` / :class:`CloneSpec`
  shape + ``as_dict`` projection.
* :func:`panel.wizard.clone.clone_country` — happy path, API failure, missing
  ``id`` in the clone response, generic exception path.
* :func:`panel.wizard.clone.orchestrator_clone_events` — happy batch, mid-list
  failure triggers rollback (delete_inbound + CloneRecord row removal),
  rollback tolerance when delete_inbound itself fails.
* ``POST /api/wizard/clone`` — SSE stream happy path (wizard advances to
  ``done`` + ``Settings.wizard_completed`` flips True), mid-batch failure
  emits ``rolled_back`` + leaves ``current_step`` at ``clone``, state-machine
  409 (wizard off-step), 409 when no template inbound stored, 409 when no
  PortAssignment rows, 409 when no cached XUI creds, 401 unauth.

No real 3x-ui network — every clone / delete happens through
:class:`FakeXuiClient`, monkey-patched in place of ``panel.wizard.router.XuiClient``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from panel.auth import hash_password
from panel.dashboard.xui_client import XuiClientError
from panel.wizard.clone import (
    CloneEvent,
    CloneSpec,
    _clone_record_row,
    clone_country,
    orchestrator_clone_events,
)


# ===========================================================================
# Shared harness
# ===========================================================================
def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase5-clone-secret")
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
# FakeXuiClient — replaces panel.wizard.router.XuiClient for endpoint tests.
# ---------------------------------------------------------------------------
class FakeXuiClient:
    """Async stand-in matching :class:`XuiClient`'s constructor + methods.

    Behaviour knobs are class-level so the router's ``XuiClient(...)``
    constructor call internally appends to ``constructed`` and behavioural
    fields can be tweaked by individual tests via ``FakeXuiClient.<field> =``.
    """

    constructed: list[tuple[str, str, str]] = []
    closed: bool = False

    # Per-call behaviour. ``clone_inbound_results`` maps
    # country_code -> clone object dict; missing entries fall through to
    # ``clone_inbound_default`` (a single CloneResponse-shaped dict); for
    # configured failures use ``clone_inbound_raises[country_code]``.
    clone_inbound_default: dict | None = None
    clone_inbound_results: dict[str, dict] | None = None
    clone_inbound_raises: dict[str, type[Exception] | Exception] | None = None

    delete_inbound_raises: dict[int, type[Exception] | Exception] | None = None
    deleted: list[int] = []
    clone_calls: list[tuple[int, str, int, int]] = []  # (template_id, code, socks, public)

    def __init__(self, base_url: str, username: str, password: str, **kwargs) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        FakeXuiClient.constructed.append((base_url, username, password))

    async def login(self) -> None:  # pragma: no cover  router uses cached creds, no login call
        return None

    async def aclose(self) -> None:
        FakeXuiClient.closed = True

    async def clone_inbound(
        self,
        template_id: int,
        country: dict,
        socks_port: int,
        public_port: int,
    ) -> dict:
        code = country.get("code", "")
        FakeXuiClient.clone_calls.append((template_id, code, socks_port, public_port))
        raises = (FakeXuiClient.clone_inbound_raises or {}).get(code)
        if raises is not None:
            raise raises if isinstance(raises, Exception) else raises("fake clone_inbound failure")
        per_country = (FakeXuiClient.clone_inbound_results or {}).get(code)
        if per_country is not None:
            return per_country
        # Generate a deterministic id from the public_port so tests can assert on it.
        return FakeXuiClient.clone_inbound_default or {"id": public_port, "remark": "stub"}

    async def delete_inbound(self, inbound_id: int) -> dict:
        FakeXuiClient.deleted.append(inbound_id)
        raises = (FakeXuiClient.delete_inbound_raises or {}).get(inbound_id)
        if raises is not None:
            raise raises if isinstance(raises, Exception) else raises("fake delete failure")
        return {"success": True}


@pytest.fixture(autouse=True)
def _patch_xui_client(monkeypatch):
    """Reset FakeXuiClient class-level state and substitute it for the
    router-level ``XuiClient`` import."""
    FakeXuiClient.constructed = []
    FakeXuiClient.closed = False
    FakeXuiClient.clone_inbound_default = None
    FakeXuiClient.clone_inbound_results = None
    FakeXuiClient.clone_inbound_raises = None
    FakeXuiClient.delete_inbound_raises = None
    FakeXuiClient.deleted = []
    FakeXuiClient.clone_calls = []
    from panel.wizard import router as router_mod

    monkeypatch.setattr(router_mod, "XuiClient", FakeXuiClient)
    yield


# ---------------------------------------------------------------------------
# DB seeders for the clone endpoint tests.
# ---------------------------------------------------------------------------
def _seed_countries(codes: list[tuple[str, str, str]]) -> None:
    """Seed (code, name, flag) rows into the Country table."""
    from sqlalchemy.orm import Session

    from panel.db import get_engine, init_db
    from panel.models import Country

    init_db()
    with Session(get_engine()) as s:
        for code, name, flag in codes:
            existing = s.get(Country, {"code": code})
            if existing is not None:
                s.delete(existing)
                s.flush()
            s.add(Country(code=code, name=name, flag_emoji=flag, region="test", enabled=True))
        s.commit()


def _seed_port_assignments(rows: list[tuple[str, int, int]]) -> None:
    """Seed (country_code, socks_port, public_port) PortAssignment rows."""
    from sqlalchemy.orm import Session

    from panel.db import get_engine, init_db
    from panel.models import PortAssignment

    init_db()
    with Session(get_engine()) as s:
        for code, socks_port, public_port in rows:
            existing = s.get(PortAssignment, {"socks_port": socks_port})
            if existing is not None:
                s.delete(existing)
                s.flush()
            s.add(
                PortAssignment(
                    socks_port=socks_port,
                    public_port=public_port,
                    country_code=code,
                )
            )
        s.commit()


def _seed_xui_link() -> None:
    """Persist a XuiLink row so _async_get_xui_client can return the FakeXuiClient."""
    from sqlalchemy.orm import Session

    from panel.auth import encrypt_creds
    from panel.db import get_engine, init_db
    from panel.models import XuiLink

    init_db()
    token = encrypt_creds({"password": "panel-pass"})
    with Session(get_engine()) as s:
        existing = s.get(XuiLink, {"id": 1})
        if existing is not None:
            s.delete(existing)
            s.flush()
        s.add(
            XuiLink(
                id=1,
                base_url="http://127.0.0.1:2053/",
                username="admin",
                password_enc=token,
            )
        )
        s.commit()


def _advance_to_clone(
    client: TestClient,
    *,
    template_id: int = 17,
    countries: list[tuple[str, str, str]] | None = None,
    assignments: list[tuple[str, int, int]] | None = None,
) -> None:
    """Force-set the wizard row to the ``clone`` step with the template_id.

    Seeds the prerequisite Country + PortAssignment rows that the clone
    handler expects (the apply step would have done this in a real wizard run).
    """
    if countries is None:
        countries = [
            ("US", "United States", "🇺🇸"),
            ("DE", "Germany", "🇩🇪"),
            ("JP", "Japan", "🇯🇵"),
        ]
    if assignments is None:
        assignments = [
            ("DE", 11001, 31001),
            ("JP", 11002, 31002),
            ("US", 11003, 31003),
        ]
    _seed_countries(countries)
    _seed_port_assignments(assignments)
    _seed_xui_link()
    _set_wizard_step(
        client,
        "clone",
        step_data={"template": {"template_inbound_id": template_id}},
    )


def _parse_sse_stream(response) -> list[dict]:
    """Drain a TestClient SSE response into a list of decoded JSON dicts."""
    events: list[dict] = []
    for line in response.iter_lines():
        if not line or not line.startswith("data:"):
            continue
        try:
            events.append(json.loads(line[len("data:") :].strip()))
        except json.JSONDecodeError:  # pragma: no cover  defensive
            continue
    return events


# ===========================================================================
# Section 1 — pure CloneEvent / CloneSpec / _clone_record_row
# ===========================================================================
class TestCloneDataclasses:
    def test_clone_spec_is_frozen(self):
        spec = CloneSpec(
            country_code="US",
            socks_port=11002,
            public_port=31002,
            template_id=17,
            country={"code": "US", "name": "United States", "flag": "🇺🇸"},
        )
        from dataclasses import FrozenInstanceError

        with pytest.raises(FrozenInstanceError):
            spec.country_code = "DE"  # type: ignore[misc]

    def test_clone_event_as_dict_shape(self):
        ev = CloneEvent(
            country_code="US",
            status="cloned",
            progress=100,
            inbound_id=31002,
            message="cloned inbound 31002 for US",
        )
        d = ev.as_dict()
        assert d == {
            "step": "clone",
            "country": "US",
            "status": "cloned",
            "progress": 100,
            "inbound_id": 31002,
            "message": "cloned inbound 31002 for US",
        }

    def test_clone_event_failed_has_null_inbound_id(self):
        ev = CloneEvent(
            country_code="US",
            status="failed",
            progress=0,
            message="bad",
        )
        assert ev.inbound_id is None
        assert ev.as_dict()["inbound_id"] is None

    def test_clone_record_row_fields(self):
        spec = CloneSpec("US", 11002, 31002, 17, {"code": "US"})
        rec = _clone_record_row(inbound_id=31002, spec=spec, healthy=True)
        assert rec.inbound_id == 31002
        assert rec.country_code == "US"
        assert rec.public_port == 31002
        assert rec.socks_port == 11002
        assert rec.healthy is True


# ===========================================================================
# Section 2 — clone_country (single-spec, no DB)
# ===========================================================================
class _StubClient:
    """Async stand-in implementing just clone_inbound. Used by the pure
    clone_country tests below — they don't need the full FakeXuiClient
    surface since they don't exercise the router."""

    def __init__(
        self,
        *,
        clone_returns: dict | None = None,
        clone_raises: type[Exception] | Exception | None = None,
        delete_raises: type[Exception] | Exception | None = None,
    ) -> None:
        self.clone_returns = clone_returns if clone_returns is not None else {"id": 4242}
        self.clone_raises = clone_raises
        self.delete_raises = delete_raises
        self.deleted: list[int] = []

    async def clone_inbound(self, *, template_id, country, socks_port, public_port) -> dict:
        if self.clone_raises is not None:
            raise (
                self.clone_raises
                if isinstance(self.clone_raises, Exception)
                else self.clone_raises("x")
            )
        return self.clone_returns

    async def delete_inbound(self, inbound_id: int) -> dict:
        if self.delete_raises is not None:
            raise (
                self.delete_raises
                if isinstance(self.delete_raises, Exception)
                else self.delete_raises("x")
            )
        self.deleted.append(inbound_id)
        return {"success": True}


def _spec(
    code: str = "US", socks: int = 11002, public: int = 31002, template_id: int = 17
) -> CloneSpec:
    return CloneSpec(
        country_code=code,
        socks_port=socks,
        public_port=public,
        template_id=template_id,
        country={"code": code, "name": code, "flag": "X"},
    )


class TestCloneCountry:
    def test_happy_returns_cloned_event_with_inbound_id(self):
        client = _StubClient(clone_returns={"id": 31002, "remark": "stub"})
        ev = asyncio.run(clone_country(_spec(), client))  # type: ignore[arg-type]
        assert ev.status == "cloned"
        assert ev.inbound_id == 31002
        assert ev.progress == 100
        assert "cloned inbound 31002" in ev.message

    def test_xui_client_error_returns_failed_progress_0(self):
        client = _StubClient(clone_raises=XuiClientError("api failure"))
        ev = asyncio.run(clone_country(_spec(), client))  # type: ignore[arg-type]
        assert ev.status == "failed"
        assert ev.progress == 0
        assert ev.inbound_id is None
        assert "api failure" in ev.message
        assert "clone_inbound failed" in ev.message

    def test_generic_exception_returns_failed_progress_0(self):
        client = _StubClient(clone_raises=RuntimeError("transport boom"))
        ev = asyncio.run(clone_country(_spec(), client))  # type: ignore[arg-type]
        assert ev.status == "failed"
        assert ev.progress == 0
        assert "RuntimeError" in ev.message
        assert "transport boom" in ev.message

    def test_missing_id_in_clone_response_returns_failed_progress_50(self):
        client = _StubClient(clone_returns={"no_id_here": True})
        ev = asyncio.run(clone_country(_spec(), client))  # type: ignore[arg-type]
        assert ev.status == "failed"
        assert ev.progress == 50
        assert "missing id" in ev.message

    def test_non_int_id_in_clone_response_returns_failed_progress_50(self):
        client = _StubClient(clone_returns={"id": "not-an-int"})
        ev = asyncio.run(clone_country(_spec(), client))  # type: ignore[arg-type]
        assert ev.status == "failed"
        assert ev.progress == 50

    def test_negative_id_in_clone_response_returns_failed_progress_50(self):
        client = _StubClient(clone_returns={"id": -1})
        ev = asyncio.run(clone_country(_spec(), client))  # type: ignore[arg-type]
        assert ev.status == "failed"
        assert ev.progress == 50


# ===========================================================================
# Section 3 — orchestrator_clone_events (pure — no DB session)
# ===========================================================================
class TestOrchestratorCloneEvents:
    def test_happy_batch_returns_cloned_events_no_rollback(self):
        client = _StubClient(clone_returns={"id": 999})
        specs = [_spec("US"), _spec("DE"), _spec("JP")]
        events, rolled_back = asyncio.run(  # type: ignore[arg-type]
            orchestrator_clone_events(specs, client)  # type: ignore[arg-type]
        )
        assert len(events) == 3
        assert all(e.status == "cloned" for e in events)
        assert all(e.inbound_id == 999 for e in events)
        assert rolled_back == []

    def test_mid_list_failure_triggers_rollback(self):
        # The middle clone raises — the orchestrator should still attempt
        # all three, then roll back the two that succeeded (US + JP = ids
        # 999 — duplicate ids are fine for the rollback check).
        class _ConditionalClient:
            def __init__(self) -> None:
                self.deleted: list[int] = []

            async def clone_inbound(self, *, template_id, country, socks_port, public_port) -> dict:
                if country["code"] == "DE":
                    raise XuiClientError("DE clone failed")
                return {"id": public_port}

            async def delete_inbound(self, inbound_id: int) -> dict:
                self.deleted.append(inbound_id)
                return {"success": True}

        client = _ConditionalClient()
        specs = [_spec("US", public=31001), _spec("DE", public=31002), _spec("JP", public=31003)]
        events, rolled_back = asyncio.run(  # type: ignore[arg-type]
            orchestrator_clone_events(specs, client)  # type: ignore[arg-type]
        )
        statuses = [e.status for e in events]
        assert statuses == ["cloned", "failed", "cloned"]
        assert rolled_back == [31001, 31003]  # the two that succeeded were rolled back
        assert sorted(client.deleted) == [31001, 31003]

    def test_no_rollback_when_every_spec_succeeds(self):
        client = _StubClient(clone_returns={"id": 1})
        specs = [_spec("US"), _spec("DE")]
        events, rolled_back = asyncio.run(  # type: ignore[arg-type]
            orchestrator_clone_events(specs, client)  # type: ignore[arg-type]
        )
        assert rolled_back == []
        assert all(e.status == "cloned" for e in events)

    def test_rollback_tolerates_delete_inbound_failure(self):
        class _DeleteFailsClient:
            def __init__(self) -> None:
                self.deleted: list[int] = []

            async def clone_inbound(self, *, template_id, country, socks_port, public_port) -> dict:
                if country["code"] == "DE":
                    raise XuiClientError("DE clone failed")
                return {"id": public_port}

            async def delete_inbound(self, inbound_id: int) -> dict:
                raise RuntimeError("delete_inbound exploded")

        client = _DeleteFailsClient()
        specs = [_spec("US", public=31001), _spec("DE", public=31002)]
        events, rolled_back = asyncio.run(  # type: ignore[arg-type]
            orchestrator_clone_events(specs, client)  # type: ignore[arg-type]
        )
        # The DE clone failed → the US clone (id=31001) should have been
        # attempted for rollback, but the delete_inbound call raised. The
        # orchestrator should NOT abort — it logs the rollback fuss but STILL
        # records the inbound_id in rolled_back so the caller knows it tried
        # (the caller may need to manually delete the orphaned clone in the
        # 3x-ui panel).
        assert [e.status for e in events] == ["cloned", "failed"]
        assert rolled_back == [31001]

    def test_empty_specs_returns_empty_lists(self):
        client = _StubClient()
        events, rolled_back = asyncio.run(  # type: ignore[arg-type]
            orchestrator_clone_events([], client)  # type: ignore[arg-type]
        )
        assert events == []
        assert rolled_back == []


# ===========================================================================
# Section 4 — POST /api/wizard/clone SSE endpoint
# ===========================================================================
@pytest.fixture
def clone_client(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    _login(client)
    return client


class TestCloneEndpoint:
    def test_clone_happy_stream_advances_to_done_and_flips_wizard_completed(self, clone_client):
        _advance_to_clone(clone_client)
        # Default FakeXuiClient clone_inbound returns per-public-port ids.
        with clone_client.stream("POST", "/api/wizard/clone") as r:
            assert r.status_code == 200
            events = _parse_sse_stream(r)

        # Three working + three terminal + one summary = 7 records.
        assert len(events) == 7, events
        # Working records (every other one starting from index 0).
        assert events[0]["status"] == "working"
        assert events[0]["country"] == "DE"  # alphabetical sort
        assert events[2]["country"] == "JP"
        assert events[4]["country"] == "US"
        # Terminal cloned records (those following the working ones).
        assert events[1]["status"] == "cloned"
        assert events[3]["status"] == "cloned"
        assert events[5]["status"] == "cloned"
        # Summary.
        summary = events[-1]
        assert summary["country"] == "*"
        assert summary["status"] == "done"
        assert summary["message"] == "cloned 3 countries — wizard complete"
        assert summary["rolled_back"] == []
        assert summary["wizard_state"]["current_step"] == "done"
        assert summary["wizard_state"]["is_completed"] is True

        # Settings row + wizard row persisted the finalize flip.
        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import Settings, Wizard

        with Session(get_engine()) as s:
            settings = s.get(Settings, {"id": 1})
            assert settings is not None
            assert settings.wizard_completed is True
            w = s.get(Wizard, {"id": 1})
            assert w.current_step == "done"

    def test_clone_persists_clonerecord_rows(self, clone_client):
        _advance_to_clone(clone_client)
        with clone_client.stream("POST", "/api/wizard/clone") as r:
            assert r.status_code == 200
            _ = _parse_sse_stream(r)

        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import CloneRecord

        with Session(get_engine()) as s:
            rows = s.query(CloneRecord).all()
            # 3 clones → 3 rows, keyed by inbound_id (== public_port under the default stub).
            assert len(rows) == 3
            by_country = {r.country_code: r for r in rows}
            assert by_country["DE"].public_port == 31001
            assert by_country["DE"].socks_port == 11001
            assert by_country["US"].public_port == 31003
            assert by_country["JP"].public_port == 31002

    def test_clone_mid_failure_emits_rolled_back_and_leaves_step_at_clone(self, clone_client):
        _advance_to_clone(clone_client)
        # Make the DE clone fail — its public_port is 31001.
        FakeXuiClient.clone_inbound_raises = {"DE": XuiClientError("DE unreachable")}

        with clone_client.stream("POST", "/api/wizard/clone") as r:
            assert r.status_code == 200
            events = _parse_sse_stream(r)

        # Order: DE-working, DE-failed, JP-working, JP-cloned, US-working, US-cloned, summary.
        statuses = [(e["country"], e["status"]) for e in events if e["country"] != "*"]
        assert ("DE", "failed") in statuses
        assert ("JP", "cloned") in statuses
        assert ("US", "cloned") in statuses

        # The successful clones (JP=31002, US=31003) should have been deleted via the fake.
        assert sorted(FakeXuiClient.deleted) == [31002, 31003]

        summary = events[-1]
        assert summary["status"] == "failed"
        assert sorted(summary["rolled_back"]) == [31002, 31003]
        assert summary["wizard_state"]["current_step"] == "clone"  # NOT advanced to done
        assert summary["wizard_state"]["is_completed"] is False

        # Settings.wizard_completed should remain False on failure.
        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import CloneRecord, Settings

        with Session(get_engine()) as s:
            settings = s.get(Settings, {"id": 1})
            assert settings.wizard_completed is False
            # Rollback should also have removed the CloneRecord rows that were
            # persisted mid-batch for the rolled-back inbounds.
            rows = s.query(CloneRecord).all()
            assert rows == []

    def test_clone_out_of_order_returns_409(self, clone_client):
        # Wizard is freshly seeded (defaults to "countries"); no _advance_to_clone.
        r = clone_client.post("/api/wizard/clone")
        assert r.status_code == 409
        detail = r.json()["detail"]
        assert "wizard is on step" in detail
        assert "clone" in detail

    def test_clone_missing_template_returns_409(self, clone_client):
        # Advance to clone but without the template_inbound_id in step_data.
        _advance_to_clone(clone_client)
        _set_wizard_step(clone_client, "clone", step_data={})
        r = clone_client.post("/api/wizard/clone")
        assert r.status_code == 409
        assert "no template inbound selected" in r.json()["detail"]

    def test_clone_no_port_assignments_returns_409(self, clone_client):
        _advance_to_clone(clone_client)
        # Wipe PortAssignment rows.
        from sqlalchemy.orm import Session

        from panel.db import get_engine, init_db
        from panel.models import PortAssignment

        init_db()
        with Session(get_engine()) as s:
            for r in s.query(PortAssignment).all():
                s.delete(r)
            s.commit()

        r = clone_client.post("/api/wizard/clone")
        assert r.status_code == 409
        assert "no PortAssignment rows" in r.json()["detail"]

    def test_clone_no_cached_xui_creds_returns_409(self, clone_client):
        _advance_to_clone(clone_client)
        # Wipe the XuiLink row that _advance_to_clone seeded.
        from sqlalchemy.orm import Session

        from panel.db import get_engine, init_db
        from panel.models import XuiLink

        init_db()
        with Session(get_engine()) as s:
            link = s.get(XuiLink, {"id": 1})
            if link is not None:
                s.delete(link)
                s.commit()

        r = clone_client.post("/api/wizard/clone")
        assert r.status_code == 409
        assert "no 3x-ui credentials stored" in r.json()["detail"]

    def test_clone_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        # NOTE: no _login(client) call → not authenticated.
        _advance_to_clone(client)  # seed wizard + DB rows so the only failure is auth
        r = client.post("/api/wizard/clone")
        assert r.status_code == 401
        # Unauthenticated SSE → 401 happens before the stream starts (raise HTTPException
        # synchronously in the handler body, not inside event_stream) — no SSE parsing needed.


# ===========================================================================
# Section 5 — POST /api/wizard/xui-detect (Phase 4 leftover from 5d)
# ===========================================================================
class TestXuiDetect:
    def test_xui_detect_advances_to_xui_creds_with_no_3xui_present(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        _set_wizard_step(client, "xui_detect")

        # detect_xui probes localhost on common ports — on a CI box without 3x-ui
        # installed, it should return detected=False with a notes string.
        r = client.post("/api/wizard/xui-detect")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["current_step"] == "xui_creds"
        assert "detect" in body
        # Regardless of detection results, the wizard advances + step_data persists.
        assert isinstance(body["detect"]["detected"], bool)
        assert "candidates_probed" in body["detect"]
        assert "notes" in body["detect"]

    def test_xui_detect_out_of_order_returns_409(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        _login(client)
        # Wizard defaults to "countries" on a fresh DB → xui_detect step-guard should 409.
        r = client.post("/api/wizard/xui-detect")
        assert r.status_code == 409
        assert "wizard is on step" in r.json()["detail"]

    def test_xui_detect_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        client = _client(monkeypatch, tmp_path)
        # No _login → 401 before the handler body even runs the step-guard.
        r = client.post("/api/wizard/xui-detect")
        assert r.status_code == 401
