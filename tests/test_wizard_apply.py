"""Phase 4 wizard apply-step tests (step 4k).

Covers::

* :func:`panel.wizard.apply.compute_port_assignments` — pure function:
  ``one_per_country`` happy path, arity mismatch, ``shared_range`` happy.
* :func:`panel.wizard.apply.apply_country` — mocked ``write_config`` /
  ``start_unit`` / ``is_unit_active`` / ``health_probe`` so we exercise each
  failure branch without touching systemd or sockets.
* :func:`panel.wizard.apply.orchestrator_events` — multiple specs,
  including a failure mid-list (the loop MUST continue for remaining countries).
* ``POST /api/wizard/apply`` SSE endpoint via :class:`TestClient` — happy
  multi-country flow produces one ``working`` + one final-status record per
  country, plus a ``status="done"`` summary; advances the wizard to
  ``xui_detect``. Calling out of order returns 409 + an SSE error record.

The SSE flow tests use ``TestClient(stream=True)`` so the streaming response
chunks arrive incrementally; the assertions iterate ``response.iter_lines()``
and decode each ``data:`` record as JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from panel.auth import hash_password
from panel.psiphon import HealthProbeResult, PsiphonUnitError
from panel.wizard.apply import (
    ApplyEvent,
    PortAssignmentSpec,
    apply_country,
    compute_port_assignments,
    orchestrator_events,
)


# ===========================================================================
# Shared harness — mirrors tests/test_wizard.py with the env flushed + engine
# reset so each test gets an isolated panel.db.
# ===========================================================================
def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase4-apply-secret")
    monkeypatch.setenv("PSIPHON3XUI_PORT", "18001")
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")

    from panel import config, db

    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    db._engine = None  # noqa: SLF001
    db._session_factory = None  # noqa: SLF001


def _seed_settings(*, panel_port: int = 18001) -> None:
    from sqlalchemy.orm import Session

    from panel.db import get_engine, init_db
    from panel.models import Country, Settings

    init_db()
    engine = get_engine()
    with Session(engine) as s:
        if s.get(Settings, {"id": 1}) is not None:
            s.delete(s.get(Settings, {"id": 1}))
            s.flush()
        s.add(
            Settings(
                id=1,
                panel_port=panel_port,
                admin_user="admin",
                admin_pass_hash=hash_password("correct-horse-battery-staple"),
                wizard_completed=False,
            )
        )
        # Make sure the country table is non-empty so we can use "all" mode in
        # the SSE happy-flow test. Use a tiny set of three test countries.
        for c in s.query(Country).all():
            s.delete(c)
        s.flush()
        for code, name, flag in (
            ("US", "United States", "US"),
            ("DE", "Germany", "DE"),
            ("JP", "Japan", "JP"),
        ):
            s.add(
                Country(
                    code=code,
                    name=name,
                    flag_emoji=flag,
                    region="test",
                    enabled=True,
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
        "/auth/login", json={"user": "admin", "password": "correct-horse-battery-staple"}
    )
    assert r.status_code == 204, r.text


def _advance_to_apply(
    client: TestClient, *, mode: str = "specific", codes: list[str] | None = None
) -> None:
    """POST /countries then /ports so the wizard is on the 'apply' step."""
    body_codes = codes or ["US", "DE"]
    r = client.post(
        "/api/wizard/countries",
        json={"mode": mode, "codes": body_codes if mode == "specific" else []},
    )
    assert r.status_code == 200, r.text
    ports_body = {
        "socks": {"start": 11001, "end": 11100},
        "public": {"start": 31001, "end": 31200},
        "assignment": "one_per_country",
        "use_recommendation": False,
    }
    r = client.post("/api/wizard/ports", json=ports_body)
    assert r.status_code == 200, r.text
    state = r.json()
    assert state["current_step"] == "apply"


# ===========================================================================
# compute_port_assignments — pure function
# ===========================================================================
class TestComputePortAssignments:
    def test_one_per_country_happy(self):
        specs = compute_port_assignments(
            country_codes=["US", "DE", "JP"],
            socks_start=11001,
            socks_end=11200,
            public_start=31001,
            public_end=31200,
            assignment="one_per_country",
        )
        assert [(s.country_code, s.socks_port, s.public_port) for s in specs] == [
            ("US", 11001, 31001),
            ("DE", 11002, 31002),
            ("JP", 11003, 31003),
        ]

    def test_shared_range_happy(self):
        specs = compute_port_assignments(
            country_codes=["US", "DE", "JP"],
            socks_start=11001,
            socks_end=11200,
            public_start=31001,
            public_end=31001,  # only ONE public port — shared
            assignment="shared_range",
        )
        # Each country still gets its own SOCKS port (one tunnel per country).
        # All share the single public_port.
        assert [s.socks_port for s in specs] == [11001, 11002, 11003]
        assert [s.public_port for s in specs] == [31001, 31001, 31001]

    def test_one_per_country_arity_mismatch_raises(self):
        with pytest.raises(ValueError, match="public ports"):
            compute_port_assignments(
                country_codes=["US", "DE", "JP"],
                socks_start=11001,
                socks_end=11200,
                public_start=31001,
                public_end=31002,  # only 2 → 3 needed
                assignment="one_per_country",
            )

    def test_shared_range_insufficient_socks_raises(self):
        with pytest.raises(ValueError, match="distinct socks ports"):
            compute_port_assignments(
                country_codes=["US", "DE", "JP"],
                socks_start=11001,
                socks_end=11002,  # only 2 → 3 needed
                public_start=31001,
                public_end=31001,
                assignment="shared_range",
            )

    def test_invalid_assignment_raises(self):
        with pytest.raises(ValueError, match="assignment must be"):
            compute_port_assignments(
                country_codes=["US"],
                socks_start=11001,
                socks_end=11002,
                public_start=31001,
                public_end=31002,
                assignment="something_invalid",
            )

    def test_empty_codes_returns_empty(self):
        specs = compute_port_assignments(
            country_codes=[],
            socks_start=11001,
            socks_end=11200,
            public_start=31001,
            public_end=31200,
            assignment="one_per_country",
        )
        assert specs == []


# ===========================================================================
# apply_country — each failure path mocked.
# ===========================================================================
class _ApplyFakePsiphon:
    """Monkey-patches the ``panel.wizard.apply``-module surface used by
    ``apply_country`` (``write_config``, ``start_unit``, ``is_unit_active``,
    ``health_probe``). Construction captures the behaviour requested for one
    country; instances can be reused across countries via repeated calls.
    """

    def __init__(
        self,
        monkeypatch,
        *,
        write_raises: bool = False,
        start_raises: bool = False,
        is_active: bool = True,
        healthy: bool = True,
        healthy_detail: str = "ok",
    ) -> None:
        self.write_calls: list[tuple[str, int]] = []
        self.start_calls: list[str] = []
        self.is_active_calls: list[str] = []
        self.health_calls: list[int] = []
        self._write_raises = write_raises
        self._start_raises = start_raises
        self._is_active = is_active
        self._healthy = healthy
        self._healthy_detail = healthy_detail

        from panel.wizard import apply as apply_mod

        def _fake_write_config(country_code, socks_port, *, config_dir=None):
            self.write_calls.append((country_code, socks_port))
            if self._write_raises:
                raise PsiphonUnitError("simulated systemctl failure")
            return Path(f"/tmp/psiphon-fake/{country_code}.json")

        def _fake_start_unit(country_code):
            self.start_calls.append(country_code)
            if self._start_raises:
                raise PsiphonUnitError("simulated start failure")

        def _fake_is_unit_active(country_code):
            self.is_active_calls.append(country_code)
            return self._is_active

        def _fake_health_probe(socks_port, **kwargs):  # noqa: ANN001
            self.health_calls.append(socks_port)
            return HealthProbeResult(healthy=self._healthy, detail=self._healthy_detail)

        monkeypatch.setattr(apply_mod, "write_config", _fake_write_config)
        monkeypatch.setattr(apply_mod, "start_unit", _fake_start_unit)
        monkeypatch.setattr(apply_mod, "is_unit_active", _fake_is_unit_active)
        monkeypatch.setattr(apply_mod, "health_probe", _fake_health_probe)


class TestApplyCountry:
    def test_happy_path_emits_healthy_event(self, monkeypatch):
        fake = _ApplyFakePsiphon(monkeypatch)
        spec = PortAssignmentSpec(country_code="US", socks_port=11001, public_port=31001)
        event = apply_country(spec)
        assert event.country_code == "US"
        assert event.status == "healthy"
        assert event.progress == 100
        assert "11001" in event.message
        assert fake.write_calls == [("US", 11001)]
        assert fake.start_calls == ["US"]
        assert fake.is_active_calls == ["US"]
        assert fake.health_calls == [11001]

    def test_write_config_failure_returns_failed_not_raises(self, monkeypatch):
        _ApplyFakePsiphon(monkeypatch, write_raises=True)
        spec = PortAssignmentSpec(country_code="US", socks_port=11001, public_port=31001)
        # Must NOT raise — apply_country short-circuits to a failed ApplyEvent.
        event = apply_country(spec)
        assert event.status == "failed"
        assert event.progress == 0
        assert "config/unit start failed" in event.message

    def test_start_unit_failure_returns_failed(self, monkeypatch):
        _ApplyFakePsiphon(monkeypatch, start_raises=True)
        spec = PortAssignmentSpec(country_code="DE", socks_port=11002, public_port=31002)
        event = apply_country(spec)
        assert event.status == "failed"
        assert event.progress == 0
        assert "config/unit start failed" in event.message

    def test_is_active_false_returns_failed_50(self, monkeypatch):
        _ApplyFakePsiphon(monkeypatch, is_active=False)
        spec = PortAssignmentSpec(country_code="JP", socks_port=11003, public_port=31003)
        event = apply_country(spec)
        assert event.status == "failed"
        assert event.progress == 50
        assert "not active after start" in event.message

    def test_unhealthy_probe_returns_failed_75(self, monkeypatch):
        _ApplyFakePsiphon(monkeypatch, healthy=False, healthy_detail="listener refused")
        spec = PortAssignmentSpec(country_code="US", socks_port=11001, public_port=31001)
        event = apply_country(spec)
        assert event.status == "failed"
        assert event.progress == 75
        assert "listener refused" in event.message
        assert "SOCKS5" in event.message


# ===========================================================================
# orchestrator_events — list dispatch + independence
# ===========================================================================
class TestOrchestratorEvents:
    def test_three_specs_yields_three_events_in_order(self, monkeypatch):
        _ApplyFakePsiphon(monkeypatch)
        specs = [
            PortAssignmentSpec("US", 11001, 31001),
            PortAssignmentSpec("DE", 11002, 31002),
            PortAssignmentSpec("JP", 11003, 31003),
        ]
        events = orchestrator_events(specs)
        assert [e.country_code for e in events] == ["US", "DE", "JP"]
        assert all(e.status == "healthy" for e in events)

    def test_failure_mid_list_does_not_short_circuit(self, monkeypatch):
        # US: healthy; DE: write fails; JP: healthy — we must still process JP.
        fake = _ApplyFakePsiphon(monkeypatch)
        # Make write_config fail *only* for DE — use a side-effect-list.
        from panel.wizard import apply as apply_mod

        def _conditional_write(country_code, socks_port, *, config_dir=None):
            if country_code == "DE":
                raise PsiphonUnitError("simulated DE failure")
            fake.write_calls.append((country_code, socks_port))
            return Path(f"/tmp/psiphon-fake/{country_code}.json")

        monkeypatch.setattr(apply_mod, "write_config", _conditional_write)

        specs = [
            PortAssignmentSpec("US", 11001, 31001),
            PortAssignmentSpec("DE", 11002, 31002),
            PortAssignmentSpec("JP", 11003, 31003),
        ]
        events = orchestrator_events(specs)
        assert [e.status for e in events] == ["healthy", "failed", "healthy"]
        assert events[1].country_code == "DE"
        # US + JP were both passed in for write_config; DE went through the
        # fail branch before write_config recorded it.
        assert ("US", 11001) in fake.write_calls
        assert ("JP", 11003) in fake.write_calls
        # DE was NOT recorded on the success path.
        assert ("DE", 11002) not in fake.write_calls


# ===========================================================================
# apply_country / ApplyEvent as_dict shape contract
# ===========================================================================
def test_apply_event_as_dict_shape():
    e = ApplyEvent(country_code="US", status="working", progress=33, message="thinking")
    assert e.as_dict() == {
        "step": "apply",
        "country": "US",
        "status": "working",
        "progress": 33,
        "message": "thinking",
    }


# ===========================================================================
# POST /api/wizard/apply — SSE endpoint via TestClient(stream=True)
# ===========================================================================
def _parse_sse_stream(response) -> list[dict[str, Any]]:
    """Decode each ``data: <json>`` line into a dict list."""
    events: list[dict[str, Any]] = []
    for line in response.iter_lines():
        if not line or not line.startswith("data:"):
            continue
        payload = line.removeprefix("data:").strip()
        try:
            events.append(json.loads(payload))
        except json.JSONDecodeError:  # pragma: no cover
            continue
    return events


@pytest.fixture
def apply_client(monkeypatch, tmp_path):
    """A TestClient logged in + advanced to the 'apply' step.

    Also patches the panel.psiphon surface so apply_country succeeds without
    touching systemctl/sockets — defaults to a happy path. Tests that need a
    different outcome can re-monkeypatch through ``panel.wizard.apply``.
    """
    client = _client(monkeypatch, tmp_path)
    _login(client)
    _advance_to_apply(client)
    # Default-succeeding patches. Per-test overrides may monkeypatch again.
    _ApplyFakePsiphon(monkeypatch)
    return client


class TestApplyEndpoint:
    def test_apply_happy_stream_emits_per_country_then_done(self, apply_client):
        with apply_client.stream("POST", "/api/wizard/apply") as r:
            assert r.status_code == 200
            events = _parse_sse_stream(r)

        # Selected codes are US + DE (from _advance_to_apply).
        statuses_by_country = {}
        done_event = None
        for ev in events:
            if ev["country"] != "*":
                if ev["status"] != "working" and ev["status"] != "done":
                    statuses_by_country[ev["country"]] = ev["status"]
            else:
                assert ev["status"] == "done"
                done_event = ev
        # 2 countries → 2 final healthy events.
        assert statuses_by_country == {"US": "healthy", "DE": "healthy"}
        assert done_event is not None
        assert done_event["progress"] == 100
        assert "applied" in done_event["message"]
        assert done_event["wizard_state"]["current_step"] == "xui_detect"
        # And the wizard state was persisted on disk — re-fetching /api/wizard
        # reports xui_detect.
        ws = apply_client.get("/api/wizard").json()
        assert ws["current_step"] == "xui_detect"

    def test_apply_emits_working_then_terminal_for_each_country(self, apply_client):
        with apply_client.stream("POST", "/api/wizard/apply") as r:
            assert r.status_code == 200
            events = _parse_sse_stream(r)
        # Order should be: US working, US healthy, DE working, DE healthy, done.
        # Find the country-tagged events.
        country_seq = [(e["country"], e["status"]) for e in events if e["country"] != "*"]
        assert ("US", "working") in country_seq
        assert ("DE", "working") in country_seq
        assert ("US", "healthy") in country_seq
        assert ("DE", "healthy") in country_seq
        # working precedes the terminal event for that country.
        us_working_idx = country_seq.index(("US", "working"))
        us_healthy_idx = country_seq.index(("US", "healthy"))
        assert us_working_idx < us_healthy_idx

    def test_apply_persists_port_assignment_rows(self, apply_client):
        with apply_client.stream("POST", "/api/wizard/apply") as r:
            assert r.status_code == 200
            _ = list(r.iter_lines())
        # After apply, port_assignment table should have one row per country.
        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import PortAssignment

        with Session(get_engine()) as s:
            rows = s.query(PortAssignment).order_by(PortAssignment.country_code).all()
            assert {row.country_code for row in rows} == {"US", "DE"}
            socks_by_code = {row.country_code: row.socks_port for row in rows}
            # The countries step sorts chosen codes alphabetically (the
            # wizard's "specific" mode dedupes+sorts). DE comes first, so DE
            # gets the lowest socks port (11001); US gets the next one.
            assert socks_by_code["DE"] == 11001
            assert socks_by_code["US"] == 11002
            # Public ports follow the same offset alphabetically.
            public_by_code = {row.country_code: row.public_port for row in rows}
            assert public_by_code["DE"] == 31001
            assert public_by_code["US"] == 31002

    def test_apply_out_of_order_returns_409(self, apply_client):
        from sqlalchemy.orm import Session

        from panel.db import get_engine
        from panel.models import Wizard

        with Session(get_engine()) as s:
            w = s.get(Wizard, {"id": 1})
            assert w is not None
            w.current_step = "countries"
            s.commit()

        # The state-machine guard raises HTTPException(409) BEFORE the SSE
        # stream starts, so the response is a plain JSON 409 — no SSE records.
        r = apply_client.post("/api/wizard/apply")
        assert r.status_code == 409
        assert "wizard is on step" in r.json()["detail"]
        ws = apply_client.get("/api/wizard").json()
        assert ws["current_step"] == "countries"

    def test_apply_unauthenticated_returns_401(self, monkeypatch, tmp_path):
        # Fresh client, no login. Set the wizard row onto 'apply' step
        # directly so the state-machine gate passes — only get_current_user
        # should reject (401) on the request envelope.
        client = _client(monkeypatch, tmp_path)
        from sqlalchemy.orm import Session

        from panel.db import get_engine, init_db
        from panel.models import Wizard

        init_db()
        with Session(get_engine()) as s:
            s.add(Wizard(id=1, current_step="apply", step_data="{}"))
            s.commit()

        r = client.post("/api/wizard/apply")
        assert r.status_code == 401
