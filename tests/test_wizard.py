"""Wizard backend tests (Phase 3 — steps 1 + 2).

Covers::

* ``GET  /api/wizard``         — fresh state + 401 when no cookie
* ``POST /api/wizard/countries``— all/specific happy, validation, normalisation
* ``POST /api/wizard/ports``    — happy explicit + overlapping + panel-port
* state-machine guards          — rejects out-of-order jumps with 409
* smart-recommendation path     — ``use_recommendation:true`` auto-ranges

Setup helpers are intentionally duplicated from ``tests/test_auth.py`` rather
than shared (cross-test imports are brittle under pytest's assertion-rewriting
import hook).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from panel.auth import hash_password


# --------------------------------------------------------------------- helpers
def _isolated_env(tmp_path: Path, monkeypatch) -> None:
    """Point the panel at a throwaway SQLite + isolated session secret.

    Also flushes the cached modules so env changes win for the next import /
    engine creation.
    """
    monkeypatch.setenv("PSIPHON3XUI_DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setenv("PSIPHON3XUI_SESSION_SECRET", "phase3-test-secret")
    monkeypatch.setenv("PSIPHON3XUI_PORT", "18001")  # panel_port reserved slot
    monkeypatch.setenv("PSIPHON3XUI_CSRF_ENFORCE", "0")
    monkeypatch.setenv("PSIPHON3XUI_LOGIN_RATE_LIMIT", "1000")

    from panel import config, db

    config.get_settings.cache_clear()
    config.load_countries.cache_clear()
    # Drop the cached engine + session factory so the next request rebuilds
    # them against the new (per-test) db_path.
    db._engine = None  # noqa: SLF001
    db._session_factory = None  # noqa: SLF001


def _seed_settings(
    *,
    admin_user: str = "admin",
    admin_pass: str = "correct-horse-battery-staple",
    panel_port: int = 18001,
    wizard_completed: bool = False,
) -> None:
    """Insert (or replace) the singleton Settings row in the test panel.db.

    Assumes :func:`_isolated_env` has already cleared the cached engine so
    ``get_engine()`` reflects the new test db_path.
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
                panel_port=panel_port,
                admin_user=admin_user,
                admin_pass_hash=hash_password(admin_pass),
                wizard_completed=wizard_completed,
            )
        )
        s.commit()


def _client(monkeypatch, tmp_path) -> TestClient:
    """Throwaway TestClient bound to an isolated panel.db with a seeded
    Settings(id=1) row. Not logged in — call :func:`_login` to set the
    cookie in the client's jar (then every subsequent request is authed)."""
    _isolated_env(tmp_path, monkeypatch)
    _seed_settings()
    from panel.main import app

    return TestClient(app)


def _login(client: TestClient) -> None:
    """POST /auth/login with the seeded test creds; raises if it failed."""
    r = client.post(
        "/auth/login",
        json={"user": "admin", "password": "correct-horse-battery-staple"},
    )
    assert r.status_code == 204, r.text
    assert "psiphon3xui_session" in client.cookies


def _authed_client(monkeypatch, tmp_path) -> TestClient:
    """Isolated, seeded, AND logged-in TestClient — the common-case helper."""
    c = _client(monkeypatch, tmp_path)
    _login(c)
    return c


_VALID_CODES = ("US", "DE")  # both exist in config/countries.yaml (test_skeleton asserts)


# ----------------------------------------------------------- GET /api/wizard
def test_wizard_state_unauthenticated_returns_401(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.get("/api/wizard")
    assert r.status_code == 401, r.text


def test_wizard_state_fresh_starts_on_countries(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    r = client.get("/api/wizard")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_step"] == "countries"
    assert body["is_completed"] is False
    assert body["step_index"] == 0
    assert body["steps"][0] == "countries"
    assert "countries" in body["steps"] and "ports" in body["steps"]
    assert body["step_data"] == {}


# -------------------------------------------------------- POST /countries
def test_countries_all_mode_happy(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "all"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_step"] == "ports"
    payload = body["step_data"]["countries"]
    # All-mode selection must contain every yaml-listed country.
    from panel.config import load_countries

    expected = sorted(c.code for c in load_countries().countries)
    assert payload["mode"] == "all"
    assert payload["codes"] == expected
    assert payload["count"] == len(expected)


@pytest.mark.parametrize(
    "codes_in,expected",
    [
        (["US", "DE"], ["DE", "US"]),  # already upper, sorted
        (["us", "de"], ["DE", "US"]),  # lowercased → normalised to UPPER
        (["DE", "US"], ["DE", "US"]),  # reorder → sorted
        (["US", "us"], ["US"]),  # mixed-case dedupe → one entry
        (["US", "DE", "US"], ["DE", "US"]),  # dupe + already-listed
    ],
)
def test_countries_specific_mode_normalises_and_dedupes(
    tmp_path,
    monkeypatch,
    codes_in,
    expected,
):
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "specific", "codes": codes_in})
    assert r.status_code == 200, r.text
    payload = r.json()["step_data"]["countries"]
    assert payload["mode"] == "specific"
    assert payload["codes"] == expected
    assert payload["count"] == len(expected)


def test_countries_specific_empty_codes_returns_400(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "specific", "codes": []})
    assert r.status_code == 400, r.text


def test_countries_specific_unknown_codes_returns_400(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "specific", "codes": ["US", "ZZ"]})
    assert r.status_code == 400, r.text


def test_countries_all_with_codes_returns_400(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "all", "codes": ["US"]})
    assert r.status_code == 400, r.text


def test_countries_invalid_mode_returns_422(tmp_path, monkeypatch):
    """mode field_validator rejects unknown enum values → 422 from FastAPI."""
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "bogus"})
    assert r.status_code == 422, r.text


# ----------------------------------------------------------------- state machine
def test_wizard_rejects_ports_step_before_countries_done(tmp_path, monkeypatch):
    """Fresh wizard is on 'countries'; POSTing to /ports out of order → 409."""
    client = _authed_client(monkeypatch, tmp_path)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11009},
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 409, r.text
    assert "countries" in r.text  # the error mentions expected step


def test_wizard_cannot_jump_back_to_countries_after_ports_done(
    tmp_path,
    monkeypatch,
):
    """After /ports succeeds, wizard is on 'apply'; re-POSTing /countries → 409."""
    client = _authed_client(monkeypatch, tmp_path)
    # Step 1 — countries (2 selected for one_per_country port math).
    r1 = client.post(
        "/api/wizard/countries", json={"mode": "specific", "codes": list(_VALID_CODES)}
    )
    assert r1.status_code == 200, r1.text
    # Step 2 — ports (happy path).
    r2 = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11009},
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["current_step"] == "apply"
    # Now backward jump must be rejected.
    r3 = client.post(
        "/api/wizard/countries", json={"mode": "specific", "codes": list(_VALID_CODES)}
    )
    assert r3.status_code == 409, r3.text


# ----------------------------------------------------------------- POST /ports
def _submit_countries(client, codes=_VALID_CODES):
    r = client.post("/api/wizard/countries", json={"mode": "specific", "codes": list(codes)})
    assert r.status_code == 200, r.text
    return r


def test_ports_happy_explicit_ranges(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11009},
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_step"] == "apply"
    ports = body["step_data"]["ports"]
    assert ports["socks"] == {"start": 11000, "end": 11009}
    assert ports["public"] == {"start": 12000, "end": 12009}
    assert ports["assignment"] == "one_per_country"
    assert ports["use_recommendation"] is False


def test_ports_overlap_socks_public_returns_400(tmp_path, monkeypatch):
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            # 1085..1090 overlaps 1080..1090.
            "socks": {"start": 1080, "end": 1090},
            "public": {"start": 1085, "end": 1095},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 400, r.text
    assert "overlap" in r.text.lower()


def test_ports_includes_panel_port_returns_400(tmp_path, monkeypatch):
    """A range containing the panel's own listening port must be refused."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 18000, "end": 18010},  # 18001 ∈ range
            "public": {"start": 12000, "end": 12010},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 400, r.text
    assert "panel" in r.text.lower() or "18001" in r.text


def test_ports_one_per_country_requires_enough_ports(tmp_path, monkeypatch):
    """With 2 countries selected, a 1-port range cannot satisfy
    ``one_per_country`` — the validator must reject."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11000},  # size 1, need ≥ 2
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 400, r.text
    assert "one_per_country" in r.text or "socks" in r.text


def test_ports_shared_range_allows_smaller_range(tmp_path, monkeypatch):
    """``shared_range`` doesn't require one port per country — a 1-port
    range is fine. Front-end multiplexes inbound keys."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11000},  # size 1, OK for shared
            "public": {"start": 12000, "end": 12000},
            "assignment": "shared_range",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_step"] == "apply"
    assert body["step_data"]["ports"]["assignment"] == "shared_range"


def test_ports_invalid_assignment_returns_422(tmp_path, monkeypatch):
    """pydantic field_validator rejects unknown assignment → 422."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11009},
            "public": {"start": 12000, "end": 12009},
            "assignment": "bogus",
        },
    )
    assert r.status_code == 422, r.text


def test_ports_range_end_lt_start_returns_422(tmp_path, monkeypatch):
    """_Range.end validator rejects end < start."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 10999},  # end < start
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 422, r.text


def test_ports_busy_port_in_range_returns_400(tmp_path, monkeypatch):
    """If the OS reports a port in either range as already-listening, the
    wizard must reject with 400."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)
    from panel.wizard import ports as ports_module
    from panel.wizard import router as router_module

    busy = {11005}
    monkeypatch.setattr(ports_module, "_listening_ports_sync", lambda: busy)
    monkeypatch.setattr(router_module, "_listening_ports_sync", lambda: busy)

    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11009},  # 11005 ∈ busy
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 400, r.text
    assert "11005" in r.text or "listening" in r.text.lower()


def test_ports_smart_recommendation_path(tmp_path, monkeypatch):
    """``use_recommendation:true`` ignores the incoming ranges and returns
    computed ones that don't collide."""
    client = _authed_client(monkeypatch, tmp_path)
    _submit_countries(client)

    # Render busy-ports detection inert so the smart scanner has free room.
    from panel.wizard import ports as ports_module
    from panel.wizard import router as router_module

    empty: set[int] = set()
    monkeypatch.setattr(ports_module, "_listening_ports_sync", lambda: empty)
    monkeypatch.setattr(router_module, "_listening_ports_sync", lambda: empty)

    r = client.post(
        "/api/wizard/ports",
        json={
            # These ranges should be IGNORED in favour of the auto-recs.
            "socks": {"start": 1, "end": 1},
            "public": {"start": 1, "end": 1},
            "assignment": "one_per_country",
            "use_recommendation": True,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_step"] == "apply"
    ports = body["step_data"]["ports"]
    assert ports["use_recommendation"] is True

    # Recommendations are well-formed, in-range, and mutually non-overlapping.
    socks = ports["socks"]
    public = ports["public"]
    assert 1024 <= socks["start"] <= socks["end"] <= 65535
    assert 1024 <= public["start"] <= public["end"] <= 65535
    # Non-overlapping ⟺ one ends strictly before the other begins.
    non_overlap = socks["end"] < public["start"] or public["end"] < socks["start"]
    assert non_overlap, (
        f"smart-recommendation should produce non-overlapping socks={socks} public={public}"
    )
    # Panel port (18001) must not sneak into either range.
    assert not (socks["start"] <= 18001 <= socks["end"])
    assert not (public["start"] <= 18001 <= public["end"])
    # one_per_country with 2 selected countries → each range must have ≥ 2 ports.
    assert socks["end"] - socks["start"] + 1 >= 2
    assert public["end"] - public["start"] + 1 >= 2


# ------------------------------------------------------- other auth-side
def test_countries_endpoint_unauthenticated_returns_401(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.post("/api/wizard/countries", json={"mode": "all"})
    assert r.status_code == 401, r.text


def test_ports_endpoint_unauthenticated_returns_401(tmp_path, monkeypatch):
    client = _client(monkeypatch, tmp_path)
    r = client.post(
        "/api/wizard/ports",
        json={
            "socks": {"start": 11000, "end": 11009},
            "public": {"start": 12000, "end": 12009},
            "assignment": "one_per_country",
        },
    )
    assert r.status_code == 401, r.text
