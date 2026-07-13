"""FastAPI router for the multi-step wizard (Phase 3 + Phase 4).

Phase 3 added the ``GET /api/wizard`` snapshot, ``POST /countries`` (step 1)
and ``POST /ports`` (step 2). Phase 4 adds:

* ``POST /apply`` — Server-Sent Events stream driving per-country config
  writing + templated-unit spawn + SOCKS5 health probe. Advances the
  wizard to the ``xui_detect`` step on completion.
* ``POST /xui-creds`` — accept the user-supplied 3x-ui credentials, attempt
  login via :class:`panel.dashboard.xui_client.XuiClient`, encrypt-cache
  them in the ``XuiLink`` singleton row. Advances the wizard to
  ``template``.
* ``GET /inbounds`` — list inbounds from the cached 3x-ui session as a
  simplified ``[{id, remark, port, protocol}]`` projection.
* ``POST /clone-template`` — store the chosen template inbound id and advance
  to ``clone``. Phase 5 picks up at the clone step.

State is persisted in the singleton :class:`panel.models.Wizard` row.
Each POST handler:

1. Validates the body against the schema for its step.
2. Stores the validated payload into ``Wizard.step_data`` under that step's
   key and advances ``Wizard.current_step`` to the next step label.
3. Returns the new wizard state (same shape as ``GET /api/wizard``) on
   success, or 400 with a structured ``{detail: .., errors: [..]}`` body
   on validation failure.

All handlers require a valid session cookie (see
:func:`panel.auth.get_current_user`).
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from ..auth import decrypt_creds, encrypt_creds, get_current_user
from ..config import get_settings, load_countries
from ..dashboard.xui_client import XuiClient, XuiClientError
from ..db import get_db
from ..models import (
    CloneRecord,
    Country,
    PortAssignment,
    Settings,
    Wizard,
    XuiLink,
)
from .apply import (
    ApplyEvent,
    apply_country,
    compute_port_assignments,
)
from .clone import (
    CloneEvent,
    CloneSpec,
    clone_country,
)
from .ports import (
    NoFreeRangeError,
    PortRange,
    PortRangeError,
    WizardPortsInput,
    _listening_ports_sync,
    recommend_port_range,
    validate_port_ranges,
)
from .steps import STEPS, WizardStep, normalize_step, step_index
from .xui_detect import XuiDetectResult, detect_xui

router = APIRouter()


# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------
class CountriesBody(BaseModel):
    """``POST /api/wizard/countries`` body.

    ``mode == "all"`` selects every country in ``countries.yaml`` and
    requires ``codes`` to be empty (or omitted). ``mode == "specific"``
    selects a subset; ``codes`` must be non-empty and each must be one of
    the supported 2-letter codes. Duplicate codes are silently deduped.
    """

    mode: str = Field(..., description='"all" or "specific"')
    codes: list[str] = Field(default_factory=list, description="ISO 3166-1 alpha-2")

    @field_validator("mode")
    @classmethod
    def _mode_is_known(cls, v: str) -> str:
        if v not in ("all", "specific"):
            raise ValueError("mode must be 'all' or 'specific'")
        return v


class _Range(BaseModel):
    start: int = Field(..., ge=1, le=65535)
    end: int = Field(..., ge=1, le=65535)

    @field_validator("end")
    @classmethod
    def _end_ge_start(cls, end: int, info) -> int:
        # info.data is the partially-validated body so far (incl. ``start``).
        start = info.data.get("start") if info.data else None
        if start is not None and end < start:
            raise ValueError("end must be >= start")
        return end

    def to_range(self) -> PortRange:
        return PortRange(start=self.start, end=self.end)


class PortsBody(BaseModel):
    """``POST /api/wizard/ports`` body — see ROADMAP §7 Phase 3."""

    socks: _Range
    public: _Range
    assignment: str = Field(..., description='"one_per_country" or "shared_range"')
    use_recommendation: bool = False

    @field_validator("assignment")
    @classmethod
    def _known_assignment(cls, v: str) -> str:
        if v not in ("one_per_country", "shared_range"):
            raise ValueError("assignment must be 'one_per_country' or 'shared_range'")
        return v


class BackBody(BaseModel):
    """``POST /api/wizard/back`` body — Hotfix #4 (Bug #7).

    Omitting ``target`` (or passing ``None``) jumps back to the immediately
    preceding step. Passing an explicit earlier step label skips directly to
    it. Both forms are gated by the rules in :func:`submit_back`:
    terminal steps (``clone``/``done``) refuse, and backing THROUGH ``apply``
    refuses because apply created per-country PortAssignment rows (with
    ``socks_port`` as a PRIMARY KEY) + systemd units + tunnel configs that
    can only be torn down via the dashboard's per-country delete flow.
    """

    target: str | None = Field(
        default=None, description="Optional earlier step label to jump back to"
    )


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def _get_wizard_row(db: Session) -> Wizard:
    """Return the singleton Wizard row, creating it with defaults if absent."""
    row = db.get(Wizard, {"id": 1})
    if row is None:
        row = Wizard(id=1, current_step=WizardStep.COUNTRIES.value, step_data="{}")
        db.add(row)
        db.flush()
    return row


def _read_step_data(row: Wizard) -> dict[str, Any]:
    """Decode the wizard's step_data JSON into a Python dict (best-effort)."""
    if not row.step_data:
        return {}
    try:
        data = json.loads(row.step_data)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _write_step_data(row: Wizard, key: WizardStep, payload: Any, db: Session) -> None:
    """Merge *payload* into the wizard's step_data under *key*'s label, commit."""
    data = _read_step_data(row)
    data[key.value] = payload
    row.step_data = json.dumps(data, separators=(",", ":"))
    db.add(row)
    db.commit()
    db.refresh(row)


def _get_num_selected_countries(row: Wizard) -> int:
    """Count the selected-countries persisted by an earlier 'countries' step.

    Returns 0 if no countries step has been completed yet, which makes the
    ports step a no-op-prerequisite when called out of order — but the wizard
    state machine rejects such out-of-order calls earlier via ``_require_step``.
    """
    payload = _read_step_data(row).get(WizardStep.COUNTRIES.value)
    if not isinstance(payload, dict):
        return 0
    mode = payload.get("mode")
    if mode == "all":
        return len(load_countries().countries)
    codes = payload.get("codes") or []
    return len(codes)


def _current_step(row: Wizard) -> WizardStep:
    return normalize_step(row.current_step)


def _require_step(row: Wizard, expected: WizardStep) -> None:
    """Raise 409 if the wizard is not currently on *expected*.

    The wizard is a strict forward state machine — handlers only accept
    input for the step the wizard is currently on. The front-end can read
    the current step via ``GET /api/wizard`` and present the matching UI.
    """
    current = _current_step(row)
    if current != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"wizard is on step '{current.value}', expected '{expected.value}'"),
        )


# ---------------------------------------------------------------------------
# GET / — current wizard state
# ---------------------------------------------------------------------------
@router.get("", response_model=None)
def wizard_state(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Return the wizard's current step + all stored step payloads.

    Shape::

        {
          "current_step": "countries",
          "is_completed": false,
          "steps": ["countries", "ports", ...],
          "step_index": 0,
          "step_data": { "countries": {...}, ... }
        }
    """
    row = _get_wizard_row(db)
    current = _current_step(row)
    return {
        "current_step": current.value,
        "is_completed": current == WizardStep.DONE,
        "steps": [s.value for s in STEPS],
        "step_index": step_index(current),
        "step_data": _read_step_data(row),
    }


# ---------------------------------------------------------------------------
# POST /countries — step 1
# ---------------------------------------------------------------------------
@router.post("/countries", status_code=status.HTTP_200_OK)
def submit_countries(
    body: CountriesBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Validate the country-picker selection and store it, advancing to *ports*."""
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.COUNTRIES)

    supported = load_countries()
    by_code = {c.code for c in supported.countries}

    # Normalise: dedupe, case-fold codes to UPPER, drop empty strings.
    codes_seen = sorted({(c or "").upper() for c in body.codes if c})
    if body.mode == "specific":
        if not codes_seen:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="mode='specific' requires at least one code in 'codes'",
            )
        unknown = [c for c in codes_seen if c not in by_code]
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"codes not supported by countries.yaml: {unknown}. "
                    f"Add them to config/countries.yaml or pick from {sorted(by_code)[:10]}…"
                ),
            )
        chosen = codes_seen
    else:  # body.mode == "all"
        if codes_seen:
            # Standardise on a single contract: "all" means all from yaml.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="mode='all' must not include 'codes' (use 'specific' for a subset)",
            )
        chosen = sorted(by_code)

    payload = {"mode": body.mode, "codes": chosen, "count": len(chosen)}
    _write_step_data(row, WizardStep.COUNTRIES, payload, db)

    # Advance state machine.
    row.current_step = "ports"
    db.add(row)
    db.commit()
    db.refresh(row)

    return wizard_state_row(row)


# ---------------------------------------------------------------------------
# POST /ports — step 2
# ---------------------------------------------------------------------------
@router.post("/ports", status_code=status.HTTP_200_OK)
def submit_ports(
    body: PortsBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Validate the port ranges (or compute smart recs) and advance to *apply*."""
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.PORTS)

    settings = db.get(Settings, {"id": 1})
    panel_port = settings.panel_port if settings else get_settings().port

    num_countries = _get_num_selected_countries(row)
    if num_countries <= 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="wizard expects a previous /countries step before /ports",
        )

    # Probe the OS once for busy listening ports (best-effort: never block the
    # wizard if /proc is silent or ss is missing — the validation relaxes its
    # "ports not already bound" check in that case).
    try:
        busy = _listening_ports_sync()
    except Exception:  # noqa: BLE001  test-monkeypatched scans can raise
        busy = set()

    # Smart-recommendation path: ignore incoming ranges, return computed ones.
    if body.use_recommendation:
        try:
            socks_range = recommend_port_range(
                num_countries,
                busy=busy,
                extra_reserved={panel_port},
            )
            public_range = recommend_port_range(
                num_countries,
                busy=busy,
                extra_reserved={panel_port} | set(range(socks_range.start, socks_range.end + 1)),
            )
        except NoFreeRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        validated = WizardPortsInput(
            socks=socks_range,
            public=public_range,
            assignment=body.assignment,
            use_recommendation=True,
        )
    else:
        try:
            validated = validate_port_ranges(
                socks=body.socks.to_range(),
                public=body.public.to_range(),
                assignment=body.assignment,
                num_countries=num_countries,
                panel_port=panel_port,
                busy=busy,
            )
        except PortRangeError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

    _write_step_data(row, WizardStep.PORTS, validated.as_dict(), db)

    row.current_step = "apply"
    db.add(row)
    db.commit()
    db.refresh(row)

    return wizard_state_row(row)


# ---------------------------------------------------------------------------
# Convenience: caller-shared state snapshot (avoids a second DB round-trip)
# ---------------------------------------------------------------------------
def wizard_state_row(row: Wizard) -> dict:
    """Return the same shape as ``GET /api/wizard`` from an already-loaded row."""
    return {
        "current_step": normalize_step(row.current_step).value,
        "is_completed": normalize_step(row.current_step) == WizardStep.DONE,
        "steps": [s.value for s in STEPS],
        "step_index": step_index(normalize_step(row.current_step)),
        "step_data": _read_step_data(row),
    }


# ---------------------------------------------------------------------------
# POST /back — Hotfix #4 (Bug #7): explicit backward-navigation endpoint.
#
# The wizard is forward-only by design — step handlers refuse out-of-order
# input via _require_step so step_data stays internally consistent. Earlier
# this meant the operator could not re-edit a previously-submitted step from
# the SPA — the only escape hatch was to start over (re-seed the panel.db
# Wizard row). Bug #7 surfaced that UX: the SPA drew a back button on every
# step but backed it with a no-op stub that toasted a confusing "the wizard
# is forward-only…" message.
#
# This endpoint is the constrained escape hatch. It allows jumps back to
# any step strictly before the apply step is reached, OR jumps that stay
# within the post-apply, pre-terminal run (template/xui_creds/xui_detect
# back-and-forth is harmless). The two hard refusals are:
#
#   (1) the *terminal* steps — `clone` (already producing cloned inbounds)
#       and `done` (wizard_completed flipped) — refuse 409 because their
#       side effects already exist; rolling them back requires the
#       dashboard's per-country teardown (delete_country stops the unit +
#       deletes the CloneRecord + PortAssignment + Country rows) — not a
#       wizard concern.
#
#   (2) backing *through* the apply step (i.e. current step already passed
#       apply, but the operator wants to step into countries/ports) —
#       refuse 409 because apply is the source of `PortAssignment` rows
#       (socks_port is a PRIMARY KEY — see panel/models.py:65-73) plus
#       the on-disk psiphon config.json + the running systemd unit. Going
#       back to ports/countries implies re-running apply, which would hit
#       the uniqueness conflict on the per-country socks_port + leave stale
#       units behind. Re-running from countries requires teardown first.
#
# Permitted backward jumps just flip `wizard.current_step`. Already-stored
# step_data for the new current step is preserved — the SPA re-renders the
# form pre-filled from the snapshot returned here so the operator edits
# incrementally without losing prior input. Re-submitting that step's POST
# (e.g. POST /api/wizard/countries) re-runs its validator and overwrites
# the stored payload in place.
# ---------------------------------------------------------------------------
@router.post("/back", status_code=status.HTTP_200_OK)
def submit_back(
    body: BackBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Jump backward within the wizard's safe-zone.

    Returns the updated wizard-state snapshot (same shape as ``GET /api/wizard``)
    on success, or 409 with a structured ``detail`` message explaining why the
    requested jump is forbidden.
    """
    row = _get_wizard_row(db)
    current = _current_step(row)

    # (1) terminal steps (clone/done) — side effects only undoable via dashboard.
    if current in (WizardStep.CLONE, WizardStep.DONE):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"cannot step back from terminal step '{current.value}' — "
                "per-country tunnels/clone-records must be torn down via the "
                "dashboard (delete a country or use Reapply) before re-running "
                "the wizard"
            ),
        )

    # Resolve target: explicit label, else the immediately-preceding step.
    if body.target is None:
        idx = step_index(current)
        if idx == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="already on the first step — nothing to step back to",
            )
        target = STEPS[idx - 1]
    else:
        try:
            target = normalize_step(body.target)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

    target_idx = step_index(target)
    current_idx = step_index(current)

    # target must be strictly earlier than current.
    if target_idx >= current_idx:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"target step '{target.value}' is not earlier than the "
                f"current step '{current.value}' — back may only navigate "
                "to a step strictly before the current one"
            ),
        )

    # (2) refuse to back THROUGH apply — apply created PortAssignment rows
    # (socks_port PRIMARY KEY) + systemd units + tunnel configs that the
    # dashboard's per-country teardown must undo before a re-run is safe.
    apply_idx = step_index(WizardStep.APPLY)
    if target_idx < apply_idx < current_idx:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "cannot back through 'apply' — apply created per-country "
                "PortAssignment rows (socks_port PRIMARY KEY) + tunnel "
                "configs + systemd units; tearing them down requires the "
                "dashboard's per-country Delete flow. Re-running the wizard "
                "from countries/ports would hit a uniqueness conflict on "
                "socks_port"
            ),
        )

    row.current_step = target.value
    db.add(row)
    db.commit()
    db.refresh(row)
    return wizard_state_row(row)


# ===========================================================================
# Phase 4 wizard handlers (steps 3–6: apply, xui-creds, inbounds, clone-template)
#
# The apply step is the longest — it drives a per-country loop that writes the
# Psiphon config, spawns the templated systemd unit, then SOCKS5-probes the
# listener. Each iteration emits an SSE record so the front-end can render a
# live progress bar. xui-creds/inbounds/clone-template are next: they fetch
# the user-supplied 3x-ui credentials, list inbounds through them, and let
# the user pick the template inbound that Phase 5 will clone for each country.
# ===========================================================================


# ---------------------------------------------------------------------------
# Helper — selected country codes pulled from the wizard's "countries" step.
# ---------------------------------------------------------------------------
def _get_selected_country_codes(row: Wizard) -> list[str]:
    """Return the sorted list of country codes persisted by the *countries* step.

    Empty list if the countries step hasn't been completed (the state machine
    rejects that path earlier via ``_require_step``).
    """
    payload = _read_step_data(row).get(WizardStep.COUNTRIES.value)
    if not isinstance(payload, dict):
        return []
    if payload.get("mode") == "all":
        return sorted({c.code for c in load_countries().countries})
    codes = payload.get("codes") or []
    return sorted({str(c).upper() for c in codes if c})


def _get_ports_payload(row: Wizard) -> dict[str, Any]:
    """Return the persisted ports step payload as a dict, or ``{}``."""
    payload = _read_step_data(row).get(WizardStep.PORTS.value)
    return payload if isinstance(payload, dict) else {}


# ---------------------------------------------------------------------------
# Pydantic bodies for the Phase 4 endpoints.
# ---------------------------------------------------------------------------
class XuiCredsBody(BaseModel):
    """``POST /api/wizard/xui-creds`` body.

    The user supplies the 3x-ui base URL + login credentials. We attempt login
    synchronously and cache the credentials encrypted at rest in the singleton
    :class:`XuiLink` row.
    """

    base_url: str = Field(..., description="3x-ui base URL (e.g. http://127.0.0.1:2053/)")
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class CloneTemplateBody(BaseModel):
    """``POST /api/wizard/clone-template`` body.

    The user picks one inbound from the ``GET /inbounds`` list; Phase 5 will
    clone it once per country.
    """

    template_inbound_id: int = Field(..., ge=1)


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------
def _sse(event: dict[str, Any]) -> str:
    """Serialise *event* as a single Server-Sent-Events record.

    Each record is ``data: <json>\\n\\n``. We do not emit an explicit event
    ``id`` / ``event:`` line — the front-end ignores them anyway, and keeping
    the wire shape tiny makes the tests readable.
    """
    return f"data: {json.dumps(event)}\n\n"


async def _async_get_xui_client(db: Session) -> XuiClient | None:
    """Build a *logged-in* :class:`XuiClient` from the cached XuiLink row.

    Mirrors ``panel.dashboard.router._async_get_xui_client``: read the cached
    XuiLink, decrypt the password, construct a XuiClient, then AWAIT
    ``client.login()`` before returning so every caller (``GET /inbounds`` at
    step *template*, ``POST /clone`` at step *clone*) gets a client whose
    ``/3x-ui`` session cookie + CSRF token are already populated and ready to
    hit ``{base}panel/api/inbounds/...``. Caller must ``aclose()`` it.

    Hotfix #6 (Bug #8): the previous version of this helper returned the
    FRESH ``XuiClient`` WITHOUT calling ``client.login()`` — the cached 3x-ui
    session lived only inside the closed ``XuiClient`` instance used by
    ``POST /xui-creds`` to verify the operator's credentials at step 5 (that
    client's ``aclose()`` dropped the session). Then ``GET /inbounds`` at
    step *template* would call ``client.list_inbound_summaries()`` on the
    un-authed client → no ``3x-ui`` session cookie + ``self._csrf is None``
    → the ``X-CSRF-Token`` header wasn't sent → 3x-ui's ``/panel/api/...``
    middleware returned HTTP 404 (its SPA 404 fallback for unauthed API
    routes — a 404 rather than a 401 because the path segment behind the
    secret ``webBasePath`` is hidden from un-authed callers). The operator
    reported this as ``3x-ui list_inbounds failed: list_inbounds: HTTP
    404:`` at wizard step 6.

    Returning ``None`` on any login failure (no cached creds, decryption
    failure, ``XuiClientError`` from login, or any other exception) lets the
    public callers surface a clean 409 ``"no 3x-ui credentials stored —
    POST /api/wizard/xui-creds first to cache 3x-ui credentials"`` (the
    pattern they already had) instead of a confusing 502 mid-list-flow. If
    the operator's creds have gone stale (3x-ui restart, password rotate,
    csrf-key rotation) the wizard's next visit to /inbounds will see the
    None return and the operator will be prompted to re-enter creds at
    step 5.
    """
    link = db.get(XuiLink, {"id": 1})
    if link is None:
        return None
    creds = decrypt_creds(link.password_enc) if link.password_enc else None
    password = creds.get("password") if creds else None
    if not password:
        return None
    client = XuiClient(
        base_url=link.base_url,
        username=link.username,
        password=password,
    )
    try:
        await client.login()
    except Exception:  # noqa: BLE001  any login failure → stale creds → None
        # Stale credentials (3x-ui rotated the password / restarted /
        # rotated its CSRF signing key) — disclose nothing to the caller,
        # return None so the public endpoint surfaces the 409 "no creds"
        # message and the operator is re-routed to step 5 to re-enter them.
        await client.aclose()
        return None
    return client


# ---------------------------------------------------------------------------
# POST /apply — Server-Sent Events stream driving per-country config write +
# unit start + SOCKS5 health probe (Phase 4 step 3).
# ---------------------------------------------------------------------------
@router.post("/apply")
async def submit_apply(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> StreamingResponse:
    """Apply step — emit one SSE record per country then a final summary.

    The handler does not require a body: the per-country port assignments come
    from the wizard's ``ports`` step_data. It must be on the ``apply`` step
    when called; on success it advances the wizard to ``xui_detect``.

    Each yielded chunk is one SSE record shaped like::

        data: {"step": "apply", "country": "US",
               "status": "healthy", "progress": 100, "message": "..."}\\n\\n

    The final record has ``country="*"``, ``status="done"`` and an ``events``
    array summarising every per-country outcome (useful for replays/tests).
    """
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.APPLY)

    codes = _get_selected_country_codes(row)
    if not codes:
        # Defensive: the state machine guarantees a prior /countries step so
        # this only fires on manual DB corruption.
        raise HTTPException(  # pragma: no cover  defensive branch
            status_code=status.HTTP_409_CONFLICT,
            detail="no countries selected — re-run the wizard's /countries step",
        )

    ports = _get_ports_payload(row)
    try:
        specs = compute_port_assignments(
            country_codes=codes,
            socks_start=int(ports["socks"]["start"]),
            socks_end=int(ports["socks"]["end"]),
            public_start=int(ports["public"]["start"]),
            public_end=int(ports["public"]["end"]),
            assignment=str(ports["assignment"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"ports step_data invalid: {exc}",
        ) from exc

    async def event_stream():
        # Persist the per-country port assignment rows BEFORE the apply loop so
        # they're queryable even if a tunnel later crashes. Tunnel failure is
        # recorded in the per-country SSE event and does NOT roll the row back.
        for spec in specs:
            existing = db.get(PortAssignment, {"socks_port": spec.socks_port})
            if existing is not None:
                continue
            db.add(
                PortAssignment(
                    socks_port=int(spec.socks_port),
                    public_port=int(spec.public_port),
                    country_code=spec.country_code,
                )
            )
        db.commit()

        events: list[ApplyEvent] = []
        total = len(specs)
        for i, spec in enumerate(specs):
            # Emit a "working" record first so the front-end can paint the row
            # in flight before the (potentially slow) health probe resolves.
            yield _sse(
                {
                    "step": "apply",
                    "country": spec.country_code,
                    "status": "working",
                    "progress": int(100 * i / max(total, 1)),
                    "message": f"starting psiphon-tunnel@{spec.country_code}…",
                }
            )
            event = apply_country(spec)
            events.append(event)
            yield _sse(event.as_dict())

            # Hotfix #9 (Bug #3): auto-enable on a healthy apply. The dashboard
            # grid reads Country.enabled to render the per-country toggle checkbox;
            # under Hotfix #8 it stayed False after apply (the model default),
            # so the operator saw rows whose tunnels were actually running but
            # whose checkbox was unchecked — and the first dashboard Enable click
            # then re-fired start_unit, surfacing Bug #2. A country whose tunnel
            # just came up healthy must be marked enabled here.
            if event.status == "healthy":
                country_row = db.get(Country, spec.country_code)
                if country_row is not None and not country_row.enabled:
                    country_row.enabled = True
                    db.add(country_row)

        # Advance the wizard to xui_detect.
        row.current_step = WizardStep.XUI_DETECT.value
        db.add(row)
        db.commit()
        db.refresh(row)

        summary: dict[str, Any] = {
            "step": "apply",
            "country": "*",
            "status": "done",
            "progress": 100,
            "message": f"applied {total} countries",
            "events": [e.as_dict() for e in events],
            "wizard_state": wizard_state_row(row),
        }
        yield _sse(summary)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
    )


# ---------------------------------------------------------------------------
# POST /xui-detect — probe the local host for a running 3x-ui panel and
# advance the wizard from *xui_detect* to *xui_creds*. The result (a dict-
# serialised ``XuiDetectResult``) is returned so the front-end can pre-fill the
# xui-creds form with the detected base_url, or display the candidate URLs
# that were probed so the user can paste one manually.
# ---------------------------------------------------------------------------
@router.post("/xui-detect", status_code=status.HTTP_200_OK)
async def submit_xui_detect(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Probe the local host for a 3x-ui login page + canonical x-ui.db file.

    Always advances the wizard to the ``xui_creds`` step (detection is a
    convenience — even if the probe comes up empty, the user can still
    type a manual ``base_url`` in the next step). The persisted
    ``step_data["xui_detect"]`` carries the full probe result so a re-query
    of ``GET /api/wizard`` can replay it for the UI without re-running the
    probe.
    """
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.XUI_DETECT)

    try:
        result = await detect_xui()
    except Exception as exc:  # noqa: BLE001  network probe — tolerate anything
        result = XuiDetectResult(
            detected=False,
            base_url="",
            db_path="",
            candidates_probed=[],
            notes=f"detect_xui raised {type(exc).__name__}: {exc}",
        )

    _write_step_data(
        row,
        WizardStep.XUI_DETECT,
        {
            "detected": result.detected,
            "base_url": result.base_url,
            "db_path": result.db_path,
            "candidates_probed": list(result.candidates_probed or []),
            "notes": result.notes,
        },
        db,
    )
    row.current_step = WizardStep.XUI_CREDS.value
    db.add(row)
    db.commit()
    db.refresh(row)

    return {
        **wizard_state_row(row),
        "detect": {
            "detected": result.detected,
            "base_url": result.base_url,
            "db_path": result.db_path,
            "candidates_probed": list(result.candidates_probed or []),
            "notes": result.notes,
        },
    }


# ---------------------------------------------------------------------------
# POST /xui-creds — accept 3x-ui base URL + credentials, attempt login, cache
# encrypted creds in the XuiLink singleton, advance the wizard to *template*.
# ---------------------------------------------------------------------------
@router.post("/xui-creds", status_code=status.HTTP_200_OK)
async def submit_xui_creds(
    body: XuiCredsBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Store 3x-ui credentials (encrypted) after verifying login works.

    On a successful login, persists ``XuiLink(id=1, base_url, username,
    password_enc)`` where ``password_enc`` is an ``itsdangerous`` signed token.
    On failure, returns 400 with the underlying 3x-ui error message so the
    wizard UI can display it.
    """
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.XUI_CREDS)

    try:
        client = XuiClient(body.base_url, body.username, body.password)
        await client.login()
        await client.aclose()
    except XuiClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"3x-ui login failed: {exc}",
        ) from exc
    except Exception as exc:  # noqa: BLE001  httpx network errors are varied
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"3x-ui unreachable: {type(exc).__name__}: {exc}",
        ) from exc

    creds_token = encrypt_creds({"password": body.password})

    link = db.get(XuiLink, {"id": 1})
    if link is None:
        link = XuiLink(
            id=1, base_url=body.base_url, username=body.username, password_enc=creds_token
        )
        db.add(link)
    else:
        link.base_url = body.base_url
        link.username = body.username
        link.password_enc = creds_token
    db.commit()
    db.refresh(link)

    _write_step_data(
        row,
        WizardStep.XUI_CREDS,
        {"base_url": body.base_url, "username": body.username},
        db,
    )
    row.current_step = WizardStep.TEMPLATE.value
    db.add(row)
    db.commit()
    db.refresh(row)

    return wizard_state_row(row)


# ---------------------------------------------------------------------------
# GET /inbounds — list inbounds from the cached 3x-ui session as a simplified
# ``[{id, remark, port, protocol, tag}]`` projection. (Phase 4 step 4 helper.)
# ---------------------------------------------------------------------------
@router.get("/inbounds", status_code=status.HTTP_200_OK)
async def list_inbounds(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Return all 3x-ui inbounds visible to the cached credentials.

    The wizard is expected to be on the ``template`` step when this is called
    (the front-end fetches this list right after ``POST /xui-creds`` succeeds
    so the user can pick which inbound to clone per country). We do NOT enforce
    the step here — the inbounds list is also useful for debugging downstream
    of the wizard, so we allow it from any step. Returns 409 if credentials
    have not been stored yet.
    """
    row = _get_wizard_row(db)
    # We permit ``GET /inbounds`` from any wizard step ≥ xui_creds. Refusing
    # earlier steps protects against confusion before creds exist.
    if step_index(_current_step(row)) < step_index(WizardStep.XUI_CREDS):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"wizard is on step '{_current_step(row).value}'; "
                "POST /api/wizard/xui-creds first to cache 3x-ui credentials"
            ),
        )

    client = await _async_get_xui_client(db)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no 3x-ui credentials stored (POST /api/wizard/xui-creds first)",
        )
    try:
        summaries = await client.list_inbound_summaries()
    except XuiClientError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"3x-ui list_inbounds failed: {exc}",
        ) from exc
    finally:
        await client.aclose()

    return {
        "inbounds": [
            {
                "id": s.id,
                "port": s.port,
                "protocol": s.protocol,
                "remark": s.remark,
                "tag": s.tag,
            }
            for s in summaries
        ],
        "count": len(summaries),
    }


# ---------------------------------------------------------------------------
# POST /clone-template — store the chosen template inbound id and advance to
# the *clone* step. Phase 5 reads this back and clones the template once per
# country.
# ---------------------------------------------------------------------------
@router.post("/clone-template", status_code=status.HTTP_200_OK)
def submit_clone_template(
    body: CloneTemplateBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Persist the user-selected template inbound id; advance to ``clone``."""
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.TEMPLATE)

    _write_step_data(
        row,
        WizardStep.TEMPLATE,
        {"template_inbound_id": int(body.template_inbound_id)},
        db,
    )
    row.current_step = WizardStep.CLONE.value
    db.add(row)
    db.commit()
    db.refresh(row)

    return wizard_state_row(row)


# ---------------------------------------------------------------------------
# Helpers for the clone step — template id + CloneSpec list pulled from the
# wizard's step_data + the PortAssignment rows persisted during apply.
# ---------------------------------------------------------------------------
def _get_template_id(row: Wizard) -> int | None:
    """Return the outbound-template inbound id persisted in step_data, or None.

    Stored at ``step_data["template"]["template_inbound_id"]`` by the
    ``POST /api/wizard/clone-template`` handler.
    """
    payload = _read_step_data(row).get(WizardStep.TEMPLATE.value)
    if not isinstance(payload, dict):
        return None
    raw = payload.get("template_inbound_id")
    if isinstance(raw, bool):  # bool is a subclass of int — reject it
        return None
    if not isinstance(raw, int) or raw < 1:
        return None
    return int(raw)


def _build_clone_specs(row: Wizard, db: Session) -> list[CloneSpec]:
    """Build one ``CloneSpec`` per persisted PortAssignment row, sorted by code.

    The country dict for each spec comes from the ``Country`` ORM row (we need
    its ``code`` + ``name`` + ``flag`` so the remark renders exactly
    ``[ 🇺🇸 United States ] :<public_port>``). Specs are sorted by country
    code for a stable progress-bar order, matching the alphabetical sort the
    apply step established.
    """
    assignments = db.query(PortAssignment).all()
    if not assignments:
        return []
    country_rows: dict[str, Country] = {c.code: c for c in db.query(Country).all()}
    specs: list[CloneSpec] = []
    for row_pa in sorted(assignments, key=lambda a: a.country_code):
        country_row = country_rows.get(row_pa.country_code)
        if country_row is None:
            # Should be impossible (apply step wrote PortAssignment rows only
            # for countries that exist), but be defensive — skip rather than
            # crash mid-wizard.
            continue
        country = {
            "code": country_row.code,
            "name": country_row.name,
            "flag": country_row.flag_emoji or "",
        }
        specs.append(
            CloneSpec(
                country_code=row_pa.country_code,
                socks_port=row_pa.socks_port,
                public_port=row_pa.public_port,
                template_id=0,  # filled in by the handler after _get_template_id
                country=country,
            )
        )
    return specs


# ---------------------------------------------------------------------------
# POST /clone — Phase 5 wizard finalize: clone the template inbound once per
# country via the persisted XuiClient, persist CloneRecord rows, run rollback
# if any clone in the batch fails, then advance the wizard step to *done* and
# flip Settings.wizard_completed. Server-Sent Events stream (same shape as
# /apply).
# ---------------------------------------------------------------------------
@router.post("/clone")
async def submit_clone(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> StreamingResponse:
    """Clone step — emit one SSE record per country then a final summary.

    The handler does not take a body — the template_id is sourced from the
    ``template`` step_data and the per-country spec list is sourced from the
    ``PortAssignment`` rows persisted during the apply step.

    Each per-country chunk is two records: a ``working`` SSE record (so the
    UI can paint the row in flight) and a terminal ``cloned`` / ``failed``
    record. After the last country, a final summary record carries the full
    ``events`` array + a ``rolled_back`` array (the list of inbound ids that
    were freshly-cloned and then deleted via the panel API because some
    clone in this batch failed; empty on full success).

    On terminal success only, this handler flips ``Settings.wizard_completed``
    to True and advances ``Wizard.current_step`` to ``done`` (the next login
    will see the management dashboard instead of the wizard).
    """
    row = _get_wizard_row(db)
    _require_step(row, WizardStep.CLONE)

    template_id = _get_template_id(row)
    if not template_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no template inbound selected (POST /api/wizard/clone-template first)",
        )

    specs = _build_clone_specs(row, db)
    if not specs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no PortAssignment rows — re-run the wizard's /apply step",
        )

    # Fill in the template_id on every spec (kept separate from _build_clone_specs
    # so the helper remains a pure row→spec function standalone in tests).
    specs = [
        CloneSpec(s.country_code, s.socks_port, s.public_port, template_id, s.country)
        for s in specs
    ]

    client = await _async_get_xui_client(db)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no 3x-ui credentials stored (POST /api/wizard/xui-creds first)",
        )

    async def _rollback_on_failure(
        events: list[CloneEvent],
        db: Session,
        client: XuiClient,
    ) -> tuple[list[CloneEvent], list[int]]:
        """Rollback freshly-cloned inbounds if any event in *events* failed.

        Mirrors the rollback piece of :func:`orchestrator_clone_events` —
        kept inline here (rather than calling the orchestrator) so the
        per-country clone calls + working SSE records stay inline in
        ``event_stream`` above for ordering clarity.

        Returns ``(events, rolled_back)`` where ``rolled_back`` is the list
        of inbound ids deleted from 3x-ui (delete_inbound failures are
        logged via appended pseudo-events with country="*" so the caller
        can surface them in the summary).
        """
        fresh_ids = [e.inbound_id for e in events if e.status == "cloned" and e.inbound_id]
        if not fresh_ids or not any(e.status != "cloned" for e in events):
            return events, []
        rolled_back: list[int] = []
        for inbound_id in fresh_ids:
            try:
                await client.delete_inbound(inbound_id)
            except Exception as exc:  # noqa: BLE001  keep rolling back
                events.append(
                    CloneEvent(
                        country_code="*",
                        status="rolled_back",
                        progress=0,
                        inbound_id=inbound_id,
                        message=f"rollback delete_inbound({inbound_id}) failed: {type(exc).__name__}: {exc}",
                    )
                )
                continue
            rolled_back.append(inbound_id)
            # Remove the CloneRecord row we persisted mid-batch.
            rec = db.get(CloneRecord, {"inbound_id": inbound_id})
            if rec is not None:
                db.delete(rec)
                db.commit()
        return events, rolled_back

    async def event_stream():
        try:
            events: list[CloneEvent] = []
            total = len(specs)

            # Emit a "working" SSE record before each clone attempt, then the
            # terminal record from clone_country. The orchestrator_clone_events
            # helper runs the rollback at the end — but we drive the per-spec
            # loop inline here so the working records stay ordered naturally
            # (no sync-callback hack to surface intermediate SSE records).
            for i, spec in enumerate(specs):
                yield _sse(
                    {
                        "step": "clone",
                        "country": spec.country_code,
                        "status": "working",
                        "progress": int(100 * i / max(total, 1)),
                        "message": (
                            f"cloning template {spec.template_id} for "
                            f"{spec.country_code} → public_port={spec.public_port}…"
                        ),
                    }
                )
                # Inline per-country clone — we use the orchestrator helper
                # only for the rollback loop after this batch finishes.
                events.append(await clone_country(spec, client, db=db))
                yield _sse(events[-1].as_dict())

            # Drive rollback through the orchestrator's rollback helper — it
            # deletes the freshly-cloned inbounds via delete_inbound and removes
            # the CloneRecord rows we persisted mid-batch. rolled_back is the
            # list of inbound ids that were successfully deleted (the user
            # would otherwise see orphaned clones in their 3x-ui panel).
            _, rolled_back = await _rollback_on_failure(
                events=events,
                db=db,
                client=client,
            )

            success = not rolled_back and all(e.status == "cloned" for e in events)
            if success:
                row.current_step = WizardStep.DONE.value
                db.add(row)
                settings = db.get(Settings, {"id": 1})
                if settings is not None:
                    settings.wizard_completed = True
                    db.add(settings)
                db.commit()
                db.refresh(row)
                summary_message = f"cloned {total} countries — wizard complete"
            else:
                cloned_n = sum(1 for e in events if e.status == "cloned")
                summary_message = (
                    f"cloned {cloned_n}/{total} countries — "
                    f"{len(rolled_back)} clone(s) rolled back via delete_inbound"
                )

            summary: dict[str, Any] = {
                "step": "clone",
                "country": "*",
                "status": "done" if success else "failed",
                "progress": 100,
                "message": summary_message,
                "events": [e.as_dict() for e in events],
                "rolled_back": rolled_back,
                "wizard_state": wizard_state_row(row),
            }
            yield _sse(summary)
        finally:
            await client.aclose()

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
    )


# ---------------------------------------------------------------------------
# Convenience export for tests.
# ---------------------------------------------------------------------------
__all__ = [
    "CloneEvent",
    "CloneSpec",
    "CloneTemplateBody",
    "PortAssignment",
    "XuiCredsBody",
    "router",
    "wizard_state_row",
]
