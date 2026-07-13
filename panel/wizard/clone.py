"""Clone-step orchestrator — mirrors the apply-step pattern but drives the
3x-ui inbound-clone engine instead of the Psiphon tunnel stack.

Phase 5 picks up where [`panel.wizard.apply`](apply.py) left off: after the
template step the wizard is on ``clone``. This module builds a list of
``CloneSpec`` rows from the persisted ``PortAssignment`` table + the
template inbound id (stored in ``Wizard.step_data["template"]``) and, for
each spec:

1. Calls ``await XuiClient.clone_inbound(template_id, country, socks_port,
   public_port)`` — which fetches the template inbound, rewrites its
   ``remark`` / ``port`` / ``streamSettings.outbound`` and POSTs the result
   to ``/panel/api/inbounds/add``.
2. Persists the new inbound id into a ``CloneRecord`` row keyed by inbound id.
3. Emits a ``CloneEvent`` describing the outcome (``cloned`` or ``failed``).

Rollback is the headline behaviour: if any clone in the batch fails, the
orchestrator continues iterating (so the SSE caller sees every attempt) but
returns a non-empty ``rolled_back`` list on the terminal summary. The router
handler then issues ``XuiClient.delete_inbound(inbound_id)`` for every
already-persisted ``CloneRecord`` in this batch — leaving the 3x-ui panel in
the same state it was in before the wizard's clone step ran.

The pure-function pieces (``CloneSpec``, ``CloneEvent``, ``_clone_record_row``)
have no I/O and are unit-tested directly; ``clone_country`` and
``orchestrator_clone_events`` are async I/O wrappers that the router-level
SSE handler drives.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from ..dashboard.xui_client import XuiClient, XuiClientError
from ..models import CloneRecord

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Specs + events (pure data, unit-tested directly).
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CloneSpec:
    """One clone request derived from a persisted PortAssignment row.

    ``country`` is the rich country dict (``{"code","name","flag"}``) — used by
    :meth:`XuiClient.clone_inbound` so the remark reads exactly
    ``[ 🇺🇸 United States ] :<public_port>``. ``template_id`` is the inbound id
    the user picked in the template step (stored in ``Wizard.step_data``).
    """

    country_code: str
    socks_port: int
    public_port: int
    template_id: int

    # Country dict (must include ``name`` and ``flag`` for the remark format)
    # — passed to ``XuiClient.clone_inbound`` verbatim.
    country: dict[str, Any]


@dataclass
class CloneEvent:
    """A single broadcast event emitted by :func:`clone_country`.

    ``status`` is one of ``"working"``, ``"cloned"``, ``"failed"``.
    ``inbound_id`` is the new inbound id on success (``None`` on failure or
    for the intermediate ``working`` record). ``message`` is a short human
    description suitable for the progress-bar UI.
    """

    country_code: str
    status: str
    progress: int
    inbound_id: int | None = None
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": "clone",
            "country": self.country_code,
            "status": self.status,
            "progress": int(self.progress),
            "inbound_id": self.inbound_id,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# Pure row factory — tested directly without touching SQLAlchemy session.
# ---------------------------------------------------------------------------
def _clone_record_row(
    *,
    inbound_id: int,
    spec: CloneSpec,
    healthy: bool = True,
) -> CloneRecord:
    """ORM row for a newly-cloned inbound keyed by its panel-assigned id.

    Caller must ``session.add(...)`` + commit it. ``healthy`` defaults to True
    because a successful clone_inbound call means 3x-ui accepted the payload
    and the inbound is enabled — actual probing of the underlying SOCKS5 port
    happens later (Phase 6 dashboard).
    """
    return CloneRecord(
        inbound_id=int(inbound_id),
        country_code=spec.country_code,
        public_port=int(spec.public_port),
        socks_port=int(spec.socks_port),
        healthy=bool(healthy),
    )


# ---------------------------------------------------------------------------
# Clone a single country — async I/O wrapper around XuiClient.clone_inbound.
# ---------------------------------------------------------------------------
async def clone_country(
    spec: CloneSpec,
    client: XuiClient,
    *,
    db: Session | None = None,
) -> CloneEvent:
    """Clone step for a single country.

    Steps:
    1. ``await client.clone_inbound(...)`` (which fetches the template inbound,
       rewrites remark/port/streamSettings.outbound, and POSTs the result).
    2. Parse the inbound id from the clone response (``{"id": <int>, ...}``).
    3. Persist a ``CloneRecord`` row to ``db`` if a session is supplied
       (the wizard's SSE handler always supplies one — the optional seam is
       there for tests and the dashboard's "re-clone" path).

    On failure this returns a ``failed`` event rather than raising — the
    orchestrator keeps going for the remaining countries, then rolls back.

    The ``progress`` field is *not* a global progress percentage here — it's
    the per-country terminal marker (100 on success, 0 on failure before the
    API call landed, 50 on a malformed clone response). The router renders a
    separate global ``working`` ``progress`` value across the batch.
    """
    try:
        clone_obj = await client.clone_inbound(
            template_id=spec.template_id,
            country=spec.country,
            socks_port=spec.socks_port,
            public_port=spec.public_port,
        )
    except XuiClientError as exc:
        return CloneEvent(
            country_code=spec.country_code,
            status="failed",
            progress=0,
            message=f"clone_inbound failed: {exc}",
        )
    except Exception as exc:  # noqa: BLE001  transport errors are varied
        return CloneEvent(
            country_code=spec.country_code,
            status="failed",
            progress=0,
            message=f"clone_inbound raised {type(exc).__name__}: {exc}",
        )

    # The clone response is the panel's persisted inbound object. Pull the id.
    inbound_id = clone_obj.get("id")
    if not isinstance(inbound_id, int) or inbound_id < 1:
        return CloneEvent(
            country_code=spec.country_code,
            status="failed",
            progress=50,
            message=f"clone response missing id: {clone_obj!r}",
        )

    if db is not None:
        # The SSE handler pre-persists the CloneRecord row so a crash mid-batch
        # still leaves a paper trail (rollback only happens at the very end on
        # the terminal-record path, removing the rows AND the upstream inbounds).
        existing = db.get(CloneRecord, {"inbound_id": inbound_id})
        if existing is None:
            db.add(_clone_record_row(inbound_id=inbound_id, spec=spec))
            db.commit()

    return CloneEvent(
        country_code=spec.country_code,
        status="cloned",
        progress=100,
        inbound_id=inbound_id,
        message=(
            f"cloned inbound {inbound_id} for {spec.country_code} "
            f"on public_port={spec.public_port} → socks={spec.socks_port}"
        ),
    )


# ---------------------------------------------------------------------------
# Batch orchestrator with rollback.
# ---------------------------------------------------------------------------
async def orchestrator_clone_events(
    specs: list[CloneSpec],
    client: XuiClient,
    *,
    db: Session | None = None,
    on_clone_begin: Any = None,
) -> tuple[list[CloneEvent], list[int]]:
    """Run :func:`clone_country` for each spec in order.

    Returns ``(events, rolled_back)`` where ``rolled_back`` is the list of
    inbound ids that were freshly-cloned in this batch and then deleted via
    ``client.delete_inbound`` because at least one spec in the batch failed.

    Semantics:
    * Every spec is attempted (we never short-circuit on the first failure)
      so the SSE caller has a full audit trail.
    * The router is expected to also stream out intermediate ``working``
      events; this helper only produces the per-country *terminal* events
      (one ``CloneEvent`` per spec).
    * ``on_clone_begin(spec, index, total)`` — optional callback used by the
      router to surface per-country "working" SSE records without having to
      wrap the inner coroutine. Kept simple (no async) so tests can stub it.
    * On any failure, the existing ``CloneRecord`` rows for the freshly-cloned
      inbounds in *this* batch are deleted from ``db`` (if provided) and the
      corresponding 3x-ui inbounds are deleted via the panel API. The rollback
      ``Exception`` paths are swallowed + logged — we'd rather surface the
      *original* clone failure to the user than crash the rollback loop mid-way
      and leave an inconsistent panel state.
    """
    events: list[CloneEvent] = []
    total = len(specs)
    fresh_inbound_ids: list[int] = []

    for i, spec in enumerate(specs):
        if on_clone_begin is not None:
            on_clone_begin(spec, i, total)
        event = await clone_country(spec, client, db=db)
        events.append(event)
        if event.status == "cloned" and event.inbound_id is not None:
            fresh_inbound_ids.append(event.inbound_id)

    rolled_back: list[int] = []
    if any(e.status != "cloned" for e in events) and fresh_inbound_ids:
        # Rollback: delete the freshly-cloned inbounds from 3x-ui and the
        # CloneRecord rows from db. Idempotent — a failed delete is logged
        # but doesn't abort the rollback loop.
        for inbound_id in fresh_inbound_ids:
            try:
                await client.delete_inbound(inbound_id)
            except Exception as exc:  # noqa: BLE001  keep rolling back
                _log.warning("rollback delete_inbound(%s) failed: %s", inbound_id, exc)
            if db is not None:
                row = db.get(CloneRecord, {"inbound_id": inbound_id})
                if row is not None:
                    db.delete(row)
                    db.commit()
            rolled_back.append(inbound_id)

    return events, rolled_back
