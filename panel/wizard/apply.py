"""Apply-step orchestrator — writes per-country Psiphon configs and brings
up the templated tunnel units.

Phase 4 scope (ROADMAP §7 Phase 4 step 3): for each selected country,

1. compute the per-country SOCKS port + public port assignment (from the
   wizard's "ports" step),
2. write ``<config_dir>/<CODE>.json``,
3. start the templated ``psiphon-tunnel@<CODE>.service`` unit,
4. health-probe its SOCKS5 listener,
5. persist a :class:`panel.models.PortAssignment` row for the country,
6. emit a progress event for the wizard's SSE stream.

Helpers are intentionally side-effect-themed pair functions — the router's
async generator drives the per-country loop, calling us one step at a time.
This keeps the orchestrator unit-testable (each helper throws on failure) and
keeps the SSE transport concerns in the router.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ..models import PortAssignment
from ..psiphon import (
    HealthProbeResult,
    PsiphonCredentialError,
    PsiphonUnitError,
    health_probe,
    is_unit_active,
    start_unit,
    write_config,
)

# ---------------------------------------------------------------------------
# Per-country port assignment
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortAssignmentSpec:
    """Pre-resolved per-country SOCKS + public ports."""

    country_code: str
    socks_port: int
    public_port: int


def compute_port_assignments(
    *,
    country_codes: list[str],
    socks_start: int,
    socks_end: int,
    public_start: int,
    public_end: int,
    assignment: str,
) -> list[PortAssignmentSpec]:
    """Build the per-country port-mapping from the wizard's ports step.

    Returns an ordered list of :class:`PortAssignmentSpec` matching the input
    ``country_codes`` order. Raises ``ValueError`` on malformed assignment
    semantically (the wizard has already validated the numeric ranges against
    overlap / panel-port / busy-port, so we mostly check the ``assignment``
    label and arity here).
    """
    if assignment not in ("one_per_country", "shared_range"):
        raise ValueError(
            f"assignment must be 'one_per_country' or 'shared_range', got {assignment!r}"
        )

    socks_size = socks_end - socks_start + 1
    public_size = public_end - public_start + 1
    n = len(country_codes)
    if n <= 0:
        return []

    if assignment == "one_per_country":
        if socks_size < n:
            raise ValueError(f"one_per_country needs {n} socks ports, range has {socks_size}")
        if public_size < n:
            raise ValueError(f"one_per_country needs {n} public ports, range has {public_size}")
        return [
            PortAssignmentSpec(
                country_code=code,
                socks_port=socks_start + i,
                public_port=public_start + i,
            )
            for i, code in enumerate(country_codes)
        ]

    # shared — every country uses the same socks + public port (front-end
    # multiplexes inbound keys; only one Psiphon tunnel process is needed
    # but service-wise we still run one per country so each gets its own
    # EgressRegion bound to a different tunnel-core). Sharing the SOCKS port
    # across multiple tunnels would conflict, so for `shared_range` we cycle
    # the socks ports within the range and reuse the shared public port.
    if socks_size < n:
        raise ValueError(
            f"shared_range still needs {n} distinct socks ports (one tunnel per "
            f"country), range has {socks_size}"
        )
    return [
        PortAssignmentSpec(
            country_code=code,
            socks_port=socks_start + i,
            public_port=public_start,  # all countries share the single public port
        )
        for i, code in enumerate(country_codes)
    ]


# ---------------------------------------------------------------------------
# Per-country apply step
# ---------------------------------------------------------------------------


@dataclass
class ApplyEvent:
    """A single broadcast event emitted by :func:`apply_country`.

    ``status`` is one of ``"working"``, ``"started"``, ``"healthy"``,
    ``"failed"``. ``message`` is a short human description suitable for the
    progress-bar UI.
    """

    country_code: str
    status: str
    progress: int
    message: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": "apply",
            "country": self.country_code,
            "status": self.status,
            "progress": int(self.progress),
            "message": self.message,
        }


def _initial_unit_start(country_code: str, socks_port: int, config_dir=None) -> dict:
    """Write the per-country config and start its templated unit. Returns
    metadata describing the work; raises :class:`PsiphonUnitError` on failure.
    """
    path = write_config(country_code, socks_port, config_dir=config_dir)
    start_unit(country_code)
    return {"config_path": str(path)}


def _port_assignment_row(spec: PortAssignmentSpec) -> PortAssignment:
    """ORM row for the country / socks / public / associations pair. Caller
    must ``session.add(...)`` + commit it."""
    return PortAssignment(
        socks_port=int(spec.socks_port),
        public_port=int(spec.public_port),
        country_code=spec.country_code,
    )


def apply_country(
    spec: PortAssignmentSpec,
    *,
    config_dir=None,
    health_probe_factory: Any = None,
) -> ApplyEvent:
    """Apply step for a single country.

    Steps:
    1. write the config file
    2. start the templated systemd unit
    3. probe the SOCKS5 listener

    Returns one ``ApplyEvent`` describing the *final* status of this country.
    Failure at any step short-circuits with a ``failed`` event — does NOT raise
    (the wizard's SSE stream should keep going for the remaining countries).
    """
    try:
        _initial_unit_start(spec.country_code, spec.socks_port, config_dir=config_dir)
    except PsiphonCredentialError as exc:
        # Hotfix #14 (Phase 23): render_config fast-failed because the
        # operator hasn't yet populated the four Psiphon-Inc upstream
        # credentials in panel.env. Surface as a failed ApplyEvent carrying
        # the actionable message — DON'T bubble so the SSE stream keeps
        # going for the remaining countries.
        return ApplyEvent(
            country_code=spec.country_code,
            status="failed",
            progress=0,
            message=f"config/unit start failed: PsiphonCredentialError: {exc}",
        )
    except (PsiphonUnitError, OSError, ValueError) as exc:
        return ApplyEvent(
            country_code=spec.country_code,
            status="failed",
            progress=0,
            message=f"config/unit start failed: {type(exc).__name__}: {exc}",
        )

    if not is_unit_active(spec.country_code):
        return ApplyEvent(
            country_code=spec.country_code,
            status="failed",
            progress=50,
            message=f"unit psiphon-tunnel@{spec.country_code}.service not active after start",
        )

    # Hotfix #11 (Bug #2): Psiphon's local SOCKS5 listener takes 5–30 seconds
    # to actually bind *after* `systemctl start` reports the unit "active"
    # (the ExecStart-ed process must bootstrap, reach the upstream Psiphon root
    # servers, handshake, and only then open its local listener). A single
    # eager probe therefore hits `Connection refused` → `failed` even on a
    # healthy tunnel — which in turn blocks the wizard's post-apply
    # auto-enable path (Bug #5, gated on `event.status == "healthy"`). We
    # retry with bounded backoff so a transient ConnectionRefused doesn't
    # fail the whole apply. `health_probe_factory` is honoured every
    # iteration so unit tests that stub the probe stay deterministic (their
    # stub returns healthy on the first call → loop exits immediately).
    deadline = time.monotonic() + 30.0
    probe: HealthProbeResult = health_probe(
        spec.socks_port,
        _sock_factory=health_probe_factory,
    )
    while not probe.healthy and time.monotonic() < deadline:
        time.sleep(1.0)
        probe = health_probe(spec.socks_port, _sock_factory=health_probe_factory)
    if not probe.healthy:
        return ApplyEvent(
            country_code=spec.country_code,
            status="failed",
            progress=75,
            message=f"SOCKS5 health probe on 127.0.0.1:{spec.socks_port} failed after retry: {probe.detail}",
        )

    return ApplyEvent(
        country_code=spec.country_code,
        status="healthy",
        progress=100,
        message=f"psiphon-tunnel@{spec.country_code} up on 127.0.0.1:{spec.socks_port}",
    )


def orchestrator_events(
    specs: list[PortAssignmentSpec],
    *,
    config_dir=None,
    health_probe_factory: Any = None,
) -> list[ApplyEvent]:
    """Drive :func:`apply_country` over a list of pre-resolved specs.

    Returns one ``ApplyEvent`` per spec. The router wraps each event as an SSE
    record; here we keep the helpers synchronous so manifest actions are
    deterministic and the unit tests don't have to monkey-patch asyncio.
    """
    return [
        apply_country(spec, config_dir=config_dir, health_probe_factory=health_probe_factory)
        for spec in specs
    ]


__all__ = [
    "ApplyEvent",
    "PortAssignmentSpec",
    "apply_country",
    "compute_port_assignments",
    "orchestrator_events",
]
