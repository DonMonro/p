"""Smart port-range recommender + range validator for the wizard.

The wizard's "ports" step asks the user for two ranges:

- ``socks``  — used for the per-country local SOCKS5 ports Psiphon listens on
                (range of `127.0.0.1:<port>`, one port per selected country).
- ``public`` — used for the public-facing 3x-ui inbound listener ports that
                route to those SOCKS ports.

Smart recommendation is "give me the smallest contiguous free range of the
right width." We probe listening TCP ports via ``/proc/net/tcp`` (fast,
parsed directly via stdlib) and supplement with ``ss -tln`` when /proc is
unavailable. The panel process runs as a dedicated system user; ``/proc``
read access is enough — we don't need full ss PID resolution.

Validation rejects:
- non-ascending ranges,
- range outside [1, 65535],
- overlap with the panel's own listening port (so we never recommend the port
  we ourselves use),
- overlap between ``socks`` and ``public`` ranges,
- ``one_per_country`` assignment without enough free ports to host every
  selected country.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

# ----- Tunables ---------------------------------------------------------
PORT_MIN = 1024  # don't recommend privileged ports; inbound binds need CAP_NET_BIND_SERVICE
PORT_MAX = 65535
PANEL_PORT_RESERVED = 8080  # default; callers pass the actual panel port


# ----- Errors -----------------------------------------------------------
class PortRangeError(ValueError):
    """Raised by :func:`validate_port_ranges` when input is invalid."""


class NoFreeRangeError(PortRangeError):
    """Raised by :func:`recommend_port_range` when no free range fits."""


# ----- Data shape -------------------------------------------------------
@dataclass(frozen=True)
class PortRange:
    """Inclusive half-open-of-1 [start, end] port range."""

    start: int
    end: int

    def __post_init__(self) -> None:
        if not (PORT_MIN <= self.start <= PORT_MAX):
            raise PortRangeError(
                f"range.start {self.start} must be within [{PORT_MIN}, {PORT_MAX}]"
            )
        if not (PORT_MIN <= self.end <= PORT_MAX):
            raise PortRangeError(f"range.end {self.end} must be within [{PORT_MIN}, {PORT_MAX}]")
        if self.end < self.start:
            raise PortRangeError(
                f"range.end ({self.end}) < range.start ({self.start}) — non-ascending"
            )

    @property
    def size(self) -> int:
        return self.end - self.start + 1

    def overlaps(self, other: PortRange) -> bool:
        return not (self.end < other.start or other.end < self.start)

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end}


# ----- Listening-port probe --------------------------------------------
def _parse_proc_net_tcp(path: str = "/proc/net/tcp") -> set[int]:
    """Return the set of local listening TCP ports by parsing /proc.

    Skips silently if /proc is not available (Windows dev box, containerised
    panel). Each row's local-address column is hex-encoded; we parse the
    port as the second 16-bit word. ``st`` (state) 0A == LISTEN.

    Returns the empty set on any parse error.
    """
    ports: set[int] = set()
    try:
        with open(path, encoding="ascii") as f:
            next(f, None)  # skip header line
            for line in f:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local = fields[1]
                state = fields[3]
                if state != "0A":  # 0A == TCP_LISTEN
                    continue
                # local = "0100007F:1F90" (hex IP:hex port, little-endian)
                port_hex = local.rsplit(":", 1)[-1]
                try:
                    ports.add(int(port_hex, 16))
                except ValueError:
                    continue
    except (OSError, ValueError):
        return set()
    return ports


async def _parse_ss_tcp() -> set[int]:
    """Run `ss -tln` and return the set of local listening ports.

    Returns empty set if `ss` is not installed or returns non-zero. We avoid
    `-p` (PID resolution) to keep permissions simple at panel-priv level.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            "ss",
            "-tln",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return set()
    stdout, _ = await proc.communicate()
    if proc.returncode != 0:
        return set()
    ports: set[int] = set()
    for raw in stdout.decode("utf-8", errors="ignore").splitlines()[1:]:
        # Each line: "State Recv-Q Send-Q Local Address:Port Peer ... "
        # Column 4 in `ss -tln` is the local address, may be `[ipv6]:port` or `ipv4:port`.
        try:
            local = raw.split()[3]
        except IndexError:
            continue
        port = local.rsplit(":", 1)[-1]
        try:
            ports.add(int(port))
        except ValueError:
            continue
    return ports


def _listening_ports_sync() -> set[int]:
    """Synchronous union of /proc-listed and `ss`-listed listening ports."""
    ports = _parse_proc_net_tcp()
    try:
        # Reuse the async path on the existing event loop in the panel's worker.
        loop = asyncio.new_event_loop()
        try:
            ss_ports = loop.run_until_complete(_parse_ss_tcp())
        finally:
            loop.close()
    except Exception:  # noqa: BLE001  best-effort; never block the wizard
        ss_ports = set()
    return ports | ss_ports


async def listening_ports() -> set[int]:
    """Async union of /proc-listed and `ss`-listed listening ports.

    Prefers the fast /proc path (no subprocess) and supplements with `ss`
    when /proc is silent or unavailable.
    """
    proc_ports = _parse_proc_net_tcp()
    ss_ports = await _parse_ss_tcp()
    return proc_ports | ss_ports


# ----- Smart recommendation ---------------------------------------------
def recommend_port_range(
    needed: int,
    *,
    busy: set[int] | None = None,
    extra_reserved: set[int] | None = None,
) -> PortRange:
    """Return the smallest contiguous port range of size ``needed`` that has
    no overlap with any busy port or any extra reserved port.

    Searches upward from :data:`PORT_MIN`. Raises :class:`NoFreeRangeError`
    if no contiguous window of the requested size is free.
    """
    if needed <= 0:
        raise PortRangeError(f"needed must be positive, got {needed}")
    needed = min(needed, PORT_MAX - PORT_MIN + 1)
    reserved = (busy or set()) | (extra_reserved or set())

    cur = PORT_MIN
    while cur + needed - 1 <= PORT_MAX:
        end = cur + needed - 1
        chunk = set(range(cur, end + 1))
        if not (chunk & reserved):
            return PortRange(start=cur, end=end)
        # Jump to the first port past the first reserved port inside the chunk.
        # This skips ahead to the next candidate window instead of sweeping by 1.
        first_blocker = next((p for p in chunk if p in reserved), cur)
        cur = first_blocker + 1
    raise NoFreeRangeError(
        f"no contiguous range of {needed} free ports available in "
        f"[{PORT_MIN}, {PORT_MAX}] (excluding reserved: {sorted(reserved)[:10]}{'…' if len(reserved) > 10 else ''})"
    )


# ----- Validation -------------------------------------------------------
@dataclass(frozen=True)
class WizardPortsInput:
    """Parsed `POST /api/wizard/ports` body.

    The ``assignment`` field controls whether public ports are mapped
    one-to-one to countries (``one_per_country``) or shared as a single
    listener with multiplexed front-end routing keys (``shared_range``).
    Phase 3 only validates and persists the choice; the actual port
    allocation happens in Phase 5's clone engine.
    """

    socks: PortRange
    public: PortRange
    assignment: str  # "one_per_country" | "shared_range"
    use_recommendation: bool = False

    def as_dict(self) -> dict:
        return {
            "socks": self.socks.as_dict(),
            "public": self.public.as_dict(),
            "assignment": self.assignment,
            "use_recommendation": self.use_recommendation,
        }


def validate_port_ranges(
    *,
    socks: PortRange,
    public: PortRange,
    assignment: str,
    num_countries: int,
    panel_port: int = PANEL_PORT_RESERVED,
    busy: set[int] | None = None,
) -> WizardPortsInput:
    """Cross-validate the user's port ranges.

    Raises :class:`PortRangeError` on any rule violation:
    - invalid assignment label,
    - ranges overlap with the panel's own listening port,
    - ranges overlap each other,
    - ranges claim ports already bound by another local process,
    - ``one_per_country`` assignment requires at least ``num_countries`` ports
      in BOTH ranges (otherwise the wizard's later apply step will run out).
    """
    if assignment not in ("one_per_country", "shared_range"):
        raise PortRangeError(
            f"assignment must be 'one_per_country' or 'shared_range', got {assignment!r}"
        )
    if socks.overlaps(public):
        raise PortRangeError(
            f"socks range [{socks.start},{socks.end}] overlaps public range "
            f"[{public.start},{public.end}]"
        )
    for r in (socks, public):
        if panel_port in range(r.start, r.end + 1):
            raise PortRangeError(
                f"port range [{r.start},{r.end}] includes the panel's own "
                f"listening port {panel_port} — cannot reuse it"
            )

    busy = busy or set()
    for r in (socks, public):
        blocked = set(range(r.start, r.end + 1)) & busy
        if blocked:
            sample = sorted(blocked)[:5]
            raise PortRangeError(
                f"port range [{r.start},{r.end}] overlaps {len(blocked)} "
                f"already-listening port(s): first {sample}"
                f"{'…' if len(blocked) > 5 else ''}"
            )

    if assignment == "one_per_country":
        for r, label in ((socks, "socks"), (public, "public")):
            if r.size < num_countries:
                raise PortRangeError(
                    f"one_per_country assignment requires at least "
                    f"{num_countries} ports in the '{label}' range, got {r.size}"
                )

    return WizardPortsInput(socks=socks, public=public, assignment=assignment)
