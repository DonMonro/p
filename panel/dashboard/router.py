"""Post-wizard management dashboard router (Phase 6).

The dashboard surfaces the panel state after :class:`panel.models.Settings`
has ``wizard_completed == True``. It lets the operator:

* list per-country state with enable/disable toggle + healthy badge;
* edit per-country SOCKS/Public ports and **re-apply** (regenerate the
  Psiphon config, restart the templated unit, and re-clone the 3x-ui inbound
  so the public port + remark stay in sync);
* delete a country's tunnel + clone entirely;
* tail the systemd journal of a per-country tunnel;
* idempotently re-apply the entire wizard state (rewrite every country
  config + restart every unit + re-clone every 3x-ui inbound);
* export/restore ``panel.db`` and ``config/*.json`` (backup/restore);
* rotate the admin password and change the panel port (with a firewall
  sync note so the operator re-runs the firewall stage).

All handlers require a valid session cookie (see
:func:`panel.auth.get_current_user`) and return JSON unless they stream
SSE/blob.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import re
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from ..auth import decrypt_creds, get_current_user, hash_password, verify_password
from ..config import get_settings
from ..db import get_db
from ..models import (
    CloneRecord,
    Country,
    PortAssignment,
    Settings,
    Wizard,
    XuiLink,
)
from ..psiphon import (
    PsiphonCredentialError,
    PsiphonUnitError,
    is_unit_active,
    restart_unit,
    start_unit,
    stop_unit,
    write_config,
)

# Hotfix #10 (Bug #3): apply_country / PortAssignmentSpec power the inline
# enable-without-existing-PortAssignment branch inside patch_country.
from ..wizard.apply import PortAssignmentSpec, apply_country
from .xui_client import XuiClient, XuiClientError

_log = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _require_wizard_completed(db: Session) -> Settings:
    """Return the singleton Settings row, 503 if missing, 409 if wizard unfinished.

    The dashboard surface is only reachable after the wizard has completed
    (``Settings.wizard_completed == True``). If the operator hits a dashboard
    endpoint before then, surface a structured 409 so the front-end can
    redirect to the wizard.
    """
    settings = db.get(Settings, {"id": 1})
    if settings is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="panel not initialised — run the installer or panel.seed first.",
        )
    if not settings.wizard_completed:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="wizard has not completed yet — finish the setup wizard first.",
        )
    return settings


def _get_country(db: Session, code: str) -> Country:
    """Return the Country row by code (uppercase-validated), or 404."""
    norm = code.strip().upper()
    if not norm or len(norm) != 2 or not norm.isalpha():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"country code must be a 2-letter ISO code, got {code!r}",
        )
    row = db.get(Country, norm)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown country code: {norm}",
        )
    return row


def _country_card(country: Country, db: Session) -> dict[str, Any]:
    """Build one row of the dashboard country listing.

    Embeds:

    * ``enabled`` straight from the Country row;
    * ``assigned`` :data:`True` iff a PortAssignment row exists;
    * ``socks_port`` / ``public_port`` from the assignment (``None`` if not assigned);
    * ``unit_active`` via :func:`panel.psiphon.is_unit_active` — best-effort,
      swallowed errors yield ``False`` rather than 500;
    * ``inbound_id`` (3x-ui clone inbound id) from the CloneRecord row if any;
    * ``healthy`` from the CloneRecord row (cached at clone time; the dashboard
      can re-probe later).
    """
    assignments = db.query(PortAssignment).filter(PortAssignment.country_code == country.code).all()
    if assignments:
        # The schema has at most one PortAssignment per country_code (the wizard
        # writes exactly one row per country); be defensive if several show up.
        pa = assignments[0]
        socks_port: int | None = int(pa.socks_port)
        public_port: int | None = int(pa.public_port)
        assigned = True
    else:
        socks_port = None
        public_port = None
        assigned = False

    clone = db.query(CloneRecord).filter(CloneRecord.country_code == country.code).first()
    inbound_id = int(clone.inbound_id) if clone is not None else None
    healthy = bool(clone.healthy) if clone is not None else False

    try:
        unit_active = bool(is_unit_active(country.code))
    except Exception as exc:  # noqa: BLE001 — dashboard must not 500 on systemctl
        _log.warning("is_unit_active(%s) raised %s: %s", country.code, type(exc).__name__, exc)
        unit_active = False

    return {
        "code": country.code,
        "name": country.name,
        "flag": country.flag_emoji or "",
        "region": country.region or "",
        "enabled": bool(country.enabled),
        "assigned": assigned,
        "socks_port": socks_port,
        "public_port": public_port,
        "unit_active": unit_active,
        "inbound_id": inbound_id,
        "healthy": healthy,
    }


async def _async_get_xui_client(db: Session) -> XuiClient | None:
    """Build a logged-in XuiClient from the cached XuiLink row, or None.

    Mirrors the wizard's ``_async_get_xui_client`` but lives in the dashboard
    namespace so the dashboard router doesn't import the wizard module.
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
    await client.login()
    return client


def _journalctl_lines(unit: str, lines: int) -> list[str]:
    """Run ``journalctl -u <unit> -n <lines> --no-pager`` and split on newlines.

    Returns the raw line list (without trailing blank). Raises
    :class:`RuntimeError` if ``journalctl`` is not on PATH or returns
    non-zero (the dashboard surfaces this as a 502).
    """
    try:
        proc = subprocess.run(  # noqa: S603 — system binary
            ["journalctl", "-u", unit, "-n", str(int(lines)), "--no-pager"],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("journalctl not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"journalctl timed out for unit {unit}") from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(
            f"journalctl -u {unit} -> exit {proc.returncode}: {stderr or '(no stderr)'}"
        )
    return [ln for ln in (proc.stdout or "").splitlines() if ln]


def _config_dir() -> Path:
    """Return the on-disk Psiphon per-country config directory."""
    return Path(get_settings().psiphon_config_dir)


def _panel_db_path() -> Path:
    """Return the on-disk path to ``panel.db``."""
    return Path(get_settings().db_path)


def _validate_port(value: int, *, name: str) -> int:
    """Reject NaN/out-of-range ports with a 422-shaped ValueError."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer 1024-65535")
    if not isinstance(value, int) or not (1024 <= value <= 65535):
        raise ValueError(f"{name} must be an integer in [1024, 65535]")
    return int(value)


def _pick_free_socks_port(db: Session) -> int:
    """Hotfix #10 (Bug #3): smart-recommend a free SOCKS port.

    Walks from 11000 upwards, skipping any port already claimed by an existing
    PortAssignment row. Returns the first free integer.
    """
    used_rows = db.query(PortAssignment).all()
    used: set[int] = {int(r.socks_port) for r in used_rows}
    panel_port = int(db.get(Settings, {"id": 1}).panel_port) if db.get(Settings, {"id": 1}) else 0
    used.add(panel_port)
    candidate = 11000
    while candidate in used or candidate < 1024:
        candidate += 1
    return candidate


def _pick_free_public_port(db: Session) -> int:
    """Hotfix #10 (Bug #3): smart-recommend a free public port.

    Walks from 31000 upwards, skipping any port already claimed by an existing
    PortAssignment row OR the panel port.
    """
    used_rows = db.query(PortAssignment).all()
    used: set[int] = {int(r.public_port) for r in used_rows}
    settings_row = db.get(Settings, {"id": 1})
    panel_port = int(settings_row.panel_port) if settings_row else 0
    used.add(panel_port)
    candidate = 31000
    while candidate in used or candidate < 1024:
        candidate += 1
    return candidate


def _reload_firewall() -> tuple[bool, str]:
    """Hotfix #10 (Bug #5): re-run installer/firewall.sh in-band.

    Returns (ok, detail). The installer directory lives adjacent to the
    installed panel. We best-effort locate it via the install prefix (the
    psiphon_install.sh places the repo at /opt/psiphon3xui). If firewall.sh
    is missing or fails, returns (False, error message).
    """
    for repo_path in ("/opt/psiphon3xui", "/usr/local/share/psiphon-3x-ui"):
        candidate = Path(repo_path) / "installer" / "firewall.sh"
        if candidate.is_file():
            try:
                proc = subprocess.run(  # noqa: S603 — system binary
                    ["bash", str(candidate)],
                    capture_output=True,
                    text=True,
                    timeout=60.0,
                    check=False,
                )
                ok = proc.returncode == 0
                detail = proc.stdout.strip() if ok else proc.stderr.strip() or proc.stdout.strip()
                return ok, detail
            except (OSError, subprocess.SubprocessError) as exc:
                return False, f"firewall.sh invocation failed: {type(exc).__name__}: {exc}"
    return False, "firewall.sh not found under /opt/psiphon3xui or /usr/local/share/psiphon-3x-ui"


def _panel_env_path() -> Path:
    """Resolve the on-disk ``panel.env`` EnvironmentFile.

    Sits as a sibling of ``panel.db`` (i.e. ``${INSTALL_PREFIX}/panel.env``).
    The systemd unit ``psiphon-3x-ui.service`` declares
    ``EnvironmentFile=/opt/psiphon-3x-ui/panel.env`` and the installer
    (installer/panel_install.sh) writes it via heredoc.
    """
    return _panel_db_path().parent / "panel.env"


def _update_panel_env_port(new_port: int) -> tuple[bool, str]:
    """Hotfix #11 (Bug #3): rewrite ``PSIPHON3XUI_PORT=<new>`` in
    ``${INSTALL_PREFIX}/panel.env`` **before** ``systemctl restart``.

    The panel process loads its listen port from the env var
    ``PSIPHON3XUI_PORT`` (panel.config.Settings via pydantic-settings, NOT
    from panel.db's Settings row — see panel/__main__.py:main → uvicorn ports
    spawned from ``settings.port``). Pre-Hotfix-#11 ``change_panel_port``
    only flipped the DB row and never touched the env file, so a
    ``systemctl restart`` bound the panel back to the OLD port — the new port
    never opened. Now we rewrite the env file in place so the next boot reads
    the new port. Returns (ok, detail).
    """
    path = _panel_env_path()
    try:
        if not path.is_file():
            return False, f"env file not found at {path}"
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        # Keep trailing newline if present. Use a regex so we tolerate the
        # installer's exact `PSIPHON3XUI_PORT=${PANEL_PORT}` rendering.
        new_lines: list[str] = []
        port_re = re.compile(r"^[#\s]*PSIPHON3XUI_PORT\s*=.*$")
        replaced = False
        for ln in lines:
            if not replaced and port_re.match(ln):
                new_lines.append(f"PSIPHON3XUI_PORT={new_port}")
                replaced = True
            else:
                new_lines.append(ln)
        if not replaced:
            # Env file exists but lacks the line entirely — append it.
            new_lines.append(f"PSIPHON3XUI_PORT={new_port}")
        out = "\n".join(new_lines)
        if not out.endswith("\n"):
            out += "\n"
        path.write_text(out, encoding="utf-8")
        return True, f"PSIPHON3XUI_PORT rewritten to {new_port} in {path}"
    except OSError as exc:
        return False, f"env rewrite failed: {type(exc).__name__}: {exc}"


def _restart_panel_service() -> tuple[bool, str]:
    """Hotfix #10 (Bug #5) + Hotfix #11 (Bug #3 part 2) + **Hotfix #12
    (Bug #3 part 2, real fix)**: trigger a detached systemctl restart of
    ``psiphon-3x-ui.service``.

    Authorised by the polkit rule (systemd/49-psiphon-3x-ui.rules — extended
    in 19f5 to allow restart of psiphon-3x-ui.service).

    Critical: the in-flight HTTP request is served by THIS panel process. A
    *synchronous* ``subprocess.run(["systemctl","restart",...])`` waits for
    the restart to finish, which kills the very process streaming our
    response back to the operator mid-stream — the browser sees no body, no
    redirect, and looks exactly like "the panel dropped offline and didn't
    restart itself" (this was the second half of Bug #3). We therefore use
    ``systemd-run --no-block`` so systemctl returns immediately while
    systemd schedules the restart fractionally after. The JSON response
    completes first; the panel then re-kicks on the new port once systemd
    stops + restarts it.

    Hotfix #12 (Bug #3 part 2): the previous implementation used plain
    ``systemctl restart psiphon-3x-ui.service`` (synchronous) — the docblock
    claimed it was detached, but the code wasn't. The operator-reported
    symptom ("panel does not change, does not restart, new page does not
    work") was the in-flight HTTP cut-off: the unit restarted fine, but the
    browser received a truncated/empty body because uvicorn's worker was
    SIGTERM'd mid-stream by systemd. Fix: spawn through ``systemd-run --no-block``
    so the child exits immediately and the actual unit restart is scheduled
    behind us (≈50–200 ms later), giving our JSON response time to flush.
    """
    # `systemd-run --no-block --no-ambush ... systemctl restart ...` returns
    # immediately while scheduling the restart after our response flushes.
    # We run it via `setsid`/`nohup`-style double-fork fallback if
    # `systemd-run` is unavailable (older/minimal Linux distros). The inner
    # `systemctl restart` is invoked synchronously from THAT detached scope.
    try:
        proc = subprocess.run(  # noqa: S603 — system binary, trusted args
            [
                "systemd-run",
                "--no-block",
                "--unit=psiphon-3x-ui-restart",
                "--description=psiphon-3x-ui panel port-change self-restart",
                "--collect",
                "systemctl",
                "restart",
                "psiphon-3x-ui.service",
            ],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        if proc.returncode == 0:
            return True, ""
        # If systemd-run isn't available (exit 127 / FileNotFoundError), fall
        # back to a `nohup ... &` detached restart so the child still runs
        # outside our process group and our HTTP response can complete.
        detail = proc.stderr.strip() or proc.stdout.strip() or f"systemd-run exit {proc.returncode}"
    except (OSError, subprocess.SubprocessError):
        detail = "systemd-run unavailable"
    # Fallback: detached `nohup systemctl restart` — survives our parent's
    # imminent SIGTERM because start_new_session re-parents the child to
    # init (PID 1) when our process dies. We deliberately do NOT poll/wait —
    # the whole point is to exit immediately so our HTTP response can flush.
    # A missing-binary OSError at Popen construction is caught below.
    try:
        subprocess.Popen(  # noqa: S603 — system binary
            ["systemctl", "restart", "psiphon-3x-ui.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            # start_new_session=True → setsid() in the child, detaching it
            # from our process group so it survives our imminent SIGTERM.
            start_new_session=True,
        )
        return True, "(detached fallback; systemd-run failed: " + detail + ")"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, (
            f"systemctl restart failed: {type(exc).__name__}: {exc} "
            f"(systemd-run also failed: {detail})"
        )


# ---------------------------------------------------------------------------
# Body schemas
# ---------------------------------------------------------------------------
class PatchCountryBody(BaseModel):
    """``PATCH /api/dashboard/countries/{code}`` body.

    Hotfix #10 (Bug #3): the dashboard now supports enabling a country that
    has NO existing PortAssignment yet. When ``enabled == True`` and the
    country has no PortAssignment, the operator MUST supply ``socks_port``
    and ``public_port`` so the backend can run ``apply_country`` inline and
    persist a new PortAssignment row. Either field may be ``None`` to opt
    into the smart-recommendation defaults (the handler picks sensible free
    ports). When ``enabled == False`` the socks/public fields are ignored.
    """

    enabled: bool = Field(..., description="true starts the unit, false stops it")
    socks_port: int | None = Field(
        default=None,
        ge=1024,
        le=65535,
        description="optional SOCKS port for enabling a no-PortAssignment country",
    )
    public_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="optional public port for enabling a no-PortAssignment country",
    )

    @field_validator("socks_port", "public_port")
    @classmethod
    def _no_bool(cls, v: int | None) -> int | None:
        if isinstance(v, bool):
            raise ValueError("port must be an integer, not bool")
        return v


class EditPortsBody(BaseModel):
    """``POST /api/dashboard/countries/{code}/_ports`` body.

    Both numbers are required: the reapply step needs to know the new
    SOCKS/internal + public/external ports. The dashboard front-end
    pre-fills them from the current PortAssignment row.
    """

    socks_port: int = Field(..., ge=1024, le=65535, description="internal SOCKS port")
    public_port: int = Field(..., ge=1, le=65535, description="external 3x-ui listen port")

    @field_validator("public_port")
    @classmethod
    def _public_not_reserved(cls, v: int) -> int:
        if isinstance(v, bool):
            raise ValueError("public_port must be an integer")
        return int(v)


class RotatePasswordBody(BaseModel):
    """``POST /api/dashboard/rotate-password`` body."""

    current_password: str = Field(..., description="current admin password (re-verify)")
    new_password: str = Field(
        ..., min_length=8, max_length=128, description="new admin password (>=8 chars)"
    )


class ChangePanelPortBody(BaseModel):
    """``POST /api/dashboard/change-panel-port`` body."""

    new_port: int = Field(..., ge=1024, le=65535, description="new panel listen port")


# ---------------------------------------------------------------------------
# Country list / powders
# ---------------------------------------------------------------------------
@router.get("/countries", status_code=status.HTTP_200_OK)
def list_dashboard_countries(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """List every persisted Country row with its full dashboard card.

    Sorted alphabetically by code. Each card embeds the enable/disable flag,
    the underlying PortAssignment (if any), the systemd unit's liveness, and
    the cached CloneRecord row (3x-ui clone inbound id + healthy flag).
    """
    _require_wizard_completed(db)
    rows = db.query(Country).order_by(Country.code).all()
    cards = [_country_card(row, db) for row in rows]
    return {
        "countries": cards,
        "count": len(cards),
        "enabled_count": sum(1 for c in cards if c["enabled"]),
        "active_count": sum(1 for c in cards if c["unit_active"]),
    }


@router.patch("/countries/{code}", status_code=status.HTTP_200_OK)
def patch_country(
    code: str,
    body: PatchCountryBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """Toggle a country's enabled flag and start/stop its systemd unit.

    * ``enabled == True`` → start_unit + Country.enabled = True
    * ``enabled == False`` → stop_unit + Country.enabled = False

    Hotfix #10 (Bug #3): if the country has NO existing PortAssignment and
    the operator requests ``enabled == True``, instead of raising 409 we
    NOW accept optional ``socks_port``/``public_port`` from the request body
    (or use sensible smart-recommendation defaults when those are null),
    persist a fresh PortAssignment row, run ``apply_country`` inline so the
    tunnel unit starts cleanly, and finally flip ``Country.enabled = True``.
    If ``apply_country`` returns a ``failed`` ApplyEvent the handler raises
    a structured 502 with the underlying failure detail so the operator sees
    a useful error message instead of being bounced back to the wizard.
    """
    _require_wizard_completed(db)
    country = _get_country(db, code)
    assignment = (
        db.query(PortAssignment).filter(PortAssignment.country_code == country.code).first()
    )
    if assignment is None and body.enabled is True:
        # Hotfix #10: enable a country that has no PortAssignment yet by
        # accepting socks_port + public_port from the operator (or picking
        # smart-recommendation defaults) and running apply_country inline.
        socks_port = int(body.socks_port) if body.socks_port else _pick_free_socks_port(db)
        public_port = int(body.public_port) if body.public_port else _pick_free_public_port(db)
        spec = PortAssignmentSpec(
            country_code=country.code,
            socks_port=socks_port,
            public_port=public_port,
        )
        event = apply_country(spec)
        if event.status != "healthy":
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(f"inline enable for {country.code} failed: {event.message}"),
            )
        # Persist the new PortAssignment row so subsequent toggles don't
        # re-enter this branch.
        port_row = PortAssignment(
            socks_port=socks_port,
            public_port=public_port,
            country_code=country.code,
        )
        db.add(port_row)
        country.enabled = True
        db.add(country)
        db.commit()
        db.refresh(country)
        db.refresh(port_row)
        _log.info(
            "patch_country inline-enabled %s socks=%d public=%d",
            country.code,
            socks_port,
            public_port,
        )
        return _country_card(country, db)

    if body.enabled:
        try:
            start_unit(country.code)
        except PsiphonUnitError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"start_unit({country.code}) failed: {exc}",
            ) from exc
    else:
        try:
            stop_unit(country.code)
        except PsiphonUnitError as exc:
            _log.warning("stop_unit(%s) failed during disable: %s", country.code, exc)
            # Best-effort — the dashboard's disable should still flip the flag
            # so the operator isn't stuck with a half-stopped unit.

    country.enabled = bool(body.enabled)
    db.add(country)
    db.commit()
    db.refresh(country)

    return _country_card(country, db)


@router.delete("/countries/{code}", status_code=status.HTTP_200_OK)
async def delete_country(
    code: str,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """Tear down a country's tunnel completely.

    Steps (best-effort, surfaced as a structured summary):

    1. Stop the templated systemd unit (logged on failure).
    2. Remove the CloneRecord row (the 3x-ui inbound id).
    3. Delete the matching 3x-ui inbound via the cached XuiClient.
    4. Remove the PortAssignment row.
    5. Flip Country.enabled = False (the Country row itself is preserved so the
       operator can re-enable later without re-running the wizard's countries step).
    """
    _require_wizard_completed(db)
    country = _get_country(db, code)
    summary: dict[str, Any] = {
        "code": country.code,
        "stopped_unit": False,
        "removed_clone_record": False,
        "deleted_inbound": False,
        "deleted_inbound_error": None,
        "removed_assignment": False,
        "country_disabled": False,
    }

    # 1. Stop the systemd unit — best-effort.
    try:
        stop_unit(country.code)
        summary["stopped_unit"] = True
    except PsiphonUnitError as exc:
        _log.warning("stop_unit(%s) failed during delete: %s", country.code, exc)
        summary["stopped_unit"] = False

    # 2. Remove the CloneRecord row (and remember the inbound id for step 3).
    clone = db.query(CloneRecord).filter(CloneRecord.country_code == country.code).first()
    inbound_id: int | None = None
    if clone is not None:
        inbound_id = int(clone.inbound_id)
        db.delete(clone)
        db.commit()
        summary["removed_clone_record"] = True

    # 3. Delete the matching 3x-ui inbound via cached XuiClient.
    if inbound_id is not None:
        client: XuiClient | None = None
        try:
            client = await _async_get_xui_client(db)
            if client is None:
                summary["deleted_inbound_error"] = "no cached 3x-ui creds"
            else:
                await client.delete_inbound(inbound_id)
                summary["deleted_inbound"] = True
        except XuiClientError as exc:
            summary["deleted_inbound_error"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            summary["deleted_inbound_error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.aclose()

    # 4. Remove the PortAssignment row (the wizard wrote exactly one).
    assignment = (
        db.query(PortAssignment).filter(PortAssignment.country_code == country.code).first()
    )
    if assignment is not None:
        db.delete(assignment)
        db.commit()
        summary["removed_assignment"] = True

    # 5. Flip Country.enabled = False (preserved as a selectable row).
    if country.enabled:
        country.enabled = False
        db.add(country)
        db.commit()
        db.refresh(country)
        summary["country_disabled"] = True

    return summary


@router.post("/countries/{code}/_ports", status_code=status.HTTP_200_OK)
async def edit_country_ports(
    code: str,
    body: EditPortsBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """Edit a country's SOCKS/Public ports and **re-apply** the tunnel + clone.

    Steps:

    1. Validate the ports (range + bool + reserved panel port).
    2. Re-write the per-country Psiphon config with the new SOCKS port.
    3. Restart the systemd unit.
    4. Update the PortAssignment row with the new socks/public ports.
    5. If a CloneRecord row exists, delete the old 3x-ui inbound and re-clone
       the template with the new public port (so the remark + listener match).
       Otherwise this is a config-only re-apply (the wizard will run clone
       later).

    ``panel_port`` is reserved — re-using it as either socks or public returns
    400. Also rejects when the new SOCKS/Public collide with another country's
    assignment.
    """
    _require_wizard_completed(db)
    country = _get_country(db, code)

    settings = db.get(Settings, {"id": 1})
    panel_port = int(settings.panel_port) if settings else 0

    try:
        socks_port = _validate_port(body.socks_port, name="socks_port")
        public_port = _validate_port(body.public_port, name="public_port")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    if socks_port == panel_port or public_port == panel_port:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ports must not collide with panel_port {panel_port}",
        )
    if socks_port == public_port:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="socks_port and public_port must not be equal",
        )

    # Ensure the new ports aren't already taken by another country's assignment.
    clashes = (
        db.query(PortAssignment)
        .filter(
            PortAssignment.country_code != country.code,
            (PortAssignment.socks_port == socks_port) | (PortAssignment.public_port == public_port),
        )
        .first()
    )
    if clashes is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"ports collide with existing assignment for {clashes.country_code} "
                f"(socks={clashes.socks_port}, public={clashes.public_port})"
            ),
        )

    summary: dict[str, Any] = {
        "code": country.code,
        "rewrote_config": False,
        "restarted_unit": False,
        "restarted_unit_error": None,
        "updated_assignment": False,
        "recloned_inbound": False,
        "reclone_error": None,
    }

    # 1. Re-write the Psiphon config with the new SOCKS port.
    try:
        write_config(country.code, socks_port, config_dir=_config_dir())
        summary["rewrote_config"] = True
    except PsiphonCredentialError as exc:
        # Hotfix #14 (Phase 23): render_config fast-failed because the
        # operator hasn't populated the four Psiphon-Inc upstream credentials
        # in panel.env. Surface as 502 with the actionable credential
        # message (names the env-var + panel.env path + restart command)
        # rather than the opaque 500.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"write_config({country.code}, {socks_port}) failed — "
                f"Psiphon upstream credentials error: {exc}"
            ),
        ) from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"write_config({country.code}, {socks_port}) failed: {exc}",
        ) from exc

    # 2. Restart the systemd unit so the new config takes effect.
    try:
        restart_unit(country.code)
        summary["restarted_unit"] = True
    except PsiphonUnitError as exc:
        summary["restarted_unit_error"] = str(exc)
        # Don't bail — the operator wants to see the assignment update too.

    # 3. Update the PortAssignment row (or insert if missing).
    assignment = (
        db.query(PortAssignment).filter(PortAssignment.country_code == country.code).first()
    )
    if assignment is None:
        assignment = PortAssignment(
            socks_port=socks_port,
            public_port=public_port,
            country_code=country.code,
        )
        db.add(assignment)
    else:
        assignment.socks_port = socks_port
        assignment.public_port = public_port
    db.commit()
    summary["updated_assignment"] = True

    # 4. Re-clone the 3x-ui inbound if there's an existing CloneRecord row.
    clone = db.query(CloneRecord).filter(CloneRecord.country_code == country.code).first()
    if clone is not None:
        client: XuiClient | None = None
        try:
            client = await _async_get_xui_client(db)
            if client is None:
                summary["reclone_error"] = "no cached 3x-ui creds"
            else:
                # Delete the stale clone, then re-clone the template with the
                # new public port (the wizard stored template_inbound_id in
                # Wizard.step_data["template"]).
                old_id = int(clone.inbound_id)
                try:
                    await client.delete_inbound(old_id)
                except XuiClientError as exc:
                    _log.warning("delete_inbound(%s) failed during re-clone: %s", old_id, exc)
                # Re-clone: pull template_id from the persisted Wizard row.
                wizard = db.get(Wizard, {"id": 1})
                template_id = _read_template_id_from_wizard(wizard)
                country_dict = {
                    "code": country.code,
                    "name": country.name,
                    "flag": country.flag_emoji or "",
                }
                if template_id is None:
                    summary["reclone_error"] = "template_inbound_id missing from Wizard.step_data"
                else:
                    new_inbound = await client.clone_inbound(
                        template_id=template_id,
                        country=country_dict,
                        socks_port=socks_port,
                        public_port=public_port,
                    )
                    new_id = int(new_inbound["obj"]["id"])
                    # Swap the CloneRecord row to the new inbound id.
                    db.delete(clone)
                    db.add(
                        CloneRecord(
                            inbound_id=new_id,
                            country_code=country.code,
                            public_port=public_port,
                            socks_port=socks_port,
                            healthy=True,
                        )
                    )
                    db.commit()
                    summary["recloned_inbound"] = True
        except XuiClientError as exc:
            summary["reclone_error"] = str(exc)
        except Exception as exc:  # noqa: BLE001
            summary["reclone_error"] = f"{type(exc).__name__}: {exc}"
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.aclose()

    return summary


def _read_template_id_from_wizard(wizard: Wizard | None) -> int | None:
    """Pull ``template_inbound_id`` out of the persisted wizard row's step_data.

    Mirrors the wizard's ``_get_template_id`` helper but lives in the dashboard
    namespace so the dashboard router doesn't import the wizard module.
    """
    if wizard is None:
        return None
    try:
        payload = json.loads(wizard.step_data or "{}")
    except (TypeError, ValueError):
        return None
    template_payload = payload.get("template")
    if not isinstance(template_payload, dict):
        return None
    raw = template_payload.get("template_inbound_id")
    if isinstance(raw, bool):
        return None
    if not isinstance(raw, int) or raw < 1:
        return None
    return int(raw)


# ---------------------------------------------------------------------------
# Tunnel logs
# ---------------------------------------------------------------------------
@router.get("/tunnels/{code}/logs", status_code=status.HTTP_200_OK)
def tunnel_logs(
    code: str,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
    lines: int = 200,
) -> dict[str, Any]:
    """Tail the most recent ``lines`` lines of the country's tunnel journal.

    Runs ``journalctl -u psiphon-tunnel@<CODE> -n <lines> --no-pager``. The
    panel must run on the install host with a non-containerised systemd. If
    ``journalctl`` is missing or non-zero, returns a structured 502 with the
    underlying error message so the front-end can show an inline hint.
    """
    _require_wizard_completed(db)
    country = _get_country(db, code)
    if lines < 1 or lines > 5000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="lines must be in [1, 5000]",
        )
    unit = f"psiphon-tunnel@{country.code}.service"
    try:
        out = _journalctl_lines(unit, lines)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"journalctl failed: {exc}",
        ) from exc
    return {
        "code": country.code,
        "unit": unit,
        "lines_requested": int(lines),
        "lines": out,
        "count": len(out),
    }


# ---------------------------------------------------------------------------
# Idempotent re-apply of the full wizard state
# ---------------------------------------------------------------------------
@router.post("/reapply", status_code=status.HTTP_200_OK)
async def reapply_all(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """Idempotently re-apply the entire panel state.

    For every PortAssignment row, re-write the per-country Psiphon config +
    restart the systemd unit. Optionally re-clone 3x-ui inbounds whose
    ``CloneRecord.healthy`` flag is False (best-effort, logged on failure).

    This is the dashboard's "make it match the wizard's intent" button — it
    does not change ports or countries, just re-establishes every country's
    running tunnel + clone state.
    """
    _require_wizard_completed(db)
    assignments = db.query(PortAssignment).order_by(PortAssignment.country_code).all()
    summary: dict[str, Any] = {
        "applied": [],
        "failed": [],
        "recloned": [],
        "reclone_errors": [],
    }

    for pa in assignments:
        code = pa.country_code
        try:
            write_config(code, int(pa.socks_port), config_dir=_config_dir())
            restart_unit(code)
            summary["applied"].append({"code": code, "socks_port": int(pa.socks_port)})
        except PsiphonCredentialError as exc:
            # Hotfix #14 (Phase 23): render_config fast-failed with an
            # actionable credential-rejection message. Surface it as a
            # per-code failed entry (carrying the actionable message naming
            # the env var + panel.env path) instead of bubbling up as a 500.
            summary["failed"].append(
                {
                    "code": code,
                    # PsiphonCredentialError's str() is the actionable message
                    # so the operator sees the same fix steps regardless of
                    # which surface (here vs inline-enable vs edit-ports)
                    # they triggered the failure from.
                    "error": f"PsiphonCredentialError: {exc}",
                }
            )
        except (OSError, ValueError, PsiphonUnitError) as exc:
            summary["failed"].append(
                {
                    "code": code,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

    # Re-clone unhealthy CloneRecord rows (best-effort).
    unhealthy = db.query(CloneRecord).filter(CloneRecord.healthy == False).all()  # noqa: E712
    if unhealthy:
        wizard = db.get(Wizard, {"id": 1})
        template_id = _read_template_id_from_wizard(wizard)
        if template_id is not None:
            client: XuiClient | None = None
            try:
                client = await _async_get_xui_client(db)
                if client is not None:
                    for clone in unhealthy:
                        country = db.get(Country, clone.country_code)
                        if country is None:
                            continue
                        try:
                            old_id = int(clone.inbound_id)
                            try:
                                await client.delete_inbound(old_id)
                            except XuiClientError as exc:
                                _log.warning("reapply delete_inbound(%s) failed: %s", old_id, exc)
                            new_inbound = await client.clone_inbound(
                                template_id=template_id,
                                country={
                                    "code": country.code,
                                    "name": country.name,
                                    "flag": country.flag_emoji or "",
                                },
                                socks_port=int(clone.socks_port),
                                public_port=int(clone.public_port),
                            )
                            new_id = int(new_inbound["obj"]["id"])
                            db.delete(clone)
                            db.add(
                                CloneRecord(
                                    inbound_id=new_id,
                                    country_code=country.code,
                                    public_port=int(clone.public_port),
                                    socks_port=int(clone.socks_port),
                                    healthy=True,
                                )
                            )
                            db.commit()
                            summary["recloned"].append(
                                {
                                    "code": country.code,
                                    "old_inbound_id": old_id,
                                    "new_inbound_id": new_id,
                                }
                            )
                        except XuiClientError as exc:
                            summary["reclone_errors"].append(
                                {
                                    "code": country.code,
                                    "error": str(exc),
                                }
                            )
            finally:
                if client is not None:
                    with contextlib.suppress(Exception):
                        await client.aclose()

    return summary


# ---------------------------------------------------------------------------
# Backup / restore
# ---------------------------------------------------------------------------
def _config_glob() -> list[Path]:
    """Return JSON config files under the psiphon config directory, sorted."""
    base = _config_dir()
    if not base.is_dir():
        return []
    return sorted(base.glob("*.json"))


@router.post("/backup", status_code=status.HTTP_200_OK)
def backup(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> StreamingResponse:
    """Stream a tarball containing ``panel.db`` + every ``config/*.json``.

    The returned body is a single ``application/x-tar`` blob named
    ``psiphon-3x-ui-backup-<UTC-timestamp>.tar``. The front-end should honour
    the ``Content-Disposition`` header.
    """
    _require_wizard_completed(db)

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        db_path = _panel_db_path()
        if db_path.is_file():
            tar.add(db_path, arcname="panel.db")
        for cfg in _config_glob():
            tar.add(cfg, arcname=f"config/{cfg.name}")
    buf.seek(0)
    payload = buf.getvalue()

    def iter_chunks() -> Any:
        yield payload

    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return StreamingResponse(
        iter_chunks(),
        media_type="application/x-tar",
        headers={
            "Content-Disposition": (f'attachment; filename="psiphon-3x-ui-backup-{ts}.tar"'),
            "Content-Length": str(len(payload)),
        },
    )


@router.post("/restore", status_code=status.HTTP_200_OK)
async def restore(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
    file: UploadFile = File(  # noqa: B008  FastAPI idiom
        ..., description="tar archive from POST /backup"
    ),
) -> dict[str, Any]:
    """Replace ``panel.db`` + ``config/*.json`` from a tarball.

    The tarball must have been produced by ``POST /api/dashboard/backup``
    (entries are read in-memory, validated by extension, then atomically
    copied to disk).
    """
    _require_wizard_completed(db)

    raw = await file.read()
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="restore archive is empty",
        )
    summary: dict[str, Any] = {
        "restored_panel_db": False,
        "restored_configs": [],
        "skipped": [],
        "errors": [],
    }
    try:
        buf = io.BytesIO(raw)
        with tarfile.open(fileobj=buf, mode="r") as tar:
            members = tar.getmembers()
            for member in members:
                if not member.isfile():
                    continue
                name = member.name
                # Zip-slip guard.
                if ".." in Path(name).parts or name.startswith("/"):
                    summary["skipped"].append({"name": name, "reason": "unsafe path"})
                    continue
                f = tar.extractfile(member)
                if f is None:
                    continue
                data = f.read()
                if name == "panel.db" or name.endswith("/panel.db"):
                    target = _panel_db_path()
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                    summary["restored_panel_db"] = True
                elif name.startswith("config/") or "/config/" in name:
                    base = Path(name).name
                    if not base.endswith(".json"):
                        summary["skipped"].append({"name": name, "reason": "not a .json config"})
                        continue
                    cfg_dir = _config_dir()
                    cfg_dir.mkdir(parents=True, exist_ok=True)
                    (cfg_dir / base).write_bytes(data)
                    summary["restored_configs"].append(base)
                else:
                    summary["skipped"].append({"name": name, "reason": "unknown archive entry"})
    except tarfile.TarError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid tar archive: {exc}",
        ) from exc
    return summary


# ---------------------------------------------------------------------------
# Rotate admin password + change panel port
# ---------------------------------------------------------------------------
@router.post("/rotate-password", status_code=status.HTTP_200_OK)
def rotate_password(
    body: RotatePasswordBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """Rotate the admin password.

    Re-verifies ``current_password`` against the stored bcrypt hash before
    writing the new hash. Returns 401 if the current password is wrong
    (so a leaked session cookie alone can't change the password).
    """
    _require_wizard_completed(db)
    settings = db.get(Settings, {"id": 1})
    if settings is None:  # pragma: no cover — _require_wizard_completed guards
        raise HTTPException(status_code=503, detail="panel not initialised")
    if not verify_password(body.current_password, settings.admin_pass_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="current password does not match",
        )
    settings.admin_pass_hash = hash_password(body.new_password)
    db.add(settings)
    db.commit()
    return {"rotated": True}


@router.post("/change-panel-port", status_code=status.HTTP_200_OK)
def change_panel_port(
    body: ChangePanelPortBody,
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict[str, Any]:
    """Persist a new panel listen port AND apply it in-band.

    Hotfix #10 (Bug #5): as well as flipping :attr:`Settings.panel_port`
    in panel.db, this endpoint NOW (a) re-runs ``installer/firewall.sh`` so
    the new port is reachable through the host firewall, and (b) calls
    ``systemctl restart psiphon-3x-ui.service`` — authorised by the polkit
    rule's newly-extended scope (see systemd/49-psiphon-3x-ui.rules). The
    operator no longer needs to drop to a shell. The response surfaces
    ``firewall_ok`` + ``service_restart_ok`` flags plus a joined note so the
    SPA can tell the user the browser must reload at the new port once the
    service comes back. Pre-Hotfix-#10 this endpoint only flipped the field
    and the operator had to run the two shell commands manually.
    """
    _require_wizard_completed(db)
    settings = db.get(Settings, {"id": 1})
    if settings is None:  # pragma: no cover
        raise HTTPException(status_code=503, detail="panel not initialised")
    old_port = int(settings.panel_port)
    new_port = int(body.new_port)
    if new_port == old_port:
        return {
            "changed": False,
            "panel_port": old_port,
            "note": "new port equals current panel_port",
        }
    # Sanity: don't allow a port known to be in use by a tunnel SOCKS listener.
    clashes = (
        db.query(PortAssignment)
        .filter((PortAssignment.socks_port == new_port) | (PortAssignment.public_port == new_port))
        .first()
    )
    if clashes is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"new panel_port {new_port} collides with assignment "
                f"for {clashes.country_code} (socks={clashes.socks_port}, "
                f"public={clashes.public_port})"
            ),
        )
    settings.panel_port = new_port
    db.add(settings)
    db.commit()

    # Hotfix #11 (Bug #3, part 1): rewrite ``PSIPHON3XUI_PORT=<new>`` in
    # ``${INSTALL_PREFIX}/panel.env`` BEFORE the restart. The panel process
    # loads its listen port from the env var (panel.config.Settings via
    # pydantic-settings; see panel/__main__.py:main → uvicorn ports spawned
    # from ``settings.port``), NOT from panel.db's Settings row — so merely
    # flipping the DB row then restarting bound the panel back at the OLD
    # port. `_update_panel_env_port` rewrites the env file in place so the
    # next boot picks up the new port. Skipped only if the env file is
    # missing (defensive — operator can drop the panel back up manually).
    env_ok, env_detail = _update_panel_env_port(new_port)
    if not env_ok:
        _log.warning("change_panel_port env-file rewrite failed: %s", env_detail)

    # Hotfix #10 (Bug #5) + Hotfix #11 (Bug #3, part 2): re-run
    # installer/firewall.sh + restart the panel service in-band so the
    # operator doesn't have to drop to a shell. The polkit rule
    # (systemd/49-psiphon-3x-ui.rules — extended in 19f5) must authorise the
    # psiphon3xui user to restart `psiphon-3x-ui.service`. If the service
    # restart succeeds the panel process is killed while this very request
    # is still streaming — the response body may be cut short in-flight.
    # We deliberately return the success payload with a browser-self-refresh
    # hint so the operator's tab reloads on the new port once the service
    # comes back.
    fw_ok, fw_detail = _reload_firewall()
    if not fw_ok:
        _log.warning("change_panel_port firewall reload failed: %s", fw_detail)
    svc_ok, svc_detail = _restart_panel_service()
    if not svc_ok:
        _log.warning("change_panel_port systemctl restart failed: %s", svc_detail)

    note_bits: list[str] = [f"panel_port updated to {new_port}"]
    note_bits.append(
        f"panel.env PSIPHON3XUI_PORT rewrite {'OK' if env_ok else 'FAILED'}"
        + (f" — {env_detail}" if env_detail else "")
    )
    note_bits.append(
        f"firewall.sh {'OK' if fw_ok else 'FAILED'}" + (f" — {fw_detail}" if fw_detail else "")
    )
    note_bits.append(
        f"systemctl restart psiphon-3x-ui.service {'OK' if svc_ok else 'FAILED'}"
        + (f" — {svc_detail}" if svc_detail else "")
    )
    note_bits.append(
        "the panel is restarting on the new port — please reload the browser "
        f"at http://<host>:{new_port}/dashboard once the service comes back"
    )
    return {
        "changed": True,
        "old_port": old_port,
        "new_port": new_port,
        "env_rewrite_ok": env_ok,
        "firewall_ok": fw_ok,
        "service_restart_ok": svc_ok,
        "note": " | ".join(note_bits),
    }
