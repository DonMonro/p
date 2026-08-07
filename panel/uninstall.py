"""Remove the 3x-ui entries this panel created, and nothing else.

Invoked by ``install.sh --uninstall`` before it tears down the service and
deletes the install prefix::

    set -a; source "${ENV_FILE}"; set +a
    ${VENV_DIR}/bin/python -m panel.uninstall --db "${DB_PATH}"

Sourcing the env file is **required**, not decorative (Phase 29, item 4). The
3x-ui password is stored signature-encrypted in ``XuiLink.password_enc`` using
``PSIPHON3XUI_SESSION_SECRET``, which systemd supplies to the panel via
``EnvironmentFile=`` and which is therefore absent from a plain root shell.
Run bare, :func:`panel.auth.decrypt_creds` falls back to the built-in default
secret, fails the signature check, returns ``None``, and this module used to
exit 0 having deleted nothing at all.

Why this exists
---------------
Up to Phase 26 the uninstaller printed:

    3x-ui's own inbounds installed by THIS panel are NOT touched — you must
    delete them from 3x-ui's UI/API manually.

which left three classes of debris in 3x-ui for every country the panel had
ever enabled:

1. the cloned **inbound** (``CloneRecord.inbound_id``),
2. the per-country **outbound** (``psiphon-out-<CC>``),
3. the **routing rule(s)** whose ``outboundTag`` points at that outbound.

The "outbound reappears" bug
----------------------------
Operators who tried to clear the debris by hand reported that deleting the
outbound in the 3x-ui UI *appeared to succeed but the entry came back*. That is
not a UI bug and not a caching artifact — it is xray-core config validation.

``SaveXraySetting`` runs the submitted config through xray-core before
persisting it. A ``routing.rules[]`` entry whose ``outboundTag`` does not
resolve to any member of ``outbounds[]`` is a **hard validation error**, so:

* deleting ONLY the outbound leaves the orphaned rule behind,
* the resulting config fails validation,
* 3x-ui rejects the write and re-renders the *unchanged* template,
* the outbound is still on screen — indistinguishable from "it came back".

The fix is to remove the rule and the outbound in the SAME write, which is what
:func:`panel.dashboard.xray_routing.strip_binding` already does. This module
applies it per country, then does one template write per country, so the config
is never transiently invalid.

Scope discipline
----------------
Only entries this panel created are removed:

* inbounds — only ids recorded in ``CloneRecord``; a hand-made inbound has no
  CloneRecord row and is never touched.
* outbounds/rules — only the ``psiphon-out-<CC>`` tag namespace, matched by
  :func:`panel.dashboard.xray_routing.outbound_tag_for`. The operator's own
  outbounds, the ``direct``/``blocked`` defaults, and the ``api``/``stats``
  blocks are left byte-identical.

Failures are reported, never fatal: an unreachable or already-removed 3x-ui
must not block the uninstall. Exit code is 0 unless ``--strict`` is passed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from typing import Any


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="panel.uninstall",
        description=(
            "Delete the 3x-ui inbounds, outbounds and routing rules this panel "
            "created (leaves everything else in 3x-ui untouched)."
        ),
    )
    p.add_argument(
        "--db",
        required=False,
        default=None,
        help=(
            "SQLite DB path. Defaults to PSIPHON3XUI_DB_PATH env or "
            "/opt/psiphon-3x-ui/panel.db."
        ),
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any cleanup step failed (default: always exit 0).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be removed without calling 3x-ui.",
    )
    return p.parse_args(argv)


async def _cleanup(db_path: str | None, *, dry_run: bool) -> dict[str, Any]:
    """Delete this panel's inbounds + outbounds + routing rules from 3x-ui.

    Returns a report dict: ``{"inbounds": [...], "countries": [...],
    "errors": [...], "skipped": str|None}``.
    """
    from sqlalchemy.orm import Session

    from .db import get_engine, init_db
    from .models import CloneRecord, Country, XuiLink

    report: dict[str, Any] = {
        "inbounds": [],
        "countries": [],
        "errors": [],
        "skipped": None,
    }

    if db_path:
        os.environ["PSIPHON3XUI_DB_PATH"] = db_path
    init_db()

    with Session(get_engine()) as db:
        clones = db.query(CloneRecord).all()
        # Every country the panel could have bound routing for — a country can
        # have an outbound+rule even with no surviving CloneRecord (the inbound
        # may have been deleted by hand while the binding stayed behind).
        codes = sorted(
            {str(c.country_code).upper() for c in clones}
            | {str(c.code).upper() for c in db.query(Country).all()}
        )
        inbound_ids = [int(c.inbound_id) for c in clones if c.inbound_id]
        link = db.get(XuiLink, {"id": 1})

        if dry_run:
            report["inbounds"] = inbound_ids
            report["countries"] = codes
            report["skipped"] = "dry-run"
            return report

        if link is None:
            report["skipped"] = "no 3x-ui link recorded in panel.db"
            return report

        from .auth import decrypt_creds

        if not link.password_enc:
            report["skipped"] = "no cached 3x-ui credentials in panel.db"
            return report

        # Phase 29 (item 4): a decrypt failure and an empty column are NOT the
        # same problem, and conflating them is what made the silent-skip bug so
        # hard to spot. password_enc is signed with PSIPHON3XUI_SESSION_SECRET,
        # which lives only in panel.env; run this module without that env var
        # loaded and decrypt_creds() returns None for a perfectly good row.
        # Saying so out loud turns an invisible no-op into a fixable error.
        creds = decrypt_creds(link.password_enc)
        if creds is None:
            report["skipped"] = (
                "could not decrypt the cached 3x-ui password — "
                "PSIPHON3XUI_SESSION_SECRET does not match the one that "
                "encrypted it. Load the panel's env file before running this "
                "module (set -a; source /opt/psiphon-3x-ui/panel.env; set +a)."
            )
            return report

        password = creds.get("password")
        if not password:
            report["skipped"] = "cached 3x-ui credentials contain no password"
            return report

        base_url = link.base_url
        username = link.username

    from .dashboard.xray_routing import outbound_tag_for, strip_binding
    from .dashboard.xui_client import XuiClient

    client = XuiClient(base_url=base_url, username=username, password=password)
    try:
        await client.login()
    except Exception as exc:  # noqa: BLE001  uninstall must not hard-fail
        report["skipped"] = f"3x-ui login failed: {type(exc).__name__}: {exc}"
        return report

    try:
        # ── 1. Delete the cloned inbounds (only ids we recorded). ──────────
        for inbound_id in inbound_ids:
            try:
                await client.delete_inbound(inbound_id)
                report["inbounds"].append(inbound_id)
            except Exception as exc:  # noqa: BLE001
                report["errors"].append(
                    f"delete_inbound({inbound_id}): {type(exc).__name__}: {exc}"
                )

        # ── 2. Strip each country's outbound + rules in ONE write. ─────────
        # Reading the template once and writing once per changed country keeps
        # every intermediate state valid: an outbound is never removed while a
        # rule still references it (see the module docstring).
        try:
            setting = await client.get_xray_setting()
            raw = setting.get("xraySetting")
            template = json.loads(raw) if isinstance(raw, str) else raw
            if not isinstance(template, dict):
                raise ValueError("xraySetting did not decode to an object")
        except Exception as exc:  # noqa: BLE001
            report["errors"].append(
                f"read xray template: {type(exc).__name__}: {exc}"
            )
            return report

        changed_codes = []
        for code in codes:
            try:
                if strip_binding(template, code, None):
                    changed_codes.append(code)
            except Exception as exc:  # noqa: BLE001
                report["errors"].append(
                    f"strip_binding({code}): {type(exc).__name__}: {exc}"
                )

        if changed_codes:
            try:
                await client.update_xray_setting(json.dumps(template, indent=2))
                report["countries"] = changed_codes
            except Exception as exc:  # noqa: BLE001
                report["errors"].append(
                    f"write xray template: {type(exc).__name__}: {exc} "
                    f"(outbounds {[outbound_tag_for(c) for c in changed_codes]} "
                    f"left in place)"
                )
        else:
            report["countries"] = []
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass

    return report


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        report = asyncio.run(_cleanup(args.db, dry_run=args.dry_run))
    except Exception as exc:  # noqa: BLE001  never block the uninstall
        print(f"3x-ui cleanup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1 if args.strict else 0

    if report["skipped"]:
        # Phase 29 (item 4): a skip means inbounds/outbounds are being LEFT in
        # 3x-ui. That is a warning, not a status line — it goes to stderr so it
        # survives the rest of the uninstall output.
        print(f"3x-ui cleanup SKIPPED: {report['skipped']}", file=sys.stderr)
        if report["skipped"] != "dry-run":
            print(
                "3x-ui cleanup SKIPPED: the inbounds and outbounds this panel "
                "created are still in 3x-ui — delete them from the 3x-ui UI.",
                file=sys.stderr,
            )
    else:
        n_in = len(report["inbounds"])
        n_co = len(report["countries"])
        print(
            f"3x-ui cleanup: removed {n_in} inbound(s) "
            f"{report['inbounds'] or ''}".rstrip()
        )
        print(
            f"3x-ui cleanup: removed outbound+routing rules for {n_co} "
            f"country/countries {report['countries'] or ''}".rstrip()
        )
    for err in report["errors"]:
        print(f"3x-ui cleanup WARNING: {err}", file=sys.stderr)

    if args.strict and report["errors"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
