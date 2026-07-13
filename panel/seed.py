"""One-shot idempotent installer step.

Invoked by ``installer/panel_install.sh`` after the panel wheel is installed in
the venv:

    ${VENV_DIR}/bin/python -m panel.seed \\
        --port "${PANEL_PORT}" \\
        --user "${PANEL_USER}" \\
        --password "${PANEL_PASS}" \\
        --db  "${DB_PATH}"

This script:

* Creates ``panel.db`` (`init_db`) at ``--db``.
* Inserts/refreshes the singleton `Settings` row:
  ``panel_port``, ``admin_user``, ``admin_pass_hash`` (bcrypt),
  ``wizard_completed=False``.
* **Idempotent**: if `Settings(id=1)` already exists, the password + user +
  port are *upserted*. This lets ``install.sh`` be re-run safely as part of
  Phase 7's "upgrade in place" promise.

Never store plaintext passwords on disk beyond this process's environment
variable or command line; seed writes only a bcrypt hash to ``panel.db``.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
from collections.abc import Sequence

# Defer panel imports until after path-munging so this works whether or not the
# panel package is already importable from CWD (e.g. when called as
# `${VENV_DIR}/bin/python -m panel.seed` from a systemd context).


def _ensure_panel_path() -> None:
    """Make sure the installed `panel` package wins the import order.

    `python -m panel.seed` resolves via sys.path[0]. When invoked as a module
    bin from a venv, sys.path[0] is '' (cwd). If a `panel/` directory happens
    to exist in cwd (dev checkout), it can shadow the installed wheel. Push
    the venv site-packages higher in priority than cwd, if the venv layout
    betrays itself via VIRTUAL_ENV.
    """
    venv = os.environ.get("VIRTUAL_ENV")
    if not venv:
        return
    vpath = pathlib.Path(venv, "lib")
    if not vpath.is_dir():
        return
    # Insert any python*/site-packages found under the venv at the front.
    inserted = []
    for site in sorted(venv_libs_install_paths(vpath.parent)):
        inserted.append(str(site))
    sys.path[:] = inserted + [p for p in sys.path if p not in inserted]


def venv_libs_install_paths(venv_root: pathlib.Path) -> list[pathlib.Path]:
    """Return every site-packages dir under ${VENV}/lib/python*/site-packages."""
    out: list[pathlib.Path] = []
    lib = venv_root / "lib"
    if not lib.is_dir():
        return out
    for entry in sorted(lib.iterdir()):
        if entry.is_dir() and entry.name.startswith("python"):
            sp = entry / "site-packages"
            if sp.is_dir():
                out.append(sp)
    return out


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="panel.seed",
        description="One-shot installer: bootstrap panel.db with admin credentials.",
    )
    p.add_argument("--port", type=int, required=True, help="Panel listen port (1-65535).")
    p.add_argument("--user", required=True, help="Admin username.")
    p.add_argument(
        "--password",
        required=True,
        help="Admin password (plaintext at runtime; bcrypt-hashed before storage).",
    )
    p.add_argument(
        "--db",
        required=False,
        default=None,
        help=(
            "Override the SQLite DB path. Defaults to PSIPHON3XUI_DB_PATH env "
            "or /opt/psiphon-3x-ui/panel.db."
        ),
    )
    return p.parse_args(argv)


def _validate(port: int, user: str, password: str) -> None:
    if not (1 <= port <= 65535):
        raise SystemExit(f"--port must be 1..65535, got {port}")
    if not user or len(user) > 64:
        raise SystemExit("--user must be 1..64 chars")
    if not password:
        raise SystemExit("--password must be non-empty")


def main(argv: Sequence[str] | None = None) -> int:
    _ensure_panel_path()
    # Import after path munging so a dev checkout's `panel/` doesn't shadow.
    from panel.auth import hash_password
    from panel.config import load_countries  # noqa: F401  (load + seed)
    from panel.db import init_db, make_engine, make_session_factory
    from panel.models import Country, Settings  # noqa: F401  (registers on Base.metadata)

    args = _parse_args(argv)
    _validate(args.port, args.user, args.password)

    # Lazy import of `load_countries` already happened above; here we set the
    # path override before init_db fires so the engine is built against the
    # caller's --db path (idempotent re-runs target the same file).
    if args.db:
        db_path = pathlib.Path(args.db).expanduser()
        # We need to override Settings.db_path before init_db constructs the
        # engine; using env here is the supported override surface (see
        # panel.config.Settings).
        os.environ["PSIPHON3XUI_DB_PATH"] = str(db_path)

    # Always drop the cached settings and the lazily-cached engine singletons
    # before init_db() so the engine is rebuilt against the current env's
    # db_path. This is essential for repeated in-process invocations under
    # pytest (each test points PSIPHON3XUI_DB_PATH at a fresh tmp_path); the
    # engine from the previous test would otherwise linger and cause
    # `init_db()` to CREATE TABLE on the wrong file, leaving the test's
    # real --db path empty when the new session queries it.
    from panel import config as panel_config
    from panel import db as panel_db

    panel_config.get_settings.cache_clear()
    panel_db._engine = None  # noqa: SLF001  (force get_engine() to rebuild)
    panel_db._session_factory = None  # noqa: SLF001

    init_db()
    engine = make_engine()
    # clear engine caching so subsequent panel imports use the same engine.
    # (`panel_db` is imported once near the top of this function — see the
    # env-cache teardown block above — so we reuse that binding here.)
    panel_db._engine = engine  # noqa: SLF001  (intentional cache replace)
    panel_db._session_factory = make_session_factory(engine)  # noqa: SLF001
    SessionFactory = panel_db._session_factory  # noqa: SLF001

    session = SessionFactory()
    try:
        existing = session.get(Settings, {"id": 1})
        pass_hash = hash_password(args.password)
        if existing is None:
            session.add(
                Settings(
                    id=1,
                    panel_port=args.port,
                    admin_user=args.user,
                    admin_pass_hash=pass_hash,
                    wizard_completed=False,
                )
            )
            print("[seed] inserted new Settings(id=1) row", file=sys.stderr)
        else:
            existing.panel_port = args.port
            existing.admin_user = args.user
            existing.admin_pass_hash = pass_hash
            existing.wizard_completed = bool(existing.wizard_completed)  # preserve existing
            print("[seed] upserted existing Settings(id=1) row", file=sys.stderr)
        session.commit()

        # Seed the Country table from countries.yaml so the wizard has
        # something to display even before the user opens a browser. This is
        # idempotent: existing rows are updated in place, new rows inserted.
        try:
            countries = load_countries()
            seen: set[str] = set()
            for c in countries.countries:
                seen.add(c.code)
                row = session.get(Country, {"code": c.code})
                if row is None:
                    session.add(
                        Country(
                            code=c.code,
                            name=c.name,
                            flag_emoji=c.flag,
                            region=c.region,
                            enabled=False,
                        )
                    )
                else:
                    row.name = c.name
                    row.flag_emoji = c.flag
                    row.region = c.region
            # Stale rows in DB but not in yaml are left in place (the dashboard
            # owns disable/delete semantics so we don't surprise the user with
            # table surgery at install/upgrade time).
            session.commit()
            print(f"[seed] country table synced ({len(seen)} entries)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001  (best-effort seed)
            print(f"[seed] warning: country seed skipped ({exc!r})", file=sys.stderr)
    finally:
        session.close()

    # Dispose the engine and clear cached singletons so the SQLite file is
    # fully released before the process exits, and so repeated in-process
    # calls (tests, daemon-style re-vendoring) don't pile up connections.
    engine.dispose()
    panel_db._engine = None  # noqa: SLF001  (force next caller to make_engine())
    panel_db._session_factory = None  # noqa: SLF001
    # Pydantic-settings cached Settings may carry an env-overridden db_path;
    # clear so a subsequent call picks up fresh env vars. (`panel_config` is
    # imported once earlier in this function — reuse the binding.)
    panel_config.get_settings.cache_clear()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
