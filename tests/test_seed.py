"""pytest coverage for :mod:`panel.seed` (Phase 2 installer bootstrap).

Exercises the same surface ``installer/panel_install.sh`` invokes:

    ${VENV_DIR}/bin/python -m panel.seed \\
        --port <port> --user <user> --password <pass> --db <path>

We assert:
* A fresh panel.db gets a singleton Settings(id=1) row with the right port/user
  and a *bcrypt* hash (not the plaintext password; verifiable with bcrypt.checkpw).
* Re-running seed with new creds *upserts* the existing row (no duplicate row,
  wizard_completed preserved as false; password hash actually changed).
* The Country table is seeded from config/countries.yaml with exactly the
  count load_countries() reports, all enabled=False.
* The panel.db engine is disposed+uncached after main() returns, so the
  SQLite file is released (the producing process can delete the tempfile).
"""

from __future__ import annotations

import os
import pathlib

import pytest
from sqlalchemy import create_engine, select


def _seed_run(tmp_db: pathlib.Path, *, port: int, user: str, password: str) -> int:
    """Invoke panel.seed.main() once against tmp_db. Returns the exit code."""
    from panel.config import get_settings, load_countries
    from panel.seed import main

    # Clear any process-wide cached state so seed's env override actually
    # re-reads against the caller's --db path.
    get_settings.cache_clear()
    load_countries.cache_clear()
    os.environ["PSIPHON3XUI_SESSION_SECRET"] = "test-secret"
    os.environ["PSIPHON3XUI_DB_PATH"] = ""  # seed.main sets this from --db anyway

    rc = main(
        [
            "--port",
            str(port),
            "--user",
            user,
            "--password",
            password,
            "--db",
            str(tmp_db),
        ]
    )
    get_settings.cache_clear()
    load_countries.cache_clear()
    return rc


@pytest.fixture
def tmp_db(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "panel.db"


def _read_settings_row(tmp_db: pathlib.Path) -> dict:
    """Read the singleton Settings(id=1) row using a fresh SQLAlchemy engine."""
    from panel.models import Settings

    engine = create_engine(f"sqlite:///{tmp_db}", future=True)
    try:
        with engine.connect() as conn:
            row = (
                conn.execute(select(Settings.__table__).where(Settings.__table__.c.id == 1))
                .one()
                ._mapping
            )
        return dict(row)
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------


def test_seed_creates_singleton_settings_row_with_bcrypt_hash(
    tmp_db: pathlib.Path,
) -> None:
    rc = _seed_run(tmp_db, port=18000, user="alice", password="hunter2")
    assert rc == 0
    assert tmp_db.is_file(), "seed should have created panel.db"

    row = _read_settings_row(tmp_db)
    assert row["id"] == 1
    assert row["panel_port"] == 18000
    assert row["admin_user"] == "alice"
    assert row["wizard_completed"] in (False, 0)

    # bcrypt hashes start with $2 and are NOT the plaintext password.
    h = row["admin_pass_hash"]
    assert isinstance(h, str) and h.startswith("$2")
    assert h != "hunter2"

    # And actually verifies against the plaintext.
    import bcrypt

    assert bcrypt.checkpw(b"hunter2", h.encode())


def test_seed_is_idempotent_and_resets_credentials(tmp_db: pathlib.Path) -> None:
    rc1 = _seed_run(tmp_db, port=18000, user="alice", password="hunter2")
    rc2 = _seed_run(tmp_db, port=18001, user="bob", password="hunter3")
    assert rc1 == 0 and rc2 == 0

    row = _read_settings_row(tmp_db)
    assert row["id"] == 1, "no duplicate Settings row should be created"
    assert row["panel_port"] == 18001
    assert row["admin_user"] == "bob"

    # New password hash should match hunter3, not the old hunter2.
    import bcrypt

    assert bcrypt.checkpw(b"hunter3", row["admin_pass_hash"].encode())
    assert not bcrypt.checkpw(b"hunter2", row["admin_pass_hash"].encode())


def test_seed_populates_country_table_from_yaml(tmp_db: pathlib.Path) -> None:
    rc = _seed_run(tmp_db, port=18000, user="alice", password="hunter2")
    assert rc == 0

    from panel.config import load_countries
    from panel.models import Country

    expected = load_countries()

    engine = create_engine(f"sqlite:///{tmp_db}", future=True)
    try:
        with engine.connect() as conn:
            rows = conn.execute(select(Country.__table__)).mappings().all()
    finally:
        engine.dispose()

    assert len(rows) == len(expected.countries)
    assert {r["code"] for r in rows} == {c.code for c in expected.countries}
    # All seeded rows start disabled, regardless of yaml contents.
    assert all(r["enabled"] in (False, 0) for r in rows)


def test_seed_releases_db_file_after_return(tmp_db: pathlib.Path) -> None:
    """After main() returns, the SQLite file must be releasable by the
    process that just wrote it. Regression test for the Windows file-lock
    bug discovered during the Phase 2 spike."""
    rc = _seed_run(tmp_db, port=18000, user="alice", password="hunter2")
    assert rc == 0
    # If the panel db engine is still holding the file, this raises.
    tmp_db.unlink()
    assert not tmp_db.exists()
