"""SQLite session + init helpers for the panel database.

Phase 0 stub: defines the engine factory and schema initialisation. The full
models (see :mod:`panel.models`) are imported here so ``init_db`` creates all
tables in one place.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    """Declarative base shared by all models in :mod:`panel.models`."""


def make_engine():
    """Create a SQLite engine bound to the configured ``db_path``.

    Ensures the parent directory of the SQLite file exists (the installer
    normally pre-creates it, but tests / portable runs may boot before that).
    """
    settings = get_settings()
    db_path = settings.db_path
    try:
        parent = db_path.parent
        if str(parent) and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError):
        # best-effort: SQLite will report a clearer error if it really can't
        # create the file.
        pass
    url = f"sqlite:///{db_path}"
    return create_engine(url, future=True, connect_args={"check_same_thread": False})


def make_session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


# Module-level lazily-initialised singletons (created on first request).
_engine = None
_session_factory = None


def get_engine():
    global _engine  # noqa: PLW0603
    if _engine is None:
        _engine = make_engine()
    return _engine


def get_session_factory():
    global _session_factory  # noqa: PLW0603
    if _session_factory is None:
        _session_factory = make_session_factory(get_engine())
    return _session_factory


def init_db() -> None:
    """Create all tables if missing. Safe to call on every boot."""
    # Import here so models register on Base before create_all runs.
    from . import models  # noqa: F401 (registers tables on Base)

    Base.metadata.create_all(get_engine())


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a scoped session and closes it on exit."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()
