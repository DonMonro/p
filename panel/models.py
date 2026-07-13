"""SQLAlchemy ORM models for ``panel.db``.

See ``plans/ROADMAP.md`` §5 (ER diagram) for the schema. Phase 0 declares the
table shapes; CRUD endpoints land in later phases.
"""

from __future__ import annotations

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class Settings(Base):
    """Singleton-ish row holding panel-wide persistent config."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    panel_port: Mapped[int] = mapped_column(Integer, nullable=False)
    admin_user: Mapped[str] = mapped_column(String(64), nullable=False)
    admin_pass_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    wizard_completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    public_port_range_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    public_port_range_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    socks_port_range_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    socks_port_range_end: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Wizard(Base):
    """Idempotent wizard state machine progress.

    The wizard advances through the ordered states in :data:`panel.wizard.steps`
    (countries → ports → apply → xui_detect → xui_creds → template → clone →
    done). ``current_step`` stores the *label* of the next step the user must
    still complete; ``step_data`` is a JSON blob with that step's saved input
    (e.g. ``{"mode": "specific", "codes": ["US", "DE"]}``).
    """

    __tablename__ = "wizard"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    # Phase-0 declared this as `Integer` despite `Mapped[str]` — pydantic / the
    # ORM tolerated it but the wizard's step labels are strings ("countries",
    # "ports", …). Aligning the column type to match the Python type.
    current_step: Mapped[str] = mapped_column(String(32), nullable=False, default="countries")
    step_data: Mapped[str] = mapped_column(String, nullable=False, default="{}")


class Country(Base):
    """One selectable country row."""

    __tablename__ = "country"

    code: Mapped[str] = mapped_column(String(2), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    flag_emoji: Mapped[str] = mapped_column(String(8), nullable=False, default="")
    region: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    assignments: Mapped[list[PortAssignment]] = relationship(back_populates="country")


class PortAssignment(Base):
    """Per-country SOCKS↔public port mapping."""

    __tablename__ = "port_assignment"

    socks_port: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_port: Mapped[int] = mapped_column(Integer, nullable=False)
    country_code: Mapped[str] = mapped_column(String(2), ForeignKey("country.code"), nullable=False)

    country: Mapped[Country] = relationship(back_populates="assignments")


class XuiLink(Base):
    """Stored 3x-ui API credentials (password encrypted at rest)."""

    __tablename__ = "xui_link"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    base_url: Mapped[str] = mapped_column(String(255), nullable=False)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    password_enc: Mapped[str] = mapped_column(String(512), nullable=False)
    token_cache: Mapped[str | None] = mapped_column(String, nullable=True)


class CloneRecord(Base):
    """Each row produced by cloning the 3x-ui template inbound once per country."""

    __tablename__ = "clone_record"

    inbound_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    country_code: Mapped[str] = mapped_column(String(2), ForeignKey("country.code"), nullable=False)
    public_port: Mapped[int] = mapped_column(Integer, nullable=False)
    socks_port: Mapped[int] = mapped_column(Integer, nullable=False)
    healthy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
