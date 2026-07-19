"""Runtime configuration & settings for the panel.

``Settings`` is loaded from environment variables (with sane defaults) at
startup. Persistent, admin-editable state (panel port, admin user, wizard
progress, port assignments, 3x-ui link, clone records) lives in ``panel.db``
via SQLAlchemy (see :mod:`panel.db` / :mod:`panel.models`).

Phase 0 provides the env-backed defaults and the countries file loader; full
persistence lands in a later phase.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository layout anchors. Resolve relative to this file so the panel works
# regardless of the CWD used by the systemd unit.
PACKAGE_DIR = Path(__file__).resolve().parent
# countries.yaml ships inside the panel package wheel as ``panel/data/countries.yaml``
# (see [tool.setuptools.package-data] in pyproject.toml) so the seeded panel can
# find it from the installed site-packages location regardless of install prefix.
# (Historical context: a dev-only duplicate lived at <repo-root>/config/
# countries.yaml, but it was removed in the cleanup pass after Phase 23 — the
# two copies had drifted, and no production code path resolved to the root
# path anyway. The canonical source of truth is now THIS file.)
COUNTRIES_FILE = PACKAGE_DIR / "data" / "countries.yaml"


class Settings(BaseSettings):
    """Environment-backed runtime settings.

    These are *defaults*; the panel populates ``panel.db`` with the actual
    admin-chosen values during install / wizard and reads persistent state from
    there at runtime. Env vars (``PSIPHON3XUI_*``) override defaults for testing.
    """

    model_config = SettingsConfigDict(
        env_prefix="PSIPHON3XUI_",
        env_file=".env",
        extra="ignore",
    )

    # Default listen host/port — overridden by values stored in panel.db during
    # install. Kept here so the panel can boot in dev before DB init exists.
    host: str = "127.0.0.1"
    port: int = 8080

    # Phase 7 — TLS termination at uvicorn. When both are populated (set by
    # installer/https_install.sh + written into panel.env), __main__.py runs
    # uvicorn with --ssl-certfile/--ssl-keyfile and the session/CSRF cookies
    # are marked Secure via the PanelHttps flag below. Either field empty
    # disables TLS at the panel layer (operator can still front with Caddy).
    tls_cert: Path | None = None
    tls_key: Path | None = None

    # Flipped on by the installer when TLS is enabled so the auth.py cookie
    # flags (Secure) flip from False→True. Defaults to False so the test
    # suite (which doesn't run over TLS) still issues login cookies.
    https_only: bool = False

    # Where the panel SQLite database lives.
    db_path: Path = Path("/opt/psiphon-3x-ui/panel.db")

    # Where per-country generated Psiphon configs are written by the wizard.
    psiphon_config_dir: Path = Path("/opt/psiphon-3x-ui/config")

    # Where the psiphon-tunnel-core binary lives (set by the installer).
    psiphon_binary: Path = Path("/opt/psiphon-3x-ui/bin/psiphon-tunnel-core")

    # Repository path to countries.yaml (overridable for tests).
    countries_file: Path = COUNTRIES_FILE

    # Secret used to sign session cookies. MUST be set in production; the
    # installer generates one and writes it to the env file watched by the
    # systemd unit.
    session_secret: str = "dev-only-change-me"

    debug: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached singleton :class:`Settings` instance."""
    return Settings()


class Country(BaseModel):
    """A single selectable Psiphon EgressRegion."""

    code: str
    name: str
    flag: str
    region: str

    @field_validator("code", mode="before")
    @classmethod
    def _validate_code(cls, v):
        # YAML 1.1 parsers silently coerce some bare 2-letter codes to
        # booleans (e.g. `NO`, `no`, `On`, `Yes`, `IN` -> int 0?). If you saw
        # this ValueError, you forgot to QUOTE the offending `code:` value in
        # countries.yaml. Refusing silently-coerced values keeps codes honest.
        if isinstance(v, bool):
            raise ValueError(
                f"country code parsed as a YAML boolean ({v!r}). "
                "Quote the `code:` value in panel/data/countries.yaml — e.g. "
                '`- code: "NO"`. See the file header comment.'
            )
        if not isinstance(v, str):
            raise ValueError(f"country code must be a string, got {type(v).__name__}: {v!r}")
        s = v.strip().upper()
        if len(s) != 2 or not s.isalpha():
            raise ValueError(f"country code must be 2 ASCII letters, got {v!r}")
        return s


class CountriesDefaults(BaseModel):
    """The default port ranges recommended by the wizard."""

    socks_port_range: dict[str, int]
    public_port_range: dict[str, int]


class CountriesFile(BaseModel):
    """In-memory representation of ``panel/data/countries.yaml``."""

    version: int
    defaults: CountriesDefaults
    countries: list[Country]

    @property
    def codes(self) -> list[str]:
        return [c.code for c in self.countries]


@lru_cache(maxsize=1)
def load_countries(path: Path | None = None) -> CountriesFile:
    """Load and parse ``countries.yaml``.

    Cached so repeated wizard calls don't re-read the disk. Pass ``path`` to
    bypass the cache (used in tests).
    """
    target = path or get_settings().countries_file
    if target is not None:
        load_countries.cache_clear()
    raw: Any = yaml.safe_load(target.read_text(encoding="utf-8"))
    return CountriesFile.model_validate(raw)
