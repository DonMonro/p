"""Phase 7 i18n scaffold (English-only v1, structured for future locales).

The translation table lives at :file:`panel/i18n/en.json` and is keyed by
feature area (e.g. ``"wizard"`` → ``{"steps.apply.progress": "Applying …"}``).
The front-end can fetch a bundle via ``GET /api/i18n/<locale>`` and translate
client-side; the panel server itself stays English-only in v1 — translation
happens only in the SPA shell so future locales ship as separate JSON files.

Loaders:

* :func:`load_locale` — load + cache a single locale's bundle (lru-cached).
* :func:`available_locales` — list the locale codes that ship a JSON file.
* :func:`t` — look up a dotted key inside a locale's bundle (returns the
  key itself if missing, so missing translations degrade gracefully rather
  than 404 / KeyError).
"""

from __future__ import annotations

import contextlib
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

I18N_DIR = Path(__file__).resolve().parent
DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES: tuple[str, ...] = ("en",)


def _locale_path(locale: str) -> Path:
    """Return the on-disk path to ``panel/i18n/<locale>.json``."""
    return I18N_DIR / f"{locale}.json"


def available_locales() -> list[str]:
    """Return the sorted list of locale codes for which a JSON file ships."""
    files = sorted(p for p in I18N_DIR.glob("*.json") if p.is_file())
    return [p.stem for p in files]


@lru_cache(maxsize=8)
def load_locale(locale: str = DEFAULT_LOCALE) -> dict[str, Any]:
    """Load the JSON bundle for *locale* and return it as a dict.

    Falls back to :data:`DEFAULT_LOCALE` if *locale* isn't available; on any
    parse error, returns an empty dict and logs a warning so the panel keeps
    booting (the front-end will then receive ``{}`` and surface raw keys).
    """
    norm = locale.strip().lower() or DEFAULT_LOCALE
    path = _locale_path(norm)
    if not path.is_file():
        if norm != DEFAULT_LOCALE:
            _log.warning("i18n: locale %r has no JSON — falling back to %s", norm, DEFAULT_LOCALE)
            return load_locale(DEFAULT_LOCALE)
        # Default locale must ship — treat as programmer error in CI.
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning("i18n: failed to load %s: %s", path, exc)
        return {}


def _resolve_key(bundle: dict[str, Any], dotted_key: str) -> str | None:
    """Walk a dotted key like ``"wizard.steps.apply.title"`` inside *bundle*.

    Returns the leaf string when found, else ``None``.
    """
    cursor: Any = bundle
    for part in dotted_key.split("."):
        if not isinstance(cursor, dict):
            return None
        if part not in cursor:
            return None
        cursor = cursor[part]
    return cursor if isinstance(cursor, str) else None


def t(
    dotted_key: str, locale: str = DEFAULT_LOCALE, *, default: str | None = None, **params: Any
) -> str:
    """Translate *dotted_key* under *locale*'s bundle, with optional interpolation.

    Missing keys return *default* if provided, otherwise the dotted key
    itself (so translation gaps degrade visibly in the UI rather than
    crashing). Interpolation replaces ``{name}`` placeholders in the
    resolved string using *params* values (best-effort — missing params are
    left as-is).
    """
    bundle = load_locale(locale)
    text = _resolve_key(bundle, dotted_key)
    if text is None:
        text = default if default is not None else dotted_key
    if params:
        with contextlib.suppress(KeyError, IndexError):
            text = text.format(**dict(params))
    return text
