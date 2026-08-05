#!/usr/bin/env python3
"""Apply a per-country Xray outbound+routing patch to 3x-ui's SQLite DB.

Companion to ``xray_apply.py`` (which patches the live ``config.json``).
This script patches the **source of truth** — 3x-ui's SQLite database —
so that outbounds and routing rules survive 3x-ui's config regeneration.

Problem solved:
    3x-ui regenerates ``/usr/local/x-ui/bin/config.json`` from its SQLite
    DB (``/usr/local/x-ui/x-ui.db`` or ``/etc/x-ui/x-ui.db``) every time
    its inbound API is touched or the service restarts.  The existing
    ``xray_apply.py`` patches ``config.json`` directly, but those changes
    are wiped on the next regeneration.  This script patches the
    ``xrayTemplateConfig`` setting inside the DB so every regeneration
    includes our outbounds + routing rules.

Patch-file schema (same as ``xray_apply.py``)::

    {
      "op":           "apply" | "remove",      # required
      "country_code": "US",                    # required
      "socks_port":   11001,                   # required for op=apply
      "public_port":  31001,                   # required
      "inbound_tag":  "in-31001-tcp"           # required
    }

Behaviour (mirrors ``xray_apply.py``):

* ``apply``  — upsert the per-country socks outbound keyed by
  ``tag == "psiphon-out-<CODE>"`` (replace in place if present, append
  otherwise) AND upsert the field routing rule keyed by
  ``(inboundTag == ["<inbound_tag>"], outboundTag == "psiphon-out-<CODE>")``
  inserted BEFORE the first existing ``bittorrent`` / ``geoip:private``
  catch-all so Xray's rule-matching prefers ours.

* ``remove`` — strip the outbound AND the rule (both keyed lookups are
  by-tag + by-inboundTag so sibling countries' entries survive intact).

Both ops are *idempotent at the DB level*: if the patch's resulting state
is already reached in the stored template, the helper exits ``10``
("no mutation needed"). On actual mutation the exit code is ``0``. On ANY
error (DB-unreadable, malformed JSON, unknown op, missing required key)
it writes a one-line diagnostic to stderr and exits non-zero.

Stdlib-only (no pydantic / no sqlalchemy / no panel imports) so it can
run under the venv's minimal interpreter AND under the system Python 3
on the host at install-time.

DB schema (Sanaei/3x-ui):
    The ``settings`` table has columns ``(id, key, value)``.
    The Xray template config is stored under key ``xrayTemplateConfig``
    as a JSON string.  This is the template 3x-ui uses to regenerate
    ``config.json`` — it contains the top-level ``outbounds[]`` and
    ``routing{}`` arrays we need to patch.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

# ────────────────────────────────────────────────────────────────────────────
# Exit codes (same convention as xray_apply.py).
# ────────────────────────────────────────────────────────────────────────────
EXIT_OK_MUTATED = 0   # patch consumed + DB mutated → restart x-ui
EXIT_OK_NO_OP = 10    # patch consumed + DB already in target state
EXIT_BAD_PATCH = 2    # malformed patch file (schema / json / missing key)
EXIT_DB_IO = 3        # DB not readable / not parseable / write failed

# The standard 3x-ui settings key for the Xray template config.
_XRAY_TEMPLATE_KEY = "xrayTemplateConfig"

# Fallback DB paths (same order as panel/wizard/xui_detect.py).
_DEFAULT_DB_PATHS = (
    "/usr/local/x-ui/x-ui.db",
    "/etc/x-ui/x-ui.db",
)


def _err(msg: str) -> None:
    sys.stderr.write(f"xray_db_apply: {msg}\n")


def _db_path() -> Path:
    """Return the path to the 3x-ui SQLite DB.

    Honours the ``PSIPHON_XUI_DB_PATH`` env var (for tests).  Otherwise
    probes the canonical install paths used by Sanaei/3x-ui.
    """
    env = os.environ.get("PSIPHON_XUI_DB_PATH", "").strip()
    if env:
        return Path(env)
    for p in _DEFAULT_DB_PATHS:
        if Path(p).is_file():
            return Path(p)
    # Default to the most common path even if it doesn't exist yet —
    # the error message will be more helpful than a generic "not found".
    return Path(_DEFAULT_DB_PATHS[0])


def _load_patch(patch_path: Path) -> dict:
    """Parse the patch JSON; raise ``SystemExit`` on any schema error.

    Identical to ``xray_apply.py._load_patch`` — kept duplicated to
    preserve the stdlib-only, no-import constraint.
    """
    try:
        raw = patch_path.read_text(encoding="utf-8")
    except OSError as exc:
        _err(f"read {patch_path} failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_BAD_PATCH) from exc
    try:
        obj = json.loads(raw)
    except (TypeError, ValueError) as exc:
        _err(f"parse {patch_path} failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_BAD_PATCH) from exc
    if not isinstance(obj, dict):
        _err(f"{patch_path}: root is not a JSON object")
        raise SystemExit(EXIT_BAD_PATCH)
    op = obj.get("op")
    if op not in ("apply", "remove"):
        _err(f"{patch_path}: 'op' must be 'apply' or 'remove' (got {op!r})")
        raise SystemExit(EXIT_BAD_PATCH)
    code = str(obj.get("country_code") or "").strip().upper()
    if not code:
        _err(f"{patch_path}: 'country_code' missing or empty")
        raise SystemExit(EXIT_BAD_PATCH)
    try:
        public_port = int(obj["public_port"])
    except (KeyError, TypeError, ValueError) as exc:
        _err(f"{patch_path}: 'public_port' missing/invalid ({exc})")
        raise SystemExit(EXIT_BAD_PATCH) from exc
    inbound_tag = str(obj.get("inbound_tag") or f"in-{public_port}-tcp").strip()
    if not inbound_tag:
        _err(f"{patch_path}: 'inbound_tag' missing")
        raise SystemExit(EXIT_BAD_PATCH)
    socks_port: int | None = None
    if op == "apply":
        try:
            socks_port = int(obj["socks_port"])
        except (KeyError, TypeError, ValueError) as exc:
            _err(f"{patch_path}: op=apply requires a valid 'socks_port' ({exc})")
            raise SystemExit(EXIT_BAD_PATCH) from exc
    return {
        "op": op,
        "country_code": code,
        "socks_port": socks_port,
        "public_port": public_port,
        "inbound_tag": inbound_tag,
    }


# ---------------------------------------------------------------------------
# Outbound + routing rule upsert/strip — identical logic to xray_apply.py.
# Duplicated to keep this script stdlib-only with zero cross-file imports.
# ---------------------------------------------------------------------------

def _apply(cfg: dict, patch: dict) -> bool:
    """Idempotently upsert outbound+rule. Returns True iff the config changed.

    Identical to ``xray_apply.py._apply`` — duplicated intentionally.
    """
    code = patch["country_code"]
    out_tag = f"psiphon-out-{code}"
    in_tag = patch["inbound_tag"]

    outbounds = cfg.setdefault("outbounds", [])
    if not isinstance(outbounds, list):
        _err("config.outbounds is not a list")
        raise SystemExit(EXIT_DB_IO)
    routing = cfg.setdefault("routing", {})
    if not isinstance(routing, dict):
        _err("config.routing is not an object")
        raise SystemExit(EXIT_DB_IO)
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        _err("config.routing.rules is not a list")
        raise SystemExit(EXIT_DB_IO)

    new_outbound = {
        "tag": out_tag,
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": patch["socks_port"],
                    "users": [],
                }
            ]
        },
    }
    changed = False

    for i, ob in enumerate(outbounds):
        if isinstance(ob, dict) and ob.get("tag") == out_tag:
            if ob != new_outbound:
                outbounds[i] = new_outbound
                changed = True
            break
    else:
        outbounds.append(new_outbound)
        changed = True

    new_rule = {
        "type": "field",
        "inboundTag": [in_tag],
        "outboundTag": out_tag,
    }
    insert_at: int | None = None
    replaced = False
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            continue
        inbound_tags = r.get("inboundTag")
        match = (
            r.get("outboundTag") == out_tag
            and isinstance(inbound_tags, list)
            and in_tag in inbound_tags
        )
        if match:
            if r != new_rule:
                rules[i] = new_rule
                changed = True
            replaced = True
            break
        if insert_at is None and (
            r.get("protocol") == ["bittorrent"]
            or (
                isinstance(r.get("ip"), list)
                and any("geoip:private" in str(x) for x in r["ip"])
            )
        ):
            insert_at = i
    if not replaced:
        if insert_at is None:
            rules.append(new_rule)
        else:
            rules.insert(insert_at, new_rule)
        changed = True

    return changed


def _remove(cfg: dict, patch: dict) -> bool:
    """Idempotently strip outbound+rule. Returns True iff the config changed.

    Identical to ``xray_apply.py._remove`` — duplicated intentionally.
    """
    code = patch["country_code"]
    out_tag = f"psiphon-out-{code}"
    in_tag = patch["inbound_tag"]
    changed = False

    outbounds = cfg.get("outbounds")
    if isinstance(outbounds, list):
        kept = [
            ob
            for ob in outbounds
            if not (isinstance(ob, dict) and ob.get("tag") == out_tag)
        ]
        if len(kept) != len(outbounds):
            cfg["outbounds"] = kept
            changed = True

    routing = cfg.get("routing")
    if isinstance(routing, dict):
        rules = routing.get("rules")
        if isinstance(rules, list):
            kept_rules = [
                r
                for r in rules
                if not (
                    isinstance(r, dict)
                    and r.get("outboundTag") == out_tag
                    and isinstance(r.get("inboundTag"), list)
                    and in_tag in r["inboundTag"]
                )
            ]
            if len(kept_rules) != len(rules):
                routing["rules"] = kept_rules
                changed = True

    return changed


# ---------------------------------------------------------------------------
# DB read/write helpers
# ---------------------------------------------------------------------------

def _load_template(db_path: Path) -> tuple[dict, int | None]:
    """Read the ``xrayTemplateConfig`` from the 3x-ui SQLite DB.

    Returns ``(template_dict, row_id)`` where ``row_id`` is the primary
    key of the settings row (needed for the UPDATE).  Raises
    ``SystemExit(EXIT_DB_IO)`` on any DB or JSON error.

    If the ``xrayTemplateConfig`` key doesn't exist yet, returns a
    minimal default template and ``row_id=None`` (caller will INSERT).
    """
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
    except sqlite3.Error as exc:
        _err(f"open {db_path} failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_DB_IO) from exc

    try:
        cur = conn.execute(
            "SELECT id, value FROM settings WHERE key = ?",
            (_XRAY_TEMPLATE_KEY,),
        )
        row = cur.fetchone()
    except sqlite3.Error as exc:
        _err(f"query settings table failed: {type(exc).__name__}: {exc}")
        conn.close()
        raise SystemExit(EXIT_DB_IO) from exc

    if row is None:
        # The key doesn't exist — return a minimal default template.
        # 3x-ui normally creates this on first run, but if we're called
        # before that, we seed it with a sane skeleton.
        conn.close()
        default = {
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom",
                },
                {
                    "tag": "block",
                    "protocol": "blackhole",
                },
            ],
            "routing": {
                "rules": [],
            },
        }
        return default, None

    row_id, raw_value = row
    try:
        template = json.loads(raw_value)
    except (TypeError, ValueError) as exc:
        _err(f"parse xrayTemplateConfig JSON failed: {type(exc).__name__}: {exc}")
        conn.close()
        raise SystemExit(EXIT_DB_IO) from exc

    if not isinstance(template, dict):
        _err("xrayTemplateConfig root is not a JSON object")
        conn.close()
        raise SystemExit(EXIT_DB_IO)

    conn.close()
    return template, row_id


def _save_template(db_path: Path, template: dict, row_id: int | None) -> None:
    """Write the updated template back to the 3x-ui SQLite DB.

    If ``row_id`` is None, INSERT a new row; otherwise UPDATE the
    existing one.  Uses ``BEGIN IMMEDIATE`` so concurrent 3x-ui writes
    are serialized.
    """
    serialized = json.dumps(template, indent=2)
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
    except sqlite3.Error as exc:
        _err(f"open {db_path} for write failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_DB_IO) from exc

    try:
        conn.execute("BEGIN IMMEDIATE")
        if row_id is not None:
            conn.execute(
                "UPDATE settings SET value = ? WHERE id = ?",
                (serialized, row_id),
            )
        else:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                (_XRAY_TEMPLATE_KEY, serialized),
            )
        conn.execute("COMMIT")
    except sqlite3.Error as exc:
        _err(f"write xrayTemplateConfig failed: {type(exc).__name__}: {exc}")
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        conn.close()
        raise SystemExit(EXIT_DB_IO) from exc

    conn.close()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(__doc__ or "")
        return EXIT_BAD_PATCH
    patch_path = Path(argv[1])
    patch = _load_patch(patch_path)
    db_path = _db_path()

    if not db_path.is_file():
        _err(f"3x-ui DB not found at {db_path}")
        return EXIT_DB_IO

    template, row_id = _load_template(db_path)

    mutated = (
        _apply(template, patch) if patch["op"] == "apply" else _remove(template, patch)
    )

    if mutated:
        _save_template(db_path, template, row_id)
        sys.stderr.write(
            f"xray_db_apply: {patch['op']} for {patch['country_code']} "
            f"mutated xrayTemplateConfig in {db_path}\n"
        )

    # NOTE: we deliberately do NOT consume (unlink) the patch file here.
    # xray_applier.sh runs THIS helper FIRST, then xray_apply.py, which
    # unlinks the file unconditionally. Unlinking here would starve the
    # config.json helper of its input. If called standalone, the caller is
    # responsible for cleanup.
    return EXIT_OK_MUTATED if mutated else EXIT_OK_NO_OP


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
