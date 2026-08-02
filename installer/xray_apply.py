#!/usr/bin/env python3
"""Apply a single per-country Xray outbound+routing patch to ``config.json``.

Phase 25 Hotfix #10: invoked ONCE per patch file by
``xray_applier.sh`` (running as root via psiphon-xray-applier.service
triggered from psiphon-xray-applier.path). The panel NEVER reads or writes
``/usr/local/x-ui/bin/config.json`` itself — the unprivileged
``psiphon3xui`` user can't (stock 3x-ui ships that file mode 0600
root:root). Instead the panel drops an atomic queue file describing the
binding into ``/opt/psiphon-3x-ui/xray-patch-queue/`` and the path
unit's trigger lands here.

Patch-file schema (a single JSON object)::

    {
      "op":           "apply" | "remove",      # required
      "country_code": "US",                    # required
      "socks_port":   11001,                   # required for op=apply
      "public_port":  31001,                   # required
      "inbound_tag":  "in-31001-tcp"           # required
    }

Behaviour:

* ``apply``  — upsert the per-country socks outbound keyed by
  ``tag == "psiphon-out-<CODE>"`` (replace in place if present, append
  otherwise) AND upsert the field routing rule keyed by
  ``(inboundTag == ["<inbound_tag>"], outboundTag == "psiphon-out-<CODE>")``
  inserted BEFORE the first existing ``bittorrent`` / ``geoip:private``
  catch-all so Xray's rule-matching prefers ours.

* ``remove`` — strip the outbound AND the rule (both keyed lookups are
  by-tag + by-inboundTag so sibling countries' entries survive intact).

Both ops are *idempotent at the config level*: if the patch's resulting
state is already reached in the on-disk config, the helper exits ``10``
("no mutation needed") so the surrounding applier script can skip the
x-ui.service restart. On actual mutation the exit code is ``0``. On ANY
error (file-unreadable, malformed JSON, unknown op, missing required key,
schema mismatch) it writes a one-line diagnostic to stderr and exits
non-zero.

Atomic reads/writes: the entire read + mutate + write is done while holding
the caller's flock(2), so no second applier instance can interleave; the
write itself is a ``pathlib.Path.write_text`` to a ``.tmp.<pid>`` sibling
followed by ``os.replace()`` — readers (x-ui itself, journald, operator)
always see either the old config or the new, never a partial.

Stdlib-only (no pydantic / no sqlalchemy / no panel imports) so it can
run under the venv's minimal interpreter AND under the system Python 3
(``/usr/bin/env python3``) on the host at install-time before the venv is
even provisioned.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# ────────────────────────────────────────────────────────────────────────────
# Exit codes (the surrounding xray_applier.sh switches on these).
# ────────────────────────────────────────────────────────────────────────────
EXIT_OK_MUTATED = 0   # patch consumed + config.json mutated → restart x-ui
EXIT_OK_NO_OP = 10    # patch consumed + config already in target state
EXIT_BAD_PATCH = 2    # malformed patch file (schema / json / missing key)
EXIT_CONFIG_IO = 3    # config.json not readable / not parseable as JSON


def _err(msg: str) -> None:
    sys.stderr.write(f"xray_apply: {msg}\n")


def _config_path() -> Path:
    env = os.environ.get("PSIPHON_XUI_XRAY_CONFIG_PATH", "").strip()
    if env:
        return Path(env)
    return Path("/usr/local/x-ui/bin/config.json")


def _load_patch(patch_path: Path) -> dict:
    """Parse the patch JSON; raise ``SystemExit`` on any schema error."""
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


def _load_config(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        _err(f"read {path} failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_CONFIG_IO) from exc
    try:
        cfg = json.loads(raw)
    except (TypeError, ValueError) as exc:
        _err(f"parse {path} failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_CONFIG_IO) from exc
    if not isinstance(cfg, dict):
        _err(f"{path}: root is not a JSON object")
        raise SystemExit(EXIT_CONFIG_IO)
    return cfg


def _atomic_write(path: Path, cfg: dict) -> None:
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    try:
        tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except OSError as exc:
        import contextlib  # noqa: PLC0415 — best-effort cleanup

        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        _err(f"write {path} failed: {type(exc).__name__}: {exc}")
        raise SystemExit(EXIT_CONFIG_IO) from exc


def _apply(cfg: dict, patch: dict) -> bool:
    """Idempotently upsert outbound+rule. Returns True iff the config changed."""
    code = patch["country_code"]
    out_tag = f"psiphon-out-{code}"
    in_tag = patch["inbound_tag"]

    outbounds = cfg.setdefault("outbounds", [])
    if not isinstance(outbounds, list):
        _err("config.outbounds is not a list")
        raise SystemExit(EXIT_CONFIG_IO)
    routing = cfg.setdefault("routing", {})
    if not isinstance(routing, dict):
        _err("config.routing is not an object")
        raise SystemExit(EXIT_CONFIG_IO)
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        _err("config.routing.rules is not a list")
        raise SystemExit(EXIT_CONFIG_IO)

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
    """Idempotently strip outbound+rule. Returns True iff the config changed."""
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


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write(__doc__ or "")
        return EXIT_BAD_PATCH
    patch_path = Path(argv[1])
    patch = _load_patch(patch_path)
    cfg_path = _config_path()
    cfg = _load_config(cfg_path)

    mutated = _apply(cfg, patch) if patch["op"] == "apply" else _remove(cfg, patch)

    if mutated:
        _atomic_write(cfg_path, cfg)
        sys.stderr.write(
            f"xray_apply: {patch['op']} for {patch['country_code']} mutated config\n"
        )
    # Remove (consume) the patch file regardless — even no-op patches are
    # "done" and must not linger to be re-consumed on the next trigger.
    try:
        patch_path.unlink(missing_ok=True)
    except OSError as exc:
        _err(f"unlink {patch_path} failed: {type(exc).__name__}: {exc}")
        return EXIT_CONFIG_IO
    return EXIT_OK_MUTATED if mutated else EXIT_OK_NO_OP


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
