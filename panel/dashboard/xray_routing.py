"""Per-country Xray outbound + routing-rule binding via the supported 3x-ui API.

Phase 26 (Bug: "only the inbound is created — no outbound, route or routing
path", users egress on the server's own IP).

Background — why this module exists
-----------------------------------
Earlier phases assumed 3x-ui exposed **no** API for mutating the top-level
``outbounds[]`` / ``routing.rules[]`` arrays (see the "No JSON API for
outbounds[] / routing.rules[]" section of ``docs/XUI_API.md``), and worked
around that with a root-privileged sidecar (Hotfix #10/#11) that patched the
SQLite ``xrayTemplateConfig`` row and ``/usr/local/x-ui/bin/config.json``
directly.

That premise was wrong. Upstream 3x-ui registers, in
``internal/web/controller/xray_setting.go``::

    g = g.Group("/xray")
    g.POST("/", a.getXraySetting)        # read the template
    g.POST("/update", a.updateSetting)   # write the template

mounted under the ``/panel/api`` group (``internal/web/controller/api.go``:
"Paths are /panel/api/setting/* and /panel/api/xray/*"). ``updateSetting``
reads the form field ``xraySetting``, calls ``SaveXraySetting`` (which
validates the config through xray-core, persists it to the
``xrayTemplateConfig`` DB setting) and then reconciles the running core —
"through the gRPC API when only inbounds, outbounds or routing rules changed,
with a process restart otherwise".

Using that endpoint is strictly better than the sidecar:

* it runs as the panel's own session (no root, no systemd path unit, no queue),
* 3x-ui validates the config before storing it (a malformed patch is rejected
  instead of bricking Xray on the next restart),
* the running core is reloaded immediately — usually *without* a disruptive
  full restart of x-ui.service,
* there is no window where the DB and the live ``config.json`` disagree.

What a country binding looks like
---------------------------------
For country ``US`` on public port ``30001`` with a Psiphon SOCKS5 listener on
``127.0.0.1:11001``, an "apply" produces exactly two entries:

``outbounds[]`` gains::

    {"tag": "psiphon-out-US", "protocol": "socks",
     "settings": {"servers": [{"address": "127.0.0.1", "port": 11001, "users": []}]}}

``routing.rules[]`` gains::

    {"type": "field", "inboundTag": ["in-30001-tcp"], "outboundTag": "psiphon-out-US"}

The rule is inserted *before* the first catch-all (``bittorrent`` /
``geoip:private``) because Xray evaluates rules top-to-bottom and the first
match wins.

Everything here is a pure function over a template ``dict`` so it is unit
testable without any HTTP or DB access; :func:`apply_country_binding` and
:func:`remove_country_binding` are the thin async I/O wrappers.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .xui_client import XuiClient, XuiClientError

_log = logging.getLogger(__name__)

__all__ = [
    "outbound_tag_for",
    "socks_outbound_for",
    "routing_rule_for",
    "upsert_binding",
    "strip_binding",
    "apply_country_binding",
    "remove_country_binding",
]


# ---------------------------------------------------------------------------
# Naming — the single source of truth for how a country maps to Xray tags.
# ---------------------------------------------------------------------------
def outbound_tag_for(country_code: str) -> str:
    """``"US"`` → ``"psiphon-out-US"``.

    Kept byte-identical to the tag the Hotfix #10/#11 sidecar helpers wrote
    (the since-deleted ``installer/xray_apply.py`` / ``xray_db_apply.py``), so a
    panel upgraded from that generation re-uses (and idempotently overwrites)
    the entries already present in the template instead of duplicating them.
    """
    return f"psiphon-out-{country_code.strip().upper()}"


def socks_outbound_for(country_code: str, socks_port: int) -> dict[str, Any]:
    """The SOCKS5 outbound pointing at this country's local Psiphon listener."""
    return {
        "tag": outbound_tag_for(country_code),
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": "127.0.0.1",
                    "port": int(socks_port),
                    "users": [],
                }
            ]
        },
    }


def routing_rule_for(country_code: str, inbound_tag: str) -> dict[str, Any]:
    """The field rule binding *inbound_tag* to this country's outbound."""
    return {
        "type": "field",
        "inboundTag": [inbound_tag],
        "outboundTag": outbound_tag_for(country_code),
    }


# ---------------------------------------------------------------------------
# Pure template transforms.
# ---------------------------------------------------------------------------
def _is_catch_all(rule: Any) -> bool:
    """True for the stock trailing rules our per-country rule must precede.

    Xray matches rules top-to-bottom and stops at the first hit, so a
    per-country rule placed *after* 3x-ui's ``bittorrent`` blackhole or its
    ``geoip:private`` block would never be reached for those flows.
    """
    if not isinstance(rule, dict):
        return False
    if rule.get("protocol") == ["bittorrent"]:
        return True
    ip = rule.get("ip")
    return isinstance(ip, list) and any("geoip:private" in str(x) for x in ip)


def upsert_binding(
    template: dict[str, Any],
    country_code: str,
    socks_port: int,
    inbound_tag: str,
) -> bool:
    """Idempotently add/refresh this country's outbound + routing rule.

    Mutates *template* in place. Returns ``True`` iff anything changed, so the
    caller can skip a no-op round-trip to the panel (which would otherwise
    bounce the Xray core for nothing).

    Only this country's two entries are touched — sibling countries, the
    operator's own outbounds, and the ``api`` / ``stats`` blocks in the
    template are all left byte-identical.
    """
    out_tag = outbound_tag_for(country_code)
    new_outbound = socks_outbound_for(country_code, socks_port)
    new_rule = routing_rule_for(country_code, inbound_tag)
    changed = False

    outbounds = template.setdefault("outbounds", [])
    if not isinstance(outbounds, list):
        raise ValueError("xray template 'outbounds' is not a list")

    for i, ob in enumerate(outbounds):
        if isinstance(ob, dict) and ob.get("tag") == out_tag:
            if ob != new_outbound:
                outbounds[i] = new_outbound
                changed = True
            break
    else:
        # A freedom/direct outbound must stay FIRST: Xray treats outbounds[0]
        # as the default egress for traffic no rule matched. Appending keeps
        # that invariant intact.
        outbounds.append(new_outbound)
        changed = True

    routing = template.setdefault("routing", {})
    if not isinstance(routing, dict):
        raise ValueError("xray template 'routing' is not an object")
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("xray template 'routing.rules' is not a list")

    # A country's rule is identified by its outboundTag ALONE, never by the
    # (outboundTag, inboundTag) pair. 3x-ui can hand the same country a
    # DIFFERENT inbound tag on a re-clone — resolveInboundTag() appends a
    # collision suffix ("-2") or swaps the protocol segment ("udp"/"tcpudp")
    # when the preferred tag is taken. Matching on the pair would leave the
    # old rule in place and append a second one; that stale rule is not just
    # cruft, it is a correctness hazard, because it sits EARLIER in the list
    # and would hijack traffic if its now-dead inbound tag is later reissued
    # to a different country. Collapse to exactly one rule per country.
    existing = [
        i for i, r in enumerate(rules) if isinstance(r, dict) and r.get("outboundTag") == out_tag
    ]
    if not (len(existing) == 1 and rules[existing[0]] == new_rule):
        for i in reversed(existing):
            del rules[i]
        insert_at = next((i for i, r in enumerate(rules) if _is_catch_all(r)), len(rules))
        rules.insert(insert_at, new_rule)
        changed = True

    return changed


def strip_binding(
    template: dict[str, Any],
    country_code: str,
    inbound_tag: str | None = None,
) -> bool:
    """Remove this country's outbound and its routing rule(s).

    Mutates *template* in place; returns ``True`` iff anything was removed.

    When *inbound_tag* is ``None`` every rule pointing at this country's
    outbound is dropped — that is what a "disable country" must do, since the
    country may have been re-cloned onto a different public port (and so a
    different inbound tag) since the rule was first written. Passing an
    explicit tag narrows the removal to that single binding.
    """
    out_tag = outbound_tag_for(country_code)
    changed = False

    outbounds = template.get("outbounds")
    if isinstance(outbounds, list):
        kept = [ob for ob in outbounds if not (isinstance(ob, dict) and ob.get("tag") == out_tag)]
        if len(kept) != len(outbounds):
            template["outbounds"] = kept
            changed = True

    routing = template.get("routing")
    if isinstance(routing, dict):
        rules = routing.get("rules")
        if isinstance(rules, list):
            kept_rules = [
                r
                for r in rules
                if not (
                    isinstance(r, dict)
                    and r.get("outboundTag") == out_tag
                    and (
                        inbound_tag is None
                        or (
                            isinstance(r.get("inboundTag"), list) and inbound_tag in r["inboundTag"]
                        )
                    )
                )
            ]
            if len(kept_rules) != len(rules):
                routing["rules"] = kept_rules
                changed = True

    return changed


# ---------------------------------------------------------------------------
# Async I/O wrappers — read template, transform, write back.
# ---------------------------------------------------------------------------
def _parse_template(raw: Any) -> dict[str, Any]:
    """Coerce the panel's ``xraySetting`` field into a dict.

    3x-ui returns it as a JSON *string* in some builds and as an already
    decoded object in others, so accept both rather than guessing.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise XuiClientError(f"xraySetting is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise XuiClientError("xraySetting did not decode to an object")
        return parsed
    raise XuiClientError(f"xraySetting has unexpected type {type(raw).__name__}")


async def _mutate_template(client: XuiClient, mutate) -> bool:
    """Read the template, apply *mutate*, and write it back if it changed.

    Returns ``True`` when an update was POSTed, ``False`` on a no-op. Skipping
    the write on a no-op matters: ``updateSetting`` reconciles the running core
    on every call, so a redundant write would disturb live connections for
    nothing.
    """
    setting = await client.get_xray_setting()
    template = _parse_template(setting.get("xraySetting"))
    if not mutate(template):
        return False
    await client.update_xray_setting(json.dumps(template, indent=2))
    return True


async def apply_country_binding(
    client: XuiClient,
    country_code: str,
    socks_port: int,
    inbound_tag: str,
) -> tuple[bool, str]:
    """Bind *inbound_tag* to this country's Psiphon SOCKS5 outbound.

    Returns ``(ok, error)``. Never raises — routing is applied *after* the
    inbound already exists, so a failure here must surface as a diagnostic
    rather than unwinding a successful clone.
    """
    try:
        changed = await _mutate_template(
            client,
            lambda t: upsert_binding(t, country_code, socks_port, inbound_tag),
        )
    except XuiClientError as exc:
        # Hotfix #14: LOG, don't just return. The silent-return design is what
        # let the double-encoded-`obj` bug ship — the clone reported success
        # and the missing routing was invisible in journalctl.
        _log.error(
            "xray routing FAILED for %s (inbound_tag=%s, socks=%s): %s — "
            "the inbound exists but has NO outbound/routing rule, so it will "
            "egress on the server's own IP",
            country_code,
            inbound_tag,
            socks_port,
            exc,
        )
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 — transport/JSON errors vary
        _log.exception(
            "xray routing FAILED for %s (inbound_tag=%s, socks=%s) — the "
            "inbound exists but has NO outbound/routing rule, so it will "
            "egress on the server's own IP",
            country_code,
            inbound_tag,
            socks_port,
        )
        return False, f"{type(exc).__name__}: {exc}"
    _log.info(
        "xray routing %s for %s (inbound_tag=%s, socks=%s)",
        "applied" if changed else "already current",
        country_code,
        inbound_tag,
        socks_port,
    )
    return True, ""


async def remove_country_binding(
    client: XuiClient,
    country_code: str,
    inbound_tag: str | None = None,
) -> tuple[bool, str]:
    """Remove this country's outbound + routing rule(s). Never raises."""
    try:
        changed = await _mutate_template(
            client,
            lambda t: strip_binding(t, country_code, inbound_tag),
        )
    except XuiClientError as exc:
        _log.error(
            "xray routing removal FAILED for %s (inbound_tag=%s): %s",
            country_code,
            inbound_tag,
            exc,
        )
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001
        _log.exception(
            "xray routing removal FAILED for %s (inbound_tag=%s)",
            country_code,
            inbound_tag,
        )
        return False, f"{type(exc).__name__}: {exc}"
    _log.info(
        "xray routing %s for %s",
        "removed" if changed else "already absent",
        country_code,
    )
    return True, ""
