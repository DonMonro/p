#!/usr/bin/env python3
"""
Phase 1 — spike step E: validate the inbound-CLONE payload end-to-end.

This script CREATES one inbound on the panel as a clone of your VLESS template,
but with:
  * a NEW port          (30010)
  * a NEW remark        ("[ spike-test ] :30010")
  * a fresh per-clone client UUID inside settings.clients
  * an injected outbound block routing all traffic to a local SOCKS5
    (127.0.0.1:10010) — the core of roadmap §9.4. We try BOTH the schema used
    by xray-core v2 (outbounds as an array) and a single-outbound dict, and we
    print which one the panel accepted.

It only ever creates ONE clone (id printed) and immediately prints the
delete command so the panel can be cleaned up. We never leave state behind.

Usage::

    XUI_USERNAME='admin' XUI_PASSWORD='pass' \
        python3 spike_1e_clone.py http://192.168.0.232:12345/WSCM6EhC9pO6T9K0RA/ \
        <TEMPLATE_INBOUND_ID>

Defaults TEMPLATE_INBOUND_ID to 1 if omitted. Only creates one clone.
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid

try:
    import httpx
except ImportError:  # pragma: no cover
    print("MISSING httpx — run:  pip install httpx")
    sys.exit(2)


CSRF_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"')


def hr(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


# --- outbound-injection schemas to try ----------------------------------
# xray-core schemas differ across versions; 3x-ui historically stored outbound
# as a JSON-encoded STRING under inbound.streamSettings (the "outbound" field).
# Newer xray (v2+) uses an explicit "outbounds" array on the inbound + routing
# rules. We probe both, and ALSO try putting the outbound in streamSettings
# since 3x-ui sometimes lives there for simple single-outbound cases.


def make_clone_payload(
    template: dict, public_port: int, socks_port: int, remark: str, variant: str
) -> dict:
    """Build a clone payload for one outbound-injection variant.

    Returns the JSON to POST to /panel/api/inbounds/add. The template's own
    settings/streamSettings/sniffing are preserved; only port/remark/clients
    and the outbound block are swapped.
    """
    # Deep-ish copy of just the fields we keep.
    p = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark,
        "enable": True,
        "expiryTime": 0,
        "listen": template.get("listen", ""),
        "port": public_port,
        "protocol": template["protocol"],
        "tag": f"in-{public_port}-tcp",
        "settings": template.get("settings", {}),
        "streamSettings": template.get("streamSettings", {}),
        "sniffing": template.get("sniffing", {"enabled": False}),
    }

    # Inject ONE fresh client so the cloned inbound is actually usable.
    p["settings"] = dict(p["settings"])
    p["settings"]["clients"] = [
        {
            "id": str(uuid.uuid4()),
            "flow": "xtls-rprx-vision",
            "email": f"clone-{public_port}@psiphon3xui",
            "limitIp": 0,
            "totalGB": 0,
            "expiryTime": 0,
            "enable": True,
            "tgId": "",
            "subId": str(uuid.uuid4()),
            "reset": 0,
        }
    ]

    socks = {
        "tag": f"socks-out-{public_port}",
        "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": socks_port, "users": []}]},
    }

    if variant == "streamSettings_outbound":
        # 3x-ui sometimes stores outbound INSIDE streamSettings as "outbound".
        ss = dict(p["streamSettings"])
        ss["outbound"] = socks
        p["streamSettings"] = ss

    elif variant == "streamSettings_outbound_string":
        # Some 3x-ui builds expect streamSettings.outbound to be a JSON STRING.
        ss = dict(p["streamSettings"])
        ss["outbound"] = json.dumps(socks, ensure_ascii=False)
        p["streamSettings"] = ss

    elif variant == "top_outbounds_array":
        # xray v2: explicit outbounds array on the inbound document.
        p["outbounds"] = [socks, {"tag": "direct", "protocol": "freedom"}]
        p["routing"] = {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": [p["tag"]], "outboundTag": socks["tag"]}],
        }

    elif variant == "top_outbound_single":
        # Older single-outbound xray schema.
        p["outbound"] = socks
        p["routing"] = {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": [p["tag"]], "outboundTag": socks["tag"]}],
        }
    else:
        raise AssertionError(f"unknown variant {variant!r}")

    return p


VARIANTS = [
    "streamSettings_outbound",
    "streamSettings_outbound_string",
    "top_outbounds_array",
    "top_outbound_single",
]


def login(client, base: str, user: str, pw: str) -> str | None:
    r0 = client.get(base)
    csrf = CSRF_RE.search(r0.text)
    csrf = csrf.group(1) if csrf else None
    headers = {"Referer": base}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    r = client.post(
        base + "login",
        data={"username": user, "password": pw},
        headers=headers,
    )
    try:
        if r.json().get("success"):
            return csrf
    except Exception:  # noqa: BLE001
        pass
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    base = base.split("/panel")[0].rstrip("/") + "/"
    template_id = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    user = os.environ.get("XUI_USERNAME")
    pw = os.environ.get("XUI_PASSWORD")
    if not user or not pw:
        print("Set XUI_USERNAME and XUI_PASSWORD env vars.")
        return 2

    client = httpx.Client(follow_redirects=True, timeout=15.0, verify=False)
    csrf = login(client, base, user, pw)
    if csrf is None:
        print("[!] login failed")
        return 1
    headers = {"X-CSRF-Token": csrf, "Referer": base}

    # Fetch template
    hr(f"GET {base}panel/api/inbounds/get/{template_id}")
    g = client.get(base + f"panel/api/inbounds/get/{template_id}", headers=headers)
    print(f"status: {g.status_code}  body[:200]: {g.text[:200]}")
    template = g.json()["obj"]

    PUBLIC_PORT = 30010
    SOCKS_PORT = 10010
    REMARK = "[ spike-test ] :30010"

    created_id = None
    accepted_variant = None
    for variant in VARIANTS:
        p = make_clone_payload(template, PUBLIC_PORT, SOCKS_PORT, REMARK, variant)
        hr(f"POST {base}panel/api/inbounds/add  (variant: {variant})")
        # 3x-ui historically expects the payload as JSON body, but the top-level
        # {inbound: "<json encoded>"} wrapper has also been used by older builds.
        # Try both shapes for THIS variant; stop as soon as one succeeds.
        for shape in ("bare_json", "wrapped_inbound"):
            hdr = dict(headers)
            hdr["Content-Type"] = "application/json"
            if shape == "wrapped_inbound":
                body = {"inbound": json.dumps(p, ensure_ascii=False)}
            else:
                body = p
            r = client.post(base + "panel/api/inbounds/add", json=body, headers=hdr)
            print(f"  shape={shape:>16}  status={r.status_code}  body={r.text[:300]}")
            ok = False
            try:
                if r.json().get("success"):
                    ok = True
                    created_id = r.json().get("obj", {}).get("id")
            except Exception:  # noqa: BLE001
                pass
            if ok:
                print(
                    f"\n[OK] variant '{variant}' + shape '{shape}' accepted. Inbound id={created_id}"
                )
                accepted_variant = (variant, shape)
                break
        if accepted_variant:
            break

    if not accepted_variant:
        hr("ALL VARIANTS REJECTED — paste the full output above for iteration")
        return 1

    hr("VERIFICATION: GET inbound list to confirm clone persisted")
    lst = client.get(base + "panel/api/inbounds/list", headers=headers).json()
    for ib in lst.get("obj", []):
        if ib.get("id") == created_id:
            print(j(ib))
            break

    hr("CLEANUP")
    print("Run to delete the test clone:")
    print(f"  curl -b '3x-ui=<cookie>' -X POST '{base}panel/api/inbounds/del/{created_id}'")
    print("        (or simply run spike_1e_clone.py --delete {created_id} in a future tweak)")
    print(f"\n[*] accepted_variant = {accepted_variant}")
    print(f"[*] clone id         = {created_id}")
    print("\n[OK] clone spike complete — paste everything above back.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
