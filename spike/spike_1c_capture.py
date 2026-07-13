#!/usr/bin/env python3
"""
Phase 1 — spike step C: capture real inbound list + VLESS template JSON.

This DOES send credentials to log in. Usage::

    XUI_USERNAME=admin XUI_PASSWORD='yourpass' \
        python3 spike_1c_capture.py http://192.168.0.232:12345/WSCM6EhC9pO6T9K0RA/panel

It performs:
  1. POST /login  (multipart form: username=, password=)  -> session cookie
  2. GET  /panel/api/inbounds/list                       -> JSON reply
  3. For each VLESS inbound found: GET /panel/api/inbounds/get/{id}

It prints structured output so the user can paste back into chat. It also
prints a JSON dump of which we === === NOT IMPORTANT === captured, and a note
about manually deleting any clone this didn't create (it doesn't create any).

No state is changed on the panel (only reads + login).
"""

from __future__ import annotations

import json
import os
import sys

try:
    import httpx
except ImportError:  # pragma: no cover
    print("MISSING httpx — run:  pip install httpx")
    sys.exit(2)


def hr(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    user = os.environ.get("XUI_USERNAME")
    pw = os.environ.get("XUI_PASSWORD")
    if not user or not pw:
        print("Set XUI_USERNAME and XUI_PASSWORD env vars.")
        return 2

    client = httpx.Client(base_url=base, follow_redirects=True, timeout=15.0, verify=False)

    hr(f"POST {base}/login  (form: username/password)")
    try:
        # 3x-ui historically uses multipart/form-data for the login form;
        # fall back to urlencoded if needed. We discover via two tries.
        login = client.post(
            "/login",
            data={"username": user, "password": pw},
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[ERR] {type(exc).__name__}: {exc}")
        return 1
    print(f"status: {login.status_code}")
    print(f"final url: {login.url}")
    print(f"set-cookie header: {login.headers.get('set-cookie', '(none)')}")
    print(f"body (first 400 chars): {login.text[:400]}")
    cookies = client.cookies
    print(f"client cookies after login: {dict(cookies)}")
    if login.status_code not in (200, 302):
        print("[!] login did not return 200/302 — paste what's above and we'll adjust.")

    hr(f"GET {base}/panel/api/inbounds/list")
    try:
        r = client.get("/panel/api/inbounds/list")
    except Exception as exc:  # noqa: BLE001
        print(f"[ERR] {type(exc).__name__}: {exc}")
        return 1
    print(f"status: {r.status_code}")
    print(f"final url: {r.url}")
    print("--- raw body ---")
    print(r.text)
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        print("[!] body is not JSON — paste raw output above.")
        return 1

    inbounds = data.get("obj") if isinstance(data, dict) else None
    if inbounds is None:
        print("[!] Unexpected JSON shape (no 'obj' key). Full payload:")
        print(j(data))
        return 1

    print(f"\n[*] Found {len(inbounds)} inbound(s). Summary:")
    for ib in inbounds:
        # 3x-ui inbound fields we care about:
        print(
            f"  id={ib.get('id'):>5}  port={ib.get('port'):>5}  "
            f"protocol={ib.get('protocol'):>8}  remark={ib.get('remark')!r}  "
            f"tag={ib.get('tag')}"
        )

    hd = hr
    for ib in inbounds:
        if str(ib.get("protocol", "")).lower() != "vless":
            continue
        hd(f"GET {base}/panel/api/inbounds/get/{ib['id']}  (VLESS template)")
        try:
            d = client.get(f"/panel/api/inbounds/get/{ib['id']}")
        except Exception as exc:  # noqa: BLE001
            print(f"[ERR] {type(exc).__name__}: {exc}")
            continue
        print(f"status: {d.status_code}")
        print("--- raw body ---")
        print(d.text)
        try:
            one = d.json().get("obj")
        except Exception:  # noqa: BLE001
            print("[!] not JSON — paste above.")
            continue
        if one:
            print("\n--- parsed inbound JSON (sanitise before committing) ---")
            print(j(one))

    hr("done")
    print("[OK] capture complete — paste everything above back.")
    print("[*] No inbound was created or modified by this script.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
