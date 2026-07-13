#!/usr/bin/env python3
"""
Phase 1 — spike step C2: corrected capture against the NEW React-based 3x-ui.

Findings from the previous run:
  * The frontend serves `window.X_UI_BASE_PATH = "/WSCM6EhC9pO6T9K0RA/"`
  * There is a `<meta name="csrf-token" content="...">` on the login page -> CSRF
  * Correct base path is `/WSCM6EhC9pO6T9K0RA/` (NOT `/panel`)
  * The login HTML is served at GET /  and the actual auth POST goes to
    /WSCM6EhC9pO6T9K0RA/login  (or possibly a JSON variant like /login)

This script:
  1. GET /  to parse the CSRF token + x_ui_base_path + cookie-refreshed session
  2. Tries MULTIPLE login variants against the right base path:
       a) POST /login  Content-Type: application/x-www-form-urlencoded  + X-CSRF-Token
       b) POST /login  Content-Type: application/json                    + X-CSRF-Token
  3. On whichever variant succeeds:
       GET /panel/api/inbounds/list      -> JSON inbound list
       GET /panel/api/inbounds/get/{id}  for each VLESS inbound (preserves your real fields)
  4. Prints a JSON dump for sanitising into tests/fixtures/xui/.

Usage::

    XUI_USERNAME='admin' XUI_PASSWORD='pass' \
        python3 spike_1c2_capture.py http://192.168.0.232:12345/WSCM6EhC9pO6T9K0RA/

Note the trailing base path now ends with /WSCM6EhC9pO6T9K0RA/  (NOT /panel).
"""

from __future__ import annotations

import json
import os
import re
import sys

try:
    import httpx
except ImportError:  # pragma: no cover
    print("MISSING httpx — run:  pip install httpx")
    sys.exit(2)


CSRF_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"')
BASE_PATH_RE = re.compile(r'window\.X_UI_BASE_PATH\s*=\s*"([^"]+)"')


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

    # We expect the user to pass the base path WITHOUT /panel. Normalise anyway.
    raw_base = sys.argv[1].rstrip("/")
    base = raw_base.split("/panel")[0].rstrip("/") + "/"  # /WSCM6EhC9pO6T9K0RA/
    user = os.environ.get("XUI_USERNAME")
    pw = os.environ.get("XUI_PASSWORD")
    if not user or not pw:
        print("Set XUI_USERNAME and XUI_PASSWORD env vars.")
        return 2

    client = httpx.Client(follow_redirects=True, timeout=15.0, verify=False)

    hr(f"GET {base}")
    r0 = client.get(base)
    print(f"status: {r0.status_code}")
    print(f"set-cookie (session refresh): {r0.headers.get('set-cookie', '(none)')[:200]}")
    body = r0.text
    csrf_match = CSRF_RE.search(body)
    bp_match = BASE_PATH_RE.search(body)
    csrf = csrf_match.group(1) if csrf_match else None
    bp = bp_match.group(1) if bp_match else None
    print(f"csrf-token from meta: {csrf!r}")
    print(f"X_UI_BASE_PATH:        {bp!r}")
    print(f"cookies after GET /:   {dict(client.cookies)}")
    if not csrf:
        print("[!] no CSRF token found — paste first 400 chars of body for inspection:")
        print(body[:400])

    login_variants = [
        # label, content-type, payload builder
        (
            "form + X-CSRF-Token",
            "application/x-www-form-urlencoded",
            {"username": user, "password": pw},
        ),
        (
            "json + X-CSRF-Token",
            "application/json",
            {"username": user, "password": pw},
        ),
    ]

    auth_success = False
    for label, ctype, payload in login_variants:
        url = base + "login"
        headers = {"Referer": base}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        hr(f"POST {url}  (variant: {label})")
        if ctype == "application/json":
            r = client.post(url, json=payload, headers=headers)
        else:
            r = client.post(url, data=payload, headers=headers)
        print(f"status: {r.status_code}")
        print(f"final url: {r.url}")
        print(f"set-cookie: {r.headers.get('set-cookie', '(none)')[:200]}")
        print(f"client cookies now: {dict(client.cookies)}")
        print(f"body (first 600 chars):\n{r.text[:600]}")
        # Heuristic: login succeeded if the response sets/refreshes the 3x-ui
        # cookie with a Path matching the base path and the body isn't an HTML
        # error page. We also accept JSON {success:true}.
        ok = False
        try:
            rj = r.json()
            ok = bool(rj.get("success") or rj.get("obj"))
            print(f"[json-parsed] ok={ok} payload={j(rj)[:300]}")
        except Exception:  # noqa: BLE001
            pass
        if not ok and "set-cookie" in r.headers and "3x-ui" in r.headers.get("set-cookie", ""):
            ok = True
            print("[heuristic] login cookie refreshed -> treating as success")
        if ok:
            auth_success = True
            print(f"\n[OK] login variant '{label}' succeeded. Stopping variants.")
            break

    if not auth_success:
        hr("LOGIN FAILED — paste everything for iteration")
        return 1

    # Now hit the inbounds endpoints with whatever cookie+csrf we have.
    api_base = base  # endpoints are like {base}panel/api/inbounds/list
    headers = {}
    if csrf:
        headers["X-CSRF-Token"] = csrf

    hr(f"GET {api_base}panel/api/inbounds/list")
    r = client.get(api_base + "panel/api/inbounds/list", headers=headers)
    print(f"status: {r.status_code}")
    print(f"final url: {r.url}")
    print(f"content-type: {r.headers.get('content-type', '?')}")
    print("--- raw body ---")
    print(r.text)
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        print("[!] not JSON — paste raw output for iteration.")
        return 1

    inbounds = data.get("obj") if isinstance(data, dict) else None
    if inbounds is None:
        print("[!] Unexpected JSON shape (no 'obj' key). Full payload:")
        print(j(data))
        return 1

    print(f"\n[*] Found {len(inbounds)} inbound(s). Summary:")
    for ib in inbounds:
        print(
            f"  id={ib.get('id'):>5}  port={ib.get('port'):>5}  "
            f"protocol={ib.get('protocol'):>8}  remark={ib.get('remark')!r}  "
            f"tag={ib.get('tag')!r}"
        )

    for ib in inbounds:
        hr(f"GET {api_base}panel/api/inbounds/get/{ib['id']}  ({ib.get('protocol')})")
        d = client.get(api_base + f"panel/api/inbounds/get/{ib['id']}", headers=headers)
        print(f"status: {d.status_code}")
        print("--- raw body ---")
        print(d.text)
        try:
            one = d.json().get("obj")
        except Exception:  # noqa: BLE001
            print("[!] not JSON — paste raw output.")
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
