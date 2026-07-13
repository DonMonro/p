#!/usr/bin/env python3
"""
Phase 1 — spike step B: connectivity + login-page probe.

Runs with NO credentials. It just confirms the base URL is reachable and the
login flow looks like the standard 3x-ui shape (HTML login page, expected
endpoints responding). Output is plain text so the user can paste it back.

Usage on the VM::

    python3 spike_1b_probe.py URL

where URL is the panel base URL WITHOUT the post-login subpaths, e.g.:

    python3 spike_1b_probe.py http://192.168.0.232:12345/WSCM6EhC9pO6T9K0RA/panel

This script writes only what it sees over HTTP — no creds sent, no DB touched.
"""

from __future__ import annotations

import sys
from urllib.parse import quote

try:
    import httpx
except ImportError:  # pragma: no cover
    print("MISSING httpx — run:  pip install httpx")
    sys.exit(2)


def hr(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    client = httpx.Client(base_url=base, follow_redirects=True, timeout=15.0, verify=False)

    hr(f"GET {base}/  (panel base)")
    try:
        r = client.get("/")
    except Exception as exc:  # noqa: BLE001
        print(f"[ERR] {type(exc).__name__}: {exc}")
        return 1
    print(f"status: {r.status_code}")
    print(f"final url: {r.url}")
    print(f"headers: {dict(r.headers)}")
    body = r.text
    print(f"body len: {len(body)}")
    # Look for telltale 3x-ui login-page markers.
    markers = [
        'id="username"',
        'name="username"',
        'id="password"',
        "3x-ui",
        "x-ui",
        "/login",
        "action",
    ]
    found = [m for m in markers if m.lower() in body.lower()]
    print(f"login markers found: {found}")
    print("--- first 800 chars of body ---")
    print(body[:800])

    hr("GET /login  (relative — testing login endpoint shape)")
    try:
        r2 = client.get("/login")
    except Exception as exc:  # noqa: BLE001
        print(f"[ERR] {type(exc).__name__}: {exc}")
        return 1
    print(f"status: {r2.status_code}")
    print(f"final url: {r2.url}")
    print("--- first 400 chars ---")
    print(r2.text[:400])

    # 3x-ui's POST login endpoint is typically POST {base}/login but the base
    # here is the *panel* path; the actual auth POST is one level up. Probe a
    # few candidates without sending any credentials so we know which returns
    # 400 (bad request, meaning the endpoint exists) vs 404 (doesn't exist).
    candidates = [
        "/login",
        "../login",
        "./login",
        "/panel/api/inbounds/list",
        "./api/inbounds/list",
    ]
    hr("Probing candidate auth/inbounds endpoint paths (HEAD where possible)")
    for path in candidates:
        try:
            r3 = client.get(path)
            print(f"GET  {path:>32}  -> {r3.status_code}  (final: {r3.url})")
        except Exception as exc:  # noqa: BLE001
            print(f"GET  {path:>32}  -> ERR {type(exc).__name__}: {exc}")

    hr("Decode the webBasePath from given URL for reference")
    print(f"base          = {base}")
    print(f"encoded base  = {quote(base, safe='/:')}")
    print("\n[OK] probe complete — paste everything above back.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
