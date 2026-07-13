# Test fixtures under tests/fixtures/xui/

Sanitised **request/response** JSON shapes captured from the live 3x-ui panel
during the Phase 1 spike. Real identifiers are replaced with obvious placeholder
zero-UUIDs — the structural shape is what the tests care about.

| File | Endpoint | Purpose |
|---|---|---|
| [`vless_template_get.json`](vless_template_get.json) | `GET /panel/api/inbounds/get/{id}` | A clean VLESS-naked template inbound (`settings.clients=[]`, plain TCP). The clone engine clones THIS. |
| [`vless_clone_add_response.json`](vless_clone_add_response.json) | `POST /panel/api/inbounds/add` | The panel's reply after accepting a clone. Note `streamSettings.outbound` is a `dict` (NOT a JSON string) — this is what 3x-ui stores — and the panel backfills/enriches the client entry server-side. |

## Verified contract (Phase 1 spike)

* **base path** — `{scheme}://{host}/{webBasePath}/`  (the `/panel` segment is a SPA page route, not the API prefix; must be stripped)
* **CSRF token** — `GET {base}` returns HTML containing `<meta name="csrf-token" content="...">` and `window.X_UI_BASE_PATH="..."`
* **login** — `POST {base}login` form-encoded `username`/`password` with header `X-CSRF-Token` → JSON `{"success": true, ...}`; sets the `3x-ui` cookie
* **read** — `GET {base}panel/api/inbounds/list` and `GET {base}panel/api/inbounds/get/{id}` with the same `X-CSRF-Token` header return `{success:true, obj: ...}`
* **create** — `POST {base}panel/api/inbounds/add` with `Content-Type: application/json` and **bare-JSON** body (NOT wrapped in `{inbound: "..."}`), header `X-CSRF-Token` → `{success:true, obj: <created inbound>}`
* **delete** — `POST {base}panel/api/inbounds/del/{id}`

## Where the SOCKS5 outbound lives

The clone engine puts the SOCKS5 outbound where 3x-ui expects it: in
**`streamSettings.outbound`** as an object (sibling of `network` / `security`),
with `settings.servers[0]` describing the local `127.0.0.1:<socks_port>` target.
This was the **first** of four variants trialled by `spike/spike_1e_clone.py`
and was accepted verbatim by the panel.

## Regenerating these fixtures

If the upstream 3x-ui frontend changes its inbound shape, re-run the spike scripts
under [`spike/`](../../spike/README.md) against a fresh test VM, sanitise the
captured JSON (replace real `uuid`/`id` values with the zero placeholders shown
here), and overwrite these files. The `pytest` suite in
[`tests/test_xui_client.py`](../test_xui_client.py) keys off structural fields
(`success`, `obj.id`, `obj.port`, `obj.streamSettings.outbound.protocol`), not
specific UUID values — so sanitised fixtures stay valid.
