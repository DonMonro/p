# 3x-ui API integration — verified contract

> Finalised during the **Phase 1 spike** against a live 3x-ui VM running the
> new React/Vite frontend. Sanitised request/response fixtures live under
> [`tests/fixtures/xui/`](../tests/fixtures/xui/README.md) and an
> `respx`-mocked pytest suite lives at
> [`tests/test_xui_client.py`](../tests/test_xui_client.py).
>
> Reference panel: [Sanaei/3x-ui](https://github.com/MHSanaei/3x-ui).

## Base path

The user's panel URL has the form:

```
http(s)://<host>:<port>/<webBasePath>/panel
```

…where `<webBasePath>` is a random secret path (here `WSCM6EhC9pO6T9K0RA`).
The `/panel` segment is a **SPA page route**, not an API prefix.

The **API base** is therefore:

```
http(s)://<host>:<port>/<webBasePath>/
```

`XuiClient.__init__` strips any `/panel` suffix the caller may have copied from
the browser address bar, and the panel itself exposes `<meta name="base-path">`
plus `window.X_UI_BASE_PATH = "/<webBasePath>/"` on the login page to confirm.

## CSRF

Every page emitted by the panel contains a per-session CSRF token:

```html
<meta name="csrf-token" content="...">
```

Extract it once on login (regex `name="csrf-token"\s+content="([^"]+)"`) and
send it as the `X-CSRF-Token` request header on every subsequent API call,
including the `POST /login` itself (the panel accepts the login-page CSRF for
the login POST).

Session identity is otherwise carried by the `3x-ui` cookie, set on either the
GET of the login page or the login POST (httpx persists both automatically).

## Endpoints

| Method | Path | Request | Response |
|---|---|---|---|
| GET  | `{base}` | — | HTML login page (parse CSRF + base path from meta/script) |
| POST | `{base}login` | form-encoded `username`, `password`; header `X-CSRF-Token` | JSON `{success:true, msg:"You have successfully logged into your account.", obj:null}` |
| GET  | `{base}panel/api/inbounds/list` | header `X-CSRF-Token` | JSON `{success:true, msg:"", obj:[<inbound>, ...]}` |
| GET  | `{base}panel/api/inbounds/get/{id}` | header `X-CSRF-Token` | JSON `{success:true, msg:"", obj:<inbound>}` |
| POST | `{base}panel/api/inbounds/add` | `Content-Type: application/json`, **bare JSON body**, header `X-CSRF-Token` | JSON `{success:true, msg:"Inbound has been successfully created.", obj:<created inbound>}` |
| POST | `{base}panel/api/inbounds/update/{id}` | same as add | same as add |
| POST | `{base}panel/api/inbounds/del/{id}` | header `X-CSRF-Token` | JSON `{success:true, msg:"Inbound deleted", obj:null}` |

> ⚠️ **Bare JSON, not wrapped.** Some older 3x-ui builds accepted
> `{inbound: "<json string>"}`; the current build (Phase-1 verified) takes the
> inbound object directly as the request body. `XuiClient.add_inbound` therefore
> sends `json=payload` (httpx serialises to bare JSON).

## Inbound shape (VLESS, no TLS)

A clean VLESS-naked inbound returned by `GET /panel/api/inbounds/get/{id}`:

```json
{
  "id": 1, "up": 0, "down": 0, "total": 0,
  "remark": "baratest",
  "subSortIndex": 1, "enable": true, "expiryTime": 0,
  "trafficReset": "never", "lastTrafficResetTime": 0,
  "clientStats": [],
  "listen": "", "port": 21777,
  "protocol": "vless", "tag": "in-21777-tcp",
  "shareAddrStrategy": "listen", "shareAddr": "",
  "settings":        {"clients": [], "decryption": "none", "encryption": "none"},
  "streamSettings":  {"network": "tcp",
                       "tcpSettings": {"acceptProxyProtocol": false,
                                        "header": {"type": "none"}},
                       "security": "none"},
  "sniffing":        {"enabled": false}
}
```

Notes:
* `settings.clients` may be **empty** in a template inbound (the one we spiked
  had `clients: []`). The clone engine therefore **injects a fresh client**
  with new `id` and `subId` UUIDs so each cloned country inbound has
  independent client credentials (roadmap §9.4).
* The `list` endpoint additionally includes an `originNodeGuid` per row that
  the `get` endpoint omits; cloning only uses `get` output.
* The panel enriches the inbound after creation: a server-side `clientStats[]`
  row keyed by the new `subId` appears in the created inbound's response, and
  the client's `tgId` becomes `0`, `comment` and `created_at`/`updated_at`
  are populated. The clone engine does **not** need to provide these — it
  sends the minimal client fields the panel accepts.

## Where the SOCKS5 outbound lives

The Phase-1 spike tried four outbound-injection schemas. The panel *accepted
on the first try* a SOCKS5 outbound placed as `streamSettings.outbound`, an
object sibling of `network` / `tcpSettings` / `security`:

```json
"streamSettings": {
  "network": "tcp",
  "tcpSettings": {"acceptProxyProtocol": false, "header": {"type": "none"}},
  "security": "none",
  "outbound": {
    "tag": "socks-out-30001",
    "protocol": "socks",
    "settings": {
      "servers": [{"address": "127.0.0.1", "port": 10001, "users": []}]
    }
  }
}
```

This is the **lock-in** shape the production clone engine uses
(`panel.dashboard.xui_client._socks_outbound`).

Rejected variants (for the record):
* `streamSettings.outbound` as a JSON **string** — not required; dict is accepted.
* top-level `outbounds: [ ... ]` array (xray-core v2 schema) — not tested past
  the first variant succeeding; reserved for Phase 5 if a protocol requires it.
* top-level single `outbound: { ... }` (older xray schema) — same.

## Clone payload (VLESS)

The exact body `XuiClient.clone_inbound` POSTs to `…/inbounds/add`:

```json
{
  "up": 0, "down": 0, "total": 0,
  "remark": "[ US United States ] :30001",
  "enable": true, "expiryTime": 0,
  "listen": "",
  "port": 30001,
  "protocol": "vless",
  "tag": "in-30001-tcp",
  "settings":  {"clients": [<fresh client>],
                "decryption": "none", "encryption": "none"},
  "streamSettings": {<preserved template fields>, "outbound": <socks5 outbound>},
  "sniffing": {"enabled": false}
}
```

with `<fresh client>`:

```json
{
  "id": "<new uuid4>",
  "flow": "xtls-rprx-vision",
  "email": "clone-30001@psiphon3xui",
  "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": true,
  "tgId": "", "subId": "<new uuid4>", "reset": 0
}
```

The remark format `[ {flag} {name} ] :{port}` is the dashboard's display label
across both the wizard and management views — it must always contain the flag,
the human-readable country name, and the public port.

## Auth quirks (confirmed)

* **Cookie name:** `3x-ui`; path is the webBasePath; `HttpOnly`, `SameSite=Lax`,
  max-age ~21600s (6h). httpx persists it automatically when the client is
  reused across calls.
* **CSRF refresh:** the login response body sometimes re-issues a fresh
  `<meta name="csrf-token">`; `XuiClient.login` reparses if present.
* **No rate limit observed** during the spike, but the dashboard should not
  spam the API; collect inbounds once per wizard session and cache.

## Unsupported protocols (Phase 5)

`_build_clone_payload` raises `XuiClientError` for any non-VLESS protocol.
**VMess / Trojan / Shadowsocks** clones need separate spikes against inbounds
of each type, because:
* their `settings`/`streamSettings`/per-client shape differs,
* the SOCKS5 outbound may need to attach differently (per roadmap §9.4).

When Phase 5 spikes each one, add a `_build_clone_payload_<proto>` function,
dispatch on `protocol`, and add per-protocol fixtures under
`tests/fixtures/xui/` mirroring this VLESS set.

## Regenerating fixtures

If upstream changes the inbound shape, rerun
[`spike/spike_1c2_capture.py`](../spike/spike_1c2_capture.py) (capture) and
[`spike/spike_1e_clone.py`](../spike/spike_1e_clone.py) (create one test
clone), sanitise the captured JSON (replace real ids/uuids with zero
placeholders shown in the existing fixtures), and overwrite the files under
[`tests/fixtures/xui/`](../tests/fixtures/xui/).

## Wizard endpoints (Phase 4)

The panel mounts four additional endpoints under `/api/wizard/` that the
setup wizard uses **after** the countries + ports steps (`POST /countries`,
`POST /ports`) but **before** the Phase 5 clone engine. They are protected
by the same signed-session cookie as the rest of the panel API.

| Method | Path | Request body | Response |
|---|---|---|---|
| POST | `/api/wizard/apply` | — | `text/event-stream` (see below) |
| POST | `/api/wizard/xui-creds` | `{"base_url","username","password"}` | `{"ok": true, "wizard": {...}}` |
| GET  | `/api/wizard/inbounds` | — | `{"inbounds": [{id,port,protocol,remark,tag}], "count": N}` |
| POST | `/api/wizard/clone-template` | `{"template_inbound_id": int}` | `{"ok": true, "wizard": {...}}` |

The state-machine order enforced by the wizard is:

```
countries → ports → apply → xui_creds → template → clone
                                  ▲         ▲           ▲
                                  └─────────┴───────────┘  (Phase 4 endpoints)
```

### `POST /api/wizard/apply` (Server-Sent Events)

The apply step emits one SSE record per country plus a final summary record.
Each record is a single `data:` line carrying a JSON object; no `id:` or
`event:` lines are sent. The connection stays open until the final `done`
record is emitted.

**Per-country intermediate records** (emitted twice per country — first a
`working` record, then the terminal record from `apply_country`):

```json
{"step":"apply","country":"US","status":"working","progress":33,
 "message":"starting psiphon-tunnel@US…"}
{"step":"apply","country":"US","status":"healthy","progress":66,
 "detail":"SOCKS5 ok on 127.0.0.1:11002"}
```

`status` is one of: `working` (intermediate), `healthy` (probe ok),
`failed@0` (write_config error), `failed@50` (systemd unit never reached
`active`), `failed@75` (SOCKS5 health probe failed). `progress` is an
integer in `[0,100]` across the whole apply sequence.

**Final summary record:**

```json
{"step":"apply","country":"*","status":"done","progress":100,
 "message":"applied 3 countries",
 "events":[{"country":"DE","status":"healthy","progress":33,"detail":null},
           {"country":"US","status":"healthy","progress":66,"detail":"…"},
           {"country":"JP","status":"healthy","progress":99,"detail":"…"}],
 "wizard_state":{"current_step":"xui_creds","completed":false}}
```

On terminal failure (409 — wizard on wrong step, no countries selected,
invalid ports payload), FastAPI short-circuits with a plain JSON `{"detail":
"…"}` 4xx **before** the stream starts; the caller should not expect SSE
formatting on those paths.

### `POST /api/wizard/xui-creds`

Body:

```json
{"base_url":"http://127.0.0.1:8080/","username":"admin","password":"panel-pass"}
```

The handler constructs an `XuiClient`, calls `await client.login()`, and on
success persists the credentials encrypted with `panel.auth.encrypt_creds`
(signed with the `Settings.session_secret`, salt
`psiphon-3x-ui-credential-vault`) into a singleton `XUI_LINK` row, then
advances the wizard to `template`. On login failure it returns `400 {"detail":
"login failed: …"}`; on transport/error reaching the panel it returns `502
{"detail":"…"}`. The wizard must be on step `xui_creds` (i.e. `apply` done)
— out-of-order callers get `409`.

### `GET /api/wizard/inbounds`

No body. Requires wizard to be at step `xui_creds` or later and a stored
`XUI_LINK` row; returns the simplified inbound projection used by the
template-picker UI:

```json
{"inbounds":[
  {"id":17,"port":30000,"protocol":"vless","remark":"template-in","tag":"in-30000-tcp"},
  {"id":42,"port":30001,"protocol":"vless","remark":"other","tag":"in-30001-tcp"}],
 "count":2}
```

Returns `409 {"detail":"no 3x-ui credentials stored…"}` if the creds step
was skipped, or `502 {"detail":"…"}` on transport error or list failure.

### `POST /api/wizard/clone-template`

Body:

```json
{"template_inbound_id": 17}
```

`template_inbound_id` must be `≥ 1` (422 otherwise; missing field → 422).
The handler stores `{"template": {"template_inbound_id": 17}}` into the
wizard's `step_data` and advances the wizard to `clone`, ready for the
Phase 5 clone engine to consume it. Wizards not on step `template` receive
`409`.

## Phase 5 — Clone engine + Wizard finalize

The setup wizard's last two endpoints (`POST /api/wizard/xui-detect` and
`POST /api/wizard/clone`) drive the per-country clone engine and flip
`Settings.wizard_completed` to True on success.

### `POST /api/wizard/xui-detect`

No body. Wizard must be on step `xui_detect` (set by the apply step on
completion). Always advances the wizard to `xui_creds` — detection is a
**convenience**, not a gate, because `POST /api/wizard/xui-creds` accepts
a manual `base_url` regardless of probe outcome.

Response (status 200):

```json
{
  "current_step": "xui_creds",
  "is_completed": false,
  "steps": ["countries","ports","apply","xui_detect","xui_creds","template","clone","done"],
  "step_index": 4,
  "step_data": {"countries": {...}, "ports": {...}, "apply": {...},
                "xui_detect": {
                  "detected": false,
                  "base_url": "",
                  "db_path": "",
                  "candidates_probed": ["http://127.0.0.1:2053/", "http://127.0.0.1/panel/"],
                  "notes": "no 3x-ui login page recognised and no canonical DB found; ..."
                }},
  "detect": {
    "detected": false,
    "base_url": "",
    "db_path": "",
    "candidates_probed": ["http://127.0.0.1:2053/", "http://127.0.0.1/panel/"],
    "notes": "no 3x-ui login page recognised and no canonical DB found; ..."
  }
}
```

`candidates_probed` is the full list of URLs the panel tried, useful for
debugging when no panel is detected (the user can paste one manually into
`POST /api/wizard/xui-creds`). Out-of-order callers get `409 {"detail":
"wizard is on step 'X'…"}`; unauthenticated callers get `401`.

### `POST /api/wizard/clone` (Server-Sent Events)

No body. Wizard must be on step `clone` (set by the clone-template step).
Three pre-condition checks raise plain JSON `409` before the stream starts:

| Condition | 409 detail |
|---|---|
| `step_data["template"]["template_inbound_id"]` missing or invalid | `"no template inbound selected (POST /api/wizard/clone-template first)"` |
| No `PortAssignment` rows in the DB | `"no PortAssignment rows — re-run the wizard's /apply step"` |
| No cached `XUI_LINK` row | `"no 3x-ui credentials stored (POST /api/wizard/xui-creds first)"` |

The handler then constructs a list of [`CloneSpec`](../panel/wizard/clone.py)
— one per persisted `PortAssignment` row (sorted alphabetically by country
code, matching the apply step's ordering) — and drives an `XuiClient` from the
cached creds:

```python
for spec in specs:
    yield working_record
    clone_obj = await xui_client.clone_inbound(
        template_id=spec.template_id,
        country=spec.country,             # {code, name, flag} from Country row
        socks_port=spec.socks_port,
        public_port=spec.public_port,
    )
    yield clone_event                     # cloned | failed
```

**Per-country intermediate record:**

```json
{"step":"clone","country":"DE","status":"working","progress":0,
 "message":"cloning template 17 for DE → public_port=31001…"}
```

**Per-country terminal record (cloned):**

```json
{"step":"clone","country":"DE","status":"cloned","progress":100,
 "inbound_id":31001,
 "message":"cloned inbound 31001 for DE on public_port=31001 → socks=11001"}
```

`status` is one of `cloned` (success), `failed` (progress 0 = API error,
progress 50 = API returned non-int / negative `id`).

**Final summary record (full success):**

```json
{"step":"clone","country":"*","status":"done","progress":100,
 "message":"cloned 3 countries — wizard complete",
 "events":[<per-country dicts>],
 "rolled_back":[],
 "wizard_state":{"current_step":"done","is_completed":true,
                 "steps":[...],"step_index":7,"step_data":{...}}}
```

On full success the wizard advances to `done`, `Settings.wizard_completed`
flips True (next login shows the management dashboard), and a
`CloneRecord` row is persisted per successful clone keyed by the new
inbound id.

**Rollback on partial failure.** If *any* clone in the batch fails, the
remaining specs are still attempted (so the caller has a full audit
trail), then the router emits a `rolled_back` list of inbound ids that
were freshly-cloned and then deleted via `XuiClient.delete_inbound`:

```json
{"step":"clone","country":"*","status":"failed","progress":100,
 "message":"cloned 2/3 countries — 2 clone(s) rolled back via delete_inbound",
 "events":[<per-country dicts>, <rollback-fuss dicts country='*' if any delete failed>],
 "rolled_back":[31002,31003],
 "wizard_state":{"current_step":"clone","is_completed":false,...}}
```

The wizard stays on `clone` on failure — the user must fix the underlying
issue (typically a port-in-use error in 3x-ui, or a missing template) and
re-submit `POST /api/wizard/clone`. The clone engine is **not yet**
idempotent across re-submits (re-submitting will create a second batch of
clones) — the dashboard's "re-apply" handler (Phase 6) will handle the
cleanup-then-recreate flow idempotently. A `delete_inbound` failure during
rollback is logged in the events array but does *not* abort the rollback
loop — the orphaned clone id appears in `rolled_back` anyway so the user
can see and manually delete it from the 3x-ui panel.

## `CloneRecord` schema (panel.db)

Each successful clone persists one row:

| Column | Type | Notes |
|---|---|---|
| `inbound_id` | INTEGER PK | The panel-assigned inbound id (from `clone_obj.id`). |
| `country_code` | TEXT, FK → `country.code` | The country this clone serves. |
| `public_port` | INTEGER | The 3x-ui inbound listener port. |
| `socks_port` | INTEGER | The local SOCKS5 port this clone routes to. |
| `healthy` | BOOLEAN | Defaults to True; the Phase 6 dashboard updates it via SOCKS5 probes. |

The router handler persists these rows *before* the rollback loop runs,
so failed batches leave no `CloneRecord` rows behind (the loop deletes
them along with the upstream inbounds). On full success they remain
queryable so the dashboard can render the country×inbound matrix.

### Rabbit-hole: why SSE for apply (and not a plain POST)

Two earlier prototypes returned a single JSON blob with an `events` array
after the entire apply sequence finished. That blocks the caller for ~10s
per country (mostly the SOCKS5 health-probe timeout) and gives the user no
progress indication; a 30-second POST is indistinguishable from a hang.
SSE gives the wizard UI a per-country tick — it can render a progress bar
scrolling per country as each `working`/`healthy` record arrives, while
still letting the final `done` record carry the full `events` list for the
Phase 5 clone engine. See [`panel/wizard/router.py`](../panel/wizard/router.py)
`submit_apply` for the exact generator shape — note FastAPI requires
`StreamingResponse(generator(), media_type="text/event-stream")` rather than
`async def` + bare `yield` (the latter returns an `async_generator` that
FastAPI does not auto-wrap).

---

## Phase 6 — Management Dashboard surface

The dashboard surface replaces the wizard on subsequent logins (when
`Settings.wizard_completed == True`). All handlers are mounted under
`/api/dashboard` (see [`panel/dashboard/router.py`](../panel/dashboard/router.py))
and require a valid session cookie. Every handler runs the
`_require_wizard_completed` gate first; pre-wizard callers get `409 {
"detail": "wizard has not completed yet …" }` so the front-end can redirect
to `/wizard`. Missing `Settings` rows return `503` instead (the installer
hasn't run yet).

Each country is listed by `GET /api/dashboard/countries` as a *card* joining
the `Country` row with its `PortAssignment` + `CloneRecord` siblings, plus a
live `unit_active` flag driven by `panel.psiphon.is_unit_active`:

```json
{
  "code": "US", "name": "United States", "flag": "🇺🇸", "region": "Americas",
  "enabled": true, "assigned": true,
  "socks_port": 11001, "public_port": 31001,
  "unit_active": true, "inbound_id": 31001, "healthy": true
}
```

`t_unit_active` and `_country_card` swallow `systemctl` failures (best-effort
→ `False`) so a transient `systemctl is-active` non-zero exit never
500s the dashboard.

`enabled` toggles through `PATCH /api/dashboard/countries/{code}`:

* `enabled == True` → `start_unit(code)` + `Country.enabled = True` (409 if
  the country has no `PortAssignment` row — add via the wizard's
  add-country flow rather than PATCH).
* `enabled == False` → `stop_unit(code)` + `Country.enabled = False`
  (best-effort: a failed `stop_unit` is logged and the flag is still
  flipped so the operator isn't stuck with a half-stopped unit).

`DELETE /api/dashboard/countries/{code}` performs a full teardown in five
best-effort steps (each step's outcome surfaces in the structured summary):

1. `stop_unit(code)` (`stopped_unit: true/false`)
2. Remove the `CloneRecord` row (`removed_clone_record: true/false`)
3. `XuiClient.delete_inbound(old_inbound_id)` (`deleted_inbound` /
   `deleted_inbound_error`)
4. Remove the `PortAssignment` row (`removed_assignment: true/false`)
5. `Country.enabled = False` (preserved as a selectable row; not deleted)

`POST /api/dashboard/countries/{code}/_ports` is the re-apply step: it
re-writes the per-country Psiphon config with the new SOCKS port, restarts
the systemd unit, updates the `PortAssignment` row, then—if a `CloneRecord`
exists—deletes the stale 3x-ui inbound and re-clones the wizard's template
with the new public port. The template id is pulled from
`Wizard.step_data["template"]["template_inbound_id"]`; if missing the
`reclone_error` field explains the issue and the local config+unit steps
still proceed.

The whole-panel reapply (`POST /api/dashboard/reapply`) iterates every
`PortAssignment` row (rewrites config + restarts unit) and optionally
re-clones unhealthy `CloneRecord` rows from the wizard template. Returned
summary:

```json
{
  "applied":     [{"code": "DE", "socks_port": 11002}, …],
  "failed":      [{"code": "US", "error": "PsiphonUnitError: …"}],
  "recloned":    [{"code": "JP", "old_inbound_id": 31002, "new_inbound_id": 31003}],
  "reclone_errors": [{"code": "GB", "error": "xui: add_inbound: API failure"}]
}
```

`GET /api/dashboard/tunnels/{code}/logs?lines=200` runs
`journalctl -u psiphon-tunnel@<CODE>.service -n <lines> --no-pager` and
returns `{code, unit, lines_requested, lines, count}`. `lines` must be in
\[1, 5000\]; missing/failed `journalctl` returns `502 {"detail": "journalctl
failed: …"}` so the front-end can show an inline hint.

`POST /api/dashboard/backup` streams `application/x-tar` containing
`panel.db` + every `config/*.json`. The front-end honors
`Content-Disposition: attachment; filename="psiphon-3x-ui-backup-<UTC-ts>.tar"`.
`POST /api/dashboard/restore` reads an uploaded tar file and overwrites
the on-disk `panel.db` + matching config entries — zip-slip guarded, with
`{restored_panel_db, restored_configs, skipped, errors}` structured reply.

`POST /api/dashboard/rotate-password` re-verifies `current_password`
against the stored bcrypt hash (a stale session cookie alone can't change
the password) and writes a fresh hash. `POST /api/dashboard/change-panel-port`
persists the new `Settings.panel_port` (rejecting collisions with existing
`PortAssignment.socks_port` / `public_port` rows) and surfaces a banner
reminding the operator to `systemctl restart psiphon-3x-ui.service` and
re-run `installer/firewall.sh` — the panel listens on the persisted port but
the actual `psiphon-3x-ui.service` unit needs a restart for that to take
effect.
