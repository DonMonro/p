# Psiphon-3X-UI Panel

[![CI](https://github.com/psiphon-3x-ui/psiphon-3x-ui/actions/workflows/ci.yml/badge.svg)](https://github.com/psiphon-3x-ui/psiphon-3x-ui/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)

> Companion FastAPI panel that installs
> [Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core) alongside
> [Sanaei's 3x-ui](https://github.com/MHSanaei/3x-ui) on an Ubuntu server,
> exposing per-country outbound traffic through clones of an existing
> 3x-ui inbound.

This wheel is the **panel** component of the Psiphon-3X-UI project. The
companion installer (under `installer/`) downloads/built it, seeds a SQLite
`panel.db` with bcrypt-hashed admin credentials, and runs it behind a
`systemd` unit. On first launch the panel serves a setup wizard that creates
per-country Psiphon tunnel instances and clones an existing 3x-ui inbound
once per country — each clone's `streamSettings.outbound` points to the
matching local SOCKS5 proxy.

## Top-level docs

For project overview, install, license, and architecture docs see the
repository root `README.md` and `docs/`.

This `panel/README.md` is the file referenced by `readme = "panel/README.md"`
in the repo-root [`pyproject.toml`](../pyproject.toml). Earlier phases kept
`pyproject.toml` inside `panel/` and tried `readme = "../README.md"` — that
escaped the build-isolation root and broke `python -m build --wheel`; see
[`docs/TROUBLESHOOTING.md`](../docs/TROUBLESHOOTING.md) for the history.

## Wizard flow (Phase 3 + Phase 4)

The first-launch wizard lives under [`panel/wizard/`](wizard/) and is fronted
by the FastAPI router [`panel/wizard/router.py`](wizard/router.py). The state
machine advances through six steps:

```
countries → ports → apply → xui_creds → template → clone
              ▲          ▲           ▲           ▲         ▲
              └──────────┴───────────┴───────────┴─────────┘
            (Phase 3)   ──────── (Phase 4) ─────────────  (Phase 5)
```

Each step is guarded by `_require_step(row, expected)` so out-of-order callers
get `409 {"detail":"wizard is on step 'X'…","expected":"…","actual":"…"}`;

the `GET /api/wizard` endpoint returns the current state plus a per-step
payload for the frontend.

### Apply surface (Phase 4)

After country selection (Phase 3 — `POST /countries`) and port assignment
(Phase 3 — `POST /ports`), Phase 4 adds four handlers that bring up the
per-country Psiphon tunnels and capture the 3x-ui inbound to clone:

1. `POST /api/wizard/apply` — Server-Sent Events stream. For each selected
   country the panel **writes** a Psiphon config to
   `/opt/psiphon-3x-ui/config/<CODE>.json` (via
   [`panel.psiphon.write_config`](psiphon/__init__.py)), **starts** the
   `psiphon-tunnel@<CODE>.service` systemd unit (via
   [`panel.psiphon.start_unit`](psiphon/__init__.py)), confirms **active
   state** (`panel.psiphon.is_unit_active`) and probes the local SOCKS5
   port (`panel.psiphon.health_probe` — a SOCKS5 method-negotiation
   handshake). Each country emits a `working` record, then a terminal
   `healthy` / `failed@0|50|75` record, then a final `done` summary carries
   the full event list + the advanced wizard state. Full event shape in
   [`docs/XUI_API.md`](../docs/XUI_API.md) § *Wizard endpoints*.
2. `POST /api/wizard/xui-creds` — body `{base_url, username, password}`.
   Constructs an [`XuiClient`](dashboard/xui_client.py), awaits
   `client.login()`, and on success persists the credentials encrypted
   ([`panel.auth.encrypt_creds`](auth.py) — itsdangerous
   `URLSafeTimedSerializer` with the `Settings.session_secret`, salt
   `psiphon-3x-ui-credential-vault`) into a singleton `XUI_LINK` row. Advances
   the wizard to `template`.
3. `GET /api/wizard/inbounds` — proxies `XuiClient.list_inbound_summaries()`
   and returns a simplified `[{id, port, protocol, remark, tag}]` projection
   for the template-picker UI. Requires wizard at step `xui_creds` or later
   and a stored `XUI_LINK` row.
4. `POST /api/wizard/clone-template` — body `{template_inbound_id: int ≥ 1}`.
   Stores the picked inbound id in `step_data["template"]` and advances the
   wizard to `clone`, ready for the Phase 5 clone engine (`XuiClient.clone_inbound`)
   to mirror the template once per country with a SOCKS5 outbound pointing at
   the matching per-country tunnel.

### Per-country tunnel lifecycle

Every per-country tunnel is a systemd instantiated unit
([`systemd/psiphon-tunnel@.service`](../systemd/psiphon-tunnel@.service))
parameterised by the uppercased country code:

* **Config:** `/opt/psiphon-3x-ui/config/<CODE>.json` — written by
  [`panel.psiphon.render_config`](psiphon/__init__.py) + `write_config`
  with `EgressRegion=<CODE>`, `LocalSocksProxyPort=<socks_port>` (one
  distinct port per country maintained in the `PortAssignment` table),
  and the upstream Psiphon server-list URL set.
* **Unit:** `psiphon-tunnel@<CODE>.service` — `Type=exec`, restarts
  `on-failure` with a 5s backoff (the unit template does not own netns
  management — that's the operator's responsibility per the unit's
  comments).
* **Health:** the apply step's SOCKS5 method-negotiation probe against
  `127.0.0.1:<socks_port>` (see `health_probe`) is the only built-in
  liveness check; Phase 6 will add periodic health badges.

For troubleshooting a per-country unit — including the common
`address already in use` port-collision case — see
[`docs/TROUBLESHOOTING.md`](../docs/TROUBLESHOOTING.md)
§ *Per-country Psiphon tunnels*.

## Clone surface (Phase 5)

After `POST /api/wizard/xui-creds` + `POST /api/wizard/clone-template`,
Phase 5 finishes the wizard with two more handlers:

1. `POST /api/wizard/xui-detect` — runs
   [`panel.wizard.xui_detect.detect_xui`](wizard/xui_detect.py) (an async
   probe of common 3x-ui web paths + the canonical `/usr/local/x-ui/x-ui.db`
   file) and always advances the wizard to `xui_creds`. Detection is a
   **convenience**, not a gate — the response includes `candidates_probed`
   so the user can paste one manually if automatic detection comes up
   empty. The result is persisted in `step_data["xui_detect"]` for replay.
2. `POST /api/wizard/clone` — Server-Sent Events stream driving the
   per-country clone engine. For each persisted `PortAssignment` row (one
   per country from the apply step) the handler constructs a
   [`CloneSpec`](wizard/clone.py) and calls
   [`XuiClient.clone_inbound`](dashboard/xui_client.py), which:
   * GETs the template inbound JSON from `GET /panel/api/inbounds/get/<id>`,
   * rewrites `remark` to `[ <flag> <name> ] :<public_port>`,
     `port` to the new public port, injects a fresh VLESS client (new UUID +
     subId so each country has independent credentials — required to avoid
     per-clone UUID collisions, see roadmap §9.4 / §9.6), and injects
     `streamSettings.outbound` SOCKS5 pointing at `127.0.0.1:<socks_port>`
     (the Phase-1-verified clone schema),
   * POSTs the result to `POST /panel/api/inbounds/add`.
   The handler emits a `working` SSE record per country, then the terminal
   `cloned` / `failed` record, then a final `done` / `failed` summary
   carrying the full per-country `events` list + the `rolled_back` list.

### Rollback on partial failure

If *any* clone in the batch fails, the remaining specs are still attempted
(auditable), then the router deletes every previously-cloned inbound in
this batch via `XuiClient.delete_inbound` and removes the corresponding
`CloneRecord` rows from the DB — leaving the 3x-ui panel in the same
state it was in before the clone step ran. `Settings.wizard_completed`
only flips True on full success, so the next login surfaces the wizard
again (not the dashboard) until the user resolves the failure
(typically a port-in-use in 3x-ui or a stale template inbound) and re-
submits `POST /api/wizard/clone`.

### `done` step + `Settings.wizard_completed`

On a fully-successful batch the wizard advances to ``done`` and
[`Settings.wizard_completed`](models.py) flips True — `GET /api/me` then
returns `wizard_completed: true` and the front-end redirects to the
management dashboard instead of the wizard. The `CloneRecord` rows
persisted during this batch remain queryable so the Phase 6 dashboard can
render the country×inbound matrix and update `healthy` columns via SOCKS5
probes against the per-country `PortAssignment.socks_port`.

The full event shape + rollback semantics + 3x-ui payload body are
documented in [`docs/XUI_API.md`](../docs/XUI_API.md) § *Phase 5 — Clone
engine + Wizard finalize*.

## Dashboard surface (Phase 6)

Once `Settings.wizard_completed == True` the front-end redirects to
[`/dashboard`](../panel/static/dashboard.html) — a self-contained
Alpine.js + Pico.css SPA that drives the new `/api/dashboard/*` handlers
in [`panel/dashboard/router.py`](dashboard/router.py). All handlers are
session-cookie gated and run `_require_wizard_completed` first (pre-wizard
callers get `409 {"detail": "wizard has not completed yet …"}`).

The dashboard surface:

* **Countries panel** (`GET /api/dashboard/countries`) lists every
  `Country` row joined with its `PortAssignment` + `CloneRecord` siblings
  and a live `unit_active` flag driven by `panel.psiphon.is_unit_active`.
  The `PATCH /api/dashboard/countries/{code}` toggle drives
  `start_unit` / `stop_unit` and flips `Country.enabled`.

* **Ports edit + re-apply** (`POST /api/dashboard/countries/{code}/_ports`)
  re-writes the per-country Psiphon config with the new SOCKS port,
  restarts the systemd unit, updates the `PortAssignment` row, and—if a
  `CloneRecord` exists—deletes the stale 3x-ui inbound and re-clones the
  wizard's template with the new public port. Collisions with another
  country's assignment or with the panel's own listen port return `400`.

* **Full teardown** (`DELETE /api/dashboard/countries/{code}`) is best-effort
  across five steps (stop unit → remove `CloneRecord` → `delete_inbound` →
  remove `PortAssignment` → flip `Country.enabled = False`); each
  step's outcome is echoed in a structured summary so the operator can see
  which sub-step failed. The `Country` row itself is *not* deleted so the
  operator can re-enable later without re-running the wizard.

* **Logs tail** (`GET /api/dashboard/tunnels/{code}/logs?lines=200`) shells
  out to `journalctl -u psiphon-tunnel@<CODE>.service` and returns lines.
  Missing `journalctl` → `502` with the captured stderr.

* **Whole-panel reapply** (`POST /api/dashboard/reapply`) iterates every
  `PortAssignment` row (rewrites config + restarts unit) and optionally
  re-clones unhealthy `CloneRecord` rows from the wizard's template. Used
  as the "make it match" button after a partial-failure recovery.

* **Backup/restore** (`POST /api/dashboard/backup` + `/restore`) — the
  backup streams an `application/x-tar` blob containing `panel.db` + every
  `config/*.json`; restore reads an uploaded tar and overwrites the
  corresponding on-disk files, with zip-slip guarded member validation.

* **Settings** (`POST /api/dashboard/rotate-password` +
  `POST /api/dashboard/change-panel-port`). `rotate-password` re-verifies
  `current_password` against the stored bcrypt hash so a leaked session
  cookie alone can't change the password. `change-panel-port` persists the
  new `Settings.panel_port` (rejecting collisions with existing
  `PortAssignment.socks_port` / `public_port` rows) and surfaces a banner
  reminding the operator to run `systemctl restart psiphon-3x-ui.service`
  + `installer/firewall.sh` for the new port to take effect.

The full request/response shape + error codes for every handler are
documented in [`docs/XUI_API.md`](../docs/XUI_API.md) § *Phase 6 —
Management Dashboard surface*.

## License

MIT — see `LICENSE` in the repository root for the full text.
