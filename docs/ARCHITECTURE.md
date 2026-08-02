# Architecture

> Source of truth: [`plans/ROADMAP.md`](../plans/ROADMAP.md) §3.

## High-level components

- `install.sh` — entry-point installer.
- `installer/*.sh` — sourced helpers, each exposing `run_<name>()`.
- `panel/` — FastAPI web app (wizard + dashboard REST API + static SPA).
- `panel/psiphon/` — generates per-country configs and (Phase 4) spawns tunnel
  processes via templated systemd units.
- `panel/dashboard/xui_client.py` — thin 3x-ui HTTP API client.
- `panel/data/countries.yaml` — single source of truth for supported countries (shipped inside the wheel).
- `systemd/` — unit templates installed at runtime.

## Data flow

```
client ──► 3x-ui inbound clone [flag country]:port ──► local SOCKS5
             │                                          │
             │  Xray core routing                       ▼
             │  (inboundTag=in-<port>-tcp         psiphon-tunnel-core
             │   → outboundTag=                      (EgressRegion=XY)
             │     psiphon-out-<CODE>)                    │
             │                                            ▼
             └── Xray socks outbound           Psiphon network ─► internet (XY exit)
                 (127.0.0.1:<socks_port>)
```

The panel maintains `panel.db` mapping each `Country` to a `PortAssignment`
(`socks_port` ↔ `public_port`) and a `CloneRecord` referencing the 3x-ui
inbound created for it.

### Per-country traffic flow at the Xray routing layer (Hotfix #10 / Phase 25)

> **Pre-Hotfix-#9 the panel relied on the cloned inbound's
> `streamSettings.outbound` field to direct traffic into the per-country
> SOCKS listener. Operationally verified to be INEFFECTIVE: Xray-core does
> not route by that field — it's a persisted sniffing hint, not a routing
> decision. The outbound selection happens in the top-level
> `routing.rules[]` array.**
>
> **Hotfix #9 tried to rewrite `/usr/local/x-ui/bin/config.json` directly
> from the panel process and DISCOVERED in production that the file is
> root:root mode 0600 on a stock 3x-ui install. The panel service runs as
> the unprivileged `psiphon3xui` user and could neither READ nor WRITE the
> live config. Every Hotfix-#9 helper call silently returned EACCES and
> the operator's traffic kept egressing via the default `freedom`
> outbound (`outbounds[0]`, tag=`direct`).**
>
> **Hotfix #10 splits the work across the privilege boundary with a tiny
> queue + oneshot applier sidecar (this section).**

The panel now writes a per-country *patch request* into a shared on-disk
queue directory; a root-running systemd `.path` + `.service` pair consumes
the queue and merges the request into `/usr/local/x-ui/bin/config.json`:

* One outbound per enabled country tagged `psiphon-out-<CODE>` (protocol
  `socks`, one server entry `127.0.0.1:<socks_port>`).
* One routing rule per enabled country:
  `{type: "field", inboundTag: ["in-<public_port>-tcp"], outboundTag:
  "psiphon-out-<CODE>"}` — the `in-<public_port>-tcp` tag matches the
  auto-tag 3x-ui assigns to every inbound.

The applier inserts the rule BEFORE the stock `bittorrent` /
`geoip:private` catch-alls so Xray matches it first. The JSON write is
atomic (tmp + rename, executed by the root service while holding an
`flock(2)` on a dedicated lockfile) and is followed by a single
`systemctl restart x-ui.service` once per trigger batch (the panel's
`.service` unit is NOT the unit being restarted, so the in-flight HTTP
response survives; the seq-of-patches-then-one-restart shape means a
wizard batch clone no longer pays N sequential restarts).

On country delete / disable the panel enqueues a `remove` patch; the
applier strips BOTH the outbound entry AND the routing rule so the
(now-absent) inbound's tag doesn't leak a stale mapping.

#### Xray applier sidecar

Three cooperating pieces bridge the panel's (unprivileged) worldview and
the root-owned on-disk config:

1. **Panel-side enqueue helper** — `panel/dashboard/router.py::
   _enqueue_xray_patch(op, country_code, socks_port, public_port)`.
   Atomically drops `<CODE>-<op>-<uuid8>.json` into
   `/opt/psiphon-3x-ui/xray-patch-queue/` via `tempfile.mkstemp` in
   the same directory followed by `os.replace` (rename — the only
   interposable-on-inotify syscall, so the watcher never sees a partial
   file). Honours `PSIPHON_XRAY_PATCH_QUEUE_DIR` for tests.

2. **Path unit** — `systemd/psiphon-xray-applier.path` (installed to
   `/etc/systemd/system/psiphon-xray-applier.path`, enabled via
   `systemctl enable --now`). Uses `PathChanged=<queue dir>` so the
   rename edge-triggers the service. Batches bursts via
   `TriggerLimitIntervalSec=70ms` so a RapidFIRE of panel edits lands as
   ONE service invocation.

3. **Service unit + applier script** —
   `systemd/psiphon-xray-applier.service` (`Type=oneshot`, `User=root`)
   execs `/usr/local/libexec/psiphon-3x-ui/xray-applier.sh`. The bash
   driver:
   * flock -x 9's `/opt/psiphon-3x-ui/xray-applier.lock` so two
     appliers never race config.json.
   * Iterates pending `*.json` in sorted order and hands each to
     `/usr/local/libexec/psiphon-3x-ui/xray_apply.py` (stdlib-only — no
     venv needed at install-time).
   * After ALL patches are processed, runs `systemctl restart
     x-ui.service` exactly once IF at least one patch mutated the config
     (the helper exits 0 = mutated / 10 = idempotent-no-op, so the
     restart is skipped on pure re-apply storms).

The polkit rule (`systemd/49-psiphon-3x-ui.rules`) authorises the panel
service user to ALSO `systemctl start psiphon-xray-applier.service` as a
belt-and-braces force-drain path; the path unit is the primary trigger.

See `docs/XUI_API.md` ("Why the panel uses a queue+applier instead of a
3x-ui JSON API") for the upstream-side rationale.
