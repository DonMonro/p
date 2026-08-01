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

### Per-country traffic flow at the Xray routing layer (Hotfix #9 / Phase 25)

> **Pre-Hotfix-#9 the panel relied on the cloned inbound's
> `streamSettings.outbound` field to direct traffic into the per-country
> SOCKS listener. Operationally verified to be INEFFECTIVE: Xray-core does
> not route by that field — it's a persisted sniffing hint, not a routing
> decision. The outbound selection happens in the top-level
> `routing.rules[]` array.**

The panel now edits `/usr/local/x-ui/bin/config.json` directly to inject:

* One outbound per enabled country tagged `psiphon-out-<CODE>` (protocol
  `socks`, one server entry `127.0.0.1:<socks_port>`).
* One routing rule per enabled country:
  `{type: "field", inboundTag: ["in-<public_port>-tcp"], outboundTag:
  "psiphon-out-<CODE>"}` — the `in-<public_port>-tcp` tag matches the
  auto-tag 3x-ui assigns to every inbound.

The routing rule is inserted BEFORE the stock `bittorrent` /
`geoip:private` catch-alls so Xray matches it first. The write is atomic
(tmp + rename) and is followed by `systemctl restart x-ui.service`
(synchronous — the panel is NOT the unit being restarted, so the in-flight
HTTP response survives; see the polkit rule extension in
`systemd/49-psiphon-3x-ui.rules`).

On country delete / disable the panel removes BOTH the outbound entry AND
the routing rule via the inverse helper, so the (now-absent) inbound's
tag doesn't leak a stale mapping.
