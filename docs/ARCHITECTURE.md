# Architecture

> Source of truth: [`plans/ROADMAP.md`](../plans/ROADMAP.md) §3.

## High-level components

- `install.sh` — entry-point installer.
- `installer/*.sh` — sourced helpers, each exposing `run_<name>()`.
- `panel/` — FastAPI web app (wizard + dashboard REST API + static SPA).
- `panel/psiphon/` — generates per-country configs and (Phase 4) spawns tunnel
  processes via templated systemd units.
- `panel/dashboard/xui_client.py` — thin 3x-ui HTTP API client.
- `config/countries.yaml` — single source of truth for supported countries.
- `systemd/` — unit templates installed at runtime.

## Data flow

```
client ──► 3x-ui inbound clone [flag country]:port ──► local SOCKS5
                                                        │
                                                        ▼
                                                psiphon-tunnel-core
                                                (EgressRegion=XY)
                                                        │
                                                        ▼
                                          Psiphon network ─► internet (XY exit)
```

The panel maintains `panel.db` mapping each `Country` to a `PortAssignment`
(`socks_port` ↔ `public_port`) and a `CloneRecord` referencing the 3x-ui
inbound created for it.
