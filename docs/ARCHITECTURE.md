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

### Per-country traffic flow at the Xray routing layer (Phase 26)

> **The panel originally relied on the cloned inbound's
> `streamSettings.outbound` field to direct traffic into the per-country
> SOCKS listener. Operationally verified to be INEFFECTIVE: Xray-core does
> not route by that field — 3x-ui persists it, but it's a persisted hint,
> not a routing decision. Outbound selection happens exclusively in the
> top-level `outbounds[]` + `routing.rules[]` arrays.**
>
> **Hotfix #9 tried to rewrite `/usr/local/x-ui/bin/config.json` directly
> from the panel process and DISCOVERED in production that the file is
> root:root mode 0600 on a stock 3x-ui install. The panel service runs as
> the unprivileged `psiphon3xui` user and could neither READ nor WRITE the
> live config. Every Hotfix-#9 helper call silently returned EACCES and
> the operator's traffic kept egressing via the default `freedom`
> outbound (`outbounds[0]`, tag=`direct`).**
>
> **Hotfix #10/#11 split the work across the privilege boundary with a
> queue + root oneshot applier sidecar. That whole design rested on the
> premise that no JSON API could write `outbounds[]`/`routing.rules[]`.
> The premise was wrong — 3x-ui exposes exactly such an API. Phase 26
> deletes the sidecar and uses it.**

The panel binds per-country routing through 3x-ui's **own supported
Xray-settings API** — see `panel/dashboard/xray_routing.py`:

* `POST /panel/api/xray/` reads the current Xray template.
* `POST /panel/api/xray/update` (form field `xraySetting`) validates the
  candidate config, persists it to the `xrayTemplateConfig` DB setting,
  and reconciles the running core — a gRPC hot-reload when only
  inbounds/outbounds/routing changed, so there's no restart and no
  dropped connections.

Because 3x-ui owns both the write and the reload, the panel needs **no
root, no polkit escalation, no systemd unit, and never touches
`/usr/local/x-ui/bin/config.json`**. This also closes the Hotfix-#10
failure mode where 3x-ui regenerated `config.json` from its SQLite DB on
restart and wiped the out-of-band edits.

### Privilege boundary — the one exception (Phase 28)

The panel runs as the unprivileged `psiphon3xui` service user and has no
shell access to the box. The **one narrow privilege escalation** is for
opening firewall ports: when the operator changes the panel port from
Settings (`POST /api/settings/panel-port`), the panel must open the new
port in ufw **before** it persists the change, or it comes back on a port
ufw is still filtering while the old port is already gone.

ufw is root-only. The polkit rule in `systemd/49-psiphon-3x-ui.rules`
grants only `org.freedesktop.systemd1.manage-units` and cannot cover ufw
(not a systemd unit). The installer drops in a sudoers file at
`/etc/sudoers.d/49-psiphon-3x-ui` (source:
[`systemd/49-psiphon-3x-ui.sudoers`](../systemd/49-psiphon-3x-ui.sudoers))
that grants the service user NOPASSWD on exactly `ufw allow <port>/tcp` —
no delete, no enable/disable, no reset, no default-policy change, and the
argument must be a bare 1-to-5-digit TCP port (see the file header for the
digit-class enumeration rationale). `install.sh --uninstall` removes it.

Each enabled country contributes:

* One outbound tagged `psiphon-out-<CODE>` (protocol `socks`, one server
  entry `127.0.0.1:<socks_port>`), **appended** — never prepended, since
  `outbounds[0]` is the default egress.
* One routing rule `{type: "field", inboundTag: [<actual inbound tag>],
  outboundTag: "psiphon-out-<CODE>"}`, inserted **before** the stock
  `bittorrent` / `geoip:private` catch-alls, since rules match top-to-bottom
  and first hit wins.

> **The inbound tag is read back, not assumed.** 3x-ui's
> `resolveInboundTag()` honours the requested tag only if it's free;
> otherwise it appends a collision suffix (`-2`) or changes the protocol
> segment (`udp`/`tcpudp` rather than `tcp`). Binding to a guessed
> `in-<port>-tcp` silently produces a rule that matches nothing, so
> `clone_country` passes the tag from the clone response (`clone_obj["tag"]`)
> through to `apply_country_binding`.

On country delete / disable the panel strips BOTH the outbound entry AND
the routing rule, so a removed inbound's tag can't leave a stale mapping
behind. Re-cloning strips before cloning for the same reason.

See `docs/XUI_API.md` for the API-shape reference and the upstream
behaviour notes.
