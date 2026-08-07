# Troubleshooting

Phase 0 / 2 entries — flesh out as Phase 3+ surfaces real failure modes.

## Installer

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to install required packages` | apt index stale / no network | `apt update`; check DNS / `time` (a broken clock breaks apt TLS) |
| `must be run as root` | ran without sudo | `sudo bash install.sh` |
| `install: invalid group 'psiphon3xui'` (during `run_psiphon_install`) | stale install of an old checkout where `installer/prepare_user.sh` is missing | re-clone / pull latest, then re-run; the helper creates the user+group *before* `run_psiphon_install` |
| `Group 'psiphon3xui' not found. Run installer/prepare_user.sh first` | helper was invoked standalone out-of-order | invoke via `bash install.sh` (which sources `prepare_user.sh` first), or source it yourself before invoking |
| Installer never opened the panel port in the firewall | Phase 29 removed host-firewall management entirely — the installer does not touch ufw | open the port yourself if you run an active firewall: `sudo ufw allow <panel_port>/tcp` (plus the cloud security group) |
| `golang-go did not install` / `Detected go 1.18` | Ubuntu 22.04 ships Go 1.18 from the base archive — too old for `psiphon-tunnel-core` v2.x | `sudo add-apt-repository ppa:longsleep/golang-backports && sudo apt-get update && sudo apt-get install golang-go`; requires Go ≥ 1.21 |
| `go build of ConsoleClient failed` | missing module cache, network blocked, or wrong Go version | Check `${LOG_FILE}`; run `cd /opt/psiphon-3x-ui/build-psiphon/ConsoleClient && GOOS=linux GOARCH=amd64 go build -v .` manually to see the real error; `go env GOPATH GOCACHE` |
| `Failed to clone psiphon-tunnel-core @ vX.Y.Z` | upstream tag missing or network blocked | browse https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases and bump `PSIPHON_TAG` at the top of `installer/psiphon_install.sh`; or `git ls-remote --tags https://github.com/Psiphon-Labs/psiphon-tunnel-core` |
| `python -m build --wheel failed` | missing build backend / setuptools | `apt install python3-build python3-setuptools python3-wheel`; or run `${VENV_DIR}/bin/pip install --upgrade build setuptools wheel` |
| `panel.seed failed to bootstrap panel.db` | wrong db_path perms / `bcrypt.gensalt` is slow on first CPU-bound run | inspect `${LOG_FILE}`; ensure `${INSTALL_PREFIX}` exists and is writable by root during install (`ls -la /opt/psiphon-3x-ui/`) |
| `systemctl start psiphon-3x-ui failed` (or socket never came up) | bad firewall / port in use / pydantic settings misread / **empty wheel** (see next row) / **port collision** (see below) | `journalctl -u psiphon-3x-ui -n 200 --no-pager`; verify `${ENV_FILE}` has `PSIPHON3XUI_PORT` set, no whitespace; `ss -ltnp` to check port collision |
| service loops crash-on-start with `ModuleNotFoundError: No module named 'panel'` (or `Status=1/FAILURE`, `Activating → active → failed`) and the panel URL is unreachable from a browser | `pyproject.toml` was inside `panel/` so setuptools' `where=["."]` looked for a non-existent `panel/panel/` and produced an **empty wheel** containing only `dist-info/*` | pull latest (pyproject.toml now lives at the repo root); the wheel now packages `panel/*.py`; rerun `sudo bash install.sh` |
| journalctl shows `Application startup complete.` followed by `[Errno 98] error while attempting to bind on address ('0.0.0.0', NNNN): address already in use` and `status=3/NOTIMPLEMENTED` in a tight restart loop | a stale Python/uvicorn process from a previous (failed) install is still bound to the panel port; the new unit can't bind | the latest `installer/panel_install.sh` runs a pre-flight `port_listeners` check AND `die`s with full journald context if the port can't come up. To fix manually: `sudo fuser -k ${PANEL_PORT}/tcp` (or `sudo ss -tlnp | grep :${PANEL_PORT}` to find the PID, then `sudo kill -9 <PID>`), then `sudo systemctl restart psiphon-3x-ui` |
| `Expected exactly one built wheel` | stale `dist/` directory containing two versions of the wheel | remove `${SCRIPT_DIR}/dist` and `${SCRIPT_DIR}/build` (now at repo root — no longer inside `panel/`) manually and re-run |

## Psiphon build-from-source notes

We build `ConsoleClient` directly from a pinned git tag rather than trusting a
prebuilt tarball because the upstream `psiphon-tunnel-core` releases ship only
mobile/Client-Library Go source — no Linux server binary. See
[`installer/README.md`](../installer/README.md) for the rationale.

If your first build fails on the `go build` step, the most common cause is an
old Go toolchain. Ubuntu 22.04 base ships Go 1.18; you need ≥ 1.21. Quick fix:

```bash
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt-get update
sudo apt-get install golang-go
go version    # should print go1.21 or newer
```

Then re-run `sudo bash /path/to/install.sh` (idempotent — it will rebuild).

## Panel

- **Can't reach the web UI:** check `systemctl status psiphon-3x-ui` and
  `journalctl -u psiphon-3x-ui -n 200`. If you run a host firewall or a cloud
  security group, confirm the panel port is allowed in it — the installer does
  not manage either (Phase 29).
- **Login fails after install:** the password was shown **once** at the end
  of the installer. If lost, re-run the installer (it's an upsert against the
  `Settings` row — a fresh `--password` will replace the bcrypt hash) or
  `${VENV_DIR}/bin/python -m panel.seed --port ... --user ... --password ...` directly.

### Changing the panel port from Settings (Phase 29)

`POST /api/settings/panel-port` does three things, in this order: refuse
up front if another process already holds the port, persist the new port
to `panel.db` **and** rewrite `PSIPHON3XUI_PORT` in `panel.env`, then
restart `psiphon-3x-ui.service`.

**The panel does not touch the host firewall.** Phase 28 tried to run
`ufw allow <port>/tcp` first, via a `sudo` grant at
`/etc/sudoers.d/49-psiphon-3x-ui`; Phase 29 removed all of it. The
installer never enabled ufw in the first place, so those rules filtered
nothing — the step's only effect was to abort port changes with a 502. If
your box does run an active firewall, open the new port yourself before
changing it here.

The browser is **not** redirected. After the request the service restarts
(the response may be cut short in flight — expected), and you reopen the
dashboard at `http://<host>:<new_port>/dashboard`.

| Symptom | Likely cause | Fix |
|---|---|---|
| Port change returns 409 `already in use` | something else on the box is listening on the requested port | `sudo ss -ltnp \| grep :<new_port>`; pick a free port or stop the other listener. Refused up front on purpose — `Restart=on-abort` does not retry a plain bind failure, so a restart onto a busy port would leave the panel down |
| Port change returns 502 `panel.env could not be rewritten` | `${INSTALL_PREFIX}/panel.env` is missing or not writable by the service user | `ls -la /opt/psiphon-3x-ui/panel.env`; re-run `sudo bash install.sh`. Nothing was persisted — the panel is still on the old port |
| Port change returned 200 but the panel never comes back | the restart failed, or a firewall/security group filters the new port | `sudo systemctl status psiphon-3x-ui`, `journalctl -u psiphon-3x-ui -n 200 --no-pager`; open the new port in your host firewall and cloud security group |
| Port change returns 502 `the firewall could not be updated …` | you are running a **pre-Phase-29 checkout** | pull latest and re-run `sudo bash install.sh`; the firewall step no longer exists |

## Wizard

- **"Country never connects"** — Psiphon tunnels may be blocked from the
  server's region. Health badges (Phase 6) will surface this; for now check
  `systemctl status psiphon-tunnel@<CODE>.service` and
  `journalctl -u psiphon-tunnel@<CODE> -n 200`.

## Psiphon Inc. upstream credentials — optional overrides (Phase 24)

> **Phase 24 (post-Hotfix-#14 cleanup): the public-bootstrap constants are
> baked in.** The four Psiphon-Inc upstream credentials the per-country
> tunnel units authenticate with (`PropagationChannelId`, `SponsorId`,
> `RemoteServerListUrl`, `RemoteServerListSignaturePublicKey`) — and the
> additional three modern Psiphon-3 client fields `ServerEntrySignaturePublicKey`,
> `ExchangeObfuscationKey`, `ObfuscatedServerListRootURLs` — are now baked
> into [`panel/psiphon/__init__.py`](../panel/psiphon/__init__.py) as
> `_PUBLIC_*` module constants. These constants are the universal
> **public-bootstrap** values Psiphon Inc. ships inside every public
> Psiphon-3 client binary (Play-Store APK, GitHub release binaries); they
> are NOT commercial secrets and embedding them in this public repo is not
> a leak. Per-country tunnels establish out-of-the-box with **no env vars
> required**.

### Background: what the panel ships + why

Pre-Hotfix #14 the panel shipped all-F's / all-0's / 64-hex placeholder
stubs for these credentials; they passed the psiphon-tunnel-core
`Config.Commit` empty-string check but failed downstream at remote
server-list signature verification, with the binary's only outward symptom
being:

```
noticeType=AvailableEgressRegions  data={"regions":[]}
noticeType=NetworkID              data={"ID":"UNKNOWN"}
…5 minutes later…
noticeType=EstablishTunnelTimeout  data={"timeout":"5m0s","Tunnels":0}  → Exiting
```

Hotfix #14 then pivoted the four credentials to **operator-supplied env-var
REQUIRED overrides** (the panel fast-failed at `render_config` time with an
actionable `PsiphonCredentialError` if any env var was missing or
placeholder-shaped). That installer-blocking gate was the root cause of
the user-reported Issues 2/3/4 ("add country throws PsiphonCredentialError
for PSIPHON_PROPAGATION_CHANNEL_ID", "after the wizard the country is not
active", "installation demands the four params with no clear path to
obtain them").

**Phase 24 inverts that gate**: the public-bootstrap constants are baked in
as defaults, and the four `PSIPHON_*` env vars become **OPTIONAL OVERRIDES**.
A commercial sponsor with its own PropagationChannelId / SponsorId / signed
server-list URL / signature public key can still substitute its values into
`/opt/psiphon-3x-ui/panel.env` and the panel picks them up at
`render_config` runtime — without forking the panel. The placeholder
rejector (`_looks_like_placeholder`) still fires on operator-supplied **BAD**
overrides so the panel fast-fails (instead of silently booting a binary that
spends 5 minutes in `EstablishTunnelTimeout`), but it does NOT fire on the
default code path (the baked-in `_PUBLIC_*` constants are pre-validated).

### How to substitute your commercial sponsor values (OPTIONAL)

The installer no longer surveys the operator at install time —
[`installer/prompt.sh`](../installer/prompt.sh)'s `_prompt_psiphon_credentials`
function was deleted in Phase 24, and
[`installer/panel_install.sh`](../installer/panel_install.sh)'s heredoc
emits an empty `${psiphon_creds_block}` by default. To substitute your own
commercial sponsor values, edit `panel.env` AFTER install + restart:

```bash
sudo vi /opt/psiphon-3x-ui/panel.env
#  append:
#    PSIPHON_PROPAGATION_CHANNEL_ID="<your 32-hex value>"
#    PSIPHON_SPONSOR_ID="<your 16-hex value>"
#    PSIPHON_REMOTE_SERVER_LIST_URL="<https://…>"
#    PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY="<base64 RSA-2048 SPKI>"
sudo systemctl restart psiphon-3x-ui
```

Then either re-run the wizard apply step (`POST /api/wizard/apply`) or hit
the inline-enable button on the dashboard. The first `render_config(...)`
call after restart picks up the override (only the four scalar fields
above can be overridden — `ServerEntrySignaturePublicKey`,
`ExchangeObfuscationKey`, and the plural `RemoteServerListURLs` /
`ObfuscatedServerListRootURLs` arrays are not env-overridable; they always
ship the public-bootstrap defaults).

| Env var (panel.env)                                | JSON field in `<CODE>.json`             | Format note |
| -------------------------------------------------- | --------------------------------------- | ----------- |
| `PSIPHON_PROPAGATION_CHANNEL_ID`                   | `PropagationChannelId`                  | 16 hex chars (uppercase; NOT all-`F`'s) |
| `PSIPHON_SPONSOR_ID`                               | `SponsorId`                             | 16 hex chars (distinct from PropChannel; NOT all-`0`'s) |
| `PSIPHON_REMOTE_SERVER_LIST_URL`                   | `RemoteServerListURLs`                  | wrapped to a 1-element TransferURL array with the URL **base64-encoded** (tunnel-core's `TransferURLs.DecodeAndValidate#90` decodes the URL field); must start with `https://` (or `http://`) |
| `PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY`  | `RemoteServerListSignaturePublicKey`   | **base64-encoded RSA-2048 SPKI** for the public client — ~716 chars. The base64 regex `[A-Za-z0-9+/]{42,}={0,2}` also tolerates shorter Ed25519 (~44 chars) keys. (NOT a bare 64-hex string.) |

> **Note**: `RemoteServerListSignaturePublicKey` is RSA-2048 (~716 base64
> chars) for the public Psiphon-3 client, NOT Ed25519. The Ed25519
> (~44 chars) key lives in the SEPARATE `ServerEntrySignaturePublicKey`
> field, which signs individual server entries inside the list (and is NOT
> env-overridable; the panel always ships the public-bootstrap Ed25519 default).

### Confirming the panel reads your override

There's no need to peek at the on-disk config JSON — the panel's
[`render_config`](../panel/psiphon/__init__.py) raises
`PsiphonCredentialError` if your override value looks like a placeholder,
**before** any config file is written. So this one-liner is a complete
credential sanity check after editing `panel.env`:

```bash
${VENV_DIR:-/opt/psiphon-3x-ui/venv}/bin/python -c \
  "from panel.psiphon import render_config; print(render_config('US', 1080).keys())"
# prints dict_keys([... 11 keys ...])  → override accepted / defaults in effect
# raises PsiphonCredentialError(...)   → your override value looks like a known placeholder
```

## Per-country Psiphon tunnels (`psiphon-tunnel@<CODE>.service`)

The Phase 4 apply step starts one systemd instantiated unit per country
selected during the wizard. Each unit reads its config from
`/opt/psiphon-3x-ui/config/<CODE>.json` (created by
[`panel.psiphon.write_config`](../panel/psiphon/__init__.py)) and listens on
`127.0.0.1:<socks_port>` only (the panel-port + each clone's public port are
separate). The unit template lives at
[`systemd/psiphon-tunnel@.service`](../systemd/psiphon-tunnel@.service).

| Symptom | Likely cause | Fix |
|---|---|---|
| `systemctl status psiphon-tunnel@US` shows `failed` (no journal) | config file missing — wizard apply step was killed mid-way or `config_dir` was wiped | `journalctl -u psiphon-tunnel@US -n 200 --no-pager`; faster-than-allows fix: re-run the wizard apply step (SSE stream is idempotent for already-applied rows). Unit screams `ERROR: … .json: no such file or directory` if the file is missing. |
| Unit starts but exits with `Status=1/FAILURE` and `bind on address ('127.0.0.1', 11002): address already in use` | a stale `ConsoleClient` process from a previous unit instance is still holding the SOCKS5 port (commonly happens after the apply step dies midway and the unit restarts before the old port is released) | `sudo ss -tlnp | grep :11002` (or use the configured `<socks_port>`); `sudo kill -9 <PID>`; `sudo systemctl reset-failed psiphon-tunnel@US`; `sudo systemctl restart psiphon-tunnel@US`. See [`panel/psiphon/__init__.py`](../panel/psiphon/__init__.py) `start_unit` for the open+connect health-probe pattern. |
| Unit is `active (running)` but SOCKS5 handshakes time out (`failed@75` in the SSE stream) | Psiphon tunnel-core hasn't yet dialled upstream; the `CONNECTION_WORKING_TIMEOUT`-second probe expires before the proxy answers | check `journalctl -u psiphon-tunnel@US -n 200`; if the unit logs "Connected" but the probe still fails, the panel-internal `health_probe` might be pointed at the wrong port — verify `/opt/psiphon-3x-ui/config/US.json` `LocalSocksProxyPort` matches the `PortAssignment.socks_port` row in `panel.db`. |
| Unit logs `Unknown EgressRegion "xx"` and exits | country code in the config filename doesn't match a `panel/data/countries.yaml` entry, or the wizard wrote the lowercase variant of a code that isn't uppercased in `render_config` (the renderer calls `.upper()`, but a hand-edited `US.json` won't be rewritten) | re-run the wizard apply step or open `/opt/psiphon-3x-ui/config/<CODE>.json` and check `PropagationChannelId` + `SponsorId` are present, `EgressRegion` is uppercase 2-letter, and `RemoteServerListUrl` matches `PSIPHON_REMOTE_SERVER_LIST_URL` in `panel.env` (see [Psiphon Inc. upstream credentials required](#psiphon-inc-upstream-credentials-required-hotfix-14) above). |
| `systemctl start psiphon-tunnel@XX` returns `Failed to start … Unit name does not match template` | `psiphon-tunnel@.service` was installed wrong (operator copied the file but didn't `systemctl daemon-reload`) | `sudo systemctl daemon-reload` then retry. Also confirm the template file mode is `0644` and lives under `/etc/systemd/system/` (not `/lib/systemd/system/`). |
| `systemctl status psiphon-tunnel@US` reports `(dead)` but `is_active` returned True during apply step | apply step spins up the unit then probes SOCKS5; if the unit dropped to `dead` between the start + probe calls (e.g. bogus `ExecStart=`), `is_unit_active` returns True from a cached `systemctl` invocation but the next call sees `dead`. The wizard replay handler now tolerates this — verify nothing else on the box is starting/stopping `psiphon-tunnel@*` outside the panel | `journalctl -u psiphon-tunnel@US -n 200` to see the actual exit reason; `systemd-analyze verify psiphon-tunnel@.service` to template-validate the unit file. |

### Investigating a stuck tunnel manually

```bash
# Inspect a per-country unit
sudo systemctl status psiphon-tunnel@US.service
sudo journalctl -u psiphon-tunnel@US.service -n 200 --no-pager

# Validate a unit's config file against the schema the panel actually writes
python -c "import json,sys; print(json.dumps(json.load(open('/opt/psiphon-3x-ui/config/US.json')), indent=2))" \
  | head -30

# Restart a single country's tunnel (idempotent — the SOCKS5 port is reused)
sudo systemctl restart psiphon-tunnel@US.service
```

### Generating all per-country units after install

The apply step writes configs and starts units for the countries selected in
the wizard, but does not start tunnels for un-selected countries or for
countries added to `panel/data/countries.yaml` after the wizard ran. To add a
new country later, re-run the wizard (the apply step is idempotent for
already-present `PortAssignment` rows) or manually:

```bash
# Render a config from the panel's own helper (must be on the box, in the venv)
${VENV_DIR}/bin/python -c "
from panel.psiphon import write_config
write_config('JP', socks_port=11003, config_dir='/opt/psiphon-3x-ui/config')
"

# Then start the per-country unit
sudo systemctl start psiphon-tunnel@JP.service
sudo systemctl status psiphon-tunnel@JP.service
```
