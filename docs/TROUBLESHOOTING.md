# Troubleshooting

Phase 0 / 2 entries — flesh out as Phase 3+ surfaces real failure modes.

## Installer

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to install required packages` | apt index stale / no network | `apt update`; check DNS / `time` (a broken clock breaks apt TLS) |
| `must be run as root` | ran without sudo | `sudo bash install.sh` |
| `install: invalid group 'psiphon3xui'` (during `run_psiphon_install`) | stale install of an old checkout where `installer/prepare_user.sh` is missing | re-clone / pull latest, then re-run; the helper creates the user+group *before* `run_psiphon_install` |
| `Group 'psiphon3xui' not found. Run installer/prepare_user.sh first` | helper was invoked standalone out-of-order | invoke via `bash install.sh` (which sources `prepare_user.sh` first), or source it yourself before invoking |
| ufw rule add failed | ufw disabled; tolerated | installer continues; check `ufw status` |
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
  `journalctl -u psiphon-3x-ui -n 200`. Confirm the panel port is allowed in
  ufw and any cloud security group.
- **Login fails after install:** the password was shown **once** at the end
  of the installer. If lost, re-run the installer (it's an upsert against the
  `Settings` row — a fresh `--password` will replace the bcrypt hash) or
  `${VENV_DIR}/bin/python -m panel.seed --port ... --user ... --password ...` directly.

## Wizard

- **"Country never connects"** — Psiphon tunnels may be blocked from the
  server's region. Health badges (Phase 6) will surface this; for now check
  `systemctl status psiphon-tunnel@<CODE>.service` and
  `journalctl -u psiphon-tunnel@<CODE> -n 200`.

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
| Unit logs `Unknown EgressRegion "xx"` and exits | country code in the config filename doesn't match a `config/countries.yaml` entry, or the wizard wrote the lowercase variant of a code that isn't uppercased in `render_config` (the renderer calls `.upper()`, but a hand-edited `US.json` won't be rewritten) | re-run the wizard apply step or open `/opt/psiphon-3x-ui/config/<CODE>.json` and check `PropagationChannelId` + `SponsorId` are present, `EgressRegion` is uppercase 2-letter, and `RemoteServerListURLs` matches [`panel.psiphon.PSIPHON_REMOTE_SERVER_LIST_URLS`](../panel/psiphon/__init__.py). |
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
countries added to `config/countries.yaml` after the wizard ran. To add a
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
