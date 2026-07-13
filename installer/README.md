# Installer helper scripts

Every file here is **sourced** by [`../install.sh`](../install.sh) (or by the
Phase-2 panel backend when it needs to invoke subsystem commands). Each helper
exposes exactly one ``run_<name>()`` function and is `shellcheck`-clean.

## Module overview

| File | `run_*()` function | Responsibility |
|------|--------------------|-----------------|
| [`deps.sh`](deps.sh) | `run_deps` | apt install: python3 (venv/pip/build), golang-go, git, jq, ufw, … |
| [`prepare_user.sh`](prepare_user.sh) | `run_prepare_user` | Create `psiphon3xui` system user/group + set prefix ownership (MUST run before psiphon_install / panel_install so their `install -g` works) |
| [`prompt.sh`](prompt.sh) | `run_prompt` | Interactive port/username/password; Enter for random value; `read -s` password |
| [`psiphon_install.sh`](psiphon_install.sh) | `run_psiphon_install` | Build `psiphon-tunnel-core` from a pinned upstream tag, install + SHA256 manifest |
| [`panel_install.sh`](panel_install.sh) | `run_panel_install` | venv, build wheel, `panel.seed` the DB, write `panel.env`, register systemd unit (defensively guards that the user/group already exists) |
| [`firewall.sh`](firewall.sh) | `run_firewall` | Open only the panel TCP port in `ufw` (the inbound range is opened later by the wizard) |
| [`bootstrap.sh`](bootstrap.sh) | (n/a) | Phase-0 stdin stub — use `bash <(curl …)` from README instead |

## Why psiphon is built from source

The upstream `Psiphon-Labs/psiphon-tunnel-core` GitHub releases ship only the
**Android / iOS / Client-Library Go-source zips** — there is no prebuilt
`linux_amd64` server binary and no published SHA256 checksum on any tagged
release (verified across v2.0.30 … v2.0.39 during the Phase 2 spike). The
[`psiphon.ca`](https://psiphon.ca) client downloads use an obfuscated endpoint
whose license is not intended for server embedding.

We therefore build the upstream `ConsoleClient` Go module directly from a
pinned git tag (default `v2.0.39`), following the `make.bash` recipe. This is
the cleanest license-safe path: we never redistribute the binary, the source
mirror is the upstream repo, and we record the SHA256 of the binary we just
built as our own tamper-detection baseline (NOT as an external trust anchor).

Bump `PSIPHON_TAG` at the top of [`psiphon_install.sh`](psiphon_install.sh) to
adopt a new release; re-run [`../install.sh`](../install.sh) to rebuild.

## Idempotent re-runs

Every helper is safe to re-run:

- `deps.sh` — `apt-get install -y` is a no-op for already-present packages.
- `psiphon_install.sh` — wipes the prior build scratch dir, reinstalls.
- `panel_install.sh` — preserves an existing `PSIPHON3XUI_SESSION_SECRET`
  in `panel.env` (so already-issued session cookies stay valid across
  upgrades), `pip install --force-reinstall` overwrites the wheel, `panel.seed`
  is an upsert against the singleton `Settings` row, and `systemctl restart`
  picks up the new wheel without dropping the listening socket. A pre-flight
  `port_listeners` check kills any stale orphan Python/uvicorn holding
  `${PANEL_PORT}` before systemd starts the unit, and `wait_for_panel_socket`
  now `die`s with the last 80 `journalctl` lines if the socket fails to come
  up — no more silent restart-loop after a "Successful" install.

## Uninstall

`../install.sh --uninstall` stops + disables the panel service, removes
`${INSTALL_PREFIX}` (`/opt/psiphon-3x-ui`) and the `psiphon3xui` system
user/group. The Sanaei 3x-ui panel itself and any inbounds created through
it are **left untouched** — you must remove them from the 3x-ui UI/API
manually.
