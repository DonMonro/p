# Phase 1 spike scripts

> Dangerous territory: these scripts talk to a **live 3x-ui panel** to capture
> the real request/response shapes the production `XuiClient` will rely on.
> All scripts in this directory are **throwaway** — they are NOT shipped,
> NOT installed by `install.sh`, and have no test coverage in CI.

| File | Purpose | Auth? |
|---|---|---|
| [`spike_1b_probe.py`](spike_1b_probe.py) | Confirm base URL reachability + login page shape | No credentials |
| `spike_1c_capture.py` | Capture real inbound list + VLESS template JSON (next script) | Yes |
| `spike_1e_clone.py` | Create one VLESS clone against live panel to validate clone engine (next) | Yes |

## Operational rules

1. **Never commit credentials.** Pass them as env vars or process args; never
   hardcode them in any file under `spike/`.
2. **Teardown matters.** Any script that creates an inbound (`spike_1e_clone.py`)
   prints a `DELETE` command the user can paste back to clean it up.
3. **Output goes to the user**, who pastes it back into the chat so we can
   iterate without direct SSH access.
4. After the spike, captured JSON fixtures are sanitised (UUIDs/real-text
   replaced) and committed under `tests/fixtures/xui/` so `XuiClient` has
   `respx`-based pytest coverage without needing a live panel.
