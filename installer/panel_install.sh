#!/usr/bin/env bash
# ============================================================================
# installer/panel_install.sh — build + install the FastAPI panel as a service
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_panel_install().
#
# Phase 2 implementation:
#   1. Create a dedicated `psiphon3xui` system user/group.
#   2. Create venv ${VENV_DIR} and upgrade pip+build.
#   3. Build the panel wheel (`python -m build --wheel` against ${SCRIPT_DIR}/panel).
#   4. Install the wheel into the venv.
#   5. Run `panel.seed` to bootstrap panel.db with bcrypt-hashed credentials.
#   6. Generate a 32-byte session secret; write ${ENV_FILE}
#      (PSIPHON3XUI_* variables consumed by panel.config.Settings).
#   7. Render the systemd unit (systemd/psiphon-3x-ui.service) with
#      EnvironmentFile + ExecStart pointing at the venv python.
#      daemon-reload + enable + start, then wait for the socket to come up.
#
# IDEMPOTENT RE-RUNS:
#   If ${ENV_FILE} already exists we preserve the prior session_secret (so
#   already-signed cookies stay valid). Re-running just upgrades the wheel +
#   reseeds creds. The service is restarted at the end.
# ============================================================================

PSIPHON3XUI_USER="${PSIPHON3XUI_USER:-psiphon3xui}"
PSIPHON3XUI_GROUP="${PSIPHON3XUI_GROUP:-psiphon3xui}"
SYSTEMD_UNIT_SRC="${SCRIPT_DIR}/systemd/psiphon-3x-ui.service"
SYSTEMD_UNIT_DST="/etc/systemd/system/psiphon-3x-ui.service"

run_panel_install() {
    info "Building the panel wheel inside venv ${VENV_DIR} …"

    # ── 1. Sanity: the service user/group must already exist ─────────────
    # The canonical creation site is installer/prepare_user.sh, which runs
    # before psiphon_install/panel_install so their `install -g`/`chown :group`
    # work. We re-check here as a defensive guard in case someone sources this
    # file standalone or skips prepare_user, but do NOT duplicate the mkdir /
    # chown of the prefix tree — that's also owned by prepare_user.
    if ! getent group "${PSIPHON3XUI_GROUP}" >/dev/null 2>&1; then
        die "Group '${PSIPHON3XUI_GROUP}' not found. Run installer/prepare_user.sh first (or 'bash install.sh' which sources it for you)."
    fi
    if ! id "${PSIPHON3XUI_USER}" >/dev/null 2>&1; then
        die "User '${PSIPHON3XUI_USER}' not found. Run installer/prepare_user.sh first."
    fi

    # ── 2. venv + pip build tooling ───────────────────────────────────────
    if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
        info "Creating Python venv at ${VENV_DIR} …"
        python3 -m venv "${VENV_DIR}" || die "python3 -m venv failed."
    fi
    "${VENV_DIR}/bin/python" -m pip install --upgrade pip build wheel setuptools \
        >/dev/null 2>&1 || die "Failed to upgrade pip+build in venv."
    ok "venv ready: $("${VENV_DIR}/bin/python" --version 2>&1)"
# ── 3. Build the panel wheel ──────────────────────────────────────────
# pyproject.toml lives at the REPO ROOT (not inside panel/) so that
# setuptools' `where=["."]` package discovery sees the panel/ subdir and
# actually packages panel/*.py. Building from inside panel/ produced an
# empty wheel that crashed systemd with ModuleNotFoundError.
if [[ ! -f "${SCRIPT_DIR}/pyproject.toml" ]]; then
    die "pyproject.toml not found at ${SCRIPT_DIR}/. Did the curl|bash flow clone the repo?"
fi
if [[ ! -d "${SCRIPT_DIR}/panel" ]]; then
    die "panel/ source directory not found at ${SCRIPT_DIR}/panel. Did the curl|bash flow clone the repo?"
fi
info "Building wheel from repo root ${SCRIPT_DIR} …"

# Clean any stale build artefacts under the repo root.
rm -rf "${SCRIPT_DIR}/dist" "${SCRIPT_DIR}/build" 2>/dev/null || true
"${VENV_DIR}/bin/python" -m build --wheel --no-isolation "${SCRIPT_DIR}" \
    || die "python -m build --wheel failed."

local wheel_glob="${SCRIPT_DIR}/dist/psiphon_3x_ui_panel-*.whl"
    # nullglob: if the glob matches nothing, the array is empty (not a literal pattern).
    # Use mapfile to safely populate the array from the glob without IFS surprises.
    local wheels=()
    shopt -s nullglob
    # shellcheck disable=SC2086  # ${wheel_glob} intentionally unquoted — we rely on
    # nullglob to expand the *.whl pattern into zero-or-more paths; quoting it
    # would feed the literal '.../*.whl' string into mapfile.
    mapfile -t wheels < <(printf '%s\n' ${wheel_glob})
    shopt -u nullglob
    if [[ ${#wheels[@]} -ne 1 ]] || [[ ! -s "${wheels[0]}" ]]; then
        die "Expected exactly one built wheel, found: ${wheels[*]:-none}"
    fi
    local wheel_path
    wheel_path="${wheels[0]}"
    ok "Built wheel: $(basename "${wheel_path}")"

    # ── 4. Install the wheel into the venv ────────────────────────────────
    info "Installing panel wheel into venv …"
    "${VENV_DIR}/bin/pip" install --force-reinstall --no-deps "${wheel_path}" \
        || die "pip install of the panel wheel failed."
    # NOTE: keep this list in sync with [project.dependencies] in pyproject.toml!
    # The wheel is installed with --no-deps (above) so pip does NOT pull runtime
    # deps from the wheel METADATA — we list them explicitly here to keep the
    # install reproducible on minimal Ubuntu installs. If you add a new import
    # to panel/, add it here AND in pyproject.toml or the panel will fail to
    # boot at import time (e.g. RuntimeError: Form data requires "python-multipart").
    "${VENV_DIR}/bin/pip" install "python-multipart>=0.0.9" \
        "fastapi>=0.110" "uvicorn[standard]>=0.29" \
        "bcrypt>=4.1" "itsdangerous>=2.1" "httpx>=0.27" "pydantic>=2.6" \
        "pydantic-settings>=2.2" "pyyaml>=6.0" "sqlalchemy>=2.0" "sse-starlette>=2.0" \
        >/dev/null 2>&1 || die "Failed to install panel runtime dependencies."
    ok "Panel installed into venv."

    # ── 5. Seed panel.db ──────────────────────────────────────────────────
    # Export env vars panel.seed needs to find db_path (the `--db` flag also works).
    export PSIPHON3XUI_DB_PATH="${DB_PATH}"
    export PSIPHON3XUI_HOST="0.0.0.0"
    export PSIPHON3XUI_PORT="${PANEL_PORT}"
    info "Seeding panel.db (${DB_PATH}) with admin credentials …"
    "${VENV_DIR}/bin/python" -m panel.seed \
        --port "${PANEL_PORT}" \
        --user "${PANEL_USER}" \
        --password "${PANEL_PASS}" \
        --db  "${DB_PATH}" \
        || die "panel.seed failed to bootstrap panel.db."

    # The panel as-root needs to be readable/writable by the service user.
    if [[ -f "${DB_PATH}" ]]; then
        chown "${PSIPHON3XUI_USER}:${PSIPHON3XUI_GROUP}" "${DB_PATH}" 2>/dev/null || true
        chmod 0660 "${DB_PATH}" 2>/dev/null || true
    fi

    # ── 6. Generate session secret + write env file ───────────────────────
    local session_secret=""
    if [[ -r "${ENV_FILE}" ]]; then
        # Preserve the existing session secret on re-runs (keep cookies valid).
        session_secret="$(awk -F= '/^[[:space:]]*PSIPHON3XUI_SESSION_SECRET[[:space:]]*=/{gsub(/[[:space:]]/,"",$2);print $2; exit}' "${ENV_FILE}")"
    fi
    if [[ -z "${session_secret}" ]]; then
        # 32 random bytes hex-encoded = 64 chars; ample for itsdangerous.
        session_secret="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
            || die "Failed to generate session secret."
        if [[ ${#session_secret} -ne 64 ]]; then
            die "Generated session secret has unexpected length ${#session_secret} (expected 64)."
        fi
    fi

    info "Writing EnvironmentFile ${ENV_FILE} …"
    # Phase 7 — append TLS + CSRF + login rate-limit knobs ONLY when applicable,
    # so DEV / non-HTTPS / scripted deploys aren't affected by extra env vars.
    local tls_env_block=""
    local https_only_line=""
    if [[ "${PANEL_ENABLE_HTTPS:-no}" == "yes" && -n "${PANEL_TLS_CERT:-}" && -s "${PANEL_TLS_CERT}" && -s "${PANEL_TLS_KEY:-}" ]]; then
        tls_env_block=$(printf 'PSIPHON3XUI_TLS_CERT=%s\nPSIPHON3XUI_TLS_KEY=%s\n' "${PANEL_TLS_CERT}" "${PANEL_TLS_KEY}")
        https_only_line="PSIPHON3XUI_HTTPS_ONLY=true"
    else
        https_only_line="PSIPHON3XUI_HTTPS_ONLY=false"
    fi

    # Phase 24 (post-Hotfix-#14 cleanup): the Psiphon-Inc public-bootstrap
    # credentials are BAKED INTO the panel wheel (panel/psiphon/__init__.py
    # ships _PUBLIC_* constants extracted from the public Psiphon-3 client
    # APK — PropagationChannelId, SponsorId, RemoteServerListURLs,
    # ObfuscatedServerListRootURLs, RemoteServerListSignaturePublicKey,
    # ServerEntrySignaturePublicKey, ExchangeObfuscationKey). The panel
    # boots + per-country tunnels establish out-of-the-box with NO env vars
    # required. The FOUR PSIPHON_* env vars below are now OPTIONAL OVERRIDES
    # — only a commercial sponsor who has its own PropChannel / SponsorId /
    # signed server-list URL / sig-pubkey needs to set them (e.g. via
    # `PSIPHON_PROPAGATION_CHANNEL_ID=... bash install.sh` or by hand-editing
    # ${ENV_FILE} after install). installer/prompt.sh no longer surveys the
    # operator at install time (the survey is gone). We still forward any
    # operator-supplied PSIPHON_* values into ${ENV_FILE} so render_config()
    # sees them as overrides at runtime. Empty values are SKIPPED (the
    # baked-in _PUBLIC_* defaults are used in their place).
    local psiphon_creds_block=""
    if [[ -n "${PSIPHON_PROPAGATION_CHANNEL_ID:-}" ]]; then
        psiphon_creds_block+="PSIPHON_PROPAGATION_CHANNEL_ID=${PSIPHON_PROPAGATION_CHANNEL_ID}\n"
    fi
    if [[ -n "${PSIPHON_SPONSOR_ID:-}" ]]; then
        psiphon_creds_block+="PSIPHON_SPONSOR_ID=${PSIPHON_SPONSOR_ID}\n"
    fi
    if [[ -n "${PSIPHON_REMOTE_SERVER_LIST_URL:-}" ]]; then
        psiphon_creds_block+="PSIPHON_REMOTE_SERVER_LIST_URL=${PSIPHON_REMOTE_SERVER_LIST_URL}\n"
    fi
    if [[ -n "${PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY:-}" ]]; then
        psiphon_creds_block+="PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY=${PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY}\n"
    fi
    if [[ -n "${psiphon_creds_block}" ]]; then
        # printf-translation escape so the literal newlines expand.
        psiphon_creds_block="$(printf "%b" "${psiphon_creds_block}")"
        # Strip the trailing newline (the heredoc already emits one).
        psiphon_creds_block="${psiphon_creds_block%$'\n'}"
    fi

    cat > "${ENV_FILE}" <<EOF
# Auto-generated by installer/panel_install.sh.
# Consumed by systemd/psiphon-3x-ui.service as EnvironmentFile=.
# Edit here, then: systemctl restart psiphon-3x-ui
PSIPHON3XUI_HOST=0.0.0.0
PSIPHON3XUI_PORT=${PANEL_PORT}
PSIPHON3XUI_DB_PATH=${DB_PATH}
PSIPHON3XUI_SESSION_SECRET=${session_secret}
PSIPHON3XUI_PSIPHON_BINARY=${BIN_DIR}/psiphon-tunnel-core
PSIPHON3XUI_PSIPHON_CONFIG_DIR=${CONFIG_DIR}
PSIPHON3XUI_DEBUG=false
${tls_env_block}${https_only_line}
# Phase 7 hardening — enabled by default in production. Set to false if you
# script the panel API with a tool whose HTTP client can't surface cookie
# values back as a header (the test suite flips this to 0).
PSIPHON3XUI_CSRF_ENFORCE=true
# 10 attempts per 60s window per IP — adjust if behind a known proxy farm.
PSIPHON3XUI_LOGIN_RATE_LIMIT=10
PSIPHON3XUI_LOGIN_RATE_WINDOW=60
# ---------------------------------------------------------------------------
# Phase 24 (post-Hotfix-#14 cleanup): Psiphon-Inc upstream credentials are
# OPTIONAL OVERRIDES — the panel ships the public-bootstrap defaults baked
# into panel/psiphon/__init__.py (_PUBLIC_* constants extracted from the
# public Psiphon-3 client APK). Per-country tunnels establish out-of-the-box
# with NO env vars set here. To substitute your own commercial sponsor /
# propagation channel / signed server-list URL / sig-pubkey, edit this file
# + run `sudo systemctl restart psiphon-3x-ui`. Only the four scalar fields
# below are overridable:
#   PSIPHON_PROPAGATION_CHANNEL_ID
#   PSIPHON_SPONSOR_ID
#   PSIPHON_REMOTE_SERVER_LIST_URL          (singular — promoted to a 1-element
#                                            TransferURL array by render_config)
#   PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY
# A bad-looking override (all-F's, all-0's, "..." stub, non-base64 sig-pubkey,
# non-https URL) still triggers PsiphonCredentialError at enable time so the
# panel doesn't burn 5 minutes in EstablishTunnelTimeout. See
# docs/TROUBLESHOOTING.md ("Psiphon Inc. credentials — optional overrides").
# Empty lines below = no overrides configured; baked-in defaults in effect.
${psiphon_creds_block}
EOF
    # Hotfix #13 (Bug #4): the panel process runs as the unprivileged
    # ${PSIPHON3XUI_USER} (a member of ${PSIPHON3XUI_GROUP}); the panel's
    # `_update_panel_env_port` helper (panel/dashboard/router.py) rewrites
    # ${ENV_FILE} in-place when the operator changes the panel port via
    # the dashboard, so the next `systemctl restart` boots the panel at
    # the new port. Pre-Hotfix-#13 the env file was chmod 0640 + chown
    # root:${PSIPHON3XUI_GROUP} — that gave the panel's group only READ
    # access (rw-r-----), so the rewrite ALWAYS failed with EACCES and
    # the operator's "change-panel-port" request silently no-op'd the
    # env file + restarted the panel at the OLD port → "panel port does
    # not change at all". Mode 0660 keeps root-owner + group-writable so
    # the panel process (group member) can now rewrite it.
    chmod 0660 "${ENV_FILE}"
    chown "root:${PSIPHON3XUI_GROUP}" "${ENV_FILE}" 2>/dev/null || true
    ok "EnvironmentFile written: ${ENV_FILE}"

    # ── 7. Render + register the systemd unit ────────────────────────────
    if [[ ! -s "${SYSTEMD_UNIT_SRC}" ]]; then
        die "Missing systemd unit template: ${SYSTEMD_UNIT_SRC}"
    fi

    info "Installing systemd unit ${SYSTEMD_UNIT_DST} …"
    # The unit already has ExecStart / EnvironmentFile paths baked in that
    # match our INSTALL_PREFIX defaults; if the user chose a non-default
    # prefix we'd sed-substitute. For now install verbatim and rely on the
    # standard /opt/psiphon-3x-ui layout matching.
    install -m 0644 "${SYSTEMD_UNIT_SRC}" "${SYSTEMD_UNIT_DST}"
    # Substitute the venv + binary paths explicitly to avoid surprising
    # configurations after a partial re-install.
    sed -i \
        -e "s|^ExecStart=.*|ExecStart=${VENV_DIR}/bin/python -m panel|" \
        -e "s|^EnvironmentFile=.*|EnvironmentFile=${ENV_FILE}|" \
        -e "s|^WorkingDirectory=.*|WorkingDirectory=${INSTALL_PREFIX}|" \
        -e "s|^ReadWritePaths=.*|ReadWritePaths=${INSTALL_PREFIX}|" \
        -e "s|^User=.*|User=${PSIPHON3XUI_USER}|" \
        -e "s|^Group=.*|Group=${PSIPHON3XUI_GROUP}|" \
        "${SYSTEMD_UNIT_DST}"

    systemctl daemon-reload || warn "systemctl daemon-reload failed."
    systemctl enable psiphon-3x-ui.service >/dev/null 2>&1 \
        || warn "systemctl enable psiphon-3x-ui failed (continuing)."

    # ── 7b. Hotfix #9 (Bug #2): install the templated tunnel unit + polkit ──
    # rule. Without these, the panel service (running as the unprivileged
    # psiphon3xui user) cannot `systemctl start psiphon-tunnel@<CODE>.service`
    # — systemd rejects with "Interactive authentication required." and the
    # dashboard's Enable toggle returns 502 with that text.
    #
    # (a) psiphon-tunnel@.service — the templated per-country tunnel unit.
    #     Idempotent: re-install overwrites in place.
    local TUNNEL_UNIT_SRC="${SCRIPT_DIR}/systemd/psiphon-tunnel@.service"
    local TUNNEL_UNIT_DST="/etc/systemd/system/psiphon-tunnel@.service"
    if [[ -f "${TUNNEL_UNIT_SRC}" ]]; then
        install -m 0644 "${TUNNEL_UNIT_SRC}" "${TUNNEL_UNIT_DST}" \
            || warn "install of psiphon-tunnel@.service to ${TUNNEL_UNIT_DST} failed (continuing)."
        # Rewrinkle the User=/Group= lines if the operator renamed the
        # service user via PSIPHON3XUI_USER (mirrors the panel unit's
        # templating just below).
        if [[ "${PSIPHON3XUI_USER}" != "psiphon3xui" ]]; then
            sed -i \
                -e "s|^User=.*|User=${PSIPHON3XUI_USER}|" \
                -e "s|^Group=.*|Group=${PSIPHON3XUI_GROUP}|" \
                "${TUNNEL_UNIT_DST}" 2>/dev/null || true
        fi
        ok "Installed templated tunnel unit: ${TUNNEL_UNIT_DST}"
    else
        warn "Missing ${TUNNEL_UNIT_SRC} — per-country tunnels will not start (re-clone the repo)."
    fi

    # (b) polkit JS rule installing the panel service's right to start/stop/
    #     restart its own tunnel fleet. Idempotent.
    local POLKIT_RULE_SRC="${SCRIPT_DIR}/systemd/49-psiphon-3x-ui.rules"
    local POLKIT_RULE_DST="/etc/polkit-1/rules.d/49-psiphon-3x-ui.rules"
    local POLKIT_RULES_DIR="/etc/polkit-1/rules.d"
    if [[ -f "${POLKIT_RULE_SRC}" ]]; then
        if [[ ! -d "${POLKIT_RULES_DIR}" ]]; then
            install -d -m 0755 "${POLKIT_RULES_DIR}" \
                || warn "mkdir ${POLKIT_RULES_DIR} failed (polkitd may use a different path on this distro)."
        fi
        install -m 0644 "${POLKIT_RULE_SRC}" "${POLKIT_RULE_DST}" \
            || warn "install of polkit rule failed (continuing — older Debian uses .pkla, see docs)."
        # If the operator renamed the service user, patch the rule's
        # literal `subject.user !== "psiphon3xui"` check.
        if [[ "${PSIPHON3XUI_USER}" != "psiphon3xui" ]]; then
            sed -i \
                -e "s|psiphon3xui|${PSIPHON3XUI_USER}|g" \
                "${POLKIT_RULE_DST}" 2>/dev/null || true
        fi
        ok "Installed polkit rule: ${POLKIT_RULE_DST}"
        # polkitd picks up rules.d/*.rules automatically on most distros; a
        # reload is belt-and-braces insurance. Do not die on failure — the
        # rule will still take effect on the next polkit restart.
        systemctl reload polkit.service 2>/dev/null \
            || systemctl restart polkit.service 2>/dev/null \
            || warn "Could not reload polkit.service — the rule will activate on the next polkit restart."
    else
        warn "Missing ${POLKIT_RULE_SRC} — the panel user will not be able to start tunnels (Bug #2 will persist)."
    fi

    # ── 8. Pre-flight: ensure PANEL_PORT is free for the new unit ──
    # Phase 24 Hotfix #2 (Bug: "Failed to restart psiphon-3x-ui.service:
    # Unit psiphon-3x-ui.service not found." + downstream "SOCKS5 health
    # probe on 127.0.0.1:11000 failed after retry: Connection refused"
    # when adding a country): the prior pre-flight trusted
    # `systemctl is-active --quiet psiphon-3x-ui.service` to decide whether
    # to look up the live unit's MainPID and exclude its PID from the
    # foreign-kill set. On a re-install AFTER a previous `install.sh
    # --uninstall` that did NOT actually kill the running orphan Python
    # process (uninstall's `systemctl stop` returns 0 the moment the stop
    # signal is issued, NOT when the SIGKILL propagates; and `rm -rf
    # ${INSTALL_PREFIX}` unlinks the venv files but the orphan's open file
    # descriptors keep the python interpreter in memory serving port
    # PANEL_PORT with the OLD wheel's panel.psiphon module loaded), the
    # stale orphaned PID can be STILL registered as MainPID in systemd's
    # transient state — so the exclude-test treated the orphan as "the
    # live unit's PID; don't kill it" → the orphan survived → `wait_for_
    # panel_socket` connected to the ORPHAN's TCP listener (not the new
    # systemd launch) and returned 0 immediately → installer printed the
    # success banner even though the new panel never came up → operator's
    # subsequent "Add UA" button kept talking to the OLD wheel that still
    # emits RAW https URLs → base64 Hotfix never actually took effect.
    #
    # The robust ordering: STOP any panel unit FIRST (we're about to
    # restart it anyway), THEN kill everything left on PANEL_PORT
    # (post-stop orphans are by definition foreign), THEN start the new
    # unit. `systemctl stop` is fire-and-forget, so we also sleep 1 to
    # let the SIGTERM propagate before snapshotting listeners.
    info "Pre-flight: stopping any prior psiphon-3x-ui.service unit …"
    systemctl stop psiphon-3x-ui.service 2>/dev/null \
        || true   # OK to fail on a fresh install
    sleep 1   # let the STOP signal propagate before snapshotting listeners

    info "Pre-flight: checking TCP/${PANEL_PORT} for stale listeners …"
    if port_listeners "${PANEL_PORT}" | grep -q .; then
        local listening_summary
        listening_summary="$(port_listeners "${PANEL_PORT}")"
        warn "A stale process is still listening on TCP/${PANEL_PORT} after stop:"
        warn "${listening_summary}"
        warn "This is almost certainly an orphaned python/uvicorn from a prior"
        warn "install that survived `install.sh --uninstall` (rm -rf deletes"
        warn "files but not running processes); killing it now."

        # Phase 24 Hotfix #2 — post-stop, every pid on PANEL_PORT is by
        # definition an orphan: we just issued `systemctl stop`, so any
        # legitimate systemd MainPID has been reaped. Do NOT exclude
        # anything based on `systemctl is-active` / `systemctl show -p
        # MainPID` — those calls are unreliable in the post-stop transient
        # window and may report the stale orphan's PID as the "live
        # MainPID", which would re-introduce the original bug.
        local foreign_pids=""
        while IFS= read -r line; do
            # Format: "PID COMMAND"
            local pid="${line%% *}"
            [[ -n "${pid}" ]] || continue
            foreign_pids="${foreign_pids:+${foreign_pids} }${pid}"
        done < <(port_listeners "${PANEL_PORT}")

        if [[ -n "${foreign_pids}" ]]; then
            warn "Killing orphan process(es) holding TCP/${PANEL_PORT} (PIDs: ${foreign_pids}) …"
            # shellcheck disable=SC2086  # intentional word-splitting of pid list
            kill -9 ${foreign_pids} 2>/dev/null || true
            sleep 1
            if port_listeners "${PANEL_PORT}" | grep -q .; then
                die "TCP/${PANEL_PORT} is STILL in use after killing PIDs ${foreign_pids}. \
Identify and free it manually: 'sudo ss -tlnp | grep :${PANEL_PORT}' \
then re-run 'sudo bash install.sh'."
            fi
            ok "Orphan listener on TCP/${PANEL_PORT} cleared."
        fi
    fi

    # Start the unit fresh (we stopped it above, never restart).
    info "Starting psiphon-3x-ui.service …"
    systemctl start psiphon-3x-ui.service \
        || warn "systemctl start psiphon-3x-ui failed."

    # ── 9. Wait for the listening socket — fatal on failure ──────────────
    # Early Phase 2 builds emitted only a `warn` here, so a port collision
    # (EBUSY/EADDRINUSE) crashed the unit silently after install "succeeded".
    # We now die loudly and dump the last 80 journald lines into install.log
    # so the failure reason is on screen without needing `journalctl`.
    if ! wait_for_panel_socket; then
        err "Panel socket did NOT come up on TCP/${PANEL_PORT} within the timeout."
        err "Last 80 lines of 'journalctl -u psiphon-3x-ui' (pasted into ${LOG_FILE}):"
        local jrn
        jrn="$(journalctl -u psiphon-3x-ui -n 80 --no-pager 2>/dev/null || true)"
        printf '%s\n' "${jrn}" | tee -a "${LOG_FILE}" 2>/dev/null || true
        printf '%s\n' "${jrn}" >&2
        die "Use 'sudo journalctl -u psiphon-3x-ui -n 200 --no-pager' for full context. \
Common causes: (1) stale listener on the port (re-run install.sh which now kills it), \
(2) firewall blocking systemd-spawned Python from binding (ufw is permissive for outbound), \
(3) PSIPHON3XUI_PORT typo in ${ENV_FILE}."
    fi
    ok "Panel listening on 0.0.0.0:${PANEL_PORT}."
    ok "Panel service installed and enabled."
}

# ── Helpers ──────────────────────────────────────────────────────────────
port_listeners() {
    # Echo one line per PID listening on the given TCP port, format:
    #   "<pid> <command-name> <user>"
    # Uses `ss` (Ubuntu ships with it via iproute2). Per-process command/user
    # metadata is assembled from /proc since ss already shows PID+program.
    local port="$1"
    local line
    # `ss -tlnp` lists listeners; the `-p` option needs root to see PIDs but
    # we already required root at install.sh entry. Each line looks like:
    #   LISTEN 0 4096 0.0.0.0:11111 0.0.0.0:* users:(("python",pid=73164,fd=5))
    ss -tlnp 2>/dev/null | awk -v port=":${port}" '
        $1 == "LISTEN" && $4 == port {
            # strip everything up to "users:((" and extract pid=NNN
            line = $0
            sub(/.*users:\(\("/, "", line)
            # line now starts with the program name
            prog = line
            sub(/".*/, "", prog)
            # isolate pid=N
            pid = line
            sub(/.*pid=/, "", pid)
            sub(/[,) ].*/, "", pid)
            if (pid != "") print pid " " prog
        }
    '
}

wait_for_panel_socket() {
    # Try connecting to 127.0.0.1:${PANEL_PORT} for up to 25 seconds.
    # (systemd RestartSec=5 + one Python boot ~1s = ~6s per attempt; 25s
    # covers the first successful bind OR at least two failed restart cycles.)
    # Hotfix #11 (Bug #6): the previous `exec 3<>"/dev/tcp/..." 2>/dev/null`
    # left bash's connect-syscall wrapper able to print "connect: Connection
    # refused" to fd 2 BEFORE the exec's redirect scope applied — so the
    # operator saw a wall of `panel_install.sh: connect: Connection refused`
    # stderr noise during installs on slow-booting hosts. We now run the
    # raw-tcp probe in a SUBSHELL with its stderr redirected for the whole
    # retry body, so any connect error is silenced at the shell layer
    # (already-known: the retry loop succeeds eventually when the unit
    # finishes booting — the noise just alarms operators).
    local tries=25
    while (( tries-- > 0 )); do
        if ( exec 3<>"/dev/tcp/127.0.0.1/${PANEL_PORT}" ) 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}
