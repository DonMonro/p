#!/usr/bin/env bash
# ============================================================================
# installer/firewall.sh — open the panel port (and later the inbound range)
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_firewall(). Phase-0 STUB: only the panel
# port is opened at install time. The *public inbound range* is opened during
# the wizard apply step (see plans/ROADMAP.md §9 item 8) once the user has
# actually chosen it — we don't know it at install time.
# ============================================================================

# Phase 27 (Hotfix #13): minimal logging helpers for STANDALONE invocation only.
# install.sh defines its own coloured info/warn/ok BEFORE it sources this file,
# so these must not clobber them — define each only if it does not exist yet.
declare -F info >/dev/null 2>&1 || info() { echo "→ $*"; }
declare -F warn >/dev/null 2>&1 || warn() { echo "⚠ $*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok() { echo "✓ $*"; }

run_firewall() {
    if ! command -v ufw >/dev/null 2>&1; then
        warn "ufw not present; skipping firewall configuration."
        return 0
    fi

    # Phase 28 (item 1, part 3): PANEL_PORT lands in a privileged command line
    # below, so refuse anything that is not a bare port number. This also keeps
    # the sudoers wildcard (`allow [0-9]*/tcp`) from ever seeing a surprise.
    if ! [[ "${PANEL_PORT:-}" =~ ^[0-9]+$ ]] \
        || (( PANEL_PORT < 1 || PANEL_PORT > 65535 )); then
        warn "PANEL_PORT='${PANEL_PORT:-}' is not a valid TCP port; refusing to touch ufw."
        return 1
    fi

    # Phase 28 (item 1, part 2): ufw is root-only. During install we ARE root, so
    # this is a no-op there. But `change_panel_port` re-runs this script from the
    # panel process, which runs as the unprivileged `psiphon3xui` service user —
    # bare `ufw allow` fails with "ERROR: You need to be root to run this
    # script".
    #
    # Previously that failure was swallowed (`|| warn`, then an unconditional
    # `ok` + implicit `return 0`), so the caller saw exit 0 and reported
    # "firewall.sh OK" while the port was never opened. The panel then restarted
    # onto a port ufw was still blocking — unreachable on the old port (closed)
    # AND the new one (filtered).
    #
    # Part 3 gives the unprivileged path a real way to succeed: the installer
    # drops systemd/49-psiphon-3x-ui.sudoers into /etc/sudoers.d, granting the
    # service user NOPASSWD on `ufw allow <port>/tcp` and nothing else. If that
    # drop-in is absent we still fail loudly (non-zero exit) so
    # change_panel_port refuses the change *before* it rewrites panel.env.
    # Resolve ufw to an absolute path: the sudoers drop-in enumerates absolute
    # paths (sudo matches the resolved binary), so passing a bare `ufw` would
    # depend on the service PATH happening to hit a listed location.
    local UFW_BIN
    UFW_BIN="$(command -v ufw 2>/dev/null)" || UFW_BIN="ufw"
    local -a UFW=("${UFW_BIN}")
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        if ! command -v sudo >/dev/null 2>&1; then
            warn "ufw requires root, this runs as UID ${EUID:-$(id -u)}, and sudo is not installed — cannot open ${PANEL_PORT}/tcp."
            return 1
        fi
        UFW=(sudo -n "${UFW_BIN}")
    fi

    info "Opening panel port ${PANEL_PORT}/tcp in ufw …"
    if ! "${UFW[@]}" allow "${PANEL_PORT}/tcp" >/dev/null 2>&1; then
        warn "${UFW[*]} allow ${PANEL_PORT}/tcp failed (uid ${EUID:-$(id -u)}); is /etc/sudoers.d/49-psiphon-3x-ui installed?"
        return 1
    fi

    # ENABLE with care: enabling ufw when SSH isn't whitelisted can lock the
    # user out. Phase 2 will enable ufw only if port 22 is already allowed or
    # explicitly confirm with the user.
    # ufw --force enable || true

    ok "Firewall updated (panel port ${PANEL_PORT}/tcp)."
}

# Phase 27 (Hotfix #13): when invoked standalone (e.g. by change_panel_port),
# PANEL_PORT must be set by the caller. install.sh sources this file and calls
# run_firewall after setting PANEL_PORT; _reload_firewall in router.py does not
# source it (bash firewall.sh runs as a subprocess), so we need a self-invoke
# path that reads PANEL_PORT from the environment.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Standalone invocation: expect PANEL_PORT in env or panel.env.
    if [[ -z "${PANEL_PORT:-}" ]]; then
        # Best-effort: look for panel.env in the standard locations.
        for candidate in /opt/psiphon-3x-ui/panel.env /usr/local/share/psiphon-3x-ui/panel.env; do
            if [[ -f "${candidate}" ]]; then
                # shellcheck source=/dev/null
                source "${candidate}"
                break
            fi
        done
        # If PANEL_PORT is still unset, fall back to the default.
        PANEL_PORT="${PANEL_PORT:-8080}"
    fi
    run_firewall
fi
