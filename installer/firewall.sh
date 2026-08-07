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

    info "Opening panel port ${PANEL_PORT}/tcp in ufw …"
    ufw allow "${PANEL_PORT}/tcp" >/dev/null 2>&1 || warn "ufw rule add failed (continuing)."

    # ENABLE with care: enabling ufw when SSH isn't whitelisted can lock the
    # user out. Phase 2 will enable ufw only if port 22 is already allowed or
    # explicitly confirm with the user.
    # ufw --force enable || true

    ok "Firewall updated (panel port)."
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
