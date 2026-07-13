#!/usr/bin/env bash
# ============================================================================
# installer/firewall.sh — open the panel port (and later the inbound range)
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_firewall(). Phase-0 STUB: only the panel
# port is opened at install time. The *public inbound range* is opened during
# the wizard apply step (see plans/ROADMAP.md §9 item 8) once the user has
# actually chosen it — we don't know it at install time.
# ============================================================================

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
