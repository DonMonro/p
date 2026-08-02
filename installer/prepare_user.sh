#!/usr/bin/env bash
# ============================================================================
# installer/prepare_user.sh — create the system user/group that owns the install prefix
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_prepare_user().
#
# This is the FIRST runtime step in install.sh (before any helper that needs to
# `chgrp`/`install -g` into ${PSIPHON3XUI_GROUP}). It must never run *after*
# psiphon_install.sh or panel_install.sh, otherwise their `install -g` /
# `chown :group` will fail with "invalid group".
#
# Idempotent: re-running checks `getent group` / `id <user>` first.
# ============================================================================

run_prepare_user() {
    # `${PSIPHON3XUI_USER}` / `${PSIPHON3XUI_GROUP}` are declared in install.sh
    # with defaults of "psiphon3xui".
    info "Ensuring system user/group '${PSIPHON3XUI_USER}'/'${PSIPHON3XUI_GROUP}' …"

    if ! getent group "${PSIPHON3XUI_GROUP}" >/dev/null 2>&1; then
        groupadd --system "${PSIPHON3XUI_GROUP}" \
            || die "groupadd ${PSIPHON3XUI_GROUP} failed."
    fi
    if ! id "${PSIPHON3XUI_USER}" >/dev/null 2>&1; then
        useradd --system --gid "${PSIPHON3XUI_GROUP}" \
            --home-dir "${INSTALL_PREFIX}" --no-create-home \
            --shell /usr/sbin/nologin "${PSIPHON3XUI_USER}" \
            || die "useradd ${PSIPHON3XUI_USER} failed."
    fi

    # Hotfix #10 (Bug #4): add the panel service user to the systemd-journal
    # + adm groups so that the panel's `journalctl -u psiphon-tunnel@<CODE>`
    # calls in panel/dashboard/router.py's _journalctl_lines() don't fail
    # with "No journal files were opened due to insufficient permissions".
    # Without these supplementary groups the operator sees:
    #   logs failed: journalctl failed: journalctl -u psiphon-tunnel@US.service
    #     -> exit 1: ... users in groups 'adm', 'systemd-journal' can see all
    #     messages ... insufficient permissions.
    # `usermod -aG` is idempotent (no-op if already a member). Re-runs of
    # install.sh are safe. The user MUST re-login / the systemd unit MUST be
    # restarted after the group change is baked for membership to take effect
    # — that's handled by the panel-install step's `systemctl restart` at the
    # end of the installer.
    for grp in systemd-journal adm; do
        if getent group "${grp}" >/dev/null 2>&1; then
            usermod --append --groups "${grp}" "${PSIPHON3XUI_USER}" \
                || warn "usermod --groups ${grp} ${PSIPHON3XUI_USER} failed"
        else
            warn "group '${grp}' missing on this host — journalctl may still fail"
        fi
    done

    # Make sure the prefix tree is owned by our service user/group so the panel
    # can write to it without root. Idempotent: chown -R is safe to re-run.
    #
    # Phase 25 Hotfix #11: instead ofs bare chmod 0770 without a setgid
    # bit, install -d with mode 2775 (setgid: files inherit the group of the
    # parent dir). This is the LAST mode fix for Hotfix #12 — on the
    # operator's box the prior version of this script's chmod 0770 (no
    # setgid) lost the setgid bit because prior mkdir -p had created the
    # dir without it. Files created inside end up with the caller's primary
    # group instead of psiphon3xui — panel.db becomes root:root 0644 and
    # sqlite's WAL can't write sidecars next to it (the "attempt to write
    # a readonly database" traceback the operator pasted). install -d
    # applies setgid AND the right mode in one shot; it also already does
    # the chown+chmod work (via -o root -g) so no separate chown -R call.
    mkdir -p "${CONFIG_DIR}" "${BIN_DIR}" "${VENV_DIR}"
    install -d -m 2775 -o root -g "${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}" 2>/dev/null || true
    chown -R "root:${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 2775 "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 2775 "${CONFIG_DIR}" 2>/dev/null || true
    chmod 0750 "${BIN_DIR}" 2>/dev/null || true

    ok "Service user '${PSIPHON3XUI_USER}' and group '${PSIPHON3XUI_GROUP}' ready."
}
