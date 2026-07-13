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
    # INSTALL_PREFIX is made GROUP-writable (0770) so the psiphon-3x-ui service
    # uid (User=psiphon3xui, in Group=psiphon3xui) can create SQLite sidecar
    # files (panel.db-wal / panel.db-shm / panel.db-journal) next to the panel.db
    # file that lives at ${INSTALL_PREFIX}/panel.db. SQLite needs WRITE access to
    # the directory containing the DB file (not just the file itself) — even
    # when WAL is OFF it still mints a -journal tmp file on the first INSERT.
    # With 0750 (group r-x) the service uid couldn't create those sidecars and
    # the very first wizard step blew up with `sqlite3.OperationalError: attempt
    # to write a readonly database` (see Hotfix #3 in the v1.0.0 amend cycle).
    mkdir -p "${CONFIG_DIR}" "${BIN_DIR}" "${VENV_DIR}"
    chown -R "root:${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 0770 "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 0770 "${CONFIG_DIR}" 2>/dev/null || true
    chmod 0750 "${BIN_DIR}" 2>/dev/null || true

    ok "Service user '${PSIPHON3XUI_USER}' and group '${PSIPHON3XUI_GROUP}' ready."
}
