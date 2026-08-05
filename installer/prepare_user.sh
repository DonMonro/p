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
    # Phase 25 Hotfix #11: changed from bare chmod 0770 (no setgid) to the
    # explicit-mode form 2775 (setgid + group-writable). Without setgid,
    # files created inside inherit the invoking process's primary group
    # — on the operator's v3 box, the prior mkdir+chmod had left the parent
    # as mode 0755 root:root (no setgid). Sqlite then created panel.db AS
    # root:root (0644) and the panel service (running as psiphon3xui)
    # couldn't write WAL/journal sidecars next to it. 2775 keeps group
    # write on the parent dir AND forces every new sub-/file created inside
    # to inherit the psiphon3xui group.
    # Phase 26 HARDENING (post-Hotfix #13): the ExecStartPre of
    # psiphon-tunnel@.service calls `mkdir -p /opt/psiphon-3x-ui/data/<COUNTRY>`
    # — which creates `data` first under parent `/opt/psiphon-3x-ui` and
    # then the per-country subdir. For that mkdir to succeed without the
    # ExecStartPre calling chown (which would EPERM under
    # `NoNewPrivileges=true` + CAP_CHOWN stripped by the sandbox), the
    # parent dir must already be `group=psiphon3xui` writable + the set-GID
    # bit applied so `mkdir`'s leading component inherits the same group.
    # We deliberately use chmod 2775 (setgid) instead of install -d (which
    # would replace the inode and break any pre-existing hardlinks in a
    # re-install). chmod does NOT clear the setgid bit on an existing dir.
    mkdir -p "${CONFIG_DIR}" "${BIN_DIR}" "${VENV_DIR}"
    chown -R root:"${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 2775 "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 2775 "${CONFIG_DIR}" 2>/dev/null || true
    chmod 0750 "${BIN_DIR}" 2>/dev/null || true

    ok "Service user '${PSIPHON3XUI_USER}' and group '${PSIPHON3XUI_GROUP}' ready."
}
