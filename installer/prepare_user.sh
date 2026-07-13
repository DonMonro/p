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

    # Make sure the prefix tree is owned by our service user/group so the panel
    # can write to it without root. Idempotent: chown -R is safe to re-run.
    mkdir -p "${CONFIG_DIR}" "${BIN_DIR}" "${VENV_DIR}"
    chown -R "root:${PSIPHON3XUI_GROUP}" "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 0750 "${INSTALL_PREFIX}" 2>/dev/null || true
    chmod 0770 "${CONFIG_DIR}" 2>/dev/null || true
    chmod 0750 "${BIN_DIR}" 2>/dev/null || true

    ok "Service user '${PSIPHON3XUI_USER}' and group '${PSIPHON3XUI_GROUP}' ready."
}
