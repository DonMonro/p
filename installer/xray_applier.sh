#!/usr/bin/env bash
# ============================================================================
# installer/xray_applier.sh — root-side consumer for the per-country Xray
# outbound+routing patch queue.
#
# Phase 25 Hotfix #10: invoked ONESHOT by psiphon-xray-applier.service (which
# is in turn triggered by psiphon-xray-applier.path every time a panel-side
# _enqueue_xray_patch() call drops a <COUNTRY>-<op>-<uuid8>.json file into
# /var/lib/psiphon-3x-ui/xray-patch-queue/).
#
# What this script does (in order):
#   1. Acquire an exclusive flock() on
#      /var/lib/psiphon-3x-ui/xray-applier.lock — serialized against any
#      concurrent applier fire-ups from rapid successive path-unit triggers,
#      so two appliers never race each other on the same config.json.
#   2. For each pending patch file under the queue dir — processed in
#      deterministic sorted(file) order so multi-country edit bursts apply
#      in name order — hand the file to
#      /usr/local/libexec/psiphon-3x-ui/xray_apply.py which:
#         * reads /usr/local/x-ui/bin/config.json
#         * idempotently upserts the per-country socks outbound keyed by
#           "psiphon-out-<CODE>"
#         * idempotently upserts (apply) or strips (remove) the inboundTag
#           routing rule keyed by ("in-<public_port>-tcp",
#           "psiphon-out-<CODE>"), inserted BEFORE the bittorrent /
#           geoip:private catch-alls
#         * writes the mutated config back ATOMICALLY (tmp+rename)
#         * removes (consumes) the patch file from the queue
#   3. If ANY patch actually mutated the config (helper returns exit 0 and
#      at least one such patch was seen), `systemctl restart x-ui.service`
#      ONCE at the very end. If every patch was a no-op (idempotent re-apply
#      of an identical binding), skip the restart — hot-path enables /
#      reclones shouldn't churn the 3x-ui panel.
#
# Shipped as /usr/local/libexec/psiphon-3x-ui/xray-applier.sh (mode 0755,
# owner root:root) by installer/panel_install.sh. runs as root via
# psiphon-xray-applier.service (User=root).
# ============================================================================

set -u  # -e deliberately omitted: we want a single patch's failure to be
        # logged and skip-ahead rather than abort the whole batch (the
        # x-ui.service restart at the end then still covers the patches
        # that DID succeed).

QUEUE_DIR="${PSIPHON_XRAY_PATCH_QUEUE_DIR:-/var/lib/psiphon-3x-ui/xray-patch-queue}"
LOCK_FILE="${PSIPHON_XRAY_APPLIER_LOCK:-/var/lib/psiphon-3x-ui/xray-applier.lock}"
APPLY_PY="${PSIPHON_XRAY_APPLY_PY:-/usr/local/libexec/psiphon-3x-ui/xray_apply.py}"
XUI_SERVICE_NAME="${PSIPHON_XUI_SERVICE_NAME:-x-ui.service}"

# ── 1. Serialize against concurrent applier invocations ─────────────────
# `flock -x 9` opens fd 9 on the lock file and blocks until the exclusive
# flock is held. systemd's Type=oneshot + ConditionPathIsDirectory already
# avoids the most common double-fire; the flock covers the rare race where
# two path-unit triggers land in the same ~10ms debounce window.
exec 9>"${LOCK_FILE}"
if ! flock -x 9; then
    printf 'xray-applier: flock %s failed\n' "${LOCK_FILE}" >&2
    exit 1
fi

# ── 2. Sanity: the python helper + at least one patch file must exist ────
if [[ ! -f "${APPLY_PY}" ]]; then
    printf 'xray-applier: %s not found — panel_install.sh did not install it\n' "${APPLY_PY}" >&2
    exit 1
fi

shopt -s nullglob
patch_files=("${QUEUE_DIR}"/*.json)
shopt -u nullglob

if (( ${#patch_files[@]} == 0 )); then
    # Empty queue — nothing to do. This is the normal boot-time / spurious-
    # trigger path; do NOT touch config.json and do NOT restart x-ui.
    exit 0
fi

# Sort deterministically (the glob already yields alphabetical-but-not-guaranteed;
# the explicit sort is belt-and-braces for cross-locale sanity).
IFS=$'\n' read -r -d '' -a patch_files < <(printf '%s\n' "${patch_files[@]}" | LC_ALL=C sort && printf '\0') || true
unset IFS

# ── 3. Apply each patch; track whether ANY config write occurred ─────────
saw_mutation=0
for patch in "${patch_files[@]}"; do
    if [[ ! -f "${patch}" ]]; then
        continue   # consumed by a racing applier before our flock acquisition
    fi
    # helper exit codes: 0 = mutation applied, 10 = idempotent no-op,
    # anything else = hard error (log + continue to next patch).
    /usr/bin/env python3 "${APPLY_PY}" "${patch}"
    rc=$?
    case "${rc}" in
        0)
            saw_mutation=1
            ;;
        10)
            :  # idempotent no-op — helper already logged
            ;;
        *)
            printf 'xray-applier: apply of %s exited with rc=%d (continuing)\n' \
                "${patch}" "${rc}" >&2
            ;;
    esac
done

# ── 4. Single x-ui restart at the VERY END iff at least one patch mutated ─
if (( saw_mutation )); then
    if ! systemctl restart "${XUI_SERVICE_NAME}"; then
        printf 'xray-applier: systemctl restart %s failed\n' "${XUI_SERVICE_NAME}" >&2
        exit 2
    fi
fi

exit 0
