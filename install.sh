#!/usr/bin/env bash
# ============================================================================
# install.sh — Psiphon-3X-UI bootstrap installer
# ----------------------------------------------------------------------------
# This is the single entrypoint referenced by the one-line install command
# documented in README.md:
#
#   bash <(curl -sL https://raw.githubusercontent.com/DonMonro/p/main/install.sh) \
#     || bash <(wget -qO- https://raw.githubusercontent.com/DonMonro/p/main/install.sh)
#
# The two-URL form gives a curl→wget fallback so the command works on minimal
# Ubuntu installs that ship only `wget`.
#
# Phase 2 implementation:
#   - one-line installer with curl/wget-aware fetching of the repo
#   - interactive prompts (port/user/pass, manual or random)
#   - apt deps (incl. golang-go for building psiphon-tunnel-core from source)
#   - build psiphon-tunnel-core from the pinned upstream tag
#   - build the panel wheel, seed panel.db, register the systemd service
#   - final summary: server IP + browser login URL + credentials (shown once)
#
# Idempotent: re-running install.sh upgrades in place; session secret + DB row
# are preserved. Use `--uninstall` to stop the service, remove the 3x-ui
# inbounds/outbounds/routing rules this panel created, and remove the install
# prefix (3x-ui itself and any entries the operator made by hand stay intact).
# ============================================================================

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INSTALL_PREFIX="/opt/psiphon-3x-ui"
CONFIG_DIR="${INSTALL_PREFIX}/config"
BIN_DIR="${INSTALL_PREFIX}/bin"
# Phase 24 Hotfix #3 (Bug: per-country tunnel unit exit 1 — binary cannot mkdir
# its default datastore dir under the systemd sandbox). The templated unit
# system/psiphon-tunnel@.service's ExecStart now passes
# `-dataRootDirectory ${DATA_DIR}/%i` so each country's psiphon-tunnel-core
# process writes its server-list cache / OSL registry / key material under
# ${DATA_DIR}/<CODE>/. The installer (installer/panel_install.sh
# run_panel_install) pre-creates ${DATA_DIR} owned by the service user/group
# so the unit's per-country `mkdir` on first start succeeds (otherwise the
# binary dies with "failed to create datastore directory" → exit 1 → SOCKS5
# listener never bound → dashboard reports "Connection refused on 11000" on
# Add UA).
# shellcheck disable=SC2034  # used by installer/panel_install.sh (per-country psiphon-tunnel-core datastore root)
DATA_DIR="${INSTALL_PREFIX}/data"
REPO_URL="https://github.com/DonMonro/p.git"
# The git ref the curl|bash flow clones its helpers from. MUST match the ref
# this copy of install.sh is served from, or the script and the installer/*.sh
# helpers it sources come from different commits — the exact skew that broke
# v1.0.0 installs when Phase 29 removed installer/firewall.sh. Bump this in
# the same commit that moves a release tag. Override for branch testing:
#   PSIPHON3XUI_REPO_REF=my-branch sudo bash install.sh
REPO_REF="${PSIPHON3XUI_REPO_REF:-v1.0.1}"
LOG_FILE="${INSTALL_PREFIX}/install.log"
PSIPHON3XUI_USER="${PSIPHON3XUI_USER:-psiphon3xui}"
PSIPHON3XUI_GROUP="${PSIPHON3XUI_GROUP:-psiphon3xui}"

# Installer helpers live in the same dir as this entry script once it's been
# cloned locally; for the curl|bash flow this bootstrap clones the repo first.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_DIR="${SCRIPT_DIR}/installer"

# The following are intentionally declared in the entry script and shared with
# the sourced installer/*.sh helpers (deps, prompt, psiphon_install,
# panel_install, firewall). shellcheck looks only at this file and can't see
# the cross-file uses — hence the disable on each line.

# shellcheck disable=SC2034  # used by panel_install.sh + psiphon_install.sh
VENV_DIR="${INSTALL_PREFIX}/venv"
# shellcheck disable=SC2034  # used by panel_install.sh (panel.env) + panel.seed --db
DB_PATH="${INSTALL_PREFIX}/panel.db"
# shellcheck disable=SC2034  # used by panel_install.sh EnvironmentFile= rendering
ENV_FILE="${INSTALL_PREFIX}/panel.env"

# ---------------------------------------------------------------------------
# Pretty logging
# ---------------------------------------------------------------------------
COLOR_RESET=""
COLOR_INFO=""
COLOR_OK=""
COLOR_WARN=""
COLOR_ERR=""
if [[ -t 1 ]]; then
    COLOR_RESET=$'\033[0m'
    COLOR_INFO=$'\033[1;36m'
    COLOR_OK=$'\033[1;32m'
    COLOR_WARN=$'\033[1;33m'
    COLOR_ERR=$'\033[1;31m'
fi

_log() {
    local level="$1"; shift
    printf '%s[%s]%s %s\n' "${level}" "$1" "${COLOR_RESET}" "$*" | tee -a "${LOG_FILE}" 2>/dev/null || true
}
info() { _log "${COLOR_INFO}"  "INFO " "$1"; shift; _log "" "INFO " "$@"; }
ok()   { _log "${COLOR_OK}"   "OK   " "$*" 1>&2 || _log "" "OK  " "$*"; }
warn() { _log "${COLOR_WARN}"  "WARN " "$*" 1>&2 || _log "" "WARN" "$*"; }
err()  { _log "${COLOR_ERR}"   "ERROR" "$*" 1>&2 || _log "" "ERR " "$*"; }
die()  { err "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This installer must be run as root (use sudo)."
    fi
}

detect_distro() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID:-unknown} ${VERSION_ID:-?}"
    else
        echo "unknown ?"
    fi
}

require_ubuntu_like() {
    local id
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"
        case "${id}" in
            ubuntu|debian)
                ok "Detected supported distro: ${PRETTY_NAME:-${id}}"
                return 0
                ;;
        esac
    fi
    warn "Unrecognised or unsupported distro ($(detect_distro))."
    warn "The installer targets Ubuntu 20.04+/22.04+. Proceed at your own risk."
}

# ---------------------------------------------------------------------------
# Fetch the installer helpers if invoked via curl|bash (no local checkout)
# ---------------------------------------------------------------------------
ensure_install_dir() {
    mkdir -p "${INSTALL_PREFIX}" "${CONFIG_DIR}" "${BIN_DIR}"
    chmod 0750 "${INSTALL_PREFIX}" 2>/dev/null || true
    : > "${LOG_FILE}" || true
    chown root:root "${LOG_FILE}" 2>/dev/null || true
}

ensure_helpers_present() {
    # If installer/ is present alongside this script we're good. Otherwise clone.
    if [[ -d "${INSTALLER_DIR}" ]]; then
        return 0
    fi
    info "Fetching installer modules from ${REPO_URL} at ref '${REPO_REF}' ..."
    if command -v git >/dev/null 2>&1; then
        # Install git first if missing (we'll need it anyway for the psiphon clone).
        if ! command -v apt-get >/dev/null 2>&1; then
            die "apt-get not found — install git manually, then re-run."
        fi
        apt-get update -qq >/dev/null 2>&1 || true
        apt-get install -y -qq git >/dev/null 2>&1 \
            || die "Failed to bootstrap git for repo fetch."
        # A prior (failed or interrupted) curl|bash install leaves an empty
        # or stale ${INSTALL_PREFIX}/repo-tmp behind — `git clone` then refuses
        # to write into it (`fatal: destination path '…/repo-tmp' already exists
        # and is not an empty directory`). Remove any stale copy BEFORE cloning
        # (Hotfix #3 — re-installs work even after a previous installer aborted
        # mid-clone, mirroring the same defensive cleanup psiphon_install.sh
        # already applies to its own build scratch dir).
        if [[ -e "${INSTALL_PREFIX}/repo-tmp" ]]; then
            warn "Removing stale ${INSTALL_PREFIX}/repo-tmp before re-cloning …"
            rm -rf "${INSTALL_PREFIX}/repo-tmp" \
                || die "Could not remove stale ${INSTALL_PREFIX}/repo-tmp — delete it manually ('sudo rm -rf ${INSTALL_PREFIX}/repo-tmp') and re-run."
        fi
        # Clone the SAME ref this script came from (Phase 29 hotfix).
        #
        # This clone used to be unpinned, which silently mixed versions: the
        # curl|bash one-liner fetches install.sh from a pinned tag, but the
        # helpers it then sources came from whatever the default branch
        # happened to be. That worked only while the two agreed. Deleting
        # installer/firewall.sh in Phase 29 made every `v1.0.0` install abort
        # with "installer/firewall.sh: No such file or directory" — a tagged
        # script looking for a file that tag still lists but main no longer
        # ships. Any future helper rename/removal would break it again.
        #
        # REPO_REF is baked in and bumped at release time, so a tagged
        # install.sh clones its own tag. PSIPHON3XUI_REPO_REF overrides it for
        # testing a branch. A ref that does not exist on the remote is a hard
        # error, never a silent fall back to the default branch — falling back
        # is precisely the version skew this fixes.
        git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${INSTALL_PREFIX}/repo-tmp" \
            || die "Failed to clone installer repository at ref '${REPO_REF}'. Check the ref exists (git ls-remote --tags --heads ${REPO_URL}) or override with PSIPHON3XUI_REPO_REF=<branch-or-tag>."
        INSTALLER_DIR="${INSTALL_PREFIX}/repo-tmp/installer"
        SCRIPT_DIR="${INSTALL_PREFIX}/repo-tmp"
    else
        die "git is required to fetch installer modules. Install git or retry after cloning the repo manually."
    fi
}

# ---------------------------------------------------------------------------
# Phase 29 (item 3): remove the Phase-28 sudoers grant.
#
# Phase 28 installed /etc/sudoers.d/49-psiphon-3x-ui to let the unprivileged
# panel run `ufw allow <port>/tcp`. Phase 29 removes host-firewall management
# entirely, so that grant is now dead weight — and dead weight in
# /etc/sudoers.d is a standing privilege the operator did not ask to keep.
#
# This runs on INSTALL as well as uninstall: an operator upgrading from the
# previous release already has the file on disk, and nothing else would ever
# clear it. Both call sites are idempotent.
# ---------------------------------------------------------------------------
_remove_stale_sudoers_dropin() {
    local dropin="/etc/sudoers.d/49-psiphon-3x-ui"
    if [[ -e "${dropin}" ]]; then
        rm -f "${dropin}" 2>/dev/null \
            && info "Removed the obsolete sudoers grant ${dropin} (the panel no longer manages the firewall)." \
            || warn "Could not remove ${dropin}; delete it manually."
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
run_uninstall() {
    echo "${COLOR_INFO}== Psiphon-3X-UI uninstaller ==${COLOR_RESET}"
    warn "This will STOP and remove the psiphon-3x-ui service and the ${INSTALL_PREFIX} tree."
    warn "3x-ui entries created by this panel (inbounds, outbounds, routing rules) will be removed automatically."
    printf '%sType "yes" to confirm: %s' "${COLOR_WARN}" "${COLOR_RESET}"
    local confirm
    read -r confirm || confirm=""
    if [[ "${confirm}" != "yes" ]]; then
        info "Uninstall cancelled."
        exit 0
    fi

    # ── Phase 27 (item 3): clean the 3x-ui entries this panel created ──────
    # Run BEFORE stopping the service so the venv + DB are still intact.
    #
    # Phase 29 (item 4) — THIS IS THE FIX for "uninstall didn't delete anything".
    #
    # The 3x-ui password is stored encrypted in panel.db (XuiLink.password_enc),
    # signed with PSIPHON3XUI_SESSION_SECRET. That secret lives ONLY in
    # ${ENV_FILE}, which systemd feeds to the panel via EnvironmentFile= — it is
    # never in a login shell's environment. Invoking the cleanup module bare, as
    # this did, meant panel.config.Settings fell back to its built-in default
    # ("dev-only-change-me"), decrypt_creds() failed the signature check and
    # returned None, and the module bailed out early with
    #
    #     3x-ui cleanup skipped: no cached 3x-ui credentials in panel.db
    #
    # printed among the other uninstall output — exit code 0, nothing deleted.
    # Every inbound and outbound the panel ever created stayed in 3x-ui.
    #
    # Sourcing ${ENV_FILE} in a SUBSHELL (so the secret never leaks into the
    # rest of this script's environment) with `set -a` gives the module the real
    # secret, so decryption succeeds and the cleanup actually runs.
    if [[ -x "${VENV_DIR}/bin/python" && -f "${DB_PATH}" ]]; then
        info "Cleaning 3x-ui entries created by this panel …"
        (
            set -a
            if [[ -f "${ENV_FILE}" ]]; then
                # shellcheck source=/dev/null
                source "${ENV_FILE}" 2>/dev/null || true
            fi
            set +a
            "${VENV_DIR}/bin/python" -m panel.uninstall --db "${DB_PATH}"
        ) || warn "3x-ui cleanup reported warnings (see above); continuing uninstall."
        if [[ ! -f "${ENV_FILE}" ]]; then
            warn "${ENV_FILE} not found — the 3x-ui password could not be decrypted, so inbounds/outbounds may remain. Remove them from the 3x-ui UI."
        fi
    else
        warn "Skipping 3x-ui cleanup: venv or panel.db not found."
    fi

    systemctl stop psiphon-3x-ui.service 2>/dev/null || true
    systemctl disable psiphon-3x-ui.service 2>/dev/null || true
    rm -f /etc/systemd/system/psiphon-3x-ui.service

    # Hotfix #9: stop + remove the per-country templated tunnel unit + the
    # polkit rule that authorized the panel user to drive it. Stops any
    # leftover running instances (--all pattern expands to every encoded
    # country) before removing the unit file.
    for unit in $(systemctl list-units --type=service --all --plain \
                  --no-legend 2>/dev/null | awk '{print $1}' \
                  | grep '^psiphon-tunnel@' 2>/dev/null); do
        systemctl stop "${unit}" 2>/dev/null || true
    done
    rm -f /etc/systemd/system/psiphon-tunnel@.service \
        "/etc/systemd/system/psiphon-tunnel@.service.d"/*.conf 2>/dev/null || true
    rm -f /etc/polkit-1/rules.d/49-psiphon-3x-ui.rules 2>/dev/null || true
    # Phase 29 (item 3): clear the obsolete Phase-28 sudoers grant if an older
    # install left one behind. Leaving a NOPASSWD rule for a user that is about
    # to be deleted would hand `ufw allow` to any future account reusing the name.
    _remove_stale_sudoers_dropin
    # Best-effort reloads so polkit+systemd release the now-removed files.
    systemctl reload polkit.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    # ── Phase 24 Hotfix #2 (Bug: orphan panel process survives uninstall) ──
    # `systemctl stop` is fire-and-forget — it issues SIGTERM and returns 0
    # immediately, NOT after the child has reaped. Worse: `rm -rf
    # ${INSTALL_PREFIX}` below unlinks the venv + wheel files from disk but
    # the orphaned python/uvicorn process keeps running on PANEL_PORT with
    # the OLD wheel code fully loaded in memory (the inodes are kept alive
    # by the open file descriptors — exactly how Linux lets you delete a
    # file that's still being executed). The orphan then keeps serving
    # panel/api/dashboard HTTP requests with whatever code was baked into
    # the wheel at the moment of its launch — including the OLD raw-https
    # RemoteServerListURLs / wrong SponsorId from a prior commit — so when
    # the operator re-runs `install.sh` after this uninstall, the new
    # installer's wait_for_panel_socket connects to the orphan (not the
    # new systemd launch), prints "Psiphon-3X-UI installed", but the
    # subsequent "Add UA" button keeps dying because the orphan serves
    # the OLD code. Symptom in the operator's journalctl:
    #   Failed to restart psiphon-3x-ui.service: Unit psiphon-3x-ui.service not found.
    # + (downstream) SOCKS5 health probe on 127.0.0.1:11000 failed after retry: Connection refused.
    #
    # Fix: BEFORE the rm -rf over INSTALL_PREFIX, snapshot every PID
    # listening on PANEL_PORT + every python/uvicorn process running as
    # the panel service user, and `kill -9` them. We do this AFTER
    # `systemctl stop` so any legitimately-tracked MainPID has been reaped
    # by systemd — anything left is by definition an orphan.
    sleep 1   # let systemctl stop's SIGTERM propagate
    _purge_orphan_panel_listeners
    _purge_orphan_panel_user_processes

    if id "${PSIPHON3XUI_USER}" >/dev/null 2>&1; then
        userdel --force "${PSIPHON3XUI_USER}" 2>/dev/null || true
    fi
    if getent group "${PSIPHON3XUI_GROUP}" >/dev/null 2>&1; then
        groupdel "${PSIPHON3XUI_GROUP}" 2>/dev/null || true
    fi

    rm -rf "${INSTALL_PREFIX}"
    ok "Psiphon-3X-UI uninstalled (3x-ui itself is untouched; entries this panel created were removed)."
    exit 0
}

# --- Phase 24 Hotfix #2 helpers (orphan-process purge) ---------------------
# Both helpers are best-effort: they print a `warn` if the snapshot fails
# (e.g., `ss` missing on minimal distros) and proceed. They are safe to
# call without sourcing panel_install.sh's port_listeners() — they use a
# cheap inline `ss -tlnp | awk` snapshot plus `pgrep -u <user>`.
_purge_orphan_panel_listeners() {
    local pids=""
    # Same shape as panel_install.sh's port_listeners(): "PID COMMAND"
    if ! command -v ss >/dev/null 2>&1; then
        warn "ss not found — orphan listener purge skipped (install iproute2)."
        return 0
    fi
    while IFS= read -r pidcmd; do
        local pid="${pidcmd%% *}"
        [[ -n "${pid}" ]] || continue
        pids="${pids:+${pids} }${pid}"
    done < <(ss -tlnp 2>/dev/null | awk -v port=":${PANEL_PORT}" '
        $1 == "LISTEN" && $4 == port {
            line = $0
            sub(/.*users:\(\("/, "", line)
            prog = line; sub(/".*/, "", prog)
            pid  = line; sub(/.*pid=/, "", pid); sub(/[,) ].*/, "", pid)
            if (pid != "") print pid " " prog
        }
    ')
    if [[ -n "${pids}" ]]; then
        warn "Killing orphan panel listener(s) holding TCP/${PANEL_PORT} (PIDs: ${pids}) …"
        # shellcheck disable=SC2086  # intentional word-splitting of pid list
        kill -9 ${pids} 2>/dev/null || true
        sleep 1
        if ss -tlnp 2>/dev/null | awk -v port=":${PANEL_PORT}" '
            $1 == "LISTEN" && $4 == port { found=1 } END { exit !found }
        '; then
            warn "TCP/${PANEL_PORT} is STILL held after kill -9; the next install's \
pre-flight will retry — or free it manually with 'sudo fuser -k ${PANEL_PORT}/tcp'."
        else
            ok "Orphan panel listener(s) on TCP/${PANEL_PORT} cleared."
        fi
    fi
}

_purge_orphan_panel_user_processes() {
    # Catch orphans that are no longer bound to PANEL_PORT (maybe a
    # different panel port from the prior install's panel.env) but ARE
    # running under the panel service user as a python process — these
    # would also survive `rm -rf ${INSTALL_PREFIX}` and could re-grab the
    # port on the next install.
    if ! id "${PSIPHON3XUI_USER}" >/dev/null 2>&1; then
        return 0   # user already deleted (or never existed) — nothing to purge
    fi
    if ! command -v pgrep >/dev/null 2>&1; then
        warn "pgrep not found — orphan-user purge skipped (install procps)."
        return 0
    fi
    local pids
    # Match: any process whose COMM is `python` or `python3` or `uvicorn`
    # or whose command-line contains `python -m panel` (the panel's
    # systemd ExecStart shape).
    pids="$(pgrep -u "${PSIPHON3XUI_USER}" -f 'python|uvicorn' 2>/dev/null || true)"
    if [[ -n "${pids}" ]]; then
        warn "Killing orphan panel-user process(es): ${pids}"
        # shellcheck disable=SC2086  # intentional word-splitting of pid list
        kill -9 ${pids} 2>/dev/null || true
        sleep 1
    fi
}

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
main() {
    # Cheap arg parsing: --uninstall short-circuits everything else.
    case "${1:-}" in
        --uninstall|-u)
            run_uninstall
            ;;
        --help|-h)
            cat <<EOF
Usage: install.sh [--uninstall]

  Install / upgrade / uninstall Psiphon-3X-UI.

  Most operators reach this script via a curl-into-bash one-liner rather than
  downloading install.sh to disk; the curl form works for every subcommand:

    bash <(curl -sL https://raw.githubusercontent.com/DonMonro/p/v1.0.0/install.sh)            # install
    sudo bash <(curl -sL https://raw.githubusercontent.com/DonMonro/p/v1.0.0/install.sh) --uninstall

  Operators who cloned the repo to disk and have install.sh in CWD can also:

    sudo bash install.sh            # install
    sudo bash install.sh --uninstall

  (no args)  Install or upgrade Psiphon-3X-UI.
             Re-runs are idempotent: wheel upgraded, panel.db admin row
             re-seeded with any newly-entered password, systemd service
             bounced.
  --uninstall  Stop the panel service and remove ${INSTALL_PREFIX}.
             Psiphon tunnel instances are stopped. The 3x-ui inbounds and
             outbounds this panel created are removed from 3x-ui; the 3x-ui
             panel itself and everything else in it are left untouched.
EOF
            exit 0
            ;;
    esac

    require_root
    echo "${COLOR_INFO}== Psiphon-3X-UI installer ==${COLOR_RESET}"
    require_ubuntu_like
    ensure_install_dir
    ensure_helpers_present

    info "Sourcing installer modules from ${INSTALLER_DIR}"
    # shellcheck disable=SC1090,SC1091
    #
    # Source order matters: prepare_user must load before any helper that uses
    # `install -g ${PSIPHON3XUI_GROUP}` (psiphon_install, panel_install); it
    # runs first because shellcheck checks can't see across files. https_install
    # runs ahead of panel_install so the latter can pick up ${PANEL_TLS_CERT}
    # / ${PANEL_TLS_KEY} into panel.env + the systemd ExecStart.
    for helper in deps prepare_user prompt psiphon_install https_install panel_install; do
        # shellcheck disable=SC1090,SC1091
        source "${INSTALLER_DIR}/${helper}.sh" || die "Failed to load ${helper}.sh"
    done

    run_deps
    run_prepare_user      # creates psiphon3xui user/group + sets prefix ownership
    run_prompt            # sets PANEL_PORT, PANEL_USER, PANEL_PASS (HTTPS prompt removed — feature parked)
    run_psiphon_install   # builds psiphon-tunnel-core from the pinned tag (needs the group)
    run_https_install     # self-signed cert helper kept for future re-enablement;
                          # short-circuits because the install prompt no longer
                          # sets PANEL_ENABLE_HTTPS=yes (re-enable manually by
                          # exporting PANEL_ENABLE_HTTPS=yes before install.sh)
    run_panel_install     # venv + wheel + seed + systemd enable (needs the user, may pick up TLS)

    # Phase 29 (item 3): the firewall stage is gone. installer/firewall.sh has
    # been deleted and this installer no longer touches ufw. On a stock install
    # ufw was never enabled anyway (the `ufw --force enable` call was always
    # commented out to avoid locking the operator out of SSH), so the allow
    # rules filtered nothing and only ever caused the in-panel port change to
    # fail. Hosts that DO run an active firewall now open the panel port the
    # same way they would for any other service.
    _remove_stale_sudoers_dropin

    print_summary
    echo
    ok "Done. Open the web UI in a browser to complete first-run setup."
}

print_summary() {
    # Hotfix #11 (Bug #1): auto-detect the server's IP for the "Web UI" line.
    # The previous probe `ip -4 -o addr show to default | awk '{print $4}'`
    # matched the loopback interface on hosts where `lo` was the only "scope
    # default"-scoped interface, returning 127.0.0.1 — so the operator saw
    # `Web UI: http://127.0.0.1:11138` instead of the reachable address.
    # The new probe chain is, in priority order:
    #   (1) `ip route get 1.1.1.1 | awk '/src/{print $NF; exit}'` — yields the
    #       IPv4 the host would actually source packets FROM for an outbound
    #       route (the address a remote browser would route to on a
    #       directly-attached VPS).
    #   (2) `curl -s --max-time 5 <ip-echo service>` — for cloud-NAT'd hosts
    #       where the local interface has a private RFC1918 address but the
    #       public IP lives in front of the NAT. Falls through on timeout.
    #   (3) "<SERVER_IP>" placeholder — kept as the last-ditch fallback so the
    #       summary still prints when both probes come up empty (broken /
    #       firewalled route + no outbound HTTPS).
    local public_ipv4=""
    public_ipv4="$(ip route get 1.1.1.1 2>/dev/null \
        | awk '/[[:space:]]src[[:space:]]/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    if [[ -z "${public_ipv4}" ]]; then
        public_ipv4="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
            || curl -s --max-time 5 https://ifconfig.me 2>/dev/null \
            || true)"
    fi
    [[ -z "${public_ipv4}" ]] && public_ipv4="<SERVER_IP>"

    local scheme="http"
    if [[ "${PANEL_ENABLE_HTTPS:-no}" == "yes" ]]; then
        scheme="https"
    fi
    cat <<EOF

${COLOR_OK}── Psiphon-3X-UI installed ─────────────────────────────────${COLOR_RESET}
 Web UI : ${scheme}://${public_ipv4}:${PANEL_PORT}
 User   : ${PANEL_USER}
 Pass   : ${PANEL_PASS}      ${COLOR_WARN}(shown once — copy it now)${COLOR_RESET}
 HTTPS  : ${PANEL_ENABLE_HTTPS:-no}      ${COLOR_WARN}(front with Caddy for real TLS)${COLOR_RESET}
 Log    : ${LOG_FILE}
${COLOR_OK}──────────────────────────────────────────────────────────${COLOR_RESET}
EOF
}

main "$@"
