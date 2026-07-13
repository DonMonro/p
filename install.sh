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
#   - ufw: open the chosen panel port only (inbound range opened later by wizard)
#   - final summary: server IP + browser login URL + credentials (shown once)
#
# Idempotent: re-running install.sh upgrades in place; session secret + DB row
# are preserved. Use `--uninstall` to stop the service and remove the install
# prefix (3x-ui inbounds in the panel stay intact with a warning).
# ============================================================================

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
INSTALL_PREFIX="/opt/psiphon-3x-ui"
CONFIG_DIR="${INSTALL_PREFIX}/config"
BIN_DIR="${INSTALL_PREFIX}/bin"
REPO_URL="https://github.com/DonMonro/p.git"
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
    info "Fetching installer modules from ${REPO_URL} ..."
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
        git clone --depth 1 "${REPO_URL}" "${INSTALL_PREFIX}/repo-tmp" \
            || die "Failed to clone installer repository."
        INSTALLER_DIR="${INSTALL_PREFIX}/repo-tmp/installer"
        SCRIPT_DIR="${INSTALL_PREFIX}/repo-tmp"
    else
        die "git is required to fetch installer modules. Install git or retry after cloning the repo manually."
    fi
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
run_uninstall() {
    echo "${COLOR_INFO}== Psiphon-3X-UI uninstaller ==${COLOR_RESET}"
    warn "This will STOP and remove the psiphon-3x-ui service and the ${INSTALL_PREFIX} tree."
    warn "3x-ui's own inbounds installed by THIS panel are NOT touched — you must delete them from 3x-ui's UI/API manually."
    printf '%sType "yes" to confirm: %s' "${COLOR_WARN}" "${COLOR_RESET}"
    local confirm
    read -r confirm || confirm=""
    if [[ "${confirm}" != "yes" ]]; then
        info "Uninstall cancelled."
        exit 0
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
    # Best-effort reloads so polkit+systemd release the now-removed files.
    systemctl reload polkit.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true

    if id "${PSIPHON3XUI_USER}" >/dev/null 2>&1; then
        userdel --force "${PSIPHON3XUI_USER}" 2>/dev/null || true
    fi
    if getent group "${PSIPHON3XUI_GROUP}" >/dev/null 2>&1; then
        groupdel "${PSIPHON3XUI_GROUP}" 2>/dev/null || true
    fi

    rm -rf "${INSTALL_PREFIX}"
    ok "Psiphon-3X-UI uninstalled (3x-ui itself is untouched)."
    exit 0
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
             Psiphon tunnel instances are stopped. The 3x-ui panel and any
             inbounds created through it are left untouched.
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
    for helper in deps prepare_user prompt psiphon_install https_install panel_install firewall; do
        # shellcheck disable=SC1090,SC1091
        source "${INSTALLER_DIR}/${helper}.sh" || die "Failed to load ${helper}.sh"
    done

    run_deps
    run_prepare_user      # creates psiphon3xui user/group + sets prefix ownership
    run_prompt            # sets PANEL_PORT, PANEL_USER, PANEL_PASS, PANEL_ENABLE_HTTPS
    run_psiphon_install   # builds psiphon-tunnel-core from the pinned tag (needs the group)
    run_https_install     # Phase 7 — self-signed cert (skips if PANEL_ENABLE_HTTPS != yes)
    run_panel_install     # venv + wheel + seed + systemd enable (needs the user, may pick up TLS)
    run_firewall          # opens panel port only (range opened later by wizard)

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
 HTTPS  : ${PANEL_ENABLE_HTTPS:-no}      ${COLOR_WARN}(self-signed: expect browser warning)${COLOR_RESET}
 Log    : ${LOG_FILE}
${COLOR_OK}──────────────────────────────────────────────────────────${COLOR_RESET}
EOF
}

main "$@"
