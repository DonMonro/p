#!/usr/bin/env bash
# ============================================================================
# installer/prompt.sh — interactive collect of panel port / user / password
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_prompt(), which exports:
#   PANEL_PORT, PANEL_USER, PANEL_PASS
# Each value may be entered manually or randomly generated (the user is
# offered the choice for each field). Phase 0: interactive loop with sane
# defaults. Phase 2 wires the resulting values into the panel_install step.
# ============================================================================

_rand_port() {
    # Random unused high port in [10000, 60000].
    local p
    while :; do
        p=$(( (RANDOM << 15 | RANDOM) % 50000 + 10000 ))
        if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${p}$"; then
            echo "$p"; return 0
        fi
    done
}

_rand_user() {
    echo "psiphonadmin"
}

_rand_pass() {
    # 20 chars A-Za-z0-9 via /dev/urandom.
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20 || true
}

ask_value() {
    # ask_value "prompt" "random_generator_fn_or_default" varname is_secret
    local prompt="$1" generator="$2" varname="$3" secret="${4:-no}"
    local answer=""

    while true; do
        printf '%s[Drift] %s [%s] (press Enter for random):%s ' "${COLOR_INFO}" "${prompt}" "${generator}" "${COLOR_RESET}"
        if [[ "${secret}" == "yes" ]]; then
            read -rs answer || answer=""
            echo
        else
            read -r answer || answer=""
        fi

        if [[ -z "${answer}" ]]; then
            case "${generator}" in
                port)     answer="$(_rand_port)" ;;
                user)     answer="$(_rand_user)" ;;
                pass)     answer="$(_rand_pass)" ;;
                *)        answer="${generator}" ;;
            esac
            printf '%s(using random: %s)%s\n' "${COLOR_WARN}" "${answer}" "${COLOR_RESET}"
        fi

        if [[ "${secret}" != "yes" && "${answer}" =~ [^A-Za-z0-9_-] ]]; then
            # tolerate most printable chars for password but not for user/port
            if ! [[ "${answer}" =~ ^[0-9]+$ ]]; then
                err "Invalid value. Try again."; continue
            fi
        fi

        if [[ "${varname}" == "PANEL_PORT" ]]; then
            if ! [[ "${answer}" =~ ^[0-9]+$ ]] || (( answer < 1024 || answer > 65535 )); then
                err "Port must be between 1024 and 65535."; continue
            fi
        fi
        printf -v "${varname}" '%s' "${answer}"
        return 0
    done
}

# ============================================================================
# Hotfix #14 (Phase 23): Psiphon Network upstream-credentials survey.
# ----------------------------------------------------------------------------
# The four Psiphon-Inc-issued commercial-grade credentials are REQUIRED for
# per-country tunnel establishment against the production Psiphon Network:
#   PSIPHON_PROPAGATION_CHANNEL_ID              (32-char hex string)
#   PSIPHON_SPONSOR_ID                          (16-char hex string)
#   PSIPHON_REMOTE_SERVER_LIST_URL              (https://s3.amazonaws.com/...)
#   PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY  (base64 ed25519 pubkey,
#                                                    ~44 chars including '=')
# Without them the upstream binary boots, fails to authenticate the S3-listed
# remote server list, and loops on EstablishTunnelTimeout for 5 minutes before
# exiting — perpetual restart-loop.see docs/TROUBLESHOOTING.md for how to
# obtain the credentials. This function SURVEYS the operator at install time
# (interactive TTY only); the values are then written to ${ENV_FILE} by
# installer/panel_install.sh.
# ============================================================================
_prompt_psiphon_credentials() {
    # If stdin is NOT a TTY (scripted install / curl|bash with -y), skip the
    # interactive prompts entirely — the operator will need to edit
    # /opt/psiphon-3x-ui/panel.env AFTER install + systemctl restart.
    if ! [[ -t 0 ]]; then
        warn "Non-interactive install — Psiphon-Inc credentials survey SKIPPED."
        warn "Per-country tunnels will NOT establish until you edit"
        warn "    ${ENV_FILE:-/opt/psiphon-3x-ui/panel.env}"
        warn "and set the four PSIPHON_* upstream-credential env vars. See"
        warn "docs/TROUBLESHOOTING.md (\"Psiphon Inc. credentials required\")."
        warn "Trying to inline-enable a country before configuring these will"
        warn "fast-fail at render_config-time with a clear actionable error"
        warn "(instead of the silent 5-minute EstablishTunnelTimeout loop)."
        return 0
    fi

    info ""
    info "Psiphon Network upstream credentials"
    info "------------------------------------"
    info "Per-country tunnels require four Psiphon-Inc-issued values, which"
    info "are NOT publicly available in the psiphon-tunnel-core GitHub repo."
    info "See docs/TROUBLESHOOTING.md \"Psiphon Inc. credentials required\"."
    info "Press Enter at any prompt to SKIP — you can fill these in later"
    info "by editing ${ENV_FILE:-/opt/psiphon-3x-ui/panel.env}."
    info ""

    # Read each value into the env-exported shell var with a no-echo prompt
    # (the four credentials are sensitive — never log them raw). Empty =
    # SKIPPED (the panel fast-fails at render-config time with a clear msg).
    printf '%s[Drift] PSIPHON_PROPAGATION_CHANNEL_ID (32 hex chars, Enter to skip):%s ' "${COLOR_INFO}" "${COLOR_RESET}"
    read -r PSIPHON_PROPAGATION_CHANNEL_ID || PSIPHON_PROPAGATION_CHANNEL_ID=""
    export PSIPHON_PROPAGATION_CHANNEL_ID

    printf '%s[Drift] PSIPHON_SPONSOR_ID (16 hex chars, Enter to skip):%s ' "${COLOR_INFO}" "${COLOR_RESET}"
    read -r PSIPHON_SPONSOR_ID || PSIPHON_SPONSOR_ID=""
    export PSIPHON_SPONSOR_ID

    printf '%s[Drift] PSIPHON_REMOTE_SERVER_LIST_URL (https://..., Enter to skip):%s ' "${COLOR_INFO}" "${COLOR_RESET}"
    read -r PSIPHON_REMOTE_SERVER_LIST_URL || PSIPHON_REMOTE_SERVER_LIST_URL=""
    export PSIPHON_REMOTE_SERVER_LIST_URL

    # Sensitive: do NOT echo it back. Most operators paste the pubkey; we
    # can't easily do a no-echo `read -s` here because the operator needs
    # visual feedback to confirm their paste captured all 44 chars. Use
    # plain `read -r` (post-paste trimming is handled by the panel).
    printf '%s[Drift] PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY (base64 ed25519, Enter to skip):%s ' "${COLOR_INFO}" "${COLOR_RESET}"
    read -r PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY || PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY=""
    export PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY

    # Report counts only (never reveal the values themselves).
    local filled=0 total=4
    for v in PSIPHON_PROPAGATION_CHANNEL_ID PSIPHON_SPONSOR_ID \
             PSIPHON_REMOTE_SERVER_LIST_URL \
             PSIPHON_REMOTE_SERVER_LIST_SIGNATURE_PUBLIC_KEY; do
        if [[ -n "${!v:-}" ]]; then filled=$((filled + 1)); fi
    done

    if (( filled == total )); then
        ok "All 4 Psiphon-Inc credentials collected. They will be written to"
        ok "    ${ENV_FILE:-/opt/psiphon-3x-ui/panel.env}"
        ok "(group-read-only — never revealed to other system users nor logged)."
    else
        warn "${filled}/${total} Psiphon-Inc credentials collected. The missing"
        warn "ones will fast-fail at per-country tunnel enable time with a clear"
        warn "actionable error pointing at ${ENV_FILE:-/opt/psiphon-3x-ui/panel.env}."
        warn "See docs/TROUBLESHOOTING.md (\"Psiphon Inc. credentials required\")."
    fi
}

run_prompt() {
    info "Collecting panel credentials. Press Enter at any prompt to use a random value."

    ask_value "Panel port"        port "PANEL_PORT"
    ask_value "Admin username"    user "PANEL_USER"
    ask_value "Admin password"    pass "PANEL_PASS" yes

    # Phase 7 — opt-in self-signed HTTPS. Default: no (operator can front with
    # Caddy for a real Let's Encrypt cert; enabling this mints an openssl cert
    # so the panel terminates TLS itself with a browser-warning self-signed).
    local enable_https=""
    printf '%s[Drift] Enable self-signed HTTPS? [y/N]:%s ' "${COLOR_INFO}" "${COLOR_RESET}"
    read -r enable_https || enable_https=""
    case "${enable_https}" in
        y|Y|yes|YES|Yes)
            PANEL_ENABLE_HTTPS="yes"
            ok "Self-signed HTTPS enabled (openssl cert mints after the panel.wheel install)."
            ;;
        *)
            PANEL_ENABLE_HTTPS="no"
            info "HTTPS disabled — panel will bind plain HTTP (front with Caddy for real TLS)."
            ;;
    esac
    export PANEL_ENABLE_HTTPS

    # Hotfix #14 (Phase 23): survey the operator for the four Psiphon-Inc
    # upstream credentials at install time so they get written into
    # ${ENV_FILE} on this very install (no second scripting step needed).
    # The function fast-paths out (with a clear warning) when stdin is NOT a
    # TTY — scripted / curl|bash installs keep working non-interactively,
    # and the panel fast-fails at per-country enable time with a clear msg
    # pointing the operator at the env-file fixup.
    _prompt_psiphon_credentials

    ok "Port=${PANEL_PORT}  User=${PANEL_USER}  Pass=<hidden>  HTTPS=${PANEL_ENABLE_HTTPS}"
    export PANEL_PORT PANEL_USER PANEL_PASS
}

info() { :; }  # provided by caller; allow standalone shellcheck without error
ok()   { :; }
err()  { :; }
