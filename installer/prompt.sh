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

    ok "Port=${PANEL_PORT}  User=${PANEL_USER}  Pass=<hidden>  HTTPS=${PANEL_ENABLE_HTTPS}"
    export PANEL_PORT PANEL_USER PANEL_PASS
}

info() { :; }  # provided by caller; allow standalone shellcheck without error
ok()   { :; }
err()  { :; }
