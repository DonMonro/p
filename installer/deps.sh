#!/usr/bin/env bash
# ============================================================================
# installer/deps.sh — install system packages needed by the panel + installer
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_deps().
#
# Phase 2 packages:
#   - python3-venv, python3-pip, python3-build, python3-setuptools :: panel wheel build
#   - golang-go (>=1.21)  :: build psiphon-tunnel-core from source
#   - git                 :: clone the pinned psiphon-tunnel-core tag
#   - jq, ufw, curl, wget, ca-certificates, tar :: misc installer bookkeeping
#
# We scope apt locking to this script and tolerate apt auto-installing
# recommended extras (golang-go pulls gccgo/clang naturally); we don't pin
# versions at the apt level because Ubuntu LTS point releases drift.
# ============================================================================

# Minimum Go toolchain version required to build modern psiphon-tunnel-core.
# 1.21 is the lowest Ubuntu 22.04 ships in `golang-go` (golang 1.18 from base;
# users on 22.04 must add the longsleep/golang PPA or use 24.04). We detect
# and warn after install if the version is too low.
REQUIRED_GO_MAJOR_MINOR="1.21"

run_deps() {
    info "Installing base system dependencies …"

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -qq

    apt-get install -y -qq \
        curl wget git jq ufw ca-certificates tar \
        python3 python3-venv python3-pip \
        python3-build python3-setuptools python3-wheel \
        golang-go \
        || die "Failed to install required packages."

    # Verify the Go toolchain is new enough for modern Go modules.
    if command -v go >/dev/null 2>&1; then
        local go_ver go_major go_minor
        go_ver="$(go version | awk '{print $3}' | sed 's/^go//')"
        go_major="${go_ver%%.*}"
        go_minor="${go_ver#*.}"
        go_minor="${go_minor%%.*}"
        if [[ "${go_major}" -lt 1 ]] || { [[ "${go_major}" -eq 1 ]] && [[ "${go_minor}" -lt 21 ]]; } 2>/dev/null; then
            warn "Detected go ${go_ver}; psiphon-tunnel-core needs >= ${REQUIRED_GO_MAJOR_MINOR}."
            warn "On Ubuntu 22.04 install a newer golang via:"
            warn "    sudo add-apt-repository ppa:longsleep/golang-backports && sudo apt-get update && sudo apt-get install golang-go"
            warn "Or upgrade to Ubuntu 24.04. The build step will fail if you continue."
        else
            ok "Go toolchain: $(go version)"
        fi
    else
        warn "golang-go did not install; the Psiphon build step will fail."
    fi

    ok "System dependencies installed."
}
