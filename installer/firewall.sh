#!/usr/bin/env bash
# ============================================================================
# installer/firewall.sh — Phase 29: host-firewall management removed (no-op)
# ============================================================================
# Phase 29 deleted the firewall stage. The installer never ran
# `ufw --force enable` (deliberately — it would risk locking an operator out
# of SSH), so on a stock install ufw is INACTIVE and the old `ufw allow`
# rules filtered nothing. The only thing the stage ever did was fail, and the
# sudoers grant added to bridge it was itself the failure.
#
# This file is a NO-OP STUB kept for backward compatibility. Releases up to
# v1.0.0 hardcode `firewall` in install.sh's sourced-helper list AND call
# `run_firewall`, while their bootstrap clones the repo unpinned (default
# branch, no --branch), so removing this file made every pinned-tag install
# abort at the source step:
#
#     /dev/fd/63: line 267: .../installer/firewall.sh: No such file or directory
#
# Deleting only the file would move the failure one line down: install.sh
# runs under `set -euo pipefail`, where a call to a now-undefined
# `run_firewall` is a command-not-found and aborts the run just as hard.
# So the stub must both EXIST and define the function as a successful no-op.
#
# Current install.sh on main sources neither this file nor calls the
# function; nothing here runs on a current install. Do not add logic to it.
# ============================================================================

# Deliberately a no-op that succeeds.
#
# `return 0` is load-bearing: under `set -e` a function whose last command
# fails takes the whole installer down, and an unpinned old install.sh calls
# this bare (not in an `if`), so a non-zero exit here would skip the
# remaining stages including print_summary.
run_firewall() {
    if declare -f info >/dev/null 2>&1; then
        info "Skipping firewall configuration — Phase 29 removed host-firewall management."
        info "If you run an active firewall, open the panel port yourself: ufw allow <panel_port>/tcp"
    fi
    return 0
}
