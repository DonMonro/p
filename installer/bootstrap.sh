#!/usr/bin/env bash
# ============================================================================
# installer/bootstrap.sh — curl|bash -aware bootstrap (optional alt entrypoint)
# ----------------------------------------------------------------------------
# Some users prefer `curl -sL URL | bash -s -- <args>`. This file mirrors the
# flow of install.sh but reads from stdin so it can be pipe-fed. Most users
# will use the recommended `bash <(curl -sL …)` form in README.md; this file
# exists for completeness and parity. Phase 0 stub: defers to main().
# ============================================================================

set -euo pipefail
# When piped in we have no script dir; download a fresh copy first.
echo "Bootstrap via stdin is not implemented in Phase 0 — use 'bash <(curl -sL …)' instead." >&2
exit 1
