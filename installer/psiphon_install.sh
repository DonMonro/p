#!/usr/bin/env bash
# ============================================================================
# installer/psiphon_install.sh — build psiphon-tunnel-core from source
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_psiphon_install().
#
# WHY BUILD FROM SOURCE:
#   The upstream `Psiphon-Labs/psiphon-tunnel-core` GitHub releases ship only
#   the Android / iOS / Client-Library Go-source zips — there is NO prebuilt
#   `linux_amd64` server binary and NO published SHA256 checksum on any tagged
#   release (verified across v2.0.30 … v2.0.39 during the Phase 2 spike). The
#   `psiphon.ca` download URLs use an obfuscated endpoint whose license terms
#   forbid server use. Building the standalone `ConsoleClient` Go module
#   directly from the pinned upstream source is the cleanest, license-safe,
#   reproducible path.
#
# BUILD STRATEGY (mirrors upstream ConsoleClient/make.bash):
#   1. Shallow-clone the pinned tag into a build scratch dir.
#   2. `cd ConsoleClient && GOOS=linux GOARCH=amd64 go build` with ldflags
#      matching the upstream recipe (buildinfo injection + `-s -w`).
#   3. Install the resulting binary at ${BIN_DIR}/psiphon-tunnel-core.
#   4. Record its SHA256 + the pinned tag to ${INSTALL_PREFIX}/psiphon-tunnel-core.sha256
#      (we built it ourselves, so the hash serves as a tamper-detection
#      baseline rather than an upstream-supplied value).
#
# RE-ENTRY:
#   Idempotent — removes any prior ${BIN_DIR}/psiphon-tunnel-core before
#   copying the freshly built one. The scratch build dir is wiped on entry.
# ============================================================================

# ────────────────────────────────────────────────────────────────────────────
# Pinned upstream tag. Bump this when modifying; record the new tag in the
# SHA256 manifest written at the end. See https://github.com/Psiphon-Labs/psiphon-tunnel-core/releases
# ────────────────────────────────────────────────────────────────────────────
PSIPHON_TAG="${PSIPHON_TAG:-v2.0.39}"
PSIPHON_REPO="https://github.com/Psiphon-Labs/psiphon-tunnel-core.git"
PSIPHON_BUILD_DIR="${INSTALL_PREFIX}/build-psiphon"
PSIPHON_SHA256_FILE="${INSTALL_PREFIX}/psiphon-tunnel-core.sha256"

run_psiphon_install() {
    info "Building psiphon-tunnel-core from source (tag ${PSIPHON_TAG}) …"

    if ! command -v go >/dev/null 2>&1; then
        die "golang-go is not installed. Re-run 'installer/deps.sh' (apt install golang-go)."
    fi
    if ! command -v git >/dev/null 2>&1; then
        die "git is not installed. Re-run 'installer/deps.sh' (apt install git)."
    fi

    # Clean any prior scratch build directory.
    if [[ -d "${PSIPHON_BUILD_DIR}" ]]; then
        rm -rf "${PSIPHON_BUILD_DIR}" || warn "Could not remove stale build dir ${PSIPHON_BUILD_DIR}; continuing."
    fi
    mkdir -p "${PSIPHON_BUILD_DIR}"

    info "Cloning ${PSIPHON_REPO} @ ${PSIPHON_TAG} into ${PSIPHON_BUILD_DIR} …"
    git clone --depth 1 --branch "${PSIPHON_TAG}" "${PSIPHON_REPO}" "${PSIPHON_BUILD_DIR}" \
        || die "Failed to clone psiphon-tunnel-core @ ${PSIPHON_TAG}."

    # Capture the actual commit SHA (works even with --depth 1).
    local build_rev
    build_rev="$(cd "${PSIPHON_BUILD_DIR}" && git rev-parse --short=10 HEAD)" \
        || die "Could not resolve git revision of the cloned tag."

    # ──────────────────────────────────────────────────────────────────────
    # ldflags mirror the upstream ConsoleClient/make.bash `prepare_build`.
    # -s -w :: strip debug info + DWARF (smaller, faster cold-start)
    # -X buildinfo.{buildDate,buildRepo,buildRev,goVersion} :: stamp provenance
    # ──────────────────────────────────────────────────────────────────────
    local build_date build_repo go_version ldflags
    build_date="$(date --iso-8601=seconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)"
    build_repo="https://github.com/Psiphon-Labs/psiphon-tunnel-core.git"
    go_version="$(go version | awk '{print $3}' | sed 's/^go//')"
    ldflags="-s -w \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=${build_date} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=${build_repo} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=${build_rev} \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=${go_version}"

    info "Compiling ConsoleClient (output binary: psiphon-tunnel-core, linux/amd64)"
    (
        cd "${PSIPHON_BUILD_DIR}/ConsoleClient" || exit 1
        # Make build artifacts land in a known location without disturbing the source tree.
        mkdir -p bin/linux
        GOOS=linux GOARCH=amd64 go build -v -ldflags "${ldflags}" \
            -o "bin/linux/psiphon-tunnel-core-x86_64" . \
            || exit 1
    ) || die "go build of ConsoleClient failed (tag ${PSIPHON_TAG})."

    local built_bin="${PSIPHON_BUILD_DIR}/ConsoleClient/bin/linux/psiphon-tunnel-core-x86_64"
    if [[ ! -s "${built_bin}" ]]; then
        die "Build completed but expected output binary not found: ${built_bin}"
    fi

    # Install the binary to ${BIN_DIR}.
    install -d -m 0750 "${BIN_DIR}"
    rm -f "${BIN_DIR}/psiphon-tunnel-core" 2>/dev/null || true
    install -m 0750 -o root -g "${PSIPHON3XUI_GROUP:-psiphon3xui}" \
        "${built_bin}" "${BIN_DIR}/psiphon-tunnel-core" \
        || die "Failed to install psiphon-tunnel-core to ${BIN_DIR}."

    # Quick smoke test: print version to confirm we built a working binary and
    # not a typo'd empty file. `--version` is supported by upstream ConsoleClient.
    if "${BIN_DIR}/psiphon-tunnel-core" -version >/dev/null 2>&1; then
        local ver_line
        ver_line="$("${BIN_DIR}/psiphon-tunnel-core" -version 2>&1 | head -n1)"
        ok "psiphon-tunnel-core built: ${ver_line}"
    else
        warn "Built binary did not respond to -version (continuing — may still work in tunnel mode)."
    fi

    # Record the SHA256 of the freshly built binary as a tamper-detection baseline.
    # Format matches sha256sum(1): "<hash>  <path>"; we include the build tag inline.
    local sha
    sha="$(sha256sum "${BIN_DIR}/psiphon-tunnel-core" | awk '{print $1}')" \
        || die "sha256sum of the installed binary failed."
    {
        echo "# psiphon-tunnel-core binary manifest"
        echo "# Built from ${PSIPHON_REPO} tag ${PSIPHON_TAG} (commit ${build_rev})"
        echo "# Toolchain: go ${go_version}"
        echo "# Build date (UTC): ${build_date}"
        echo "# Re-run installer to rebuild after a tag bump or kernel/GCC upgrade."
        echo "${sha}  ${BIN_DIR}/psiphon-tunnel-core"
    } > "${PSIPHON_SHA256_FILE}"
    chmod 0644 "${PSIPHON_SHA256_FILE}"

    # Free up space: keep only the binary + manifest; drop the source tree.
    rm -rf "${PSIPHON_BUILD_DIR}" 2>/dev/null || warn "Could not prune build scratch dir ${PSIPHON_BUILD_DIR}."

    ok "psiphon-tunnel-core installed:"
    info "  binary : ${BIN_DIR}/psiphon-tunnel-core"
    info "  manifest: ${PSIPHON_SHA256_FILE}"
    info "  sha256  : ${sha:0:24}..."
}
