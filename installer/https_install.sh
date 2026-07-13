#!/usr/bin/env bash
# ============================================================================
# installer/https_install.sh — self-signed TLS cert hook (Phase 7)
# ----------------------------------------------------------------------------
# Sourced by install.sh. Exposes run_https_install(), which (when the operator
# opts into self-signed HTTPS at the prompt) does:
#
#   1. Create ${INSTALL_PREFIX}/tls (0750, owned by root).
#   2. Detect the server's primary FQDN (hostname -f) for the certificate's
#      Subject Alternative Name. Falls back to the panel's bound IP.
#   3. Run `openssl req -x509 -newkey rsa:2048 -nodes` to mint a self-signed
#      cert + key with a 1-year validity window and SAN covering that name.
#   4. chmod 0600 + chown root:${PSIPHON3XUI_GROUP} so the panel service user
#      can read both (uvicorn needs the key).
#   5. Export PANEL_TLS_CERT / PANEL_TLS_KEY (consumed by panel_install.sh
#      when it writes panel.env and templates the systemd unit ExecStart).
#
# IDEMPOTENT RE-RUNS:
#   If both cert + key already exist at the expected paths they ARE NOT
#   regenerated — reuse is preferred to keep the cert identity stable and
#   not blow away clients' pinned trust (browser "proceed" consent). To
#   rotate, rm ${INSTALL_PREFIX}/tls/{cert.pem,key.pem} and re-run install.sh.
# ============================================================================

TLS_DIR="${INSTALL_PREFIX}/tls"
TLS_CERT="${TLS_DIR}/cert.pem"
TLS_KEY="${TLS_DIR}/key.pem"
TLS_DAYS="${TLS_DAYS:-365}"  # 1-year self-signed validity (ops rotate by rm+re-run)

run_https_install() {
    if [[ "${PANEL_ENABLE_HTTPS:-no}" != "yes" ]]; then
        info "TLS not requested (PANEL_ENABLE_HTTPS != yes) — panel will bind plain HTTP."
        return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        warn "openssl not found — cannot generate self-signed cert; falling back to HTTP."
        warn "Install openssl manually: 'sudo apt-get install -y openssl', then re-run install.sh with HTTPS=yes."
        return 0
    fi

    mkdir -p "${TLS_DIR}"
    chmod 0750 "${TLS_DIR}" 2>/dev/null || true
    chown "root:${PSIPHON3XUI_GROUP}" "${TLS_DIR}" 2>/dev/null || true

    # Re-use existing cert/key on re-runs — DON'T silently rotate.
    if [[ -s "${TLS_CERT}" && -s "${TLS_KEY}" ]]; then
        ok "Reusing existing TLS cert at ${TLS_CERT} (rm it to force rotation)."
        export PANEL_TLS_CERT="${TLS_CERT}"
        export PANEL_TLS_KEY="${TLS_KEY}"
        return 0
    fi

    # Subject Alternative Name: prefer hostname -f, fall back to primary IPv4.
    local san
    san="$(hostname -f 2>/dev/null || true)"
    if [[ -z "${san}" ]] || [[ "${san}" == "localhost" ]]; then
        san="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    if [[ -z "${san}" ]]; then
        san="127.0.0.1"
    fi

    local subject="/O=Psiphon-3X-UI/CN=${san}"

    info "Generating self-signed TLS cert for SAN=${san} (valid ${TLS_DAYS} days) …"
    if ! openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${TLS_KEY}" -out "${TLS_CERT}" \
            -days "${TLS_DAYS}" -subj "${subject}" \
            -addext "subjectAltName=DNS:${san},IP:${san}" 2>/dev/null; then
        warn "openssl self-signed generation failed — falling back to HTTP."
        return 0
    fi

    chmod 0644 "${TLS_CERT}" 2>/dev/null || true
    chmod 0600 "${TLS_KEY}" 2>/dev/null || true
    chown "root:${PSIPHON3XUI_GROUP}" "${TLS_CERT}" 2>/dev/null || true
    chown "root:${PSIPHON3XUI_GROUP}" "${TLS_KEY}" 2>/dev/null || true

    ok "Self-signed cert installed at ${TLS_CERT} (key: ${TLS_KEY})."
    warn "Browsers will show a 'not trusted' warning for self-signed certs —"
    warn "click 'Proceed/Advanced' to continue, or front the panel with Caddy"
    warn "for a real Let's Encrypt cert."
    export PANEL_TLS_CERT="${TLS_CERT}"
    export PANEL_TLS_KEY="${TLS_KEY}"
}

info() { :; }
ok()   { :; }
warn() { :; }
