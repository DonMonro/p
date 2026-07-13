"""Entrypoint for `python -m panel`.

Lets the systemd unit run the panel without invoking uvicorn's CLI directly.
Phase 0 stub: real host/port resolution from the DB lands in another phase.
"""

from __future__ import annotations

import logging
from pathlib import Path

import uvicorn

from .config import get_settings


def main() -> None:
    settings = get_settings()
    # Phase 7 — TLS termination. If the installer has populated
    # settings.tls_cert + settings.tls_key (via panel.env) we bind with
    # --ssl-certfile/--ssl-keyfile. Either blank → plain HTTP (operator can
    # instead front the panel with Caddy/nginx).
    ssl_kwargs: dict = {}
    if settings.tls_cert and settings.tls_key:
        cert = Path(settings.tls_cert)
        key = Path(settings.tls_key)
        if cert.is_file() and key.is_file():
            ssl_kwargs["ssl_certfile"] = str(cert)
            ssl_kwargs["ssl_keyfile"] = str(key)
        else:  # pragma: no cover — defensive; installer always writes both
            logging.getLogger("panel").warning(
                "TLS settings present but cert/key missing (%s, %s) — falling back to HTTP.",
                cert,
                key,
            )
    uvicorn.run(
        "panel.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        **ssl_kwargs,
    )


if __name__ == "__main__":
    main()
