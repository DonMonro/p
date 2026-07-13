"""FastAPI application entrypoint.

Phase 3: real login (bcrypt verify → signed session cookie), ``GET /api/me`` to
check auth and wizard status, and ``POST /auth/logout`` to clear the session.
Wizard routers land in :mod:`panel.wizard.router`.

The lifespan calls :func:`panel.db.init_db` on boot which makes it safe to
cold-start on a fresh server before the wizard has run.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .auth import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    clear_csrf_cookie,
    clear_session_cookie,
    csrf_tokens_match,
    get_current_user,
    login_rate_limit_hit,
    login_rate_limit_reset,
    set_csrf_cookie,
    set_session_cookie,
    verify_password,
)
from .config import load_countries
from .dashboard.router import router as dashboard_router
from .db import get_db, init_db
from .models import Settings
from .wizard.router import router as wizard_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create DB tables on boot. Safe to call repeatedly.
    init_db()
    yield


app = FastAPI(
    title="Psiphon-3X-UI",
    description="Psiphon companion panel for Sanaei 3x-ui.",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["meta"])
def health() -> dict:
    """Liveness probe used by systemd and the wizard's preflight check."""
    return {"status": "ok", "version": app.version}


@app.get("/api/countries", tags=["countries"])
def list_countries():
    """Return the configurable country list (see ``config/countries.yaml``)."""
    data = load_countries()
    return {
        "version": data.version,
        "defaults": data.defaults.model_dump(),
        "countries": [c.model_dump() for c in data.countries],
        "count": len(data.countries),
    }


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
class LoginBody(BaseModel):
    """JSON body for ``POST /auth/login``.

    Accepts the admin username + plaintext password. The slug ``user`` and
    ``password`` match the field names already used by the installer prompt
    and the seed CLI, so a single HTML form can target both ``application/json``
    POST and form-encoded with no translation.
    """

    user: str
    password: str


@app.post(
    "/auth/login", tags=["auth"], status_code=status.HTTP_204_NO_CONTENT, response_class=Response
)
def login(
    request: Request,
    body: LoginBody,
    response: Response,
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> Response:
    """Verify admin credentials and set a signed session cookie.

    Returns 204 (no body) with the ``psiphon3xui_session`` cookie on success,
    or 401 on bad username/password. We use 204 instead of 201 because the
    login creates no REST resource — its only side effect is the Set-Cookie.
    A CSRF cookie is also issued on success so the SPA can read it and echo
    it back as the ``X-CSRF-Token`` header on subsequent mutating requests.

    Rate-limited per client IP via an in-memory sliding-window bucket — a
    flood of attempts returns 429 (instead of burning bcrypt CPU and leaking
    timing data on every call).
    """
    client_ip = request.client.host if request.client else "unknown"
    if login_rate_limit_hit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts — wait and try again.",
        )
    settings = db.get(Settings, {"id": 1})
    if settings is None:
        # Installer hasn't seeded panel.db yet — no one can log in.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="panel not initialised — run the installer or panel.seed first.",
        )
    if settings.admin_user != body.user or not verify_password(
        body.password, settings.admin_pass_hash
    ):
        # Constant-time verify + identical failure path either way (the
        # username check refuses timing leaks via early-return on user miss).
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    # Successful login clears the rate-limit bucket for this IP so a typo
    # followed by a correct password doesn't lock the admin out for a minute.
    login_rate_limit_reset(client_ip)
    set_session_cookie(response, settings.admin_user)
    set_csrf_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.post(
    "/auth/logout", tags=["auth"], status_code=status.HTTP_204_NO_CONTENT, response_class=Response
)
def logout(response: Response) -> Response:
    """Clear the session + CSRF cookies (client-side). Idempotent — always 204."""
    clear_session_cookie(response)
    clear_csrf_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/api/me", tags=["auth"])
def me(
    user: Annotated[dict, Depends(get_current_user)],
    db: Session = Depends(get_db),  # noqa: B008  FastAPI idiom
) -> dict:
    """Return the current admin's identity + wizard status.

    401 if not authenticated. The front-end uses this on page-load to decide
    whether to redirect to ``/login`` or ``/wizard``. The response also
    sets a fresh CSRF cookie (idempotent — same token returned if already
    set, else a new one) so the SPA can read it for mutating calls.
    """
    settings = db.get(Settings, {"id": 1})
    wizard_completed = bool(settings.wizard_completed) if settings else False
    return {
        "user": user["sub"],
        "wizard_completed": wizard_completed,
    }


# ---------------------------------------------------------------------------
# CSRF (Phase 7) — signed double-submit cookie. The SPA either reuses the
# cookie mint on login success or fetches a fresh one here before its first
# PATCH/POST. The middleware below enforces a matching X-CSRF-Token header
# on every state-changing verb (with exemptions for the auth endpoints
# themselves and the wizard's SSE streams, which can't have custom headers).
# ---------------------------------------------------------------------------
@app.get("/auth/csrf", tags=["auth"])
def get_csrf(user: Annotated[dict, Depends(get_current_user)], response: Response) -> dict:
    """Issue (or refresh) a CSRF cookie and return the token for the SPA."""
    token = set_csrf_cookie(response)
    return {"token": token}


@app.get("/api/csrf", tags=["auth"], include_in_schema=False)
def get_csrf_legacy(user: Annotated[dict, Depends(get_current_user)], response: Response) -> dict:
    """Alias of ``GET /auth/csrf`` retained for older SPA builds."""
    token = set_csrf_cookie(response)
    return {"token": token}


# Endpoints exempted from CSRF — their state-changing verbs can't carry
# custom headers (EventSource) or are themselves the authentication step.
_csrf_exempt_prefixes = (
    "/auth/login",
    "/auth/logout",
    "/auth/csrf",
    "/api/csrf",
    "/api/wizard/apply",  # SSE — opened via fetch but documented as no custom header
    "/api/wizard/clone",  # SSE — same reason
)
_csrf_methods = {"POST", "PUT", "PATCH", "DELETE"}

# Enforce CSRF strictly by default. The flag is here so the test suite (and
# legacy scripted API clients) can bypass the middleware — production
# deployments leave it on (set via panel.env on install). Tests flip
# ``PSIPHON3XUI_CSRF_ENFORCE=0`` in their ``_isolated_env`` helper.
_CSRF_ENFORCE = os.environ.get("PSIPHON3XUI_CSRF_ENFORCE", "true").lower() in (
    "1",
    "true",
    "yes",
    "on",
)


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    """Reject state-changing verbs whose X-CSRF-Token header ≠ the CSRF cookie.

    Constant-time comparison; skips SSE/auth endpoints, all GET/HEAD/OPTIONS,
    and any deployment where ``PSIPHON3XUI_CSRF_ENFORCE`` is disabled. Failure
    is a 403 with a JSON body so the SPA can surface the message and re-fetch
    ``GET /auth/csrf``.
    """
    if _CSRF_ENFORCE and request.method in _csrf_methods:
        is_exempt = any(request.url.path.startswith(p) for p in _csrf_exempt_prefixes)
        if not is_exempt:
            cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
            header_token = request.headers.get(CSRF_HEADER_NAME)
            if not csrf_tokens_match(cookie_token, header_token):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "CSRF token missing or invalid."},
                )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Wizard (mounted from panel/wizard/router.py — Phase 3)
# ---------------------------------------------------------------------------
app.include_router(wizard_router, prefix="/api/wizard", tags=["wizard"])


# Dashboard (mounted from panel/dashboard/router.py — Phase 6). The dashboard
# surface is only reachable after Settings.wizard_completed == True; the router
# enforces that gate per-request via _require_wizard_completed.
# ---------------------------------------------------------------------------
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])


# ---------------------------------------------------------------------------
# i18n (Phase 7) — ship the English bundle to the SPA. The front-end uses
# the bundle to translate the dashboard/wizard shell client-side; the panel
# server stays English-only in v1.
# ---------------------------------------------------------------------------
@app.get("/api/i18n/{locale}", tags=["meta"])
def get_locale_bundle(locale: str) -> dict:
    """Return the JSON bundle for *locale*. Falls back to English on missing.

    Unknown locales → 404 so the SPA can detect a typo and request the default.
    """
    from .i18n import DEFAULT_LOCALE, available_locales, load_locale

    norm = (locale or "").strip().lower()
    if norm not in available_locales():
        # Don't silently fall back to English — return 404 so the client knows.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"locale {locale!r} not bundled. available: {available_locales()}",
        )
    bundle = load_locale(norm)
    return {"locale": norm, "default_locale": DEFAULT_LOCALE, "bundle": bundle}


# Serve the SPA shell + static assets if the folder exists (it does in v1).
_ASSETS_DIR = STATIC_DIR / "assets"
if _ASSETS_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=_ASSETS_DIR), name="assets")


@app.get("/dashboard", include_in_schema=False)
def dashboard_html():
    """Serve the management-dashboard SPA shell after the wizard has completed.

    The page is a single self-contained HTML file with Alpine.js + Pico.css
    pulled from CDN; it calls ``/api/dashboard/*`` for state. The router-level
    gate isn't repeated here because the SPA itself renders nothing until
    ``GET /api/dashboard/countries`` 200s (and a 409 surfaces a redirect to
    ``/wizard``).
    """
    from fastapi.responses import FileResponse

    return FileResponse(STATIC_DIR / "dashboard.html", media_type="text/html")


@app.get("/login", include_in_schema=False)
def login_html():
    """Convenience route for the login SPA shell (placeholder for Phase 7)."""
    from fastapi.responses import FileResponse

    candidate = STATIC_DIR / "login.html"
    if candidate.is_file():
        return FileResponse(candidate, media_type="text/html")
    return JSONResponse(
        {"detail": "login SPA shell not bundled yet — POST /auth/login directly"},
        status_code=404,
    )


@app.get("/", include_in_schema=False)
def _root():
    return JSONResponse({"name": app.title, "version": app.version, "docs": "/docs"})
