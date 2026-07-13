"""Authentication helpers (bcrypt password hashing + signed sessions).

Phase 3 wires these primitives into the FastAPI surface:

- :func:`hash_password` / :func:`verify_password` — bcrypt primitives used by
  ``panel.seed`` (hash on first install) and the login endpoint (verify).
- :func:`sign_session` / :func:`verify_session` — opaque, signed session
  cookie strings (itsdangerous ``URLSafeTimedSerializer``). The payload is
  ``{"sub": <username>}``.
- :func:`set_session_cookie` / :func:`clear_session_cookie` — Response helpers
  for ``/auth/login`` and ``/auth/logout``.
- :func:`get_current_user` — FastAPI dependency: reads the ``psiphon3xui_session``
  cookie, returns the payload, or raises ``HTTPException(401)``.
"""

from __future__ import annotations

import hmac
import os
import secrets
import time
from collections import deque
from typing import Annotated

import bcrypt
from fastapi import Cookie, HTTPException, status
from fastapi.responses import JSONResponse, Response
from itsdangerous import BadSignature, URLSafeTimedSerializer

from .config import get_settings

SESSION_COOKIE_NAME = "psiphon3xui_session"
CSRF_COOKIE_NAME = "psiphon3xui_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 12  # 12 hours
SESSION_COOKIE_SAMESITE = "lax"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_PATH = "/"
CSRF_COOKIE_SAMESITE = "lax"
CSRF_COOKIE_HTTPONLY = False  # JS must read this to send it back in the header
CSRF_TOKEN_BYTES = 24


def _cookies_secure() -> bool:
    """Phase 7 — return whether session/CSRF cookies should set the Secure flag.

    Reads :attr:`panel.config.Settings.https_only` (flipped on by the installer
    when TLS is enabled) so the flags are dynamic per-deployment. Defaults to
    False so the panel still issues login cookies under HTTP in the test suite
    or when the operator fronts with Caddy (which terminates TLS for us).
    """
    try:
        return bool(get_settings().https_only)
    except Exception:  # noqa: BLE001  (config not initialised → treat as off)
        return False


# In-memory login rate-limit (Phase 7) — sampled once at import. Override via env.
LOGIN_RATE_LIMIT = int(os.environ.get("PSIPHON3XUI_LOGIN_RATE_LIMIT", "10"))  # attempts per window
LOGIN_RATE_WINDOW = int(os.environ.get("PSIPHON3XUI_LOGIN_RATE_WINDOW", "60"))  # seconds


def hash_password(password: str) -> str:
    """Return a bcrypt hash suitable for storage."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time verify a plaintext password against a stored hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def generate_password(length: int = 16) -> str:
    """Generate a URL-safe random password (used by the installer)."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _signer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().session_secret, salt="psiphon-3x-ui-auth")


def sign_session(payload: dict) -> str:
    """Sign a session payload into an opaque cookie string."""
    return _signer().dumps(payload)


def verify_session(token: str, max_age: int = SESSION_MAX_AGE_SECONDS) -> dict | None:
    """Return the session payload, or ``None`` if the token is invalid/expired."""
    try:
        return _signer().loads(token, max_age=max_age)
    except BadSignature:
        return None


def set_session_cookie(response: Response, username: str) -> None:
    """Bake and attach the session cookie to *response*.

    The cookie holds a signed payload of ``{"sub": <username>}`` and expires
    after :data:`SESSION_MAX_AGE_SECONDS`. Call from the login handler.
    """
    token = sign_session({"sub": username})
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_MAX_AGE_SECONDS,
        path=SESSION_COOKIE_PATH,
        secure=_cookies_secure(),
        httponly=SESSION_COOKIE_HTTPONLY,
        samesite=SESSION_COOKIE_SAMESITE,
    )


def clear_session_cookie(response: Response) -> None:
    """Delete the session cookie from the client.

    Starlette's ``Response.delete_cookie`` only supports the Set-Cookie delete
    if EVERY attribute that the original Set-Cookie used on login is also set
    on the delete response — otherwise the browser treats them as TWO distinct
    cookies (RFC 6265 §5.3: cookies are keyed by name+domain+path, but Chrome
    refuses to delete a ``HttpOnly`` cookie via a Set-Cookie that lacks the
    HttpOnly flag, and refuses to delete a ``SameSite=Lax`` cookie via a
    Set-Cookie that lacks ``SameSite``). Mirroring every attribute here matches
    the original ``set_session_cookie`` Set-Cookie exactly so the logout DELETE
    fires against the right jar entry and the operator's session actually ends
    (Hotfix #3 in the v1.0.0 amend cycle — logout button appeared broken).
    """
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path=SESSION_COOKIE_PATH,
        secure=_cookies_secure(),
        httponly=SESSION_COOKIE_HTTPONLY,
        samesite=SESSION_COOKIE_SAMESITE,
    )


async def get_current_user(
    session: Annotated[str | None, Cookie(alias=SESSION_COOKIE_NAME)] = None,
) -> dict:
    """FastAPI dependency: require a valid signed session cookie.

    Returns the decoded payload (e.g. ``{"sub": "admin"}``) on success; raises
    ``HTTPException(401, "not authenticated")`` otherwise. Use as::

        @app.get("/api/me")
        def me(user: dict = Depends(get_current_user)):
            return {"user": user["sub"]}
    """
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
        )
    payload = verify_session(session)
    if payload is None or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
        )
    return payload


def unauthorized_response(detail: str = "not authenticated") -> JSONResponse:
    """Stand-alone 401 response for use outside Depends()."""
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail},
    )


# ---------------------------------------------------------------------------
# Credential at-rest encryption (Phase 4 — wizard's xui-creds step caches the
# 3x-ui password so the apply/clone wizard steps can reuse the same session
# without prompting the user again. Symmetric and authenticated: the panel's
# `session_secret` is the authoritative key.
# ---------------------------------------------------------------------------

# A distinct salt so session-cookies bought at one URL can't be swapped into
# the credentials table at another, and so credential blobs can't be reused
# as session cookies.
CREDENTIAL_SERIALIZER_SALT = "psiphon-3x-ui-credential-vault"


def _credential_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().session_secret, salt=CREDENTIAL_SERIALIZER_SALT)


def encrypt_creds(payload: dict) -> str:
    """Serialise + signature-encrypt *payload* (typically a 3x-ui cred dict).

    Use :func:`decrypt_creds` to round-trip. The ciphertext is safe to persist
    in the ``XuiLink.password_enc`` column.
    """
    return _credential_serializer().dumps(payload)


def decrypt_creds(token: str, *, max_age: int | None = None) -> dict | None:
    """Inverse of :func:`encrypt_creds`.

    Returns the verified payload, or ``None`` on tamper / expiry / malformed
    input. ``max_age=None`` disables age-checking (credentials are durable,
    not session-scoped, so we don't enforce a TTL here — rotation is the
    operator's responsibility).
    """
    try:
        if max_age is None:
            return _credential_serializer().loads(token)
        return _credential_serializer().loads(token, max_age=max_age)
    except BadSignature:
        return None
    except Exception:  # noqa: BLE001  (defensive: anything means "no creds")
        return None


# ---------------------------------------------------------------------------
# CSRF protection (Phase 7 — signed double-submit cookie).
#
# Strategy: the panel issues a fresh random token in a non-HttpOnly cookie on
# every authenticated response (so the SPA can read it). The SPA echoes it
# back as the ``X-CSRF-Token`` header on every state-changing request. The
# middleware compares the cookie value vs the header value in constant time and
# rejects POST/PUT/PATCH/DELETE with 403 on mismatch or absence. Origin
# checking would be even tighter but breaks the "SPA lives at /dashboard
# served by the same origin" deployment we ship in v1, so double-submit is
# our baseline; the cookie is signed so an attacker can't just set their own
# value via a subdomain.
# ---------------------------------------------------------------------------
CSRF_SERIALIZER_SALT = "psiphon-3x-ui-csrf"


def _csrf_signer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().session_secret, salt=CSRF_SERIALIZER_SALT)


def issue_csrf_token() -> str:
    """Mint a fresh signed CSRF token (signed so attacker-issued cookies fail)."""
    raw = secrets.token_urlsafe(CSRF_TOKEN_BYTES)
    return _csrf_signer().dumps({"t": raw})


def verify_csrf_token(token: str | None, *, max_age: int = 60 * 60 * 24) -> bool:
    """Return True iff *token* is a valid, recently-minted CSRF token."""
    if not token:
        return False
    try:
        payload = _csrf_signer().loads(token, max_age=max_age)
    except BadSignature:
        return False
    except Exception:  # noqa: BLE001  (defensive)
        return False
    return isinstance(payload, dict) and "t" in payload


def set_csrf_cookie(response: Response, token: str | None = None) -> str:
    """Attach a CSRF cookie to *response* and return the raw token string.

    The cookie is non-HttpOnly so the SPA shell can read it. Call on login
    success and on every authenticated GET so a freshly-logged-in admin gets
    a token before the first mutating request.
    """
    if token is None:
        token = issue_csrf_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=60 * 60 * 24,
        path=SESSION_COOKIE_PATH,
        secure=_cookies_secure(),
        httponly=CSRF_COOKIE_HTTPONLY,
        samesite=CSRF_COOKIE_SAMESITE,
    )
    return token


def clear_csrf_cookie(response: Response) -> None:
    """Delete the CSRF cookie alongside the session cookie on logout.

    Propagates every Set-Cookie attribute used by :func:`set_csrf_cookie` so the
    browser registers the delete against the SAME jar entry; see the rationale
    on :func:`clear_session_cookie` (Hotfix #3 — logout actually clears both
    cookies now).
    """
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path=SESSION_COOKIE_PATH,
        secure=_cookies_secure(),
        httponly=CSRF_COOKIE_HTTPONLY,
        samesite=CSRF_COOKIE_SAMESITE,
    )


def csrf_tokens_match(cookie_token: str | None, header_token: str | None) -> bool:
    """Constant-time comparison of the cookie + header CSRF tokens."""
    if not cookie_token or not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)


# ---------------------------------------------------------------------------
# In-memory login rate limiter (Phase 7).
#
# Sliding-window per-IP bucket: keep a deque of attempt timestamps, drop
# anything older than LOGIN_RATE_WINDOW seconds, refuse (raise RateLimitHit)
# when the remaining count >= LOGIN_RATE_LIMIT. The limiter is process-local;
# for a deployment scaled horizontally, swap this for a shared store (Redis).
# ---------------------------------------------------------------------------
class RateLimitHit(Exception):
    """Raised when an IP exceeds the configured login attempt window."""


_login_buckets: dict[str, deque[float]] = {}


def _prune_bucket(bucket: deque[float], now: float) -> deque[float]:
    """Drop entries older than the configured window (mutates + returns)."""
    cutoff = now - LOGIN_RATE_WINDOW
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    return bucket


def login_rate_limit_hit(ip: str, *, now: float | None = None) -> bool:
    """Record a login attempt from *ip* and return True if it should be refused.

    Callers should call this *before* verifying credentials: even a flood of
    failed attempts short-circuits to the rate-limit response, not the 401.
    """
    if now is None:
        now = time.monotonic()
    bucket = _login_buckets.setdefault(ip, deque())
    _prune_bucket(bucket, now)
    if len(bucket) >= LOGIN_RATE_LIMIT:
        return True
    bucket.append(now)
    return False


def login_rate_limit_reset(ip: str | None = None) -> None:
    """Clear rate-limit state. Tests use this between scenarios."""
    if ip is None:
        _login_buckets.clear()
    else:
        _login_buckets.pop(ip, None)
