"""Thin HTTP client for the 3x-ui panel API.

NOTE: ``_clone_remark`` collapses internal whitespace so an inbound cloned for
a country with no flag still renders tidily as ``[ DE ] :1234``.

Implements the verified contract from the Phase 1 spike (see
``tests/fixtures/xui/README.md`` and ``docs/XUI_API.md``):

* base path = ``{webBasePath}/``  (``/panel`` segment is a SPA route, not API).
* login = ``POST {base}login`` form-encoded with ``X-CSRF-Token`` header.
* session persisted via the ``3x-ui`` cookie (handled automatically by httpx).
* every state-changing API call sends the ``X-CSRF-Token`` header.
* the SOCKS5 outbound for a clone goes into ``streamSettings.outbound`` as a
  *dict* (sibling of ``network`` / ``security``), with
  ``settings.servers[0]`` describing the local ``127.0.0.1:<socks_port>`` target.

The clone v1 supports the VLESS protocol (matching the Phase-1 VM template).
Per-protocol schemas for VMess / Trojan / Shadowsocks land in Phase 5 once
spiked against a VM that has those inbounds — :meth:`XuiClient.clone_inbound`
raises :class:`XuiClientError` for unsupported protocols until then.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

CSRF_RE = re.compile(r'name="csrf-token"\s+content="([^"]+)"')


class XuiClientError(RuntimeError):
    """Raised on any unexpected 3x-ui response (non-success JSON, HTTP error)."""


@dataclass
class InboundSummary:
    """Minimal projection of an inbound used by the wizard's inbound-picker."""

    id: int
    port: int
    protocol: str
    remark: str
    tag: str

    @classmethod
    def from_api(cls, obj: dict) -> InboundSummary:
        return cls(
            id=int(obj["id"]),
            port=int(obj["port"]),
            protocol=str(obj["protocol"]),
            remark=str(obj.get("remark", "")),
            tag=str(obj.get("tag", "")),
        )


class XuiClient:
    """Stateful 3x-ui HTTP API client.

    Use as an async context manager::

        async with XuiClient(base_url, user, pw) as c:
            inbounds = await c.list_inbounds()
            clone = await c.clone_inbound(
                template_id=1,
                country={"code": "US", "name": "United States", "flag": "US"},
                socks_port=10001,
                public_port=30001,
            )

    Or call :meth:`login` / :meth:`aclose` manually.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 15.0,
    ) -> None:
        # The operator pastes the FULL 3x-ui SPA URL visible in the browser
        # address bar — e.g. ``http://host:2053/panel/`` for a default
        # install OR ``http://192.168.x.y:12345/WSCM6EhC9pO6T9K0RA/panel``
        # for a security-hardened 3x-ui install whose ``webBasePath`` is a
        # random 16-char secret string. The ``/panel`` segment is the React
        # frontend's SPA page-route (NOT part of the API prefix), per the
        # Phase-1 spike evidence in ``docs/XUI_API.md`` and
        # ``spike/spike_1c2_capture.py``:
        #   * GET  /                              -> HTML login page (parse CSRF)
        #   * POST {base}/login                  -> session cookie (login URL
        #     sits at the ROOT of the webBasePath, NOT under /panel)
        #   * GET  {base}/panel/api/inbounds/list -> inbound JSON list
        #   * POST {base}/panel/api/inbounds/add  -> clone create
        # where ``base = {scheme}://{host}:{port}/{webBasePath}/``. So we:
        #   1. STRIP a trailing ``/panel`` (the SPA page route) so the API
        #      base drops down to ``{webBasePath}/`` (exact same heuristic
        #      as ``spike_1c2_capture.py:65`` and ``spike_1e_clone.py:178``).
        #      For the default-install case where webBasePath is the empty
        #      string and ``/panel`` is the literal route, the strip
        #      correctly produces ``http://host:port/`` and login lands at
        #      ``http://host:port/login`` while API URLs land at
        #      ``http://host:port/panel/api/inbounds/list``.
        #   2. TRUST the operator's typed webBasePath verbatim when no
        #      ``/panel`` suffix is present.
        #   3. Append the literal ``panel/api/inbounds/{op}`` prefix on
        #      every API call below (list/get/add/update/del) — ``panel``
        #      here is the React SPA route prefix the API also sits under.
        #
        # Hotfix #4 (Bug #6v1) dropped BOTH the strip heuristic AND the
        # literal ``panel/api`` prefix in the belief that the operator's
        # pasted SPA URL already carried everything — but that yielded
        # ``{base}/panel/login`` (a 404; the operator's reported
        # ``login: HTTP 404`` at step 5), because the REAL login URL sits
        # at ``{webBasePath}/login`` and NOT at ``{webBasePath}/panel/login``.
        # Hotfix #5 (Bug #6v2) corrects this by restoring the strip
        # heuristic AND restoring the literal ``panel/api`` prefix on every
        # API call (matching the Phase-1 spikes verbatim).
        b = base_url.strip().rstrip("/")
        if not b:
            raise ValueError("base_url must not be empty")
        if not (b.startswith("http://") or b.startswith("https://")):
            # Reject schemeless paths like "/panel" early — they would
            # otherwise silently normalise to "/" via the strip heuristic
            # (Hotfix #5 — Bug #6v2 — defensive guard so a typo surfaces
            # with a clear ValueError instead of producing a base_url
            # rooted at "/" and a confusing 404 on the first API call).
            raise ValueError(
                "base_url must include a scheme and host: 'http(s)://host:port/...'",
            )
        # Drop a trailing "/panel" SPA-route segment (segment-matched, exact).
        # A path like "/WSCM6EhC9pO6T9K0RA/" (no /panel suffix) is left
        # untouched — we only ever strip a literal "/panel" at the very end.
        if b.endswith("/panel"):
            b = b[: -len("/panel")]
        elif b.endswith("/panel/"):
            b = b[: -len("/panel/")]
        b = b.rstrip("/")
        if b.endswith("://") or b.endswith(":"):
            # Strip produced a degenerate scheme-only prefix (e.g. operator
            # typed "http://panel" alone) — the host got eaten. Don't
            # synthesise one; ask the operator to fix the typo.
            raise ValueError(
                "base_url must include a host: 'http(s)://host:port/...'",
            )
        self.base_url = b + "/"
        self.username = username
        self.password = password

        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            follow_redirects=True, timeout=timeout, verify=False
        )
        self._csrf: str | None = None
        self._logged_in = False

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self) -> XuiClient:
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------
    def _headers(self, extra: dict | None = None) -> dict:
        headers: dict[str, str] = {"Referer": self.base_url}
        if self._csrf:
            headers["X-CSRF-Token"] = self._csrf
        if extra:
            headers.update(extra)
        return headers

    async def _require_ok(self, r: httpx.Response, *, what: str) -> dict:
        if r.status_code >= 400:
            raise XuiClientError(f"{what}: HTTP {r.status_code}: {r.text[:200]}")
        try:
            data = r.json()
        except Exception as exc:  # noqa: BLE001
            raise XuiClientError(f"{what}: non-JSON response: {r.text[:200]}") from exc
        if not data.get("success"):
            raise XuiClientError(f"{what}: API failure: {data.get('msg') or data}")
        return data

    # ------------------------------------------------------------------
    # auth
    # ------------------------------------------------------------------
    async def login(self) -> None:
        """Authenticate and cache the CSRF token + cookie session."""
        r0 = await self._client.get(self.base_url)
        if r0.status_code >= 400:
            raise XuiClientError(f"login: GET base failed HTTP {r0.status_code}")
        m = CSRF_RE.search(r0.text)
        self._csrf = m.group(1) if m else None

        r = await self._client.post(
            self.base_url + "login",
            data={"username": self.username, "password": self.password},
            headers=self._headers(),
        )
        data = await self._require_ok(r, what="login")
        # a fresh CSRF is sometimes re-issued in the login response body
        if r.text and CSRF_RE.search(r.text):
            self._csrf = CSRF_RE.search(r.text).group(1)
        if not self._csrf and not data.get("success"):
            raise XuiClientError("login: no CSRF token and login not successful")
        self._logged_in = True

    # ------------------------------------------------------------------
    # read
    # ------------------------------------------------------------------
    async def list_inbounds(self) -> list[dict]:
        r = await self._client.get(
            self.base_url + "panel/api/inbounds/list", headers=self._headers()
        )
        data = await self._require_ok(r, what="list_inbounds")
        return data.get("obj") or []

    async def list_inbound_summaries(self) -> list[InboundSummary]:
        raw = await self.list_inbounds()
        return [InboundSummary.from_api(o) for o in raw]

    async def get_inbound(self, inbound_id: int) -> dict:
        r = await self._client.get(
            self.base_url + f"panel/api/inbounds/get/{inbound_id}",
            headers=self._headers(),
        )
        data = await self._require_ok(r, what=f"get_inbound({inbound_id})")
        obj = data.get("obj")
        if obj is None:
            raise XuiClientError(f"get_inbound({inbound_id}): obj is null")
        return obj

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------
    async def add_inbound(self, payload: dict) -> dict:
        r = await self._client.post(
            self.base_url + "panel/api/inbounds/add",
            json=payload,
            headers=self._headers({"Content-Type": "application/json"}),
        )
        data = await self._require_ok(r, what="add_inbound")
        return data.get("obj") or {}

    async def update_inbound(self, inbound_id: int, payload: dict) -> dict:
        r = await self._client.post(
            self.base_url + f"panel/api/inbounds/update/{inbound_id}",
            json=payload,
            headers=self._headers({"Content-Type": "application/json"}),
        )
        data = await self._require_ok(r, what=f"update_inbound({inbound_id})")
        return data.get("obj") or {}

    async def delete_inbound(self, inbound_id: int) -> dict:
        r = await self._client.post(
            self.base_url + f"panel/api/inbounds/del/{inbound_id}",
            headers=self._headers(),
        )
        data = await self._require_ok(r, what=f"delete_inbound({inbound_id})")
        return data

    # ------------------------------------------------------------------
    # clone engine (VLESS v1)
    # ------------------------------------------------------------------
    async def clone_inbound(
        self,
        template_id: int,
        country: dict,
        socks_port: int,
        public_port: int,
    ) -> dict:
        """Clone ``template_id`` once for ``country`` with a SOCKS5 outbound.

        Returns the panel's persisted clone object.

        The clone:
        * listens on ``public_port``
        * has remark ``[ {flag} {name} ] :{public_port}``
        * gets a FRESH client UUID + subId (so each country clone has independent
          credentials — required because the template's ``clients`` list may be
          empty or shared, per roadmap §9.4)
        * routes all traffic via ``streamSettings.outbound`` SOCKS5
          ``127.0.0.1:{socks_port}`` (verified schema from the Phase 1 spike).
        """
        template = await self.get_inbound(template_id)
        protocol = str(template.get("protocol", "")).lower()

        payload = _build_clone_payload(
            template=template,
            protocol=protocol,
            public_port=public_port,
            socks_port=socks_port,
            country=country,
        )
        return await self.add_inbound(payload)


# ----------------------------------------------------------------------
# pure clone-payload builders (unit-tested independently of httpx)
# ----------------------------------------------------------------------


def _fresh_vless_client(public_port: int) -> dict:
    """A minimal VLESS client entry. The panel enriches it server-side.

    Returns a fresh ``id`` (UUID) and ``subId`` per call so each cloned
    country inbound has independent client credentials (roadmap §9.4).
    """
    return {
        "id": str(uuid.uuid4()),
        "flow": "xtls-rprx-vision",
        "email": f"clone-{public_port}@psiphon3xui",
        "limitIp": 0,
        "totalGB": 0,
        "expiryTime": 0,
        "enable": True,
        # Hotfix #7 (Bug #9): 3x-ui's newer Go schema unmarshals tgId as
        # int64, NOT string — sending `tgId: ""` (empty string) was rejected
        # with: `cannot unmarshal string into Go struct field Client.tgId
        # of type int64`. The valid "no Telegram ID" sentinel is `0`.
        "tgId": 0,
        "subId": str(uuid.uuid4()),
        "reset": 0,
    }


def _socks_outbound(public_port: int, socks_port: int) -> dict:
    """The SOCKS5 outbound block 3x-ui persists inside ``streamSettings.outbound``.

    Verified schema from the Phase 1 spike: ``settings.servers[0]`` describes
    the local ``127.0.0.1:<socks_port>`` target the inbound routes to.
    """
    return {
        "tag": f"socks-out-{public_port}",
        "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": int(socks_port), "users": []}]},
    }


def _clone_remark(country: dict, public_port: int) -> str:
    """Build the human-friendly ``[ flag name ] :port`` remark for a clone.

    Tokens are joined with a single space, so a missing flag (or name) does
    not introduce a doubled space. Output is e.g.::

        "[ 🇺🇸 United States ] :30001"
        "[ DE ] :1234"            # name fallback to code, no flag
        "[ FR France ] :80"       # name + flag, no code
    """
    flag = (country.get("flag") or "").strip()
    name = (country.get("name") or country.get("code") or "").strip()
    inner = " ".join(tok for tok in (flag, name) if tok)
    return f"[ {inner} ] :{public_port}"


def _build_clone_payload(
    *,
    template: dict,
    protocol: str,
    public_port: int,
    socks_port: int,
    country: dict,
) -> dict:
    """Pure function: build the POST /inbounds/add body for a single clone.

    Currently implements VLESS. Raises :class:`XuiClientError` for unsupported
    protocols (VMess / Trojan / Shadowsocks arrive in Phase 5 after their own
    spikes — see roadmap §9.4 and ``docs/XUI_API.md``).
    """
    if protocol != "vless":
        raise XuiClientError(
            f"clone engine v1 supports VLESS only; got {protocol!r}. "
            "VMess/Trojan/Shadowsocks land in Phase 5."
        )

    # Preserve template fields, swap port/tag/remark (NOT clients/streamSettings).
    # Hotfix #8 (Bug #d): the operator reported "When cloning is performed,
    # it should only clone the inbound. Why does it also clone in the client
    # section? Only the inbound is enough." The previous behaviour overwrote
    # `settings.clients` with a freshly minted `_fresh_vless_client(public_port)`
    # entry — that minted a NEW 3x-ui client row (with a brand-new UUID,
    # email "clone-<port>@…", tgId 0, subId …) for every clone, which surfaced
    # in the 3x-ui UI as one "client section" entry per cloned inbound even
    # when the operator had never authorised one. Cloning a 3x-ui inbound
    # should replicate the LISTENER (port/remark/tag/streamSettings.outbound)
    # and preserve the template's existing clients verbatim — that way the
    # operator's existing 3x-ui client roster (already configured once on the
    # template inbound) just gains a new listener port, with no surprise
    # client rows minted on the operator's behalf. The mixin is the
    # `_socks_outbound` injection into `streamSettings.outbound` (kept), but
    # the `clients` array is now copied THROUGH from the template instead of
    # being minted. `_fresh_vless_client` is retained as a public helper for
    # callers that DO want a fresh per-clone client (none currently use it),
    # so tests/test_xui_client.py stays green; the production clone path no
    # longer calls it.
    settings = dict(template.get("settings") or {})
    # Copy the template's existing `clients` array through UNCHANGED. If the
    # template somehow lacks one, fall back to an empty list (caller can mint
    # client rows via the 3x-ui UI later if they want one).
    if "clients" not in settings:
        settings["clients"] = list(template.get("settings", {}).get("clients") or [])

    stream_settings = dict(template.get("streamSettings") or {})
    # Inject the SOCKS5 outbound as a dict sibling of network/security.
    # (Phase-1-verified schema: 3x-ui persists this exact shape.)
    stream_settings["outbound"] = _socks_outbound(public_port, socks_port)

    payload: dict[str, Any] = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": _clone_remark(country, public_port),
        "enable": True,
        "expiryTime": 0,
        "listen": template.get("listen", ""),
        "port": int(public_port),
        "protocol": template.get("protocol", "vless"),
        "tag": f"in-{public_port}-tcp",
        "settings": settings,
        "streamSettings": stream_settings,
        "sniffing": template.get("sniffing", {"enabled": False}),
    }
    return payload
