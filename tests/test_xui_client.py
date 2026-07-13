"""respx-mocked tests for panel.dashboard.xui_client.XuiClient.

These exercise the verified Phase-1 contract (CSRF + cookie + bare-JSON POST +
streamSettings.outbound SOCKS injection) without needing a live 3x-ui panel.
Fixtures live under tests/fixtures/xui/ and key off structural fields, not
specific UUIDs (see README.md there).

Run with::

    pytest tests/test_xui_client.py -ra
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
import respx

from panel.dashboard.xui_client import (
    InboundSummary,
    XuiClient,
    XuiClientError,
    _build_clone_payload,
    _clone_remark,
    _fresh_vless_client,
    _socks_outbound,
)

FIXTURES = Path(__file__).parent / "fixtures" / "xui"
BASE = "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/"  # test base path incl. webBasePath
TEMPLATE_ID = 1
PUBLIC_PORT = 30001
SOCKS_PORT = 10001
COUNTRY = {"code": "US", "name": "United States", "flag": "US"}
CSRF = "test-csrf-token"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def template_json() -> dict:
    """The *inbound* object (i.e. ``obj`` from the API response), matching
    what ``XuiClient.get_inbound()`` returns in production — NOT the whole
    ``{success, msg, obj}`` envelope."""
    data = json.loads((FIXTURES / "vless_template_get.json").read_text("utf-8"))
    return data["obj"]


@pytest.fixture
def clone_response_json() -> dict:
    """The *created inbound* object (``obj`` only), so assertions in the
    clone tests match what ``XuiClient.add_inbound()`` returns."""
    data = json.loads((FIXTURES / "vless_clone_add_response.json").read_text("utf-8"))
    return data["obj"]


def login_html() -> str:
    """A minimal HTML login page containing the CSRF meta + base path JS."""
    return (
        "<!doctype html><html><head>"
        f'<meta name="csrf-token" content="{CSRF}">'
        f'<script>window.X_UI_BASE_PATH="/WSCM6EhC9pO6T9K0RA/";</script>'
        '</head><body><div id="app"></div></body></html>'
    )


# ---------------------------------------------------------------------------
# pure-builder unit tests (no HTTP)
# ---------------------------------------------------------------------------


def test_clone_remark_format():
    assert _clone_remark(COUNTRY, PUBLIC_PORT) == "[ US United States ] :30001"
    assert _clone_remark({"code": "DE"}, 1234) == "[ DE ] :1234"
    assert _clone_remark({"name": "France", "flag": "FR"}, 80) == "[ FR France ] :80"


def test_socks_outbound_shape():
    ob = _socks_outbound(PUBLIC_PORT, SOCKS_PORT)
    assert ob["protocol"] == "socks"
    assert ob["tag"] == f"socks-out-{PUBLIC_PORT}"
    srv = ob["settings"]["servers"][0]
    assert srv["address"] == "127.0.0.1"
    assert srv["port"] == SOCKS_PORT
    assert srv["users"] == []


def test_fresh_vless_client_is_unique_and_well_formed():
    c1 = _fresh_vless_client(PUBLIC_PORT)
    c2 = _fresh_vless_client(PUBLIC_PORT)
    assert c1["id"] != c2["id"]  # fresh UUID each call
    assert c1["subId"] != c2["subId"]  # fresh subId each call
    # both are valid UUIDs
    uuid.UUID(c1["id"])
    uuid.UUID(c1["subId"])
    assert c1["flow"] == "xtls-rprx-vision"
    assert c1["email"] == f"clone-{PUBLIC_PORT}@psiphon3xui"
    assert c1["enable"] is True
    # Hotfix #7 (Bug #9): tgId MUST be an int (NOT a string). 3x-ui's newer
    # Go schema unmarshals Client.tgId as int64 — sending "" was rejected
    # with `cannot unmarshal string into Go struct field Client.tgId of
    # type int64`. The valid "no Telegram ID" sentinel is `0`.
    assert c1["tgId"] == 0
    assert isinstance(c1["tgId"], int), (
        "_fresh_vless_client tgId MUST be an int (0, NOT empty string) — "
        "3x-ui's Go schema unmarshals tgId as int64 and rejects string "
        "(Bug #9 — Hotfix #7)."
    )
    assert "limitIp" in c1 and isinstance(c1["limitIp"], int)
    assert "totalGB" in c1 and isinstance(c1["totalGB"], int)
    assert "expiryTime" in c1 and isinstance(c1["expiryTime"], int)
    assert "reset" in c1 and isinstance(c1["reset"], int)


def test_build_clone_payload_vless_perserves_template_streamsettings(template_json):
    p = _build_clone_payload(
        template=template_json,
        protocol="vless",
        public_port=PUBLIC_PORT,
        socks_port=SOCKS_PORT,
        country=COUNTRY,
    )
    assert p["protocol"] == "vless"
    assert p["port"] == PUBLIC_PORT
    assert p["tag"] == f"in-{PUBLIC_PORT}-tcp"
    assert p["remark"] == "[ US United States ] :30001"
    # Template's streamSettings preserved except for the injected outbound
    assert p["streamSettings"]["network"] == "tcp"
    assert p["streamSettings"]["security"] == "none"
    assert p["streamSettings"]["tcpSettings"]["header"]["type"] == "none"
    assert p["streamSettings"]["outbound"]["protocol"] == "socks"
    assert p["streamSettings"]["outbound"]["settings"]["servers"][0]["port"] == SOCKS_PORT
    # Hotfix #8 (Bug #d): the clone MUST preserve the template's `clients`
    # array VERBATIM and MUST NOT mint a fresh `_fresh_vless_client(public_port)`.
    # The fixture template ships `clients: []` (the sanitized Phase-1 capture),
    # so the clone inherits an empty clients list — exactly what the operator
    # requested ("only clone the inbound, not the client section"). The
    # contract this lock-in enforces:
    #   * whatever clients array the template carries is copied THROUGH
    #     unchanged (same length, same content) — no fresh per-clone client
    #     row is synthesised on the operator's behalf.
    assert p["settings"]["clients"] == []  # empty template → empty clone
    assert len(p["settings"]["clients"]) == 0  # no fresh client minted
    assert p["settings"]["decryption"] == "none"  # preserved from template
    assert p["sniffing"]["enabled"] is False  # preserved from template


def test_build_clone_payload_preserves_non_empty_template_clients_verbatim(template_json):
    """Hotfix #8 (Bug #d): cloning a 3x-ui inbound must NOT mint a fresh
    `_fresh_vless_client` row on the operator's behalf — the clone should
    inherit the template's existing `clients` array, byte-for-byte, so the
    operator's already-configured client roster merely gains a new listener
    port instead of sprouting a new 'client section' row per clone.

    This pin: passes a template carrying ONE existing client (a fixed UUID,
    a real email, tgId=0 int) and asserts the clone's settings.clients is
    that exact entity — same `id`, same `email`, same `tgId` — preserved
    through, NOT replaced with a freshly minted entry.
    """
    existing_client = {
        "id": "11111111-2222-3333-4444-555555555555",
        "flow": "xtls-rprx-vision",
        "email": "operator@psiphon3xui",
        "limitIp": 0,
        "totalGB": 0,
        "expiryTime": 0,
        "enable": True,
        # tgId already int-zero on a properly-typed template (Hotfix #7)
        "tgId": 0,
        "subId": "77777777-8888-9999-aaaa-bbbbbbbbbbbb",
        "reset": 0,
    }
    template_with_clients = {**template_json, "settings": {
        **template_json["settings"], "clients": [existing_client],
    }}
    p = _build_clone_payload(
        template=template_with_clients,
        protocol="vless",
        public_port=PUBLIC_PORT,
        socks_port=SOCKS_PORT,
        country=COUNTRY,
    )
    # exactly one client (matching the template — NOT a fresh mint)
    assert len(p["settings"]["clients"]) == 1
    cloned_client = p["settings"]["clients"][0]
    # The clone engine copies the template's `settings` dict shallowly
    # (settings = dict(template.get("settings") or {}) then explicitly
    # copies `clients` through) — it does NOT deep-clone the inner
    # client dict, so the originally-supplied "existing_client" dict
    # reference MAY be aliased into the clone payload. That aliasing is
    # FINE — what matters is that the SAME client row (same UUID, same
    # email, same tgId, same subId) reaches the wire, NOT a freshly
    # minted one with a NEW UUID. The contracts this assertion pins:
    #   * structural-equal: the clone carries the original client
    #     unchanged (same id + email + tgId + subId + every other
    #     field).
    #   * NOT minted: the cloned client's UUID equals the template's
    #     existing client's UUID (a freshly minted `_fresh_vless_client`
    #     would have a uuid4 freshly generated per call, so this assert
    #     catches that regression even if the new code minted and then
    #     aliased by coincidence).
    assert cloned_client == existing_client  # structurally identical (Bug #d)
    assert cloned_client["id"] == existing_client["id"]
    assert cloned_client["email"] == existing_client["email"]
    assert cloned_client["subId"] == existing_client["subId"]
    assert cloned_client["tgId"] == 0 and isinstance(cloned_client["tgId"], int)
    # Strong negative: a freshly minted _fresh_vless_client uses an email
    # shape of "clone-<public_port>@psiphon3xui" (see _fresh_vless_client
    # in panel/dashboard/xui_client.py). If the clone had minted a fresh
    # client, this assert would catch it (Bug #d).
    assert cloned_client["email"] != f"clone-{PUBLIC_PORT}@psiphon3xui"
    assert cloned_client["email"] == "operator@psiphon3xui"


def test_build_clone_payload_rejects_non_vless(template_json):
    with pytest.raises(XuiClientError, match="VLESS only"):
        _build_clone_payload(
            template={**template_json, "protocol": "vmess"},
            protocol="vmess",
            public_port=PUBLIC_PORT,
            socks_port=SOCKS_PORT,
            country=COUNTRY,
        )


# ---------------------------------------------------------------------------
# HTTP tests via respx
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    return XuiClient(BASE, username="admin", password="pass")


@respx.mock
async def test_login_extracts_csrf_and_sets_cookie(client):
    respx.get(BASE).respond(text=login_html())
    respx.post(BASE + "login").respond(
        json={"success": True, "msg": "logged in", "obj": None},
        headers={"set-cookie": "3x-ui=ABC; Path=/WSCM6EhC9pO6T9K0RA/"},
    )
    await client.login()
    assert client._csrf == CSRF
    assert client._logged_in is True


@respx.mock
async def test_login_failure_raises(client):
    respx.get(BASE).respond(text=login_html())
    respx.post(BASE + "login").respond(
        json={"success": False, "msg": "invalid username or password", "obj": None}
    )
    with pytest.raises(XuiClientError, match="API failure"):
        await client.login()
    await client.aclose()


@respx.mock
async def test_list_inbound_summaries(client):
    respx.get(BASE).respond(text=login_html())
    respx.post(BASE + "login").respond(json={"success": True, "msg": "ok", "obj": None})
    # Hotfix #5 (Bug #6v2): XuiClient appends the literal `panel/api/inbounds/list`
    # prefix on every API call (the `/panel` SPA route prefix is part of EVERY
    # API URL the Phase-1 spike captured; login sits at the webBasePath root,
    # NOT under /panel — see docs/XUI_API.md and spike/spike_1c2_capture.py).
    respx.get(BASE + "panel/api/inbounds/list").respond(
        json={
            "success": True,
            "msg": "",
            "obj": [
                {
                    "id": 1,
                    "port": 21777,
                    "protocol": "vless",
                    "remark": "baratest",
                    "tag": "in-21777-tcp",
                },
                {
                    "id": 2,
                    "port": 22222,
                    "protocol": "vmess",
                    "remark": "vmess-in",
                    "tag": "in-22222-tcp",
                },
            ],
        }
    )

    async with client:
        summaries = await client.list_inbound_summaries()

    assert [s.id for s in summaries] == [1, 2]
    assert isinstance(summaries[0], InboundSummary)
    assert summaries[0].protocol == "vless"
    assert summaries[1].port == 22222


@respx.mock
async def test_clone_inbound_posts_bare_json_with_csrf_and_stream_outbound(
    client, template_json, clone_response_json
):
    respx.get(BASE).respond(text=login_html())
    respx.post(BASE + "login").respond(json={"success": True, "msg": "ok", "obj": None})
    # template fetch returns the *envelope*; XuiClient.get_inbound unwraps obj.
    respx.get(BASE + f"panel/api/inbounds/get/{TEMPLATE_ID}").respond(
        json={"success": True, "msg": "", "obj": template_json}
    )
    # the add endpoint returns the clone-response envelope; capture req body.
    # XuiClient.add_inbound unwraps `obj` and returns it as `clone`.
    add_route = respx.post(BASE + "panel/api/inbounds/add").respond(
        json={
            "success": True,
            "msg": "Inbound has been successfully created.",
            "obj": clone_response_json,
        }
    )

    async with client:
        clone = await client.clone_inbound(
            template_id=TEMPLATE_ID,
            country=COUNTRY,
            socks_port=SOCKS_PORT,
            public_port=PUBLIC_PORT,
        )

    # request shape assertions
    assert add_route.called
    req = add_route.calls.last.request
    assert req.headers["X-CSRF-Token"] == CSRF
    assert req.headers["Content-Type"] == "application/json"
    sent = json.loads(req.content)
    # bare JSON (NOT wrapped in {"inbound": "..."})
    assert "inbound" not in sent
    assert sent["port"] == PUBLIC_PORT
    assert sent["remark"] == "[ US United States ] :30001"
    assert sent["streamSettings"]["outbound"]["protocol"] == "socks"
    assert sent["streamSettings"]["outbound"]["settings"]["servers"][0]["port"] == SOCKS_PORT
    # Hotfix #8 (Bug #d): the clone payload preserves the template's clients
    # array verbatim — the test fixture ships `clients: []`, so the wire
    # payload's settings.clients is also an empty list (NOT a freshly minted
    # 1-element `_fresh_vless_client` array).
    assert sent["settings"]["clients"] == []
    assert len(sent["settings"]["clients"]) == 0

    # response shape assertions
    assert clone["id"] == 2
    assert clone["port"] == PUBLIC_PORT
    assert clone["streamSettings"]["outbound"]["settings"]["servers"][0]["address"] == "127.0.0.1"


@respx.mock
async def test_clone_inbound_rollback_on_api_failure(client, template_json):
    respx.get(BASE).respond(text=login_html())
    respx.post(BASE + "login").respond(json={"success": True, "msg": "ok", "obj": None})
    respx.get(BASE + f"panel/api/inbounds/get/{TEMPLATE_ID}").respond(
        json={"success": True, "msg": "", "obj": template_json}
    )
    respx.post(BASE + "panel/api/inbounds/add").respond(
        json={"success": False, "msg": "port in use", "obj": None}
    )

    async with client:
        with pytest.raises(XuiClientError, match="add_inbound: API failure"):
            await client.clone_inbound(
                template_id=TEMPLATE_ID,
                country=COUNTRY,
                socks_port=SOCKS_PORT,
                public_port=PUBLIC_PORT,
            )


@respx.mock
async def test_delete_inbound(client):
    respx.get(BASE).respond(text=login_html())
    respx.post(BASE + "login").respond(json={"success": True, "msg": "ok", "obj": None})
    del_route = respx.post(BASE + "panel/api/inbounds/del/42").respond(
        json={"success": True, "msg": "inbound deleted", "obj": None}
    )

    async with client:
        out = await client.delete_inbound(42)
    assert del_route.called
    assert out["success"] is True


@respx.mock
async def test_base_url_normalisation_strips_panel_SPA_route():
    """Hotfix #5 (Bug #6v2): the operator pastes the FULL SPA URL visible in
    the browser address bar — including the ``/panel`` SPA page-route segment
    that 3x-ui's React frontend uses. The ``/panel`` segment is NOT part of
    the API prefix; the API base is ``{webBasePath}/`` and EVERY API URL is
    prefixed with the literal ``panel/api/...`` by the panel itself
    (see spike/spike_1c2_capture.py:65 & spike/spike_1e_clone.py:178 both
    do ``base.split("/panel")[0]`` and spike/spike_1c2_capture.py:106 POSTs
    ``{base}login``, line 149 GETs ``{base}panel/api/inbounds/list``).

    For a default install (empty webBasePath), the operator pastes
    ``http://localhost:2053/panel`` — strip ``/panel`` → base
    ``http://localhost:2053/``, login POST → ``http://localhost:2053/login``,
    list_inbounds GET → ``http://localhost:2053/panel/api/inbounds/list``.

    For a hardened install (random ``webBasePath``), the operator pastes
    ``http://3x-ui.test/WSCM6EhC9pO6T9K0RA/panel`` — strip ``/panel`` → base
    ``http://3x-ui.test/WSCM6EhC9pO6T9K0RA/``, login URL
    ``http://3x-ui.test/WSCM6EhC9pO6T9K0RA/login``, list_inbounds URL
    ``http://3x-ui.test/WSCM6EhC9pO6T9K0RA/panel/api/inbounds/list``.

    Hotfix #4 (Bug #6v1) dropped both the strip heuristic AND the literal
    ``panel/api`` prefix — the operator pasted
    ``http://host:2053/panel/`` → base kept the /panel → login URL became
    ``/panel/login`` → 404 (reported as ``xui-creds step failed: 3x-ui
    login failed: login: HTTP 404:``). This Hotfix-#5 test pins the
    CORRECTED convention so future refactors don't silently resurrect either
    half of the Hotfix-#4 mistake.
    """
    # ── 1. Hardened webBasePath install typed with a trailing /panel SPA route
    c = XuiClient(
        "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/panel   ",
        username="u",
        password="p",
    )
    # Trailing whitespace trimmed, /panel matched-and-stripped, slash appended.
    assert c.base_url == "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/"
    # Login sits at the ROOT of webBasePath (NOT under the /panel SPA route).
    assert c.base_url + "login" == "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/login"
    # Every API URL is prefixed with the literal "panel/api/…" (the React
    # SPA route prefix the API also sits under).
    assert c.base_url + "panel/api/inbounds/list" == (
        "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/panel/api/inbounds/list"
    )

    # ── 2. Default-install URL typed with /panel (the bare SPA route, since
    #      3x-ui's default webBasePath is "" — "/panel" is the literal route).
    c2 = XuiClient(
        "http://localhost:2053/panel",
        username="u",
        password="p",
    )
    # /panel stripped → base reduces to the host root.
    assert c2.base_url == "http://localhost:2053/"
    assert c2.base_url + "login" == "http://localhost:2053/login"
    assert c2.base_url + "panel/api/inbounds/list" == (
        "http://localhost:2053/panel/api/inbounds/list"
    ), (
        "The API URL MUST be prefixed with the literal `panel/api/...` "
        "segment — Hotfix #4 (Bug #6v1) dropped the panel-api prefix and "
        "the operator hit 404 on list_inbounds (API URL became "
        "`http://localhost:2053/panel/api/inbounds/list` only by accident "
        "of having kept the /panel in base_url); Bug #6v2 restores the "
        "literal prefix so the API URL sits under the React SPA route even "
        "after base_url has been normalised down to the webBasePath root."
    )

    # ── 3. Hardened install URL with NO /panel suffix (operator copied only
    #      the {webBasePath}/ part) → strip heuristic is a no-op, base kept.
    c3 = XuiClient(
        "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/",
        username="u",
        password="p",
    )
    assert c3.base_url == "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/"
    assert c3.base_url + "login" == (
        "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/login"
    )
    assert c3.base_url + "panel/api/inbounds/list" == (
        "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/panel/api/inbounds/list"
    )

    # ── 4. /panel/ with a trailing slash is also stripped.
    c4 = XuiClient(
        "http://localhost:2053/panel/",
        username="u",
        password="p",
    )
    assert c4.base_url == "http://localhost:2053/"
    assert c4.base_url + "login" == "http://localhost:2053/login"

    # ── 5. Empty base_url must raise on construction so a UI typo surfaces as
    #      an obvious value-error, not a far-down-the-road OID-error.
    with pytest.raises(ValueError, match="base_url must not be empty"):
        XuiClient("   ", username="u", password="p")

    # ── 6. A bare "/panel" URL (just the SPA route, no scheme/host) is
    #      rejected — Hotfix #5 (Bug #6v2) added a scheme-prefix check that
    #      fires before the /panel strip heuristic so a typo like "/panel"
    #      raises with a clear message instead of silently normalising to "/".
    #      Match on a substring both error messages contain ("include" + "host")
    #      so the assertion is robust against the two slightly different
    #      messages ("must include a scheme and host" vs.
    #      "must include a host").
    with pytest.raises(ValueError, match=r"include.*host"):
        XuiClient("/panel", username="u", password="p")
    with pytest.raises(ValueError, match=r"include.*host"):
        XuiClient("http:///panel", username="u", password="p")
    with pytest.raises(ValueError, match=r"include.*host"):
        XuiClient("http://panel", username="u", password="p")
