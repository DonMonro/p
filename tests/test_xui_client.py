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
    # Exactly one fresh client injected
    assert len(p["settings"]["clients"]) == 1
    assert p["settings"]["clients"][0]["id"] != ""
    assert p["settings"]["decryption"] == "none"  # preserved from template
    assert p["sniffing"]["enabled"] is False  # preserved from template


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
    assert len(sent["settings"]["clients"]) == 1

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
async def test_base_url_normalisation_strips_panel_suffix():
    """The SPA URL has /panel; the API base path must not."""
    respx.get("http://3x-ui.test/WSCM6EhC9pO6T9K0RA/").pass_through()
    c = XuiClient(
        "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/panel/   ",
        username="u",
        password="p",
    )
    assert c.base_url == "http://3x-ui.test/WSCM6EhC9pO6T9K0RA/"
