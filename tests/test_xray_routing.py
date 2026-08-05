"""Unit tests for panel.dashboard.xray_routing — the pure template transforms.

The async I/O wrappers (apply_country_binding, remove_country_binding) are
integration-tested in test_dashboard.py + test_wizard_clone.py via FakeXuiClient.
"""

import pytest

from panel.dashboard import xray_routing


class TestOutboundTagFor:
    """Country code → Xray outbound tag."""

    def test_two_letter_code_uppercase(self):
        assert xray_routing.outbound_tag_for("US") == "psiphon-out-US"

    def test_two_letter_code_lowercase(self):
        assert xray_routing.outbound_tag_for("us") == "psiphon-out-US"

    def test_two_letter_code_mixed_case(self):
        assert xray_routing.outbound_tag_for("Us") == "psiphon-out-US"

    def test_strips_whitespace(self):
        assert xray_routing.outbound_tag_for(" GB ") == "psiphon-out-GB"


class TestSocksOutboundFor:
    """Country code + port → SOCKS outbound dict."""

    def test_shape(self):
        out = xray_routing.socks_outbound_for("US", 11001)
        assert out == {
            "tag": "psiphon-out-US",
            "protocol": "socks",
            "settings": {
                "servers": [
                    {"address": "127.0.0.1", "port": 11001, "users": []}
                ]
            },
        }

    def test_different_port(self):
        out = xray_routing.socks_outbound_for("GB", 11002)
        assert out["settings"]["servers"][0]["port"] == 11002

    def test_coerces_port_to_int(self):
        out = xray_routing.socks_outbound_for("FR", "11003")
        assert out["settings"]["servers"][0]["port"] == 11003
        assert isinstance(out["settings"]["servers"][0]["port"], int)


class TestRoutingRuleFor:
    """Country code + inbound tag → routing rule dict."""

    def test_shape(self):
        rule = xray_routing.routing_rule_for("US", "in-30001-tcp")
        assert rule == {
            "type": "field",
            "inboundTag": ["in-30001-tcp"],
            "outboundTag": "psiphon-out-US",
        }

    def test_binds_to_actual_tag_not_assumed_form(self):
        rule = xray_routing.routing_rule_for("GB", "in-30002-tcp-2")
        assert rule["inboundTag"] == ["in-30002-tcp-2"]
        assert rule["outboundTag"] == "psiphon-out-GB"


class TestIsCatchAll:
    """Recognise the stock 3x-ui catch-all rules our rules must precede."""

    def test_bittorrent_blackhole_is_catch_all(self):
        rule = {
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "blocked",
        }
        assert xray_routing._is_catch_all(rule)

    def test_geoip_private_block_is_catch_all(self):
        rule = {
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "blocked",
        }
        assert xray_routing._is_catch_all(rule)

    def test_geoip_private_in_list_is_catch_all(self):
        rule = {
            "type": "field",
            "ip": ["1.2.3.4", "geoip:private", "5.6.7.8"],
            "outboundTag": "blocked",
        }
        assert xray_routing._is_catch_all(rule)

    def test_per_country_rule_is_not_catch_all(self):
        rule = {
            "type": "field",
            "inboundTag": ["in-30001-tcp"],
            "outboundTag": "psiphon-out-US",
        }
        assert not xray_routing._is_catch_all(rule)

    def test_non_dict_is_not_catch_all(self):
        assert not xray_routing._is_catch_all("not a dict")
        assert not xray_routing._is_catch_all(None)
        assert not xray_routing._is_catch_all([])


class TestUpsertBinding:
    """Idempotently add/refresh a country's outbound + routing rule."""

    def test_empty_template_gets_outbound_and_rule(self):
        template = {}
        changed = xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        assert changed
        assert len(template["outbounds"]) == 1
        assert template["outbounds"][0]["tag"] == "psiphon-out-US"
        assert template["outbounds"][0]["settings"]["servers"][0]["port"] == 11001
        assert len(template["routing"]["rules"]) == 1
        assert template["routing"]["rules"][0]["inboundTag"] == ["in-30001-tcp"]
        assert template["routing"]["rules"][0]["outboundTag"] == "psiphon-out-US"

    def test_second_call_with_same_data_is_no_op(self):
        template = {}
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        changed = xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        assert not changed

    def test_updates_outbound_port_when_changed(self):
        template = {}
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        changed = xray_routing.upsert_binding(template, "US", 11002, "in-30001-tcp")
        assert changed
        assert len(template["outbounds"]) == 1
        assert template["outbounds"][0]["settings"]["servers"][0]["port"] == 11002

    def test_updates_rule_inbound_tag_when_changed(self):
        template = {}
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        changed = xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp-2")
        assert changed
        assert len(template["routing"]["rules"]) == 1
        assert template["routing"]["rules"][0]["inboundTag"] == ["in-30001-tcp-2"]

    def test_re_clone_onto_new_tag_leaves_no_stale_rule(self):
        """A country re-cloned onto a different inbound tag must end up with
        exactly ONE rule.

        3x-ui's resolveInboundTag() can hand the same country a different tag
        on re-clone (collision suffix "-2", or udp/tcpudp protocol segment).
        Keying the rule on the (outboundTag, inboundTag) PAIR would append a
        second rule and leave the first — and the stale one sorts earlier, so
        if its dead inbound tag were later reissued to another country, that
        country's traffic would be hijacked into this country's outbound.
        """
        template = {}
        for tag in ("in-30001-tcp", "in-30001-tcp-2", "in-30001-tcpudp"):
            xray_routing.upsert_binding(template, "US", 11001, tag)

        us_rules = [
            r
            for r in template["routing"]["rules"]
            if r.get("outboundTag") == "psiphon-out-US"
        ]
        assert len(us_rules) == 1, f"stale rules left behind: {us_rules}"
        assert us_rules[0]["inboundTag"] == ["in-30001-tcpudp"]

    def test_rule_stays_ahead_of_catch_alls_after_retag(self):
        """The re-inserted rule must still precede the catch-alls."""
        template = {
            "routing": {
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                ]
            }
        }
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp-2")
        rules = template["routing"]["rules"]
        assert rules[0]["outboundTag"] == "psiphon-out-US"
        assert rules[0]["inboundTag"] == ["in-30001-tcp-2"]
        assert rules[1]["protocol"] == ["bittorrent"]

    def test_appends_outbound_never_prepends(self):
        template = {
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "blocked", "protocol": "blackhole"},
            ]
        }
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        # The stock direct/blocked stay first; US outbound is appended.
        assert template["outbounds"][0]["tag"] == "direct"
        assert template["outbounds"][1]["tag"] == "blocked"
        assert template["outbounds"][2]["tag"] == "psiphon-out-US"

    def test_inserts_rule_before_catch_all(self):
        template = {
            "routing": {
                "rules": [
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
                    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
                ]
            }
        }
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        # The US rule must precede the bittorrent catch-all.
        assert template["routing"]["rules"][0]["outboundTag"] == "psiphon-out-US"
        assert template["routing"]["rules"][1]["protocol"] == ["bittorrent"]

    def test_multiple_countries_each_get_their_own_slots(self):
        template = {}
        xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")
        xray_routing.upsert_binding(template, "GB", 11002, "in-30002-tcp")
        assert len(template["outbounds"]) == 2
        assert template["outbounds"][0]["tag"] == "psiphon-out-US"
        assert template["outbounds"][1]["tag"] == "psiphon-out-GB"
        assert len(template["routing"]["rules"]) == 2

    def test_raises_if_outbounds_is_not_a_list(self):
        template = {"outbounds": "not a list"}
        with pytest.raises(ValueError, match="outbounds.*not a list"):
            xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")

    def test_raises_if_routing_is_not_a_dict(self):
        template = {"routing": "not a dict"}
        with pytest.raises(ValueError, match="routing.*not an object"):
            xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")

    def test_raises_if_routing_rules_is_not_a_list(self):
        template = {"routing": {"rules": "not a list"}}
        with pytest.raises(ValueError, match="routing.rules.*not a list"):
            xray_routing.upsert_binding(template, "US", 11001, "in-30001-tcp")


class TestStripBinding:
    """Remove a country's outbound and its routing rule(s)."""

    def test_empty_template_is_no_op(self):
        template = {}
        changed = xray_routing.strip_binding(template, "US")
        assert not changed

    def test_removes_outbound_by_tag(self):
        template = {
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "psiphon-out-US", "protocol": "socks", "settings": {}},
                {"tag": "blocked", "protocol": "blackhole"},
            ]
        }
        changed = xray_routing.strip_binding(template, "US")
        assert changed
        assert len(template["outbounds"]) == 2
        tags = [o["tag"] for o in template["outbounds"]]
        assert "psiphon-out-US" not in tags

    def test_removes_rule_by_outbound_tag_when_inbound_tag_is_none(self):
        template = {
            "routing": {
                "rules": [
                    {"type": "field", "inboundTag": ["in-30001-tcp"], "outboundTag": "psiphon-out-US"},
                    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
                ]
            }
        }
        changed = xray_routing.strip_binding(template, "US", inbound_tag=None)
        assert changed
        assert len(template["routing"]["rules"]) == 1
        assert template["routing"]["rules"][0]["protocol"] == ["bittorrent"]

    def test_removes_rule_by_outbound_and_inbound_tag_when_both_match(self):
        template = {
            "routing": {
                "rules": [
                    {"type": "field", "inboundTag": ["in-30001-tcp"], "outboundTag": "psiphon-out-US"},
                    {"type": "field", "inboundTag": ["in-30002-tcp"], "outboundTag": "psiphon-out-US"},
                ]
            }
        }
        # Only the first rule (in-30001-tcp) is removed.
        changed = xray_routing.strip_binding(template, "US", inbound_tag="in-30001-tcp")
        assert changed
        assert len(template["routing"]["rules"]) == 1
        assert template["routing"]["rules"][0]["inboundTag"] == ["in-30002-tcp"]

    def test_second_call_is_no_op(self):
        template = {
            "outbounds": [{"tag": "psiphon-out-US", "protocol": "socks"}],
            "routing": {"rules": [{"outboundTag": "psiphon-out-US", "inboundTag": ["in-30001-tcp"]}]},
        }
        xray_routing.strip_binding(template, "US")
        changed = xray_routing.strip_binding(template, "US")
        assert not changed

    def test_leaves_sibling_countries_intact(self):
        template = {
            "outbounds": [
                {"tag": "psiphon-out-US", "protocol": "socks"},
                {"tag": "psiphon-out-GB", "protocol": "socks"},
            ],
            "routing": {
                "rules": [
                    {"outboundTag": "psiphon-out-US", "inboundTag": ["in-30001-tcp"]},
                    {"outboundTag": "psiphon-out-GB", "inboundTag": ["in-30002-tcp"]},
                ]
            },
        }
        xray_routing.strip_binding(template, "US")
        assert len(template["outbounds"]) == 1
        assert template["outbounds"][0]["tag"] == "psiphon-out-GB"
        assert len(template["routing"]["rules"]) == 1
        assert template["routing"]["rules"][0]["outboundTag"] == "psiphon-out-GB"

    def test_tolerates_missing_outbounds_key(self):
        template = {"routing": {"rules": []}}
        changed = xray_routing.strip_binding(template, "US")
        assert not changed

    def test_tolerates_missing_routing_key(self):
        template = {"outbounds": []}
        changed = xray_routing.strip_binding(template, "US")
        assert not changed

    def test_tolerates_non_list_outbounds(self):
        template = {"outbounds": "not a list"}
        changed = xray_routing.strip_binding(template, "US")
        assert not changed

    def test_tolerates_non_dict_routing(self):
        template = {"routing": "not a dict"}
        changed = xray_routing.strip_binding(template, "US")
        assert not changed
