import unittest

from loha.config import normalize_mapping
from loha.exceptions import RulesValidationError
from loha.models import AliasRecord, PortRecord, PortSpec, RenderContext, RulesFile
from loha.render import render_ruleset
from loha.rules import parse_rules_text


def base_config(**overrides):
    values = {
        "EXTERNAL_IFS": "eth0",
        "PRIMARY_EXTERNAL_IF": "eth0",
        "LISTEN_IPS": "203.0.113.10",
        "DEFAULT_SNAT_IP": "203.0.113.10",
        "LAN_IFS": "br0",
        "LAN_NETS": "192.168.10.0/24",
        "PROTECTION_MODE": "both",
        "PROTECTED_NETS": "192.168.10.0/24",
        "ENABLE_EGRESS_SNAT": "on",
        "EGRESS_NETS": "192.168.10.0/24",
        "ENABLE_HAIRPIN": "on",
        "ENABLE_WAN_TO_WAN": "on",
        "ENABLE_TCPMSS_CLAMP": "off",
        "COUNTER_MODE": "minimal",
    }
    values.update(overrides)
    return normalize_mapping(values)


class RenderTests(unittest.TestCase):
    def test_full_ruleset_starts_with_idempotent_table_destroy(self):
        config = base_config(AUTH_MODE="mark", DNAT_MARK="0x10000000")
        rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n")
        rendered = render_ruleset(RenderContext(config, rules)).full_ruleset
        self.assertIn("destroy table ip loha_port_forwarder", rendered)
        self.assertLess(
            rendered.index("destroy table ip loha_port_forwarder"),
            rendered.index("table ip loha_port_forwarder {"),
        )

    def test_mark_mode_contains_miss_cleanup_and_mark_gating(self):
        config = base_config(AUTH_MODE="mark", DNAT_MARK="0x10000000")
        rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n")
        rendered = render_ruleset(RenderContext(config, rules)).full_ruleset
        self.assertIn("ct mark set ct mark and $DNAT_MARK_CLEAR_MASK", rendered)
        self.assertIn("ct status dnat ct mark & $DNAT_MARK != 0 accept", rendered)
        self.assertIn("ip daddr @protected_backend_hosts ct mark & $DNAT_MARK == 0 counter drop", rendered)

    def test_label_mode_uses_dnat_status_gating(self):
        config = base_config(AUTH_MODE="label", DNAT_LABEL="56")
        rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n")
        rendered = render_ruleset(RenderContext(config, rules)).full_ruleset
        self.assertIn("ct status dnat ct label $DNAT_LABEL accept", rendered)
        self.assertIn("ct status dnat ct label $DNAT_LABEL masquerade", rendered)
        self.assertNotIn("ct label != $DNAT_LABEL", rendered)

    def test_template_checksum_stays_stable_when_only_rules_change(self):
        config = base_config(AUTH_MODE="mark", DNAT_MARK="0x10000000")
        first_rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n")
        second_rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8081\tVM_WEB\t80\n")
        first = render_ruleset(RenderContext(config, first_rules))
        second = render_ruleset(RenderContext(config, second_rules))
        self.assertEqual(first.template_checksum, second.template_checksum)
        self.assertEqual(first.control_state, second.control_state)

    def test_template_checksum_stays_stable_when_only_listener_set_changes(self):
        first = render_ruleset(
            RenderContext(
                base_config(AUTH_MODE="mark", DNAT_MARK="0x10000000", LISTEN_IPS="203.0.113.10", DEFAULT_SNAT_IP="203.0.113.10"),
                parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n"),
            )
        )
        second = render_ruleset(
            RenderContext(
                base_config(
                    AUTH_MODE="mark",
                    DNAT_MARK="0x10000000",
                    LISTEN_IPS="203.0.113.10,203.0.113.11",
                    DEFAULT_SNAT_IP="203.0.113.10",
                ),
                parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n"),
            )
        )
        self.assertEqual(first.template_checksum, second.template_checksum)
        self.assertEqual(first.control_state, second.control_state)

    def test_template_checksum_changes_when_default_snat_changes(self):
        rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n")
        first = render_ruleset(
            RenderContext(
                base_config(
                    AUTH_MODE="mark",
                    DNAT_MARK="0x10000000",
                    LISTEN_IPS="203.0.113.10,203.0.113.11",
                    DEFAULT_SNAT_IP="203.0.113.10",
                ),
                rules,
            )
        )
        second = render_ruleset(
            RenderContext(
                base_config(
                    AUTH_MODE="mark",
                    DNAT_MARK="0x10000000",
                    LISTEN_IPS="203.0.113.10,203.0.113.11",
                    DEFAULT_SNAT_IP="203.0.113.11",
                ),
                rules,
            )
        )
        self.assertNotEqual(first.template_checksum, second.template_checksum)
        self.assertNotEqual(first.control_state, second.control_state)

    def test_template_checksum_changes_when_external_binding_shifts(self):
        rules = parse_rules_text("ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n")
        first = render_ruleset(
            RenderContext(
                base_config(
                    AUTH_MODE="mark",
                    DNAT_MARK="0x10000000",
                    EXTERNAL_IFS="eth0",
                    PRIMARY_EXTERNAL_IF="eth0",
                    LISTEN_IPS="203.0.113.10",
                    DEFAULT_SNAT_IP="203.0.113.10",
                ),
                rules,
            )
        )
        second = render_ruleset(
            RenderContext(
                base_config(
                    AUTH_MODE="mark",
                    DNAT_MARK="0x10000000",
                    EXTERNAL_IFS="eth1",
                    PRIMARY_EXTERNAL_IF="eth1",
                    LISTEN_IPS="198.51.100.20",
                    DEFAULT_SNAT_IP="198.51.100.20",
                ),
                rules,
            )
        )
        self.assertNotEqual(first.template_checksum, second.template_checksum)
        self.assertNotEqual(first.control_state, second.control_state)

    def test_renderer_rejects_conflicting_duplicate_dnat_keys(self):
        rules = RulesFile(
            aliases=(
                AliasRecord("VM_WEB", "192.168.10.20"),
                AliasRecord("VM_API", "192.168.10.30"),
            ),
            ports=(
                PortRecord("tcp", PortSpec(5001, 5100), "VM_WEB", PortSpec(5001, 5100)),
                PortRecord("tcp", PortSpec(5090, 5120), "VM_API", PortSpec(5090, 5120)),
            ),
        )
        with self.assertRaises(RulesValidationError) as ctx:
            render_ruleset(RenderContext(base_config(AUTH_MODE="mark", DNAT_MARK="0x10000000"), rules))
        self.assertIn("duplicate dnat_rules key", str(ctx.exception))
        self.assertIn("tcp . 5090", str(ctx.exception))

    def test_renderer_deduplicates_identical_dnat_keys(self):
        rules = RulesFile(
            aliases=(AliasRecord("VM_WEB", "192.168.10.20"),),
            ports=(
                PortRecord("tcp", PortSpec(8080, 8080), "VM_WEB", PortSpec(80, 80)),
                PortRecord("tcp", PortSpec(8080, 8080), "VM_WEB", PortSpec(80, 80)),
            ),
        )
        rendered = render_ruleset(RenderContext(base_config(AUTH_MODE="mark", DNAT_MARK="0x10000000"), rules))
        self.assertEqual(1, rendered.map_update.count("tcp . 8080 : 192.168.10.20 . 80,"))


if __name__ == "__main__":
    unittest.main()
