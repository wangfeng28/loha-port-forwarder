import textwrap
from pathlib import Path
import tempfile
import unittest

from loha.config import load_config, normalize_mapping, parse_canonical_text, render_canonical_text
from loha.constants import CONFIG_KEYS
from loha.exceptions import ConfigSyntaxError, ConfigValidationError


class ConfigTests(unittest.TestCase):
    def test_strict_parser_rejects_export_and_spaces(self):
        with self.assertRaises(ConfigSyntaxError):
            parse_canonical_text('export EXTERNAL_IFS="eth0"\n')
        with self.assertRaises(ConfigSyntaxError):
            parse_canonical_text('EXTERNAL_IFS = "eth0"\n')

    def test_normalize_materializes_primary_and_default_snat(self):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "LAN_IFS": "br0",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )
        self.assertEqual("eth0", config["PRIMARY_EXTERNAL_IF"])
        self.assertEqual("203.0.113.10", config["DEFAULT_SNAT_IP"])
        self.assertNotIn("WAN_IF", config.as_dict())
        self.assertNotIn("WAN_IP", config.as_dict())

    def test_input_shortcut_auto_is_rejected(self):
        with self.assertRaises(ConfigValidationError):
            normalize_mapping(
                {
                    "EXTERNAL_IFS": "auto",
                    "LISTEN_IPS": "203.0.113.10",
                    "LAN_IFS": "br0",
                    "LAN_NETS": "192.168.10.0/24",
                }
            )

    def test_multi_external_config_is_rejected_by_product_boundary(self):
        with self.assertRaises(ConfigValidationError) as ctx:
            normalize_mapping(
                {
                    "EXTERNAL_IFS": "eth0,eth1",
                    "PRIMARY_EXTERNAL_IF": "eth0",
                    "LISTEN_IPS": "203.0.113.10",
                    "DEFAULT_SNAT_IP": "203.0.113.10",
                    "LAN_IFS": "br0",
                    "LAN_NETS": "192.168.10.0/24",
                    "PROTECTION_MODE": "backends",
                }
            )
        self.assertIn("single-external product boundary", str(ctx.exception))

    def test_strict_parser_rejects_removed_runtime_mirror_keys(self):
        with self.assertRaises(ConfigSyntaxError):
            parse_canonical_text('WAN_IF="eth0"\n')

    def test_strict_reader_rejects_missing_condition_field(self):
        temp_dir = Path(tempfile.mkdtemp())
        path = temp_dir / "loha.conf"
        path.write_text(
            textwrap.dedent(
                """
                EXTERNAL_IFS="eth0"
                PRIMARY_EXTERNAL_IF="eth0"
                LISTEN_IPS="203.0.113.10"
                DEFAULT_SNAT_IP="203.0.113.10"
                LAN_IFS="br0"
                LAN_NETS="192.168.10.0/24"
                PROTECTION_MODE="backends"
                PROTECTED_NETS=""
                AUTH_MODE="mark"
                DNAT_MARK="0x10000000"
                DNAT_LABEL=""
                ENABLE_HAIRPIN="on"
                ENABLE_WAN_TO_WAN="on"
                ENABLE_EGRESS_SNAT="on"
                EGRESS_NETS=""
                ENABLE_TCPMSS_CLAMP="off"
                ENABLE_STRICT_LAN_VALIDATION="off"
                INTERNAL_IFS=""
                TRUSTED_INTERNAL_NETS=""
                COUNTER_MODE="minimal"
                ENABLE_CONFIG_HISTORY="on"
                RP_FILTER_MODE="system"
                CONNTRACK_MODE="system"
                CONNTRACK_TARGET_MAX=""
                CONNTRACK_PEAK=""
                CONNTRACK_MEMORY_PERCENT=""
                LOCALE="en_US"
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(ConfigValidationError):
            load_config(path)

    def test_canonical_writer_emits_all_keys_in_config_order(self):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "LAN_IFS": "br0",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )
        rendered = render_canonical_text(config)
        lines = rendered.splitlines()
        keys = [line.split("=", 1)[0] for line in lines]

        self.assertEqual(list(CONFIG_KEYS), keys)
        self.assertEqual(len(CONFIG_KEYS), len(lines))
        self.assertTrue(rendered.endswith("\n"))
        self.assertEqual(list(CONFIG_KEYS), list(parse_canonical_text(rendered).keys()))

    def test_canonical_writer_round_trips_materialized_conditional_defaults_without_drift(self):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "LAN_IFS": "br0",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "both",
                "ENABLE_EGRESS_SNAT": "on",
                "ENABLE_STRICT_LAN_VALIDATION": "on",
                "AUTH_MODE": "mark",
                "DNAT_MARK": "0x10000000",
            }
        )
        temp_dir = Path(tempfile.mkdtemp())
        path = temp_dir / "loha.conf"
        first_render = render_canonical_text(config)
        path.write_text(first_render, encoding="utf-8")

        loaded = load_config(path)
        second_render = render_canonical_text(loaded)

        self.assertEqual(config, loaded)
        self.assertEqual(first_render, second_render)
        self.assertEqual("192.168.10.0/24", loaded["PROTECTED_NETS"])
        self.assertEqual("192.168.10.0/24", loaded["EGRESS_NETS"])
        self.assertEqual("br0", loaded["INTERNAL_IFS"])
        self.assertEqual("192.168.10.0/24", loaded["TRUSTED_INTERNAL_NETS"])


if __name__ == "__main__":
    unittest.main()
