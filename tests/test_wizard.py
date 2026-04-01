import unittest
from contextlib import redirect_stdout
import io
from subprocess import CompletedProcess

from loha.config import normalize_mapping, recommended_config
from loha.models import CanonicalConfig
from loha.system import SystemAdapter
from loha.wizard import build_summary, run_config_wizard, run_config_wizard_flow


class FakeAdapter(SystemAdapter):
    def command_exists(self, name: str) -> bool:
        return True

    def run(self, argv, *, input_text: str = "", check: bool = True):
        if tuple(argv) == ("nft", "-c", "-f", "-"):
            return CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected command in wizard unit tests: {argv!r}")

    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return ("lo", "eth0", "eth1", "eth2")

    def global_ipv4s(self, interface: str):
        return {"eth0": ("203.0.113.10",)}.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {"eth1": ("192.168.10.0/24",), "eth2": ("192.168.20.0/24",)}.get(interface, ())

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        raise AssertionError("nft_apply should not be used in wizard unit tests")

    def systemctl(self, action: str, unit: str = "") -> None:
        raise AssertionError("systemctl should not be used in wizard unit tests")

    def scan_listeners(self):
        return set()


class MultiWanAdapter(FakeAdapter):
    def default_ipv4_ifaces(self):
        return ("eth0", "eth9")

    def list_interfaces(self):
        return ("lo", "eth0", "eth9", "eth1", "eth2")

    def global_ipv4s(self, interface: str):
        return {
            "eth0": ("203.0.113.10",),
            "eth9": ("198.51.100.10", "198.51.100.11"),
        }.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {
            "eth1": ("192.168.10.0/24",),
            "eth2": ("192.168.20.0/24",),
        }.get(interface, ())


class WizardSummaryTests(unittest.TestCase):
    def test_summary_uses_four_fixed_sections(self):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "br0",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )
        titles = [title for title, _lines in build_summary(config)]
        self.assertEqual(
            ["Network Topology", "Exposure and Protection", "Default Egress NAT", "Advanced Settings"],
            titles,
        )

    def test_summary_includes_runtime_binding_status_lines(self):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10,203.0.113.11",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "br0",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )
        network_lines = build_summary(config)[0][1]
        self.assertIn("External interface binding: compatible now via the configured single-interface binding", network_lines)
        self.assertIn(
            "Exposure address binding: compatible now via the configured external IP list used for exposure",
            network_lines,
        )

    def test_wizard_accepts_detected_defaults_with_enter(self):
        answers = iter(["", "", "", "", "", "", "", "", ""])
        config = run_config_wizard(
            FakeAdapter(),
            initial=recommended_config(),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("eth0", config["PRIMARY_EXTERNAL_IF"])
        self.assertEqual("203.0.113.10", config["LISTEN_IPS"])
        self.assertEqual("eth1", config["LAN_IFS"])
        self.assertEqual("192.168.10.0/24", config["LAN_NETS"])
        self.assertEqual("off", config["ENABLE_EGRESS_SNAT"])
        self.assertEqual("off", config["ENABLE_TCPMSS_CLAMP"])

    def test_wizard_cancel_token_aborts_from_network_section(self):
        answers = iter(["0"])
        with self.assertRaises(KeyboardInterrupt):
            run_config_wizard_flow(
                FakeAdapter(),
                initial=recommended_config(),
                input_func=lambda _prompt: next(answers),
                show_summary=False,
            )

    def test_wizard_flow_can_resume_from_advanced_without_internal_summary(self):
        initial = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_HAIRPIN": "on",
                "ENABLE_EGRESS_SNAT": "off",
            }
        )
        answers = iter(["", "", "", "", "", "", ""])
        outcome = run_config_wizard_flow(
            FakeAdapter(),
            initial=initial,
            initial_stage="advanced",
            show_summary=False,
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("mark", outcome.config["AUTH_MODE"])
        self.assertEqual("system", outcome.config["RP_FILTER_MODE"])
        self.assertTrue(outcome.advanced_checked)

    def test_wizard_materializes_imported_auto_bindings_before_accepting_defaults(self):
        raw = recommended_config().as_dict()
        raw.update(
            {
                "EXTERNAL_IFS": "auto",
                "PRIMARY_EXTERNAL_IF": "",
                "LISTEN_IPS": "auto",
                "DEFAULT_SNAT_IP": "",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )
        answers = iter(["", "", "", "", "", "", "", "", "", ""])
        config = run_config_wizard(
            FakeAdapter(),
            initial=CanonicalConfig(raw),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("eth0", config["EXTERNAL_IFS"])
        self.assertEqual("203.0.113.10", config["DEFAULT_SNAT_IP"])
        self.assertNotEqual("auto", config["LISTEN_IPS"])

    def test_wizard_recomputes_listen_candidates_after_external_selection(self):
        answers = iter(["2", "", "", "", "", "", "", "", "", ""])
        config = run_config_wizard(
            MultiWanAdapter(),
            initial=recommended_config(),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("eth9", config["PRIMARY_EXTERNAL_IF"])
        self.assertEqual("198.51.100.10,198.51.100.11", config["LISTEN_IPS"])
        self.assertEqual("198.51.100.10", config["DEFAULT_SNAT_IP"])

    def test_wizard_allows_direct_listen_ip_input_when_candidates_exist(self):
        answers = iter(["", "198.51.100.20,198.51.100.21", "", "", "", "", "", "", "", ""])
        config = run_config_wizard(
            MultiWanAdapter(),
            initial=recommended_config(),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("198.51.100.20,198.51.100.21", config["LISTEN_IPS"])
        self.assertEqual("198.51.100.20", config["DEFAULT_SNAT_IP"])

    def test_wizard_allows_direct_lan_net_input_when_candidates_exist(self):
        answers = iter(["", "", "", "10.10.0.0/24,10.20.0.0/24", "", "", "", "", ""])
        config = run_config_wizard(
            FakeAdapter(),
            initial=recommended_config(),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("10.10.0.0/24,10.20.0.0/24", config["LAN_NETS"])

    def test_wizard_retries_invalid_direct_lan_nets_in_place(self):
        answers = iter(["", "", "", "not-a-cidr", "10.10.0.0/24", "", "", "", "", ""])
        config = run_config_wizard(
            FakeAdapter(),
            initial=recommended_config(),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("10.10.0.0/24", config["LAN_NETS"])

    def test_wizard_displays_imported_lan_nets_as_current_candidates(self):
        initial = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24,10.20.0.0/24",
                "PROTECTION_MODE": "backends",
            }
        )
        answers = iter(["", "", "", "", "", "", "", "", ""])
        output = io.StringIO()
        with redirect_stdout(output):
            config = run_config_wizard(
                FakeAdapter(),
                initial=initial,
                input_func=lambda _prompt: next(answers),
            )
        rendered = output.getvalue()
        self.assertIn(" 1. 192.168.10.0/24 (current)", rendered)
        self.assertIn(" 2. 10.20.0.0/24 (current)", rendered)
        self.assertEqual("192.168.10.0/24,10.20.0.0/24", config["LAN_NETS"])

    def test_wizard_retries_duplicate_multi_selection_in_place(self):
        answers = iter(["", "", "1,1", "1", "", "", "", "", "", ""])
        config = run_config_wizard(
            FakeAdapter(),
            initial=recommended_config(),
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("eth1", config["LAN_IFS"])

    def test_cli_wizard_flow_can_skip_gateway_section_and_keep_existing_gateway_values(self):
        initial = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_EGRESS_SNAT": "off",
                "RP_FILTER_MODE": "system",
                "CONNTRACK_MODE": "system",
            }
        )
        answers = iter(["", "", "", "", "", "", "", "", "", "", ""])
        outcome = run_config_wizard_flow(
            FakeAdapter(),
            initial=initial,
            show_summary=False,
            surface="cli",
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("off", outcome.config["ENABLE_EGRESS_SNAT"])
        self.assertEqual("system", outcome.config["RP_FILTER_MODE"])
        self.assertFalse(outcome.advanced_checked)

    def test_cli_wizard_label_mode_populates_dnat_label_via_shared_planner(self):
        initial = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_EGRESS_SNAT": "off",
            }
        )
        answers = iter(["", "", "", "", "", "", "2", "", "", "", "2"])
        outcome = run_config_wizard_flow(
            FakeAdapter(),
            initial=initial,
            show_summary=False,
            surface="cli",
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("label", outcome.config["AUTH_MODE"])
        self.assertEqual("56", outcome.config["DNAT_LABEL"])
        self.assertEqual("", outcome.config["DNAT_MARK"])

    def test_installer_manual_advanced_label_mode_populates_dnat_label(self):
        initial = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_HAIRPIN": "on",
                "ENABLE_EGRESS_SNAT": "off",
            }
        )
        answers = iter(["2", "2", "", "", "", "", "", ""])
        outcome = run_config_wizard_flow(
            FakeAdapter(),
            initial=initial,
            initial_stage="advanced",
            show_summary=False,
            input_func=lambda _prompt: next(answers),
        )
        self.assertEqual("label", outcome.config["AUTH_MODE"])
        self.assertEqual("56", outcome.config["DNAT_LABEL"])


if __name__ == "__main__":
    unittest.main()
