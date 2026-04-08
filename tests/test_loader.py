import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from loha.config import render_canonical_text
from loha.exceptions import ApplyError
from loha.loader import LoaderService, main
from loha.models import Paths
from loha.rules import parse_rules_text, render_rules_text
from loha.system import SystemAdapter
from loha.config import normalize_mapping


class FakeAdapter(SystemAdapter):
    def __init__(self, *, destroy_supported=False):
        self.applied = []
        self.ifaces = ("eth0", "eth1", "br0")
        self.iface_ips = {
            "eth0": ("203.0.113.10", "203.0.113.11"),
            "eth1": ("198.51.100.20",),
        }
        self.destroy_supported = destroy_supported
        self.tables = set()

    def command_exists(self, name: str) -> bool:
        return True

    def run(self, argv, *, input_text: str = "", check: bool = True):
        raise AssertionError("run should not be used in loader unit tests")

    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return self.ifaces

    def global_ipv4s(self, interface: str):
        return self.iface_ips.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {"br0": ("192.168.10.0/24",)}.get(interface, ())

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        self.applied.append(("check" if check_only else "apply", ruleset))
        if not check_only and "table ip loha_port_forwarder {" in ruleset:
            self.tables.add(("ip", "loha_port_forwarder"))

    def nft_supports_destroy(self, *, family: str = "ip", table: str = "__loha_destroy_probe__") -> bool:
        return self.destroy_supported

    def nft_table_exists(self, family: str, table: str) -> bool:
        return (family, table) in self.tables

    def systemctl(self, action: str, unit: str = "") -> None:
        raise AssertionError("systemctl should not be used in loader unit tests")

    def scan_listeners(self):
        return set()


class LoaderTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return Paths(etc_dir=temp_dir / "etc", run_dir=temp_dir / "run")

    def _write_fixture(self, paths: Paths, *, auth_mode="mark", listen_port="8080", config_overrides=None):
        config_values = {
            "EXTERNAL_IFS": "eth0",
            "PRIMARY_EXTERNAL_IF": "eth0",
            "LISTEN_IPS": "203.0.113.10",
            "DEFAULT_SNAT_IP": "203.0.113.10",
            "LAN_IFS": "br0",
            "LAN_NETS": "192.168.10.0/24",
            "PROTECTION_MODE": "backends",
            "AUTH_MODE": auth_mode,
            "DNAT_MARK": "0x10000000",
            "DNAT_LABEL": "56",
        }
        if config_overrides:
            config_values.update(config_overrides)
        config = normalize_mapping(config_values)
        rules = parse_rules_text(f"ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t{listen_port}\tVM_WEB\t80\n")
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.loha_conf.write_text(render_canonical_text(config), encoding="utf-8")
        paths.rules_conf.write_text(render_rules_text(rules), encoding="utf-8")

    def test_reload_hot_swaps_when_control_state_matches(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths)
        service = LoaderService(paths=paths, adapter=adapter)
        first_message = service.apply(mode="full")
        self.assertIn("Full ruleset initialized successfully", first_message)
        self.assertNotIn("delete table ip loha_port_forwarder", adapter.applied[0][1])
        self.assertNotIn("destroy table ip loha_port_forwarder", adapter.applied[0][1])
        second_message = service.apply(mode="reload")
        self.assertIn("Mappings hot-swapped successfully", second_message)

    def test_full_apply_uses_destroy_when_supported(self):
        paths = self._paths()
        adapter = FakeAdapter(destroy_supported=True)
        self._write_fixture(paths)
        service = LoaderService(paths=paths, adapter=adapter)

        service.apply(mode="full")

        self.assertIn("destroy table ip loha_port_forwarder", adapter.applied[0][1])

    def test_second_full_apply_uses_delete_when_destroy_is_unavailable(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths)
        service = LoaderService(paths=paths, adapter=adapter)

        service.apply(mode="full")
        self._write_fixture(paths, config_overrides={"AUTH_MODE": "label", "DNAT_MARK": "", "DNAT_LABEL": "56"})
        service.apply(mode="full")

        self.assertIn("delete table ip loha_port_forwarder", adapter.applied[1][1])

    def test_auth_mode_change_forces_full(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths, auth_mode="mark")
        service = LoaderService(paths=paths, adapter=adapter)
        service.apply(mode="full")
        self._write_fixture(paths, auth_mode="label")
        message = service.apply(mode="reload")
        self.assertIn("Full ruleset initialized successfully", message)

    def test_reload_keeps_hot_swap_for_rule_only_changes(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths, listen_port="8080")
        service = LoaderService(paths=paths, adapter=adapter)
        service.apply(mode="full")
        self._write_fixture(paths, listen_port="8081")
        message = service.apply(mode="reload")
        self.assertIn("Mappings hot-swapped successfully", message)
        self.assertEqual(2, len(adapter.applied))
        self.assertNotIn("delete table ip loha_port_forwarder", adapter.applied[1][1])
        self.assertIn("8081", adapter.applied[1][1])

    def test_reload_refreshes_debug_ruleset_snapshot(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths, listen_port="8080")
        service = LoaderService(paths=paths, adapter=adapter)
        service.apply(mode="full")
        self.assertIn("8080", paths.debug_ruleset_file.read_text(encoding="utf-8"))

        self._write_fixture(paths, listen_port="8081")
        service.apply(mode="reload")

        self.assertIn("8081", paths.debug_ruleset_file.read_text(encoding="utf-8"))

    def test_reload_keeps_hot_swap_for_listener_set_only_changes(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths)
        service = LoaderService(paths=paths, adapter=adapter)
        service.apply(mode="full")
        self._write_fixture(
            paths,
            config_overrides={
                "LISTEN_IPS": "203.0.113.10,203.0.113.11",
                "DEFAULT_SNAT_IP": "203.0.113.10",
            },
        )
        message = service.apply(mode="reload")
        self.assertIn("Mappings hot-swapped successfully", message)
        self.assertEqual(2, len(adapter.applied))
        self.assertNotIn("delete table ip loha_port_forwarder", adapter.applied[1][1])
        self.assertIn("203.0.113.11", adapter.applied[1][1])

    def test_default_snat_change_forces_full_reload(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(
            paths,
            config_overrides={
                "LISTEN_IPS": "203.0.113.10,203.0.113.11",
                "DEFAULT_SNAT_IP": "203.0.113.10",
            },
        )
        service = LoaderService(paths=paths, adapter=adapter)
        service.apply(mode="full")
        self._write_fixture(
            paths,
            config_overrides={
                "LISTEN_IPS": "203.0.113.10,203.0.113.11",
                "DEFAULT_SNAT_IP": "203.0.113.11",
            },
        )
        message = service.apply(mode="reload")
        self.assertIn("Full ruleset initialized successfully", message)
        self.assertEqual(2, len(adapter.applied))
        self.assertIn("delete table ip loha_port_forwarder", adapter.applied[1][1])

    def test_external_binding_shift_forces_full_reload(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths)
        service = LoaderService(paths=paths, adapter=adapter)
        service.apply(mode="full")
        self._write_fixture(
            paths,
            config_overrides={
                "EXTERNAL_IFS": "eth1",
                "PRIMARY_EXTERNAL_IF": "eth1",
                "LISTEN_IPS": "198.51.100.20",
                "DEFAULT_SNAT_IP": "198.51.100.20",
            },
        )
        message = service.apply(mode="reload")
        self.assertIn("Full ruleset initialized successfully", message)
        self.assertEqual(2, len(adapter.applied))
        self.assertIn('define PRIMARY_EXTERNAL_IF = "eth1"', adapter.applied[1][1])
        self.assertIn("delete table ip loha_port_forwarder", adapter.applied[1][1])

    def test_runtime_binding_failure_blocks_nft_apply(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(
            paths,
            config_overrides={
                "LISTEN_IPS": "198.51.100.20",
                "DEFAULT_SNAT_IP": "198.51.100.20",
            },
        )
        service = LoaderService(paths=paths, adapter=adapter)

        with self.assertRaises(ApplyError):
            service.apply(mode="full")
        self.assertEqual([], adapter.applied)

    def test_check_only_full_apply_does_not_write_runtime_state_files(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths)
        service = LoaderService(paths=paths, adapter=adapter)

        message = service.apply(mode="full", check_only=True)

        self.assertIn("Full ruleset initialized successfully", message)
        self.assertEqual(1, len(adapter.applied))
        self.assertEqual("check", adapter.applied[0][0])
        self.assertFalse(paths.control_state_file.exists())
        self.assertFalse(paths.debug_ruleset_file.exists())

    def test_loader_main_uses_runtime_locale_from_config(self):
        paths = self._paths()
        adapter = FakeAdapter()
        self._write_fixture(paths, config_overrides={"LOCALE": "zh_CN"})
        out = io.StringIO()

        with patch("loha.loader.SubprocessSystemAdapter", return_value=adapter), redirect_stdout(out):
            exit_code = main(["full", "--etc-dir", str(paths.etc_dir), "--run-dir", str(paths.run_dir)])

        self.assertEqual(0, exit_code)
        self.assertIn("完整规则集已成功初始化", out.getvalue())


if __name__ == "__main__":
    unittest.main()
