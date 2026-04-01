import subprocess
import unittest
from pathlib import Path

from loha.constants import LOHA_CT_LABEL_PROBE_TABLE_NAME
from loha.precheck import count_level, has_failures, run_install_prechecks
from loha.system import SystemAdapter


class FakeAdapter(SystemAdapter):
    def __init__(self, *, commands=None, nft_version="nftables v1.0.8 (Old Doc Yak #5)", ct_label_ok=True):
        self.commands = set(commands or {"python3", "ip", "nft", "sysctl", "systemctl"})
        self.nft_version = nft_version
        self.ct_label_ok = ct_label_ok

    def command_exists(self, name: str) -> bool:
        return name in self.commands

    def run(self, argv, *, input_text: str = "", check: bool = True):
        command = tuple(argv)
        if command == ("nft", "--version"):
            return subprocess.CompletedProcess(argv, 0, stdout=self.nft_version, stderr="")
        if command == ("systemctl", "list-unit-files"):
            return subprocess.CompletedProcess(argv, 0, stdout="loha.service enabled\n", stderr="")
        if command == ("nft", "-c", "-f", "-"):
            self.last_ct_label_probe = input_text
            return subprocess.CompletedProcess(argv, 0 if self.ct_label_ok else 1, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {argv!r}")

    def default_ipv4_ifaces(self):
        raise AssertionError("not used")

    def list_interfaces(self):
        raise AssertionError("not used")

    def global_ipv4s(self, interface: str):
        raise AssertionError("not used")

    def ipv4_networks(self, interface: str):
        raise AssertionError("not used")

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        raise AssertionError("not used")

    def systemctl(self, action: str, unit: str = "") -> None:
        raise AssertionError("not used")

    def scan_listeners(self):
        raise AssertionError("not used")


class PrecheckTests(unittest.TestCase):
    def setUp(self):
        self.repo_root = Path(__file__).resolve().parents[1]

    def test_prechecks_pass_and_include_dry_run_notice(self):
        adapter = FakeAdapter()
        results = run_install_prechecks(
            adapter,
            repo_root=self.repo_root,
            is_root=True,
            kernel_release="6.6.12",
            dry_run=True,
        )
        self.assertFalse(has_failures(results))
        self.assertEqual(0, count_level(results, "warn"))
        self.assertIn("install.precheck.ct_label_ok", [result.message_key for result in results])
        self.assertIn("install.precheck.dry_run", [result.message_key for result in results])
        self.assertIn(f"table inet {LOHA_CT_LABEL_PROBE_TABLE_NAME}", adapter.last_ct_label_probe)

    def test_prechecks_warn_when_ct_label_probe_fails(self):
        adapter = FakeAdapter(ct_label_ok=False)
        results = run_install_prechecks(
            adapter,
            repo_root=self.repo_root,
            is_root=True,
            kernel_release="6.6.12",
        )
        self.assertFalse(has_failures(results))
        self.assertEqual(1, count_level(results, "warn"))
        self.assertIn("install.precheck.ct_label_warn", [result.message_key for result in results])
        self.assertIn(f"table inet {LOHA_CT_LABEL_PROBE_TABLE_NAME}", adapter.last_ct_label_probe)

    def test_prechecks_fail_when_root_or_kernel_contract_is_missing(self):
        results = run_install_prechecks(
            FakeAdapter(),
            repo_root=self.repo_root,
            is_root=False,
            kernel_release="4.19.0",
        )
        self.assertTrue(has_failures(results))
        self.assertGreaterEqual(count_level(results, "fail"), 2)
        self.assertIn("install.precheck.root_fail", [result.message_key for result in results])
        self.assertIn("install.precheck.kernel_low", [result.message_key for result in results])


if __name__ == "__main__":
    unittest.main()
