import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from loha.config import recommended_config, render_canonical_text
from loha.doctor import run_doctor, summarize_doctor_results
from loha.history import write_transaction
from loha.i18n import build_runtime_i18n
from loha.install import (
    _activate_install_service,
    _apply_install_system_features,
    _deploy_install_files,
    _probe_install_initial_state,
    _remove_installation_payload,
    _remove_uninstall_data,
    _sync_uninstall_runtime,
    detect_upstream_firewall_target,
)
from loha.loader import LoaderService
from loha.rules import render_rules_text
from loha.system import SystemAdapter


@dataclass(frozen=True)
class SmokePaths:
    root: Path

    @property
    def etc_dir(self) -> Path:
        return self.root / "etc" / "loha"

    @property
    def prefix(self) -> Path:
        return self.root / "prefix"

    @property
    def run_dir(self) -> Path:
        return self.root / "run" / "loha"

    @property
    def systemd_unit_dir(self) -> Path:
        return self.root / "systemd"

    @property
    def loha_conf(self) -> Path:
        return self.etc_dir / "loha.conf"

    @property
    def rules_conf(self) -> Path:
        return self.etc_dir / "rules.conf"

    @property
    def history_dir(self) -> Path:
        return self.etc_dir / "history"

    @property
    def forwarding_sysctl(self) -> Path:
        return self.root / "sysctl.d" / "90-loha-forwarding.conf"

    @property
    def conntrack_sysctl(self) -> Path:
        return self.root / "sysctl.d" / "90-loha-conntrack.conf"

    @property
    def conntrack_modprobe(self) -> Path:
        return self.root / "modprobe.d" / "loha-conntrack.conf"

    @property
    def service_unit(self) -> Path:
        return self.systemd_unit_dir / "loha.service"

    @property
    def loader_wrapper(self) -> Path:
        return self.prefix / "libexec" / "loha" / "loader.sh"

    @property
    def cli_wrapper(self) -> Path:
        return self.prefix / "bin" / "loha"

    @property
    def package_root(self) -> Path:
        return self.prefix / "lib" / "loha-port-forwarder"

    @property
    def share_dir(self) -> Path:
        return self.prefix / "share" / "loha"

    @property
    def locale_dir(self) -> Path:
        return self.share_dir / "locales"

    @property
    def control_state_file(self) -> Path:
        return self.run_dir / "control_plane.state"

    @property
    def debug_ruleset_file(self) -> Path:
        return self.run_dir / "loha_debug.nft"


class FakeSmokeAdapter(SystemAdapter):
    def __init__(self):
        self.run_calls = []
        self.systemctl_calls = []
        self.enabled_units = {"firewalld.service"}
        self.active_units = {"firewalld.service"}
        self.live_ruleset = ""

    def command_exists(self, name: str) -> bool:
        return name in {"python3", "ip", "nft", "sysctl", "systemctl", "ss"}

    def run(self, argv, *, input_text: str = "", check: bool = True):
        command = tuple(argv)
        self.run_calls.append(command)
        if command[:4] == ("systemctl", "show", "--property=LoadState", "--value"):
            unit = command[-1]
            state = "loaded\n" if unit in {"firewalld.service", "loha.service"} else "not-found\n"
            return subprocess.CompletedProcess(argv, 0, stdout=state, stderr="")
        if command == ("systemctl", "list-unit-files"):
            return subprocess.CompletedProcess(argv, 0, stdout="loha.service enabled\n", stderr="")
        if len(command) >= 2 and command[0] == "systemctl" and command[1] in {"is-active", "is-enabled"}:
            unit = command[-1]
            stem = unit[:-8] if unit.endswith(".service") else unit
            name = f"{stem}.service"
            state_set = self.active_units if command[1] == "is-active" else self.enabled_units
            return subprocess.CompletedProcess(argv, 0 if name in state_set else 3, stdout="", stderr="")
        if command == ("systemctl", "stop", "loha.service"):
            self.active_units.discard("loha.service")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if command == ("systemctl", "disable", "loha.service"):
            self.enabled_units.discard("loha.service")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if command == ("systemctl", "daemon-reload"):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if command == ("nft", "--version"):
            return subprocess.CompletedProcess(argv, 0, stdout="nftables v1.0.8", stderr="")
        if command == ("nft", "-c", "-f", "-"):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if command == ("nft", "list", "table", "ip", "loha_port_forwarder"):
            if self.live_ruleset:
                return subprocess.CompletedProcess(argv, 0, stdout=self.live_ruleset, stderr="")
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="No such file or directory")
        if command == ("nft", "destroy", "table", "ip", "loha_port_forwarder"):
            self.live_ruleset = ""
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if command == ("sysctl", "--system"):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected command in smoke adapter: {argv!r}")

    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return ("lo", "eth0", "eth1")

    def global_ipv4s(self, interface: str):
        return {"eth0": ("203.0.113.10",)}.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {"eth1": ("192.168.10.0/24",)}.get(interface, ())

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        if not check_only:
            self.live_ruleset = ruleset

    def systemctl(self, action: str, unit: str = "") -> None:
        unit_name = unit if unit.endswith(".service") else f"{unit}.service"
        self.systemctl_calls.append((action, unit_name))
        if action == "enable":
            self.enabled_units.add(unit_name)
            return
        if action == "restart":
            self.active_units.add(unit_name)
            return
        if action == "daemon-reload":
            return
        raise AssertionError(f"unexpected systemctl action in smoke adapter: {action} {unit}")

    def scan_listeners(self):
        return set()

    def read_text(self, path: Path) -> str:
        proc_map = {
            "/proc/sys/net/ipv4/ip_forward": "1\n",
            "/proc/sys/net/ipv4/conf/default/rp_filter": "0\n",
            "/proc/sys/net/ipv4/conf/all/rp_filter": "0\n",
            "/proc/sys/net/ipv4/conf/eth0/rp_filter": "0\n",
            "/proc/sys/net/ipv4/conf/eth1/rp_filter": "0\n",
            "/proc/sys/net/netfilter/nf_conntrack_max": "262144\n",
            "/proc/sys/net/netfilter/nf_conntrack_buckets": "2048\n",
        }
        mapped = proc_map.get(str(path))
        if mapped is not None:
            return mapped
        return super().read_text(path)


class SmokeFlowTests(unittest.TestCase):
    def test_repo_local_offline_smoke_flow(self):
        root = Path(tempfile.mkdtemp())
        paths = SmokePaths(root)
        adapter = FakeSmokeAdapter()
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales")

        config = _probe_install_initial_state(recommended_config(), adapter)
        config = config.as_dict()
        config["LOCALE"] = "en_US"

        upstream_target = detect_upstream_firewall_target(adapter, pve_nodes_dir=root / "pve-nodes")
        self.assertEqual("firewalld.service", upstream_target)

        deploy_result = _deploy_install_files(
            paths,
            repo_root=Path(__file__).resolve().parents[1],
            upstream_target=upstream_target,
            dry_run=False,
            i18n=runtime,
        )
        self.assertTrue(deploy_result.ok)

        from loha.config import normalize_mapping

        canonical = normalize_mapping(config)
        system_feature_result = _apply_install_system_features(paths, canonical, adapter, dry_run=False, i18n=runtime)
        self.assertTrue(system_feature_result.ok)
        write_transaction(
            paths,
            config_text=render_canonical_text(canonical),
            rules_text=render_rules_text(type("Rules", (), {"aliases": (), "ports": ()})()),
            source="installer",
            reason="install",
        )
        activation_result = _activate_install_service(paths, adapter, dry_run=False, i18n=runtime)
        self.assertTrue(activation_result.ok)

        loader = LoaderService(paths=paths, adapter=adapter)
        message = loader.apply_result(mode="full").render()
        self.assertIn("Full ruleset initialized successfully", message)
        self.assertTrue(paths.control_state_file.exists())
        self.assertTrue(paths.debug_ruleset_file.exists())

        doctor_results = run_doctor(paths=paths, adapter=adapter)
        self.assertFalse(any(result.level == "fail" for result in doctor_results))
        self.assertIn("Doctor summary", summarize_doctor_results(doctor_results))

        _sync_uninstall_runtime(paths, adapter, dry_run=False, i18n=runtime)
        payload_result = _remove_installation_payload(paths, dry_run=False, i18n=runtime)
        self.assertTrue(payload_result.ok)
        data_result = _remove_uninstall_data(
            paths,
            remove_config_data=True,
            remove_system_tuning=True,
            dry_run=False,
            i18n=runtime,
        )
        self.assertTrue(data_result.ok)

        self.assertFalse(paths.etc_dir.exists())
        self.assertFalse(paths.cli_wrapper.exists())
        self.assertFalse(paths.loader_wrapper.exists())
        self.assertFalse(paths.package_root.exists())
        self.assertFalse(paths.share_dir.exists())
        self.assertFalse(paths.service_unit.exists())
        self.assertFalse(paths.run_dir.exists())
        self.assertFalse(paths.forwarding_sysctl.exists())
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())
        self.assertFalse(adapter.live_ruleset)
        self.assertNotIn("loha.service", adapter.enabled_units)
        self.assertNotIn("loha.service", adapter.active_units)


if __name__ == "__main__":
    unittest.main()
