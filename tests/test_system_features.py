import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from loha.config import normalize_mapping
from loha.models import RPFilterStatusReport
from loha.system_features import (
    apply_conntrack_files,
    apply_rp_filter_files,
    collect_conntrack_status,
    collect_rp_filter_status,
    conntrack_doctor_results,
    format_conntrack_status_lines,
    format_rp_filter_status_lines,
    rp_filter_doctor_results,
    rp_filter_runtime_sysctl_results,
)


class SystemFeatureFileTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return SimpleNamespace(
            forwarding_sysctl=temp_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=temp_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=temp_dir / "loha-conntrack.conf",
        )

    def _runtime_paths(self, base: Path):
        conf_base = base / "ipv4" / "conf"
        return {
            "ip_forward": base / "ipv4" / "ip_forward",
            "conf_base": conf_base,
            "default": conf_base / "default" / "rp_filter",
            "all": conf_base / "all" / "rp_filter",
            "max": base / "netfilter" / "nf_conntrack_max",
            "buckets": base / "netfilter" / "nf_conntrack_buckets",
        }

    def _adapter(self):
        return SimpleNamespace(read_text=lambda path: path.read_text(encoding="utf-8"))

    def test_rp_filter_files_render_from_shared_config(self):
        paths = self._paths()
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "RP_FILTER_MODE": "loose_scoped",
            }
        )
        apply_rp_filter_files(
            paths,
            config,
            write_text=lambda path, text: path.write_text(text, encoding="utf-8"),
        )
        content = paths.forwarding_sysctl.read_text(encoding="utf-8")
        self.assertIn("net.ipv4.ip_forward = 1", content)
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", content)
        self.assertIn("net.ipv4.conf.eth1.rp_filter = 2", content)

    def test_conntrack_files_are_removed_in_system_mode(self):
        paths = self._paths()
        paths.conntrack_sysctl.write_text("stale\n", encoding="utf-8")
        paths.conntrack_modprobe.write_text("stale\n", encoding="utf-8")
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "CONNTRACK_MODE": "system",
            }
        )
        apply_conntrack_files(
            paths,
            config,
            write_text=lambda path, text: path.write_text(text, encoding="utf-8"),
            remove_path=lambda path: path.unlink() if path.exists() else None,
        )
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())

    def test_rp_filter_status_report_tracks_matching_runtime(self):
        paths = self._paths()
        runtime_root = Path(tempfile.mkdtemp())
        runtime_paths = self._runtime_paths(runtime_root)
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "RP_FILTER_MODE": "loose_scoped",
            }
        )
        apply_rp_filter_files(
            paths,
            config,
            write_text=lambda path, text: path.write_text(text, encoding="utf-8"),
        )
        runtime_paths["ip_forward"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["ip_forward"].write_text("1\n", encoding="utf-8")
        for iface in ("eth0", "eth1"):
            iface_path = runtime_paths["conf_base"] / iface / "rp_filter"
            iface_path.parent.mkdir(parents=True, exist_ok=True)
            iface_path.write_text("2\n", encoding="utf-8")

        report = collect_rp_filter_status(paths, config, self._adapter(), runtime_paths=runtime_paths)

        self.assertTrue(report.file_matches_expected)
        self.assertEqual("match", report.runtime_state)
        self.assertEqual("loose_scoped", report.runtime_mode)
        rendered = "\n".join(format_rp_filter_status_lines(report))
        self.assertIn("Current scope:", rendered)
        self.assertIn("Effective hint:", rendered)
        self.assertIn("Runtime: matches the configured rp_filter mode", rendered)
        self.assertTrue(any(result.level == "pass" for result in rp_filter_doctor_results(report)))

    def test_rp_filter_system_mode_accepts_system_owned_runtime_state(self):
        paths = self._paths()
        runtime_root = Path(tempfile.mkdtemp())
        runtime_paths = self._runtime_paths(runtime_root)
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "RP_FILTER_MODE": "system",
            }
        )
        apply_rp_filter_files(
            paths,
            config,
            write_text=lambda path, text: path.write_text(text, encoding="utf-8"),
        )
        runtime_paths["ip_forward"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["ip_forward"].write_text("1\n", encoding="utf-8")
        runtime_paths["default"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["default"].write_text("1\n", encoding="utf-8")
        runtime_paths["all"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["all"].write_text("1\n", encoding="utf-8")
        for iface in ("eth0", "eth1"):
            iface_path = runtime_paths["conf_base"] / iface / "rp_filter"
            iface_path.parent.mkdir(parents=True, exist_ok=True)
            iface_path.write_text("1\n", encoding="utf-8")

        report = collect_rp_filter_status(paths, config, self._adapter(), runtime_paths=runtime_paths)

        self.assertEqual("runtime_only", report.file_mode)
        self.assertEqual("strict", report.runtime_mode)
        self.assertEqual("system", report.runtime_state)
        doctor_results = rp_filter_doctor_results(report)
        self.assertEqual(
            ["doctor.rpfilter.config.system_coherent", "doctor.rpfilter.runtime.coherent"],
            [result.summary_key for result in doctor_results],
        )

    def test_rp_filter_runtime_sysctl_results_accept_disabled_defaults(self):
        report = RPFilterStatusReport(
            configured_mode="system",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="net.ipv4.ip_forward = 1\n",
            file_present=True,
            file_matches_expected=True,
            file_mode="runtime_only",
            runtime_ip_forward="1",
            runtime_default_value="0",
            runtime_all_value="0",
            runtime_iface_values={"eth0": "0", "eth1": "0"},
            runtime_mode="custom",
            runtime_state="system",
        )
        results = rp_filter_runtime_sysctl_results(report)
        self.assertEqual(
            [
                "doctor.runtime_sysctl.ip_forward_ok",
                "doctor.runtime_sysctl.rp_all_ok",
                "doctor.runtime_sysctl.rp_default_ok",
            ],
            [result.summary_key for result in results],
        )
        self.assertTrue(all(result.level == "pass" for result in results))

    def test_conntrack_status_report_tracks_matching_runtime(self):
        paths = self._paths()
        runtime_root = Path(tempfile.mkdtemp())
        runtime_paths = self._runtime_paths(runtime_root)
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "CONNTRACK_MODE": "standard",
            }
        )
        apply_conntrack_files(
            paths,
            config,
            write_text=lambda path, text: path.write_text(text, encoding="utf-8"),
            remove_path=lambda path: path.unlink() if path.exists() else None,
        )
        runtime_paths["max"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["max"].write_text("262144\n", encoding="utf-8")
        runtime_paths["buckets"].write_text("2048\n", encoding="utf-8")

        report = collect_conntrack_status(paths, config, self._adapter(), runtime_paths=runtime_paths)

        self.assertEqual("match", report.runtime_state)
        self.assertTrue(report.sysctl_matches_expected)
        self.assertTrue(report.modprobe_matches_expected)
        rendered = "\n".join(format_conntrack_status_lines(report))
        self.assertIn("Configured target: nf_conntrack_max=262144, nf_conntrack_buckets=2048", rendered)
        self.assertIn("Current runtime: nf_conntrack_max=262144, nf_conntrack_buckets=2048", rendered)
        self.assertIn("Runtime: matches runtime nf_conntrack_max=262144 for mode standard", rendered)
        self.assertTrue(any(result.level == "pass" for result in conntrack_doctor_results(report)))


if __name__ == "__main__":
    unittest.main()
