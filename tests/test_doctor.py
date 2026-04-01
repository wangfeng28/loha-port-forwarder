import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from loha.config import normalize_mapping, render_canonical_text
from loha.doctor import run_doctor, summarize_doctor_results
from loha.models import ConntrackStatusReport, Paths, RPFilterStatusReport
from loha.rules import parse_rules_text, render_rules_text
from loha.system import SystemAdapter


class FakeDoctorAdapter(SystemAdapter):
    def __init__(
        self,
        *,
        listeners=None,
        nft_permission_denied: bool = False,
        service_enabled: bool = True,
        service_active: bool = True,
        nft_error_detail: str = "",
    ):
        self.listeners = listeners if listeners is not None else set()
        self.nft_permission_denied = nft_permission_denied
        self.service_enabled = service_enabled
        self.service_active = service_active
        self.nft_error_detail = nft_error_detail

    def command_exists(self, name: str) -> bool:
        return name in {"python3", "ip", "nft", "systemctl"}

    def run(self, argv, *, input_text: str = "", check: bool = True):
        command = tuple(argv)
        if command == ("systemctl", "is-enabled", "loha"):
            return CompletedProcess(argv, 0 if self.service_enabled else 1, stdout="enabled\n" if self.service_enabled else "", stderr="")
        if command == ("systemctl", "is-active", "--quiet", "loha"):
            return CompletedProcess(argv, 0 if self.service_active else 3, stdout="", stderr="" if self.service_active else "inactive\n")
        if command == ("nft", "list", "table", "ip", "loha_port_forwarder"):
            if self.nft_permission_denied:
                return CompletedProcess(argv, 1, stdout="", stderr="Operation not permitted")
            if self.nft_error_detail:
                return CompletedProcess(argv, 1, stdout="", stderr=self.nft_error_detail)
            return CompletedProcess(
                argv,
                0,
                stdout="table ip loha_port_forwarder {\n    map dnat_rules { }\n    ct mark set 0x10000000\n}\n",
                stderr="",
            )
        raise AssertionError(f"unexpected command: {command}")

    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return ("eth0", "eth1")

    def global_ipv4s(self, interface: str):
        return {"eth0": ("203.0.113.10",)}.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {"eth1": ("192.168.10.0/24",)}.get(interface, ())

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        raise AssertionError("nft_apply should not be used in doctor unit tests")

    def systemctl(self, action: str, unit: str = "") -> None:
        raise AssertionError("systemctl() should not be used in doctor unit tests")

    def scan_listeners(self):
        return self.listeners


class DoctorTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return Paths(
            etc_dir=temp_dir / "etc",
            run_dir=temp_dir / "run",
            prefix=temp_dir / "prefix",
            systemd_unit_dir=temp_dir / "systemd",
        )

    def _write_fixture(self, paths: Paths, *, listen_ips: str = "203.0.113.10", default_snat_ip: str = "203.0.113.10"):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": listen_ips,
                "DEFAULT_SNAT_IP": default_snat_ip,
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "AUTH_MODE": "mark",
                "RP_FILTER_MODE": "system",
                "CONNTRACK_MODE": "system",
            }
        )
        rules = parse_rules_text("PORT\ttcp\t8080\t192.168.10.20\t80\n")
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.systemd_unit_dir.mkdir(parents=True, exist_ok=True)
        paths.loha_conf.write_text(render_canonical_text(config), encoding="utf-8")
        paths.rules_conf.write_text(render_rules_text(rules), encoding="utf-8")
        paths.service_unit.write_text("[Unit]\nDescription=LOHA\n", encoding="utf-8")

    def _rpfilter_report(self):
        return RPFilterStatusReport(
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

    def _conntrack_report(self):
        return ConntrackStatusReport(
            configured_mode="system",
            expected_max=0,
            expected_buckets=0,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=False,
            modprobe_file_present=False,
            sysctl_matches_expected=False,
            modprobe_matches_expected=False,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="system",
        )

    def test_run_doctor_includes_layered_systemd_nft_and_listener_checks(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter()
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        summaries = [result.summary for result in results]
        self.assertIn("Systemd check: unit file loha.service exists", summaries)
        self.assertIn("nft runtime check: live loha_port_forwarder table is present", summaries)
        self.assertIn("Listener conflict check: no local listener conflicts detected", summaries)
        self.assertIn("Runtime binding check: external binding uses configured values", summaries)

    def test_run_doctor_reports_listener_conflicts(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter(listeners={("tcp", 8080)})
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        conflict = next(result for result in results if result.summary.startswith("Listener conflict check:"))
        self.assertEqual("warn", conflict.level)
        self.assertIn("tcp 8080", conflict.detail)

    def test_summarize_doctor_results_counts_fail_and_warn(self):
        summary = summarize_doctor_results(
            [
                type("Result", (), {"level": "pass"})(),
                type("Result", (), {"level": "warn"})(),
                type("Result", (), {"level": "fail"})(),
            ]
        )
        self.assertEqual("Doctor summary: 1 fail, 1 warn", summary)

    def test_run_doctor_adds_root_hint_when_live_nft_inspection_needs_privilege(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter(nft_permission_denied=True)
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        nft_result = next(result for result in results if result.summary_key == "doctor.nft.inspect_permission_denied")
        self.assertEqual("warn", nft_result.level)
        self.assertIn("Operation not permitted", nft_result.detail)
        self.assertIn("Re-run `loha doctor` as root", nft_result.hint)

    def test_run_doctor_treats_absent_table_as_coherent_when_service_is_inactive(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter(service_enabled=False, service_active=False, nft_error_detail="No such file or directory")
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        nft_result = next(result for result in results if result.summary_key.startswith("doctor.nft."))
        self.assertEqual("pass", nft_result.level)
        self.assertEqual("doctor.nft.table_absent_service_inactive", nft_result.summary_key)
        self.assertIn("service is not active", nft_result.summary)

    def test_run_doctor_treats_absent_table_as_coherent_when_service_unit_is_missing(self):
        paths = self._paths()
        self._write_fixture(paths)
        paths.service_unit.unlink()
        adapter = FakeDoctorAdapter(service_enabled=False, service_active=False, nft_error_detail="No such file or directory")
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        systemd_result = next(result for result in results if result.summary_key == "doctor.systemd.missing_unit_file")
        nft_result = next(result for result in results if result.summary_key.startswith("doctor.nft."))
        self.assertEqual("fail", systemd_result.level)
        self.assertEqual("pass", nft_result.level)
        self.assertEqual("doctor.nft.table_absent_service_missing", nft_result.summary_key)

    def test_run_doctor_fails_when_service_is_active_but_live_table_is_missing(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter(nft_error_detail="No such file or directory")
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        nft_result = next(result for result in results if result.summary_key == "doctor.nft.table_missing_while_active")
        self.assertEqual("fail", nft_result.level)
        self.assertIn("No such file or directory", nft_result.detail)
        self.assertIn("loha reload", nft_result.hint)

    def test_run_doctor_does_not_treat_missing_table_as_service_missing_without_systemctl(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter(service_enabled=False, service_active=False, nft_error_detail="No such file or directory")
        with patch.object(adapter, "command_exists", side_effect=lambda name: name in {"python3", "ip", "nft"}), patch(
            "loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()
        ), patch("loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()):
            results = run_doctor(paths=paths, adapter=adapter)

        systemd_result = next(result for result in results if result.summary_key == "doctor.systemd.missing_systemctl")
        nft_result = next(result for result in results if result.summary_key.startswith("doctor.nft."))
        self.assertEqual("fail", systemd_result.level)
        self.assertEqual("warn", nft_result.level)
        self.assertEqual("doctor.nft.table_absent_unknown", nft_result.summary_key)

    def test_run_doctor_fails_when_listener_binding_is_outside_primary_interface(self):
        paths = self._paths()
        self._write_fixture(paths, listen_ips="198.51.100.20", default_snat_ip="198.51.100.20")
        adapter = FakeDoctorAdapter()
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        listener_result = next(result for result in results if result.summary_key == "doctor.runtime_binding.listener_outside_primary")
        self.assertEqual("fail", listener_result.level)
        self.assertIn("outside the primary external interface (eth0)", listener_result.summary)

    def test_run_doctor_accepts_system_mode_rpfilter_defaults_without_warning(self):
        paths = self._paths()
        self._write_fixture(paths)
        adapter = FakeDoctorAdapter()
        with patch("loha.doctor.collect_rp_filter_status", return_value=self._rpfilter_report()), patch(
            "loha.doctor.collect_conntrack_status", return_value=self._conntrack_report()
        ):
            results = run_doctor(paths=paths, adapter=adapter)

        rpfilter_results = [result for result in results if result.summary_key.startswith("doctor.rpfilter.")]
        runtime_sysctl_results = [result for result in results if result.summary_key.startswith("doctor.runtime_sysctl.")]
        self.assertTrue(all(result.level == "pass" for result in rpfilter_results))
        self.assertEqual(
            {
                "doctor.runtime_sysctl.ip_forward_ok",
                "doctor.runtime_sysctl.rp_all_ok",
                "doctor.runtime_sysctl.rp_default_ok",
            },
            {result.summary_key for result in runtime_sysctl_results},
        )
        self.assertTrue(all(result.level == "pass" for result in runtime_sysctl_results))



if __name__ == "__main__":
    unittest.main()
