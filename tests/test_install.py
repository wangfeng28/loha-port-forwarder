import io
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from loha.config import normalize_mapping, recommended_config, render_canonical_text
from loha.exceptions import ApplyError, ConfigSyntaxError
from loha.history import list_snapshots
from loha.i18n import build_runtime_i18n
from loha.install import (
    _build_install_i18n,
    _activate_install_service,
    _apply_install_system_features,
    _choose_install_initial_config,
    _confirm_install_execution,
    _deploy_install_files,
    _probe_install_initial_state,
    _remove_installation_payload,
    _remove_uninstall_data,
    _run_interactive_prechecks,
    _select_install_import_path,
    _service_unit,
    _sync_uninstall_runtime,
    cmd_install,
    cmd_uninstall,
    detect_upstream_firewall_target,
    main,
)
from loha.models import InstallStepResult, LocalizedMessage, PrecheckResult
from loha.system_features import collect_conntrack_status, collect_rp_filter_status


class RecordingAdapter:
    def __init__(self):
        self.run_calls = []
        self.systemctl_calls = []

    def command_exists(self, name: str) -> bool:
        return name in {"sysctl", "systemctl"}

    def run(self, argv, *, input_text: str = "", check: bool = True):
        self.run_calls.append(tuple(argv))
        if tuple(argv) == ("systemctl", "show", "--property=LoadState", "--value", "firewalld.service"):
            return subprocess.CompletedProcess(argv, 0, stdout="loaded\n", stderr="")
        if tuple(argv) in {
            ("systemctl", "is-active", "--quiet", "firewalld.service"),
            ("systemctl", "is-enabled", "--quiet", "firewalld.service"),
        }:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def systemctl(self, action: str, unit: str = "") -> None:
        self.systemctl_calls.append((action, unit))


class MissingSysctlAdapter(RecordingAdapter):
    def command_exists(self, name: str) -> bool:
        return name == "systemctl"


class FailingSystemctlAdapter(RecordingAdapter):
    def systemctl(self, action: str, unit: str = "") -> None:
        self.systemctl_calls.append((action, unit))
        if action == "restart":
            raise ApplyError("restart boom")


class ProbeAdapter(RecordingAdapter):
    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return ("lo", "eth0", "eth9", "eth1")

    def global_ipv4s(self, interface: str):
        return {"eth0": ("203.0.113.10",)}.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {"eth1": ("192.168.10.0/24",)}.get(interface, ())


class UninstallAdapter(RecordingAdapter):
    def command_exists(self, name: str) -> bool:
        return name in {"sysctl", "systemctl", "nft"}


class SysctlAdapter(RecordingAdapter):
    def command_exists(self, name: str) -> bool:
        return name == "sysctl"


class FlakySysctlAdapter(SysctlAdapter):
    def __init__(self):
        super().__init__()
        self.sysctl_calls = 0

    def run(self, argv, *, input_text: str = "", check: bool = True):
        self.run_calls.append(tuple(argv))
        if tuple(argv) == ("sysctl", "--system"):
            self.sysctl_calls += 1
            if self.sysctl_calls == 1:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


class RestartFailingInstallAdapter(RecordingAdapter):
    def __init__(self, *, service_enabled: bool, service_active: bool):
        super().__init__()
        self.service_enabled = service_enabled
        self.service_active = service_active
        self.restart_failures_remaining = 1

    def command_exists(self, name: str) -> bool:
        return name in {"sysctl", "systemctl"}

    def run(self, argv, *, input_text: str = "", check: bool = True):
        self.run_calls.append(tuple(argv))
        command = tuple(argv)
        if command == ("sysctl", "--system"):
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        if command == ("systemctl", "is-enabled", "loha.service"):
            return subprocess.CompletedProcess(argv, 0 if self.service_enabled else 1, stdout="", stderr="")
        if command == ("systemctl", "is-active", "--quiet", "loha.service"):
            return subprocess.CompletedProcess(argv, 0 if self.service_active else 3, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def systemctl(self, action: str, unit: str = "") -> None:
        self.systemctl_calls.append((action, unit))
        if action == "restart" and self.restart_failures_remaining:
            self.restart_failures_remaining -= 1
            raise ApplyError("restart boom")


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales")
        self.config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
            }
        )

    def test_install_confirmation_defaults_to_confirm(self):
        result = _confirm_install_execution(
            self.config,
            self.runtime,
            advanced_checked=False,
            input_func=lambda _prompt: "",
        )
        self.assertEqual("confirm", result)

    def test_install_confirmation_can_return_to_network_stage(self):
        result = _confirm_install_execution(
            self.config,
            self.runtime,
            advanced_checked=False,
            input_func=lambda _prompt: "2",
        )
        self.assertEqual("network", result)

    def test_install_confirmation_can_return_to_advanced_stage(self):
        result = _confirm_install_execution(
            self.config,
            self.runtime,
            advanced_checked=False,
            input_func=lambda _prompt: "5",
        )
        self.assertEqual("advanced", result)

    def test_select_install_import_path_can_choose_between_repo_and_system_configs(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_config = temp_dir / "repo.conf"
        system_config = temp_dir / "system.conf"
        repo_config.write_text('LOCALE="en_US"\n', encoding="utf-8")
        system_config.write_text('LOCALE="en_US"\n', encoding="utf-8")
        with patch("loha.install._candidate_config_paths", return_value=(repo_config, system_config)):
            selected = _select_install_import_path(
                SimpleNamespace(loha_conf=system_config),
                non_interactive=False,
                i18n=self.runtime,
                input_func=lambda _prompt: "2",
            )
        self.assertEqual(system_config, selected)

    def test_select_install_import_path_single_candidate_uses_numeric_default(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_config = temp_dir / "repo.conf"
        system_config = temp_dir / "system.conf"
        repo_config.write_text('LOCALE="en_US"\n', encoding="utf-8")
        with patch("loha.install._candidate_config_paths", return_value=(repo_config, system_config)):
            selected = _select_install_import_path(
                SimpleNamespace(loha_conf=system_config),
                non_interactive=False,
                i18n=self.runtime,
                input_func=lambda _prompt: "",
            )
        self.assertEqual(repo_config, selected)

    def test_select_install_import_path_single_candidate_can_skip_to_defaults(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_config = temp_dir / "repo.conf"
        system_config = temp_dir / "system.conf"
        repo_config.write_text('LOCALE="en_US"\n', encoding="utf-8")
        with patch("loha.install._candidate_config_paths", return_value=(repo_config, system_config)):
            selected = _select_install_import_path(
                SimpleNamespace(loha_conf=system_config),
                non_interactive=False,
                i18n=self.runtime,
                input_func=lambda _prompt: "0",
            )
        self.assertIsNone(selected)

    def test_select_install_import_path_retries_invalid_choice_before_accepting_selection(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_config = temp_dir / "repo.conf"
        system_config = temp_dir / "system.conf"
        repo_config.write_text('LOCALE="en_US"\n', encoding="utf-8")
        system_config.write_text('LOCALE="en_US"\n', encoding="utf-8")
        answers = iter(["9", "2"])
        out = io.StringIO()
        with patch("loha.install._candidate_config_paths", return_value=(repo_config, system_config)), redirect_stdout(out):
            selected = _select_install_import_path(
                SimpleNamespace(loha_conf=system_config),
                non_interactive=False,
                i18n=self.runtime,
                input_func=lambda _prompt: next(answers),
            )
        self.assertEqual(system_config, selected)
        self.assertIn("Invalid choice.", out.getvalue())

    def test_build_install_i18n_switches_runtime_to_selected_locale(self):
        runtime = _build_install_i18n(
            SimpleNamespace(
                loha_conf=Path(tempfile.mkdtemp()) / "loha.conf",
                locale_dir=Path(__file__).resolve().parents[1] / "locales",
            ),
            non_interactive=False,
            input_func=lambda _prompt="": "2",
        )
        self.assertEqual("zh_CN", runtime.locale)
        self.assertEqual("简体中文", runtime.locale_name())
        self.assertEqual("外部接口", runtime.t("wizard.steps.external_ifs.title", "External Interface"))
        self.assertEqual("安装总览", runtime.t("install.summary.title", "Install Summary"))

    def test_probe_install_initial_state_prefers_lan_iface_with_detected_networks(self):
        probed = _probe_install_initial_state(recommended_config(), ProbeAdapter())
        self.assertEqual("eth1", probed["LAN_IFS"])
        self.assertEqual("192.168.10.0/24", probed["LAN_NETS"])

    def test_choose_install_initial_config_can_skip_import_and_use_defaults(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_config = temp_dir / "repo.conf"
        system_config = temp_dir / "system.conf"
        repo_config.write_text('PRIMARY_EXTERNAL_IF="eth9"\n', encoding="utf-8")
        system_config.write_text('PRIMARY_EXTERNAL_IF="eth8"\n', encoding="utf-8")
        with patch("loha.install._candidate_config_paths", return_value=(repo_config, system_config)), patch(
            "loha.install._probe_install_initial_state",
            side_effect=lambda config, _adapter: config,
        ):
            result = _choose_install_initial_config(
                SimpleNamespace(loha_conf=system_config),
                non_interactive=False,
                adapter=RecordingAdapter(),
                i18n=self.runtime,
                input_func=lambda _prompt: "0",
            )
        self.assertNotEqual("eth9", result["PRIMARY_EXTERNAL_IF"])
        self.assertNotEqual("eth8", result["PRIMARY_EXTERNAL_IF"])
        self.assertEqual("en_US", result["LOCALE"])

    def test_choose_install_initial_config_rejects_legacy_syntax_import(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_config = temp_dir / "repo.conf"
        system_config = temp_dir / "system.conf"
        repo_config.write_text('PRIMARY_EXTERNAL_IF = "eth9"\n', encoding="utf-8")
        system_config.write_text('PRIMARY_EXTERNAL_IF="eth8"\n', encoding="utf-8")
        with patch("loha.install._candidate_config_paths", return_value=(repo_config, system_config)):
            with self.assertRaises(ConfigSyntaxError):
                _choose_install_initial_config(
                    SimpleNamespace(loha_conf=system_config),
                    non_interactive=False,
                    adapter=RecordingAdapter(),
                    i18n=self.runtime,
                    input_func=lambda _prompt: "1",
                )

    def test_install_prechecks_stop_install_on_failure(self):
        prompts = []

        def fake_input(prompt: str) -> str:
            prompts.append(prompt)
            return ""

        with patch(
            "loha.install.run_install_prechecks",
            return_value=[
                PrecheckResult(
                    level="fail",
                    message_key="install.precheck.root_fail",
                    default_message="Installer must run as root",
                )
            ],
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                result = _run_interactive_prechecks(
                    object(),
                    repo_root=Path(__file__).resolve().parents[1],
                    i18n=self.runtime,
                    non_interactive=False,
                    dry_run=False,
                    input_func=fake_input,
                )
        self.assertFalse(result)
        self.assertTrue(prompts)
        self.assertIn("Prechecks failed: 1", output.getvalue())

    def test_install_prechecks_localize_level_label(self):
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="zh_CN")
        output = io.StringIO()
        with patch(
            "loha.install.run_install_prechecks",
            return_value=[
                PrecheckResult(
                    level="warn",
                    message_key="install.precheck.ct_label_warn",
                    default_message="nftables ct label check failed; label mode may be unavailable",
                )
            ],
        ):
            with redirect_stdout(output):
                result = _run_interactive_prechecks(
                    object(),
                    repo_root=Path(__file__).resolve().parents[1],
                    i18n=runtime,
                    non_interactive=True,
                    dry_run=False,
                )
        self.assertTrue(result)
        self.assertIn("[警告]", output.getvalue())

    def test_install_activation_runs_service_commands_in_order(self):
        adapter = RecordingAdapter()
        paths = SimpleNamespace(service_unit=Path("/tmp/loha.service"))
        result = _activate_install_service(paths, adapter, dry_run=False)
        self.assertTrue(result.ok)
        self.assertEqual(
            [("daemon-reload", ""), ("enable", "loha.service"), ("restart", "loha.service")],
            adapter.systemctl_calls,
        )

    def test_install_activation_dry_run_is_localized(self):
        adapter = RecordingAdapter()
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="zh_CN")
        paths = SimpleNamespace(service_unit=Path("/tmp/loha.service"))
        output = io.StringIO()
        with redirect_stdout(output):
            result = _activate_install_service(paths, adapter, dry_run=True, i18n=runtime)
        self.assertTrue(result.ok)
        rendered = output.getvalue()
        self.assertIn("[dry-run] 执行 systemctl daemon-reload", rendered)
        self.assertIn("[dry-run] 执行 systemctl enable loha.service", rendered)
        self.assertIn("[dry-run] 执行 systemctl restart loha.service", rendered)

    def test_install_activation_reports_failed_step(self):
        adapter = FailingSystemctlAdapter()
        result = _activate_install_service(SimpleNamespace(service_unit=Path("/tmp/loha.service")), adapter, dry_run=False)
        self.assertFalse(result.ok)
        self.assertIn("systemctl restart loha.service", result.error.render())
        self.assertIn("restart boom", result.error.render())

    def test_deploy_install_files_creates_layout_and_wrappers(self):
        temp_dir = Path(tempfile.mkdtemp())
        paths = SimpleNamespace(
            etc_dir=temp_dir / "etc",
            history_dir=temp_dir / "etc" / "history",
            rules_conf=temp_dir / "etc" / "rules.conf",
            cli_wrapper=temp_dir / "prefix" / "bin" / "loha",
            loader_wrapper=temp_dir / "prefix" / "libexec" / "loha" / "loader.sh",
            package_root=temp_dir / "prefix" / "lib" / "loha-port-forwarder",
            share_dir=temp_dir / "prefix" / "share" / "loha",
            locale_dir=temp_dir / "prefix" / "share" / "loha" / "locales",
            systemd_unit_dir=temp_dir / "systemd",
            service_unit=temp_dir / "systemd" / "loha.service",
        )
        result = _deploy_install_files(
            paths,
            repo_root=Path(__file__).resolve().parents[1],
            upstream_target="firewalld.service",
            dry_run=False,
            i18n=self.runtime,
        )
        self.assertTrue(result.ok)
        self.assertTrue(paths.history_dir.is_dir())
        self.assertTrue(paths.rules_conf.exists())
        self.assertTrue((paths.package_root / "loha" / "cli.py").exists())
        self.assertTrue((paths.locale_dir / "en_US.toml").exists())
        self.assertIn("python3", paths.cli_wrapper.read_text(encoding="utf-8"))
        self.assertIn("ExecStart=", paths.service_unit.read_text(encoding="utf-8"))

    def test_install_system_feature_apply_writes_files_and_runs_sysctl(self):
        temp_dir = Path(tempfile.mkdtemp())
        paths = SimpleNamespace(
            forwarding_sysctl=temp_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=temp_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=temp_dir / "loha-conntrack.conf",
        )
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "RP_FILTER_MODE": "strict",
                "CONNTRACK_MODE": "custom",
                "CONNTRACK_TARGET_MAX": "131072",
                "CONNTRACK_MEMORY_PERCENT": "35",
            }
        )
        adapter = RecordingAdapter()
        result = _apply_install_system_features(paths, config, adapter, dry_run=False)
        self.assertTrue(result.ok)
        self.assertEqual([("sysctl", "--system")], adapter.run_calls)
        self.assertIn("net.ipv4.ip_forward = 1", paths.forwarding_sysctl.read_text(encoding="utf-8"))
        self.assertTrue(paths.conntrack_sysctl.exists())
        self.assertTrue(paths.conntrack_modprobe.exists())

    def test_install_system_feature_apply_dry_run_is_localized(self):
        temp_dir = Path(tempfile.mkdtemp())
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="zh_CN")
        paths = SimpleNamespace(
            forwarding_sysctl=temp_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=temp_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=temp_dir / "loha-conntrack.conf",
        )
        adapter = RecordingAdapter()
        output = io.StringIO()
        with redirect_stdout(output):
            result = _apply_install_system_features(paths, self.config, adapter, dry_run=True, i18n=runtime)
        self.assertTrue(result.ok)
        self.assertIn("[dry-run] 执行 sysctl --system", output.getvalue())
        self.assertFalse(adapter.run_calls)

    def test_install_system_feature_apply_reports_missing_sysctl(self):
        temp_dir = Path(tempfile.mkdtemp())
        paths = SimpleNamespace(
            forwarding_sysctl=temp_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=temp_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=temp_dir / "loha-conntrack.conf",
        )
        result = _apply_install_system_features(paths, self.config, MissingSysctlAdapter(), dry_run=False)
        self.assertFalse(result.ok)
        self.assertIn("`sysctl` is unavailable", result.error.render())

    def test_install_system_feature_apply_leaves_system_modes_coherent_for_status_reports(self):
        temp_dir = Path(tempfile.mkdtemp())
        runtime_root = temp_dir / "runtime"
        paths = SimpleNamespace(
            forwarding_sysctl=temp_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=temp_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=temp_dir / "loha-conntrack.conf",
        )
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
                "RP_FILTER_MODE": "system",
                "CONNTRACK_MODE": "system",
            }
        )
        adapter = RecordingAdapter()
        result = _apply_install_system_features(paths, config, adapter, dry_run=False)
        self.assertTrue(result.ok)
        self.assertEqual([("sysctl", "--system")], adapter.run_calls)
        self.assertEqual("net.ipv4.ip_forward = 1\n", paths.forwarding_sysctl.read_text(encoding="utf-8"))
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())

        runtime_paths = {
            "ip_forward": runtime_root / "ipv4" / "ip_forward",
            "conf_base": runtime_root / "ipv4" / "conf",
            "default": runtime_root / "ipv4" / "conf" / "default" / "rp_filter",
            "all": runtime_root / "ipv4" / "conf" / "all" / "rp_filter",
            "max": runtime_root / "netfilter" / "nf_conntrack_max",
            "buckets": runtime_root / "netfilter" / "nf_conntrack_buckets",
        }
        runtime_paths["ip_forward"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["ip_forward"].write_text("1\n", encoding="utf-8")
        runtime_paths["default"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["default"].write_text("0\n", encoding="utf-8")
        runtime_paths["all"].parent.mkdir(parents=True, exist_ok=True)
        runtime_paths["all"].write_text("0\n", encoding="utf-8")
        adapter = SimpleNamespace(read_text=lambda path: path.read_text(encoding="utf-8"))
        rpfilter_report = collect_rp_filter_status(paths, config, adapter, runtime_paths=runtime_paths)
        conntrack_report = collect_conntrack_status(paths, config, adapter, runtime_paths=runtime_paths)

        self.assertEqual("runtime_only", rpfilter_report.file_mode)
        self.assertEqual("system", rpfilter_report.runtime_state)
        self.assertEqual("system", conntrack_report.runtime_state)

    def test_remove_installation_payload_removes_runtime_files(self):
        temp_dir = Path(tempfile.mkdtemp())
        paths = SimpleNamespace(
            cli_wrapper=temp_dir / "prefix" / "bin" / "loha",
            loader_wrapper=temp_dir / "prefix" / "libexec" / "loha" / "loader.sh",
            package_root=temp_dir / "prefix" / "lib" / "loha-port-forwarder",
            share_dir=temp_dir / "prefix" / "share" / "loha",
            service_unit=temp_dir / "systemd" / "loha.service",
            run_dir=temp_dir / "run" / "loha",
        )
        paths.cli_wrapper.parent.mkdir(parents=True, exist_ok=True)
        paths.loader_wrapper.parent.mkdir(parents=True, exist_ok=True)
        paths.package_root.mkdir(parents=True, exist_ok=True)
        paths.share_dir.mkdir(parents=True, exist_ok=True)
        paths.service_unit.parent.mkdir(parents=True, exist_ok=True)
        paths.run_dir.mkdir(parents=True, exist_ok=True)
        paths.cli_wrapper.write_text("cli", encoding="utf-8")
        paths.loader_wrapper.write_text("loader", encoding="utf-8")
        (paths.package_root / "loha").mkdir(parents=True, exist_ok=True)
        (paths.share_dir / "locales").mkdir(parents=True, exist_ok=True)
        paths.service_unit.write_text("unit", encoding="utf-8")
        result = _remove_installation_payload(paths, dry_run=False, i18n=self.runtime)
        self.assertTrue(result.ok)
        self.assertFalse(paths.cli_wrapper.exists())
        self.assertFalse(paths.loader_wrapper.exists())
        self.assertFalse(paths.package_root.exists())
        self.assertFalse(paths.share_dir.exists())
        self.assertFalse(paths.service_unit.exists())
        self.assertFalse(paths.run_dir.exists())

    def test_remove_uninstall_data_can_remove_config_and_sysctl_files(self):
        temp_dir = Path(tempfile.mkdtemp())
        paths = SimpleNamespace(
            etc_dir=temp_dir / "etc",
            forwarding_sysctl=temp_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=temp_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=temp_dir / "loha-conntrack.conf",
        )
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        (paths.etc_dir / "loha.conf").write_text("conf", encoding="utf-8")
        paths.forwarding_sysctl.write_text("nat", encoding="utf-8")
        paths.conntrack_sysctl.write_text("ct", encoding="utf-8")
        paths.conntrack_modprobe.write_text("modprobe", encoding="utf-8")
        result = _remove_uninstall_data(
            paths,
            remove_config_data=True,
            remove_system_tuning=True,
            dry_run=False,
            i18n=self.runtime,
        )
        self.assertTrue(result.ok)
        self.assertFalse(paths.etc_dir.exists())
        self.assertFalse(paths.forwarding_sysctl.exists())
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())

    def test_sync_uninstall_runtime_runs_best_effort_cleanup_sequence(self):
        adapter = UninstallAdapter()
        paths = SimpleNamespace(service_unit=Path("/tmp/loha.service"))
        _sync_uninstall_runtime(paths, adapter, dry_run=False, i18n=self.runtime)
        self.assertEqual(
            [
                ("systemctl", "stop", "loha.service"),
                ("systemctl", "disable", "loha.service"),
                ("nft", "destroy", "table", "ip", "loha_port_forwarder"),
                ("sysctl", "--system"),
                ("systemctl", "daemon-reload"),
            ],
            adapter.run_calls,
        )

    def test_detect_upstream_firewall_target_prefers_active_firewall_service(self):
        adapter = RecordingAdapter()
        target = detect_upstream_firewall_target(adapter, pve_nodes_dir=Path("/nonexistent-pve"))
        self.assertEqual("firewalld.service", target)

    def test_service_unit_includes_upstream_after_line_and_runtime_settings(self):
        paths = SimpleNamespace(loader_wrapper=Path("/usr/local/libexec/loha/loader.sh"))
        rendered = _service_unit(paths, upstream_target="firewalld.service")
        self.assertIn("After=network.target", rendered)
        self.assertIn("After=firewalld.service", rendered)
        self.assertIn("RuntimeDirectory=loha", rendered)
        self.assertIn("ExecStartPre=/bin/sleep 0.2", rendered)
        self.assertIn("Restart=on-failure", rendered)

    def test_uninstall_prompt_uses_runtime_locale(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "LOCALE": "zh_CN",
            }
        )
        (etc_dir / "loha.conf").write_text(render_canonical_text(config), encoding="utf-8")
        output = io.StringIO()
        prompts = []

        def fake_input(prompt: str) -> str:
            prompts.append(prompt)
            return "n"

        with patch("builtins.input", side_effect=fake_input), patch(
            "loha.install._remove_installation_payload",
            return_value=InstallStepResult(ok=True),
        ), patch(
            "loha.install._remove_uninstall_data",
            return_value=InstallStepResult(ok=True),
        ), patch(
            "loha.install._sync_uninstall_runtime",
        ), redirect_stdout(output):
            exit_code = cmd_uninstall(
                SimpleNamespace(
                    etc_dir=str(etc_dir),
                    prefix=str(temp_dir / "prefix"),
                    run_dir=str(temp_dir / "run"),
                    systemd_dir=str(temp_dir / "systemd"),
                    uninstall=True,
                    yes=False,
                )
            )
        self.assertEqual(1, exit_code)
        self.assertEqual("是否删除已安装的 LOHA 文件？[y/N]: ", prompts[0])
        self.assertIn("已取消。", output.getvalue())

    def test_uninstall_yes_removes_all_and_prints_completion(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        (etc_dir / "loha.conf").write_text('LOCALE="en_US"\n', encoding="utf-8")
        output = io.StringIO()
        with patch(
            "loha.install._remove_installation_payload",
            return_value=InstallStepResult(ok=True),
        ) as payload_mock, patch(
            "loha.install._remove_uninstall_data",
            return_value=InstallStepResult(ok=True),
        ) as data_mock, patch(
            "loha.install._sync_uninstall_runtime",
        ) as sync_mock, redirect_stdout(output):
            exit_code = cmd_uninstall(
                SimpleNamespace(
                    etc_dir=str(etc_dir),
                    prefix=str(temp_dir / "prefix"),
                    run_dir=str(temp_dir / "run"),
                    systemd_dir=str(temp_dir / "systemd"),
                    uninstall=True,
                    yes=True,
                )
            )
        self.assertEqual(0, exit_code)
        payload_mock.assert_called_once()
        data_mock.assert_called_once()
        _, kwargs = data_mock.call_args
        self.assertTrue(kwargs["remove_config_data"])
        self.assertTrue(kwargs["remove_system_tuning"])
        sync_mock.assert_called_once()
        self.assertIn("LOHA has been removed from the system.", output.getvalue())

    def test_uninstall_non_interactive_alias_removes_all_without_prompts(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        (etc_dir / "loha.conf").write_text('LOCALE="en_US"\n', encoding="utf-8")
        output = io.StringIO()
        with patch("builtins.input") as input_mock, patch(
            "loha.install._remove_installation_payload",
            return_value=InstallStepResult(ok=True),
        ) as payload_mock, patch(
            "loha.install._remove_uninstall_data",
            return_value=InstallStepResult(ok=True),
        ) as data_mock, patch(
            "loha.install._sync_uninstall_runtime",
        ) as sync_mock, redirect_stdout(output):
            exit_code = cmd_uninstall(
                SimpleNamespace(
                    etc_dir=str(etc_dir),
                    prefix=str(temp_dir / "prefix"),
                    run_dir=str(temp_dir / "run"),
                    systemd_dir=str(temp_dir / "systemd"),
                    uninstall=True,
                    yes=False,
                    non_interactive=True,
                )
            )
        self.assertEqual(0, exit_code)
        input_mock.assert_not_called()
        payload_mock.assert_called_once()
        data_mock.assert_called_once()
        _, kwargs = data_mock.call_args
        self.assertTrue(kwargs["remove_config_data"])
        self.assertTrue(kwargs["remove_system_tuning"])
        sync_mock.assert_called_once()
        self.assertIn("LOHA has been removed from the system.", output.getvalue())

    def test_cmd_install_prints_localized_system_feature_failure(self):
        temp_dir = Path(tempfile.mkdtemp())
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="zh_CN")
        adapter = SysctlAdapter()
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        (etc_dir / "rules.conf").write_text("", encoding="utf-8")
        args = SimpleNamespace(
            etc_dir=str(etc_dir),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=runtime
        ), patch(
            "loha.install._run_interactive_prechecks",
            return_value=True,
        ), patch(
            "loha.install._choose_install_initial_config",
            return_value=self.config,
        ), patch(
            "loha.install._resolve_install_config",
            return_value=(self.config, False, ()),
        ), patch(
            "loha.install.detect_upstream_firewall_target",
            return_value="network.target",
        ), patch(
            "loha.install._deploy_install_files",
            return_value=InstallStepResult(ok=True),
        ), patch(
            "loha.install._apply_install_system_features",
            return_value=InstallStepResult(
                ok=False,
                error=LocalizedMessage(
                    "install.system_features.sysctl_failed",
                    "Install system-feature apply failed during `sysctl --system`: {error}",
                    values={"error": "boom"},
                ),
            ),
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertIn("错误：安装阶段执行 `sysctl --system` 失败：boom", output.getvalue())

    def test_cmd_install_rolls_back_clean_install_when_activation_fails(self):
        temp_dir = Path(tempfile.mkdtemp())
        adapter = RestartFailingInstallAdapter(service_enabled=False, service_active=False)
        args = SimpleNamespace(
            etc_dir=str(temp_dir / "etc"),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=self.runtime
        ), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=self.config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._apply_install_system_features", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._activate_install_service",
            return_value=InstallStepResult(
                ok=False,
                error=LocalizedMessage(
                    "install.service.action_failed",
                    "Install service activation failed during `{command}`: {error}",
                    values={"command": "systemctl restart loha.service", "error": "boom"},
                ),
            ),
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertFalse((temp_dir / "etc").exists())
        self.assertFalse((temp_dir / "prefix" / "bin" / "loha").exists())
        self.assertFalse((temp_dir / "prefix" / "lib" / "loha-port-forwarder").exists())
        self.assertFalse((temp_dir / "prefix" / "share" / "loha").exists())
        self.assertFalse((temp_dir / "systemd" / "loha.service").exists())
        self.assertIn("partial changes were rolled back", output.getvalue())

    def test_cmd_install_resyncs_sysctl_runtime_when_activation_fails_after_system_feature_apply(self):
        temp_dir = Path(tempfile.mkdtemp())
        adapter = RestartFailingInstallAdapter(service_enabled=False, service_active=False)
        args = SimpleNamespace(
            etc_dir=str(temp_dir / "etc"),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )

        def fake_apply(_paths, _config, adapter, *, dry_run: bool, i18n=None):
            result = adapter.run(["sysctl", "--system"], check=False)
            if result.returncode != 0:
                return InstallStepResult(
                    ok=False,
                    error=LocalizedMessage(
                        "install.system_features.sysctl_failed",
                        "Install system-feature apply failed during `sysctl --system`: {error}",
                        values={"error": result.stderr.strip() or result.stdout.strip() or "sysctl --system failed"},
                    ),
                )
            return InstallStepResult(ok=True)

        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=self.runtime
        ), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=self.config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._apply_install_system_features", side_effect=fake_apply
        ), patch(
            "loha.install._activate_install_service",
            return_value=InstallStepResult(
                ok=False,
                error=LocalizedMessage(
                    "install.service.action_failed",
                    "Install service activation failed during `{command}`: {error}",
                    values={"command": "systemctl restart loha.service", "error": "boom"},
                ),
            ),
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertEqual([("sysctl", "--system"), ("sysctl", "--system")], adapter.run_calls)
        self.assertIn("partial changes were rolled back", output.getvalue())

    def test_cmd_install_resyncs_sysctl_runtime_after_sysctl_apply_failure(self):
        temp_dir = Path(tempfile.mkdtemp())
        adapter = FlakySysctlAdapter()
        args = SimpleNamespace(
            etc_dir=str(temp_dir / "etc"),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )

        def fake_apply(_paths, _config, adapter, *, dry_run: bool, i18n=None):
            result = adapter.run(["sysctl", "--system"], check=False)
            if result.returncode != 0:
                return InstallStepResult(
                    ok=False,
                    error=LocalizedMessage(
                        "install.system_features.sysctl_failed",
                        "Install system-feature apply failed during `sysctl --system`: {error}",
                        values={"error": result.stderr.strip() or result.stdout.strip() or "sysctl --system failed"},
                    ),
                )
            return InstallStepResult(ok=True)

        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=self.runtime
        ), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=self.config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._apply_install_system_features", side_effect=fake_apply
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertEqual(
            [("sysctl", "--system"), ("sysctl", "--system")],
            adapter.run_calls,
        )
        rendered = output.getvalue()
        self.assertIn("Install system-feature apply failed during `sysctl --system`: boom", rendered)
        self.assertIn("partial changes were rolled back", rendered)

    def test_cmd_install_reloads_systemd_manager_after_restart_failure_on_clean_install(self):
        temp_dir = Path(tempfile.mkdtemp())
        adapter = RestartFailingInstallAdapter(service_enabled=False, service_active=False)
        args = SimpleNamespace(
            etc_dir=str(temp_dir / "etc"),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )

        def fake_apply(_paths, _config, adapter, *, dry_run: bool, i18n=None):
            result = adapter.run(["sysctl", "--system"], check=False)
            if result.returncode != 0:
                return InstallStepResult(
                    ok=False,
                    error=LocalizedMessage(
                        "install.system_features.sysctl_failed",
                        "Install system-feature apply failed during `sysctl --system`: {error}",
                        values={"error": result.stderr.strip() or result.stdout.strip() or "sysctl --system failed"},
                    ),
                )
            return InstallStepResult(ok=True)

        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=self.runtime
        ), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=self.config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._apply_install_system_features", side_effect=fake_apply
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertEqual(
            [
                ("daemon-reload", ""),
                ("enable", "loha.service"),
                ("restart", "loha.service"),
                ("stop", "loha.service"),
                ("disable", "loha.service"),
                ("daemon-reload", ""),
            ],
            adapter.systemctl_calls,
        )
        self.assertIn("partial changes were rolled back", output.getvalue())

    def test_cmd_install_restores_previous_service_state_after_restart_failure(self):
        temp_dir = Path(tempfile.mkdtemp())
        adapter = RestartFailingInstallAdapter(service_enabled=True, service_active=True)
        service_unit = temp_dir / "systemd" / "loha.service"
        service_unit.parent.mkdir(parents=True, exist_ok=True)
        service_unit.write_text("legacy-unit\n", encoding="utf-8")
        args = SimpleNamespace(
            etc_dir=str(temp_dir / "etc"),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )

        def fake_apply(_paths, _config, adapter, *, dry_run: bool, i18n=None):
            result = adapter.run(["sysctl", "--system"], check=False)
            if result.returncode != 0:
                return InstallStepResult(
                    ok=False,
                    error=LocalizedMessage(
                        "install.system_features.sysctl_failed",
                        "Install system-feature apply failed during `sysctl --system`: {error}",
                        values={"error": result.stderr.strip() or result.stdout.strip() or "sysctl --system failed"},
                    ),
                )
            return InstallStepResult(ok=True)

        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=self.runtime
        ), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=self.config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._apply_install_system_features", side_effect=fake_apply
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertEqual(
            [
                ("daemon-reload", ""),
                ("enable", "loha.service"),
                ("restart", "loha.service"),
                ("stop", "loha.service"),
                ("disable", "loha.service"),
                ("daemon-reload", ""),
                ("enable", "loha.service"),
                ("restart", "loha.service"),
            ],
            adapter.systemctl_calls,
        )
        self.assertIn("partial changes were rolled back", output.getvalue())

    def test_cmd_install_restores_previous_state_when_activation_fails_after_deploy(self):
        temp_dir = Path(tempfile.mkdtemp())
        adapter = RestartFailingInstallAdapter(service_enabled=False, service_active=False)
        etc_dir = temp_dir / "etc"
        old_config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth9",
                "PRIMARY_EXTERNAL_IF": "eth9",
                "LISTEN_IPS": "198.51.100.20",
                "DEFAULT_SNAT_IP": "198.51.100.20",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_CONFIG_HISTORY": "on",
            }
        )
        etc_dir.mkdir(parents=True, exist_ok=True)
        (etc_dir / "loha.conf").write_text(render_canonical_text(old_config), encoding="utf-8")
        (etc_dir / "rules.conf").write_text("ALIAS\tVM_OLD\t192.0.2.10\n", encoding="utf-8")
        old_cli = temp_dir / "prefix" / "bin" / "loha"
        old_cli.parent.mkdir(parents=True, exist_ok=True)
        old_cli.write_text("legacy-cli\n", encoding="utf-8")
        old_loader = temp_dir / "prefix" / "libexec" / "loha" / "loader.sh"
        old_loader.parent.mkdir(parents=True, exist_ok=True)
        old_loader.write_text("legacy-loader\n", encoding="utf-8")
        old_package = temp_dir / "prefix" / "lib" / "loha-port-forwarder" / "loha"
        old_package.mkdir(parents=True, exist_ok=True)
        (old_package / "legacy.txt").write_text("legacy-package\n", encoding="utf-8")
        old_share = temp_dir / "prefix" / "share" / "loha"
        old_share.mkdir(parents=True, exist_ok=True)
        (old_share / "legacy.txt").write_text("legacy-share\n", encoding="utf-8")
        old_unit = temp_dir / "systemd" / "loha.service"
        old_unit.parent.mkdir(parents=True, exist_ok=True)
        old_unit.write_text("legacy-unit\n", encoding="utf-8")
        args = SimpleNamespace(
            etc_dir=str(etc_dir),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        output = io.StringIO()
        with patch("loha.install.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.install._build_install_i18n", return_value=self.runtime
        ), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=old_config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._apply_install_system_features", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._activate_install_service",
            return_value=InstallStepResult(
                ok=False,
                error=LocalizedMessage(
                    "install.service.action_failed",
                    "Install service activation failed during `{command}`: {error}",
                    values={"command": "systemctl restart loha.service", "error": "boom"},
                ),
            ),
        ), redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(1, exit_code)
        self.assertIn('PRIMARY_EXTERNAL_IF="eth9"', (etc_dir / "loha.conf").read_text(encoding="utf-8"))
        self.assertIn("ALIAS\tVM_OLD\t192.0.2.10", (etc_dir / "rules.conf").read_text(encoding="utf-8"))
        self.assertEqual("legacy-cli\n", old_cli.read_text(encoding="utf-8"))
        self.assertEqual("legacy-loader\n", old_loader.read_text(encoding="utf-8"))
        self.assertTrue((old_package / "legacy.txt").exists())
        self.assertFalse((old_package / "cli.py").exists())
        self.assertEqual("legacy-share\n", (old_share / "legacy.txt").read_text(encoding="utf-8"))
        self.assertEqual("legacy-unit\n", old_unit.read_text(encoding="utf-8"))
        self.assertEqual(1, len(list_snapshots(SimpleNamespace(history_dir=etc_dir / "history"))))
        self.assertIn("partial changes were rolled back", output.getvalue())

    def test_cmd_install_returns_zero_when_wizard_is_cancelled(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        args = SimpleNamespace(
            etc_dir=str(etc_dir),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=False,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        output = io.StringIO()
        with patch(
            "loha.install._build_install_i18n",
            return_value=self.runtime,
        ), patch(
            "loha.install._run_interactive_prechecks",
            return_value=True,
        ), patch(
            "loha.install._choose_install_initial_config",
            return_value=self.config,
        ), patch(
            "loha.install._resolve_install_config",
            side_effect=KeyboardInterrupt("wizard cancelled"),
        ), patch(
            "loha.install._deploy_install_files",
        ) as deploy_mock, redirect_stdout(output):
            exit_code = cmd_install(args)
        self.assertEqual(0, exit_code)
        self.assertIn("Installation was cancelled before applying changes.", output.getvalue())
        deploy_mock.assert_not_called()

    def test_cmd_install_captures_preinstall_snapshot_from_existing_state(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        old_config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth9",
                "PRIMARY_EXTERNAL_IF": "eth9",
                "LISTEN_IPS": "198.51.100.20",
                "DEFAULT_SNAT_IP": "198.51.100.20",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_CONFIG_HISTORY": "on",
            }
        )
        (etc_dir / "loha.conf").write_text(render_canonical_text(old_config), encoding="utf-8")
        (etc_dir / "rules.conf").write_text("ALIAS\tVM_OLD\t192.0.2.10\n", encoding="utf-8")
        args = SimpleNamespace(
            etc_dir=str(etc_dir),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        with patch("loha.install._build_install_i18n", return_value=self.runtime), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=old_config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._deploy_install_files", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._apply_install_system_features", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._activate_install_service", return_value=InstallStepResult(ok=True)
        ):
            exit_code = cmd_install(args)
        self.assertEqual(0, exit_code)
        snapshots = list_snapshots(SimpleNamespace(history_dir=etc_dir / "history"))
        self.assertEqual(1, len(snapshots))
        self.assertEqual("installer", snapshots[0].source)
        self.assertEqual("install-apply", snapshots[0].reason)
        self.assertIn('PRIMARY_EXTERNAL_IF="eth9"', (snapshots[0].path / "loha.conf").read_text(encoding="utf-8"))
        self.assertIn("ALIAS\tVM_OLD\t192.0.2.10", (snapshots[0].path / "rules.conf").read_text(encoding="utf-8"))

    def test_cmd_install_does_not_create_snapshot_for_clean_install(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        args = SimpleNamespace(
            etc_dir=str(etc_dir),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        with patch("loha.install._build_install_i18n", return_value=self.runtime), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=self.config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._deploy_install_files", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._apply_install_system_features", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._activate_install_service", return_value=InstallStepResult(ok=True)
        ):
            exit_code = cmd_install(args)
        self.assertEqual(0, exit_code)
        self.assertEqual([], list_snapshots(SimpleNamespace(history_dir=etc_dir / "history")))

    def test_cmd_install_skips_preinstall_snapshot_when_history_is_disabled(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        old_config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth9",
                "PRIMARY_EXTERNAL_IF": "eth9",
                "LISTEN_IPS": "198.51.100.20",
                "DEFAULT_SNAT_IP": "198.51.100.20",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_CONFIG_HISTORY": "off",
            }
        )
        (etc_dir / "loha.conf").write_text(render_canonical_text(old_config), encoding="utf-8")
        (etc_dir / "rules.conf").write_text("ALIAS\tVM_OLD\t192.0.2.10\n", encoding="utf-8")
        args = SimpleNamespace(
            etc_dir=str(etc_dir),
            prefix=str(temp_dir / "prefix"),
            run_dir=str(temp_dir / "run"),
            systemd_dir=str(temp_dir / "systemd"),
            non_interactive=True,
            dry_run=False,
            uninstall=False,
            yes=False,
        )
        with patch("loha.install._build_install_i18n", return_value=self.runtime), patch(
            "loha.install._run_interactive_prechecks", return_value=True
        ), patch(
            "loha.install._choose_install_initial_config", return_value=old_config
        ), patch(
            "loha.install._resolve_install_config", return_value=(self.config, False, ())
        ), patch(
            "loha.install.detect_upstream_firewall_target", return_value="network.target"
        ), patch(
            "loha.install._deploy_install_files", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._apply_install_system_features", return_value=InstallStepResult(ok=True)
        ), patch(
            "loha.install._activate_install_service", return_value=InstallStepResult(ok=True)
        ):
            exit_code = cmd_install(args)
        self.assertEqual(0, exit_code)
        self.assertEqual([], list_snapshots(SimpleNamespace(history_dir=etc_dir / "history")))

    def test_install_main_catches_apply_error_using_runtime_locale(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        etc_dir.mkdir(parents=True, exist_ok=True)
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "LOCALE": "zh_CN",
            }
        )
        (etc_dir / "loha.conf").write_text(render_canonical_text(config), encoding="utf-8")
        output = io.StringIO()
        with patch("loha.install.cmd_install", side_effect=ApplyError("boom")), redirect_stdout(output):
            exit_code = main(["--etc-dir", str(etc_dir), "--prefix", str(temp_dir / "prefix"), "--run-dir", str(temp_dir / "run"), "--systemd-dir", str(temp_dir / "systemd")])
        self.assertEqual(1, exit_code)
        self.assertIn("错误：boom", output.getvalue())


if __name__ == "__main__":
    unittest.main()
