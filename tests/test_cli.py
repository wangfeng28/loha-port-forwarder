import io
import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from loha.cli import (
    _confirm_rules_conf_edit,
    _detect_listener_conflicts,
    _edit_rules_conf,
    _interactive_auth_switch,
    _interactive_menu,
    _menu_advanced,
    _menu_alias,
    _menu_add_port,
    _menu_counter_mode,
    _menu_conntrack,
    _menu_config_history,
    _menu_rpfilter,
    _menu_strict_validation,
    _menu_tcpmss_clamp,
    _menu_wan_to_wan,
    _prompt_yes_no,
    _resolve_editor_command,
    _run_menu_action,
    _runtime_i18n,
    _validate_rules_after_edit,
    _watch_mark_detection_interactive,
    build_parser,
    cmd_alias_add,
    cmd_config_show,
    cmd_config_get,
    cmd_config_history,
    cmd_config_normalize,
    cmd_config_rollback,
    cmd_config_wizard,
    cmd_config_set,
    cmd_conntrack_auto,
    cmd_conntrack_profile,
    cmd_conntrack_status,
    cmd_doctor,
    cmd_conntrack_system,
    cmd_list,
    cmd_port_add,
    cmd_rules_render,
    main,
    cmd_reload,
    cmd_rpfilter,
    cmd_rpfilter_status,
)
from loha.config import normalize_mapping, render_canonical_text
from loha.exceptions import ApplyError, ConfigValidationError, HistoryError, RulesLockError, RulesSyntaxError
from loha.history import write_transaction
from loha.i18n import build_runtime_i18n_for_paths
from loha.models import ConntrackStatusReport, DoctorResult, LocalizedMessage, Paths, RPFilterStatusReport
from loha.rules import render_rules_text
from loha.version import __version__


class RecordingAdapter:
    def __init__(self):
        self.run_calls = []
        self.listeners = None

    def command_exists(self, name: str) -> bool:
        return name == "sysctl"

    def run(self, argv, *, input_text: str = "", check: bool = True):
        self.run_calls.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    def default_ipv4_ifaces(self):
        return ("eth0",)

    def list_interfaces(self):
        return ("lo", "eth0", "eth1")

    def global_ipv4s(self, interface: str):
        return {"eth0": ("203.0.113.10", "203.0.113.11")}.get(interface, ())

    def ipv4_networks(self, interface: str):
        return {"eth1": ("192.168.10.0/24",)}.get(interface, ())

    def scan_listeners(self):
        return self.listeners

    def read_text(self, _path):
        return ""


class ServiceAdapter(RecordingAdapter):
    def __init__(self):
        super().__init__()
        self.systemctl_calls = []

    def command_exists(self, name: str) -> bool:
        return name == "systemctl"

    def systemctl(self, action: str, unit: str = "") -> None:
        self.systemctl_calls.append((action, unit))


class CliTests(unittest.TestCase):
    def _paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        return Paths(etc_dir=temp_dir / "etc", run_dir=temp_dir / "run")

    def _cli_paths(self):
        temp_dir = Path(tempfile.mkdtemp())
        etc_dir = temp_dir / "etc"
        return SimpleNamespace(
            etc_dir=etc_dir,
            run_dir=temp_dir / "run",
            prefix=temp_dir / "prefix",
            systemd_unit_dir=temp_dir / "systemd",
            loha_conf=etc_dir / "loha.conf",
            rules_conf=etc_dir / "rules.conf",
            history_dir=etc_dir / "history",
            forwarding_sysctl=etc_dir / "90-loha-forwarding.conf",
            conntrack_sysctl=etc_dir / "90-loha-conntrack.conf",
            conntrack_modprobe=etc_dir / "loha-conntrack.conf",
        )

    def _write_config(self, paths: Paths, *, history_mode: str, locale: str = "en_US"):
        config = normalize_mapping(
            {
                "EXTERNAL_IFS": "eth0",
                "PRIMARY_EXTERNAL_IF": "eth0",
                "LISTEN_IPS": "203.0.113.10",
                "DEFAULT_SNAT_IP": "203.0.113.10",
                "LAN_IFS": "eth1",
                "LAN_NETS": "192.168.10.0/24",
                "PROTECTION_MODE": "backends",
                "ENABLE_CONFIG_HISTORY": history_mode,
                "LOCALE": locale,
            }
        )
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.loha_conf.write_text(render_canonical_text(config), encoding="utf-8")
        paths.rules_conf.write_text("", encoding="utf-8")

    def test_config_history_status_reports_enabled(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_config_history(
                Namespace(
                    subcommand="status",
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual("Automatic snapshots: enabled", out.getvalue().strip())

    def test_config_history_status_uses_runtime_locale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_config_history(
                Namespace(
                    subcommand="status",
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual("自动快照：已启用", out.getvalue().strip())

    def test_config_history_show_prints_detailed_snapshot_fields(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        write_transaction(
            paths,
            config_text=paths.loha_conf.read_text(encoding="utf-8"),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\n",
            source="cli",
            reason="alias-add",
        )
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_config_history(
                Namespace(
                    subcommand="show",
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("Configuration History", rendered)
        self.assertIn("Source: cli", rendered)
        self.assertIn("Reason: alias-add", rendered)
        self.assertIn("Config hash:", rendered)
        self.assertIn("Rules hash:", rendered)

    def test_config_history_show_prints_rollback_checkpoint_separately(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        write_transaction(
            paths,
            config_text=paths.loha_conf.read_text(encoding="utf-8"),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\n",
            source="cli",
            reason="alias-add",
        )
        write_transaction(
            paths,
            config_text=render_canonical_text(
                normalize_mapping(
                    {
                        "EXTERNAL_IFS": "eth0",
                        "PRIMARY_EXTERNAL_IF": "eth0",
                        "LISTEN_IPS": "203.0.113.10,198.51.100.20",
                        "DEFAULT_SNAT_IP": "198.51.100.20",
                        "LAN_IFS": "eth1",
                        "LAN_NETS": "192.168.10.0/24",
                        "PROTECTION_MODE": "backends",
                        "ENABLE_CONFIG_HISTORY": "on",
                    }
                )
            ),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\nALIAS\tVM_API\t192.0.2.20\n",
            source="cli",
            reason="config-set",
        )
        cmd_config_rollback(
            Namespace(
                selector="latest",
                apply=False,
                etc_dir=str(paths.etc_dir),
                prefix=str(paths.prefix),
                run_dir=str(paths.run_dir),
                systemd_dir=str(paths.systemd_unit_dir),
            )
        )

        out = io.StringIO()
        with redirect_stdout(out):
            cmd_config_history(
                Namespace(
                    subcommand="show",
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("Rollback checkpoint", rendered)
        self.assertIn("Not counted in regular history limit.", rendered)
        self.assertIn("Reason: checkpoint", rendered)

    def test_config_get_accepts_lowercase_key(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_config_get(
                Namespace(
                    key="external_ifs",
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual("eth0", out.getvalue().strip())

    def test_config_get_rejects_legacy_syntax_before_normalize(self):
        paths = self._paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        paths.loha_conf.write_text(
            "\n".join(
                [
                    'EXTERNAL_IFS = "eth0"',
                    'PRIMARY_EXTERNAL_IF = "eth0"',
                    'LISTEN_IPS = "203.0.113.10"',
                    'DEFAULT_SNAT_IP = "203.0.113.10"',
                    'LAN_IFS = "eth1"',
                    'LAN_NETS = "192.168.10.0/24"',
                    'PROTECTION_MODE = "backends"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_get(Namespace(key="external_ifs"))
        self.assertEqual(2, exit_code)
        self.assertIn('expected KEY="VALUE"', out.getvalue())

    def test_config_get_reports_invalid_current_value_clearly(self):
        paths = self._paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        paths.loha_conf.write_text(
            "\n".join(
                [
                    'EXTERNAL_IFS="eth0"',
                    'PRIMARY_EXTERNAL_IF="eth0"',
                    'LISTEN_IPS="203.0.113.10"',
                    'DEFAULT_SNAT_IP="203.0.113.10"',
                    'LAN_IFS="eth1"',
                    'LAN_NETS="192.168.10.0/24"',
                    'PROTECTION_MODE="backends"',
                    'AUTH_MODE="bogus"',
                    'LOCALE="en_US"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_get(Namespace(key="auth_mode"))
        rendered = out.getvalue()
        self.assertEqual(3, exit_code)
        self.assertIn("The current value of auth_mode in loha.conf is invalid.", rendered)
        self.assertIn("AUTH_MODE must be one of: mark/label", rendered)

    def test_config_show_uses_shared_summary_output(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        rp_report = RPFilterStatusReport(
            configured_mode="system",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="",
            file_present=False,
            file_matches_expected=True,
            file_mode="missing",
            runtime_ip_forward="1",
            runtime_default_value="0",
            runtime_all_value="0",
            runtime_iface_values={"eth0": "0", "eth1": "0"},
            runtime_mode="runtime_only",
            runtime_state="system",
        )
        ct_report = ConntrackStatusReport(
            configured_mode="system",
            expected_max=0,
            expected_buckets=0,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=False,
            modprobe_file_present=False,
            sysctl_matches_expected=True,
            modprobe_matches_expected=True,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="system",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_rp_filter_status", return_value=rp_report), patch(
            "loha.cli.collect_conntrack_status",
            return_value=ct_report,
        ), redirect_stdout(out):
            cmd_config_show(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("Current Core Configuration", rendered)
        self.assertIn("Network Topology", rendered)
        self.assertIn("External interface binding:", rendered)
        self.assertIn("Canonical Values", rendered)
        self.assertIn("EXTERNAL_IFS: eth0", rendered)
        self.assertIn("ENABLE_CONFIG_HISTORY: on", rendered)
        self.assertIn("External interface binding status:", rendered)
        self.assertIn("rp_filter runtime status:", rendered)
        self.assertIn("Conntrack runtime status:", rendered)

    def test_config_show_uses_runtime_locale_for_detailed_sections(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        rp_report = RPFilterStatusReport(
            configured_mode="system",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="",
            file_present=False,
            file_matches_expected=True,
            file_mode="missing",
            runtime_ip_forward="1",
            runtime_default_value="0",
            runtime_all_value="0",
            runtime_iface_values={"eth0": "0", "eth1": "0"},
            runtime_mode="runtime_only",
            runtime_state="system",
        )
        ct_report = ConntrackStatusReport(
            configured_mode="system",
            expected_max=0,
            expected_buckets=0,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=False,
            modprobe_file_present=False,
            sysctl_matches_expected=True,
            modprobe_matches_expected=True,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="system",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_rp_filter_status", return_value=rp_report), patch(
            "loha.cli.collect_conntrack_status",
            return_value=ct_report,
        ), redirect_stdout(out):
            cmd_config_show(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("当前核心配置", rendered)
        self.assertIn("canonical 配置值", rendered)
        self.assertIn("运行时与系统集成", rendered)
        self.assertIn("外部接口绑定:", rendered)
        self.assertIn("rp_filter 运行时状态：", rendered)
        self.assertIn("conntrack 运行时状态：", rendered)

    def test_config_show_supports_json_output(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        rp_report = RPFilterStatusReport(
            configured_mode="system",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="",
            file_present=False,
            file_matches_expected=True,
            file_mode="missing",
            runtime_ip_forward="1",
            runtime_default_value="0",
            runtime_all_value="0",
            runtime_iface_values={"eth0": "0", "eth1": "0"},
            runtime_mode="runtime_only",
            runtime_state="system",
        )
        ct_report = ConntrackStatusReport(
            configured_mode="system",
            expected_max=0,
            expected_buckets=0,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=False,
            modprobe_file_present=False,
            sysctl_matches_expected=True,
            modprobe_matches_expected=True,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="system",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_rp_filter_status", return_value=rp_report), patch(
            "loha.cli.collect_conntrack_status",
            return_value=ct_report,
        ), redirect_stdout(out):
            exit_code = cmd_config_show(
                Namespace(
                    json=True,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("eth0", payload["config"]["EXTERNAL_IFS"])
        self.assertEqual("compatible", payload["runtime"]["external_binding"]["status"])
        self.assertEqual("system", payload["runtime"]["rp_filter"]["configured_mode"])
        self.assertEqual("system", payload["runtime"]["conntrack"]["runtime_state"])

    def test_list_command_uses_runtime_locale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_list(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("LOHA 摘要", rendered)
        self.assertIn("别名", rendered)
        self.assertIn("端口", rendered)

    def test_list_command_supports_json_output(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        paths.rules_conf.write_text(
            "ALIAS\tVM_WEB\t192.168.10.20\nPORT\ttcp\t8080\tVM_WEB\t80\n",
            encoding="utf-8",
        )
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = cmd_list(
                Namespace(
                    json=True,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("summary", payload["result"]["code"])
        self.assertEqual("state_summary", payload["result"]["category"])
        self.assertEqual("eth0", payload["summary"]["primary_external_if"])
        self.assertEqual(["203.0.113.10"], payload["summary"]["listen_ips"])
        self.assertEqual("VM_WEB", payload["rules"]["aliases"][0]["name"])
        self.assertEqual("8080", payload["rules"]["ports"][0]["listen"]["canonical"])

    def test_alias_add_check_reports_preview_without_writing_rules(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        before = paths.rules_conf.read_text(encoding="utf-8")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_alias_add(Namespace(name="VM_WEB", ip="192.168.10.20", check=True))
        self.assertEqual(0, exit_code)
        self.assertEqual(before, paths.rules_conf.read_text(encoding="utf-8"))
        self.assertIn("Check mode: changes would be applied", out.getvalue())

    def test_alias_add_supports_json_changed_and_noop_output(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_alias_add(Namespace(name="VM_WEB", ip="192.168.10.20", json=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("update", payload["result"]["code"])
        self.assertEqual("rules_update", payload["result"]["category"])
        self.assertTrue(payload["changed"])
        self.assertEqual("192.168.10.20", payload["rules"]["aliases"][0]["ip"])

        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_alias_add(Namespace(name="VM_WEB", ip="192.168.10.20", json=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("rules_update", payload["result"]["category"])
        self.assertFalse(payload["changed"])

    def test_port_add_check_supports_json_preview_without_writing_rules(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        before = paths.rules_conf.read_text(encoding="utf-8")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_port_add(
                Namespace(
                    proto="tcp",
                    orig_port_spec="8080",
                    dest_addr="192.168.10.20",
                    dest_port_spec="80",
                    force=True,
                    check=True,
                    json=True,
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("rules_check", payload["result"]["category"])
        self.assertTrue(payload["would_change"])
        self.assertEqual(before, paths.rules_conf.read_text(encoding="utf-8"))
        self.assertEqual("tcp", payload["rules"]["ports"][0]["proto"])
        self.assertEqual("8080", payload["rules"]["ports"][0]["listen"]["canonical"])
        self.assertEqual([], adapter.run_calls)

    def test_config_set_auth_mode_label_uses_shared_planner(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_set(Namespace(key="AUTH_MODE", value="label"))
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('AUTH_MODE="label"', rendered)
        self.assertIn('DNAT_LABEL="56"', rendered)
        self.assertIn('DNAT_MARK=""', rendered)
        self.assertIn("Authorization mode switched to ct label (label value 56).", out.getvalue())
        self.assertIn("Run `loha reload --full` to apply the authorization mode change.", out.getvalue())

    def test_config_set_auth_mode_label_uses_runtime_locale(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_set(Namespace(key="AUTH_MODE", value="label"))
        rendered = out.getvalue()
        self.assertIn("授权模式已切换为 ct label", rendered)
        self.assertIn("运行 `loha reload --full`", rendered)

    def test_config_set_auth_mode_mark_reports_already_configured(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_set(Namespace(key="AUTH_MODE", value="mark"))
        self.assertIn("Authorization mode is already ct mark (mark value 0x10000000).", out.getvalue())
        self.assertNotIn("reload --full", out.getvalue())

    def test_config_set_auth_mode_check_reports_plan_without_writing(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        before = paths.loha_conf.read_text(encoding="utf-8")
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_config_set(Namespace(key="AUTH_MODE", value="label", check=True))
        self.assertEqual(0, exit_code)
        self.assertEqual(before, paths.loha_conf.read_text(encoding="utf-8"))
        rendered = out.getvalue()
        self.assertIn("AUTH_MODE would switch to ct label", rendered)
        self.assertIn("Check mode: changes would be applied", rendered)

    def test_config_set_auth_mode_json_reports_changed_and_noop(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_config_set(Namespace(key="AUTH_MODE", value="label", json=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("update", payload["result"]["code"])
        self.assertEqual("config_update", payload["result"]["category"])
        self.assertTrue(payload["changed"])
        self.assertEqual("label", payload["config"]["AUTH_MODE"])
        self.assertEqual("switched_label", payload["message"]["message_key"].split(".")[-1])

        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_config_set(Namespace(key="AUTH_MODE", value="label", json=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("config_update", payload["result"]["category"])
        self.assertFalse(payload["changed"])
        self.assertEqual("label", payload["config"]["AUTH_MODE"])

    def test_config_set_accepts_hyphenated_key_and_rewrites_canonical_config(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        cmd_config_set(
            Namespace(
                key="protection-mode",
                value="nets",
                etc_dir=str(paths.etc_dir),
                prefix=str(paths.prefix),
                run_dir=str(paths.run_dir),
                systemd_dir=str(paths.systemd_unit_dir),
            )
        )
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('PROTECTION_MODE="nets"', rendered)
        self.assertIn('PROTECTED_NETS="192.168.10.0/24"', rendered)

    def test_config_set_check_does_not_write_config(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        before = paths.loha_conf.read_text(encoding="utf-8")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_set(Namespace(key="protection-mode", value="nets", check=True))
        self.assertEqual(0, exit_code)
        self.assertEqual(before, paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("Check mode: changes would be applied", out.getvalue())

    def test_config_set_json_reports_noop_for_same_value(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_set(Namespace(key="protection-mode", value="backends", json=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("config_update", payload["result"]["category"])
        self.assertFalse(payload["changed"])
        self.assertEqual("backends", payload["config"]["PROTECTION_MODE"])

    def test_config_set_external_ifs_auto_materializes_explicit_value(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_set(Namespace(key="external_ifs", value="auto"))
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('EXTERNAL_IFS="eth0"', rendered)
        self.assertIn('PRIMARY_EXTERNAL_IF="eth0"', rendered)
        self.assertNotIn('EXTERNAL_IFS="auto"', rendered)
        self.assertIn("EXTERNAL_IFS=auto was resolved to eth0", out.getvalue())

    def test_config_set_listen_ips_auto_materializes_explicit_value(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_set(Namespace(key="listen_ips", value="auto"))
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('LISTEN_IPS="203.0.113.10,203.0.113.11"', rendered)
        self.assertIn('DEFAULT_SNAT_IP="203.0.113.10"', rendered)
        self.assertNotIn('LISTEN_IPS="auto"', rendered)
        self.assertIn("LISTEN_IPS=auto was resolved to 203.0.113.10,203.0.113.11", out.getvalue())

    def test_config_normalize_rejects_noncanonical_syntax(self):
        paths = self._paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        paths.loha_conf.write_text(
            "\n".join(
                [
                    "EXTERNAL_IFS=eth0",
                    "PRIMARY_EXTERNAL_IF=eth0",
                    "LISTEN_IPS=203.0.113.10",
                    "DEFAULT_SNAT_IP=203.0.113.10",
                    "LAN_IFS=eth1",
                    "LAN_NETS=192.168.10.0/24",
                    "PROTECTION_MODE=backends",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_normalize(Namespace())
        self.assertEqual(2, exit_code)
        self.assertIn('expected KEY="VALUE"', out.getvalue())

    def test_config_normalize_materializes_runtime_binding_shortcuts_before_save(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        rendered = rendered.replace('EXTERNAL_IFS="eth0"', 'EXTERNAL_IFS="auto"')
        rendered = rendered.replace('LISTEN_IPS="203.0.113.10"', 'LISTEN_IPS="auto"')
        paths.loha_conf.write_text(rendered, encoding="utf-8")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_normalize(Namespace())
        normalized = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('EXTERNAL_IFS="eth0"', normalized)
        self.assertIn('LISTEN_IPS="203.0.113.10,203.0.113.11"', normalized)
        self.assertNotIn('"auto"', normalized)
        self.assertIn("EXTERNAL_IFS=auto was resolved to eth0", out.getvalue())
        self.assertIn("LISTEN_IPS=auto was resolved to 203.0.113.10,203.0.113.11", out.getvalue())

    def test_config_normalize_materialization_notice_uses_runtime_locale(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        rendered = rendered.replace('EXTERNAL_IFS="eth0"', 'EXTERNAL_IFS="auto"')
        paths.loha_conf.write_text(rendered, encoding="utf-8")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_normalize(Namespace())
        self.assertIn("EXTERNAL_IFS=auto 已在保存前解析为 eth0", out.getvalue())

    def test_config_normalize_check_does_not_rewrite_files(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        rendered = rendered.replace('EXTERNAL_IFS="eth0"', 'EXTERNAL_IFS="auto"')
        paths.loha_conf.write_text(rendered, encoding="utf-8")
        before = paths.loha_conf.read_text(encoding="utf-8")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_config_normalize(Namespace(check=True))
        self.assertEqual(0, exit_code)
        self.assertEqual(before, paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("Check mode: changes would be applied", out.getvalue())

    def test_config_normalize_rejects_removed_runtime_mirror_keys(self):
        paths = self._paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        paths.loha_conf.write_text(
            "\n".join(
                [
                    'WAN_IF="eth0"',
                    "LAN_IFS=eth1",
                    "LAN_NETS=192.168.10.0/24",
                    "PROTECTION_MODE=backends",
                    "AUTH_MODE=mark",
                    "DNAT_MARK=0x10000000",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_normalize(Namespace())
        self.assertEqual(2, exit_code)
        self.assertIn("unsupported config key: WAN_IF", out.getvalue())

    def test_config_set_rpfilter_writes_sysctl_file_and_syncs_runtime(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_config_set(
                Namespace(
                    key="rp_filter_mode",
                    value="loose-scoped",
                )
            )
        self.assertEqual([("sysctl", "--system")], adapter.run_calls)
        self.assertIn('RP_FILTER_MODE="loose_scoped"', paths.loha_conf.read_text(encoding="utf-8"))
        forwarding_sysctl = paths.forwarding_sysctl.read_text(encoding="utf-8")
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 2", forwarding_sysctl)
        self.assertIn("net.ipv4.conf.eth1.rp_filter = 2", forwarding_sysctl)
        rendered = out.getvalue()
        self.assertIn("rp_filter mode: loose_scoped", rendered)
        self.assertIn("Runtime:", rendered)

    def test_config_set_rejects_removed_runtime_mirror_keys_in_current_config(self):
        paths = self._cli_paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        paths.loha_conf.write_text(
            "\n".join(
                [
                    'WAN_IF="eth0"',
                    'LAN_IFS="eth1"',
                    'LAN_NETS="192.168.10.0/24"',
                    'PROTECTION_MODE="backends"',
                    'AUTH_MODE="mark"',
                    'DNAT_MARK="0x10000000"',
                    'ENABLE_TCPMSS_CLAMP="off"',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            exit_code = cmd_config_set(Namespace(key="enable_tcpmss_clamp", value="on"))
        self.assertEqual(2, exit_code)
        self.assertIn("unsupported config key: WAN_IF", out.getvalue())

    def test_config_set_materializes_existing_toggle_auto_shortcuts_before_persisting(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        rendered = rendered.replace('ENABLE_HAIRPIN="on"', 'ENABLE_HAIRPIN="auto"')
        rendered = rendered.replace('ENABLE_WAN_TO_WAN="off"', 'ENABLE_WAN_TO_WAN="auto"')
        rendered = rendered.replace('ENABLE_TCPMSS_CLAMP="off"', 'ENABLE_TCPMSS_CLAMP="auto"')
        paths.loha_conf.write_text(rendered, encoding="utf-8")
        adapter = RecordingAdapter()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ):
            exit_code = cmd_config_set(Namespace(key="external_ifs", value="auto"))
        written = paths.loha_conf.read_text(encoding="utf-8")
        self.assertEqual(0, exit_code)
        self.assertIn('EXTERNAL_IFS="eth0"', written)
        self.assertIn('ENABLE_HAIRPIN="on"', written)
        self.assertIn('ENABLE_WAN_TO_WAN="off"', written)
        self.assertIn('ENABLE_TCPMSS_CLAMP="off"', written)
        self.assertNotIn('"auto"', written)

    def test_config_set_accepts_toggle_auto_shortcut(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        with patch("loha.cli._paths_from_args", return_value=paths):
            exit_code = cmd_config_set(Namespace(key="enable_hairpin", value="auto"))
        written = paths.loha_conf.read_text(encoding="utf-8")
        self.assertEqual(0, exit_code)
        self.assertIn('ENABLE_HAIRPIN="on"', written)

    def test_explicit_rpfilter_command_reuses_shared_update_path(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_rpfilter(
                Namespace(
                    mode="strict",
                )
            )
        self.assertEqual([("sysctl", "--system")], adapter.run_calls)
        self.assertIn('RP_FILTER_MODE="strict"', paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("net.ipv4.conf.eth0.rp_filter = 1", paths.forwarding_sysctl.read_text(encoding="utf-8"))
        self.assertIn("rp_filter mode: strict", out.getvalue())

    def test_explicit_rpfilter_command_supports_json_output(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_rpfilter(
                Namespace(
                    mode="strict",
                    json=True,
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("update", payload["result"]["code"])
        self.assertEqual("rpfilter_update", payload["result"]["category"])
        self.assertTrue(payload["changed"])
        self.assertEqual(["RP_FILTER_MODE"], payload["changed_keys"])
        self.assertEqual("strict", payload["config"]["RP_FILTER_MODE"])
        self.assertEqual("strict", payload["rp_filter"]["configured_mode"])

    def test_rpfilter_check_supports_json_preview_without_writing_files(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_rpfilter(
                Namespace(
                    mode="strict",
                    json=True,
                    check=True,
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["check"])
        self.assertEqual("rpfilter_check", payload["result"]["category"])
        self.assertTrue(payload["would_change"])
        self.assertEqual(["RP_FILTER_MODE"], payload["changed_keys"])
        self.assertEqual("strict", payload["config"]["RP_FILTER_MODE"])
        self.assertEqual("write", payload["artifacts"]["forwarding_sysctl"]["action"])
        self.assertFalse(paths.forwarding_sysctl.exists())
        self.assertEqual([], adapter.run_calls)

    def test_rpfilter_status_uses_shared_report_output(self):
        report = RPFilterStatusReport(
            configured_mode="strict",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="",
            file_present=True,
            file_matches_expected=True,
            file_mode="strict",
            runtime_ip_forward="1",
            runtime_default_value="1",
            runtime_all_value="1",
            runtime_iface_values={"eth0": "1", "eth1": "1"},
            runtime_mode="strict",
            runtime_state="match",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_rp_filter_status", return_value=report), redirect_stdout(out):
            cmd_rpfilter_status(
                Namespace(
                    json=False,
                    etc_dir="/tmp/etc",
                    prefix="/tmp/prefix",
                    run_dir="/tmp/run",
                    systemd_dir="/tmp/systemd",
                )
            )
        rendered = out.getvalue()
        self.assertIn("rp_filter mode: strict", rendered)
        self.assertIn("Runtime: matches the configured rp_filter mode", rendered)

    def test_rpfilter_status_supports_json_output(self):
        report = RPFilterStatusReport(
            configured_mode="strict",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="",
            file_present=True,
            file_matches_expected=True,
            file_mode="strict",
            runtime_ip_forward="1",
            runtime_default_value="1",
            runtime_all_value="1",
            runtime_iface_values={"eth0": "1", "eth1": "1"},
            runtime_mode="strict",
            runtime_state="match",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_rp_filter_status", return_value=report), redirect_stdout(out):
            exit_code = cmd_rpfilter_status(
                Namespace(
                    json=True,
                    etc_dir="/tmp/etc",
                    prefix="/tmp/prefix",
                    run_dir="/tmp/run",
                    systemd_dir="/tmp/systemd",
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("strict", payload["rp_filter"]["configured_mode"])
        self.assertEqual("match", payload["rp_filter"]["runtime_state"])
        self.assertIn("matches the configured rp_filter mode", payload["rp_filter"]["runtime_description"])

    def test_rpfilter_status_uses_runtime_locale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        report = RPFilterStatusReport(
            configured_mode="strict",
            target_ifaces=("eth0", "eth1"),
            expected_file_content="",
            file_present=True,
            file_matches_expected=True,
            file_mode="strict",
            runtime_ip_forward="1",
            runtime_default_value="1",
            runtime_all_value="1",
            runtime_iface_values={"eth0": "1", "eth1": "1"},
            runtime_mode="strict",
            runtime_state="match",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_rp_filter_status", return_value=report), redirect_stdout(out):
            cmd_rpfilter_status(
                Namespace(
                    json=False,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("当前作用域：", rendered)
        self.assertIn("运行时：当前运行时状态与配置的 rp_filter 模式一致", rendered)

    def test_rules_render_prints_full_ruleset(self):
        paths = self._paths()
        rendered = SimpleNamespace(full_ruleset="table ip loha_port_forwarder {\n}\n")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), patch(
            "loha.cli.LoaderService.render",
            return_value=rendered,
        ), redirect_stdout(out):
            exit_code = cmd_rules_render(Namespace(json=False))
        self.assertEqual(0, exit_code)
        self.assertEqual(rendered.full_ruleset, out.getvalue())

    def test_rules_render_supports_json_output(self):
        paths = self._paths()
        rendered = SimpleNamespace(full_ruleset="table ip loha_port_forwarder {\n}\n")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), patch(
            "loha.cli.LoaderService.render",
            return_value=rendered,
        ), redirect_stdout(out):
            exit_code = cmd_rules_render(Namespace(json=True))
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("render", payload["result"]["code"])
        self.assertEqual("rules_render", payload["result"]["category"])
        self.assertEqual(rendered.full_ruleset, payload["ruleset"])

    def test_explicit_conntrack_system_command_reuses_shared_update_path(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        paths.conntrack_sysctl.parent.mkdir(parents=True, exist_ok=True)
        paths.conntrack_sysctl.write_text("stale\n", encoding="utf-8")
        paths.conntrack_modprobe.write_text("stale\n", encoding="utf-8")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            cmd_conntrack_system(
                Namespace()
            )
        self.assertEqual([("sysctl", "--system")], adapter.run_calls)
        self.assertIn('CONNTRACK_MODE="system"', paths.loha_conf.read_text(encoding="utf-8"))
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())
        rendered = out.getvalue()
        self.assertIn("Conntrack mode: system", rendered)
        self.assertIn("Runtime: system mode", rendered)

    def test_conntrack_profile_check_does_not_write_side_effect_files(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_conntrack_profile(
                Namespace(
                    profile="high",
                    check=True,
                )
            )
        self.assertEqual(0, exit_code)
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())
        self.assertEqual([], adapter.run_calls)
        self.assertIn("Check mode: changes would be applied", out.getvalue())

    def test_conntrack_profile_supports_json_changed_and_noop_output(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_conntrack_profile(
                Namespace(
                    profile="high",
                    json=True,
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("conntrack_update", payload["result"]["category"])
        self.assertTrue(payload["changed"])
        self.assertEqual("high", payload["config"]["CONNTRACK_MODE"])

        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_conntrack_profile(
                Namespace(
                    profile="high",
                    json=True,
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("conntrack_update", payload["result"]["category"])
        self.assertFalse(payload["changed"])

    def test_conntrack_auto_check_supports_json_preview_without_writing_files(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        adapter = RecordingAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), patch(
            "loha.cli._paths_from_args", return_value=paths
        ), redirect_stdout(out):
            exit_code = cmd_conntrack_auto(
                Namespace(
                    peak=12000,
                    memory_percent=35,
                    check=True,
                    json=True,
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertEqual("conntrack_check", payload["result"]["category"])
        self.assertTrue(payload["would_change"])
        self.assertEqual("auto", payload["config"]["CONNTRACK_MODE"])
        self.assertEqual("12000", payload["config"]["CONNTRACK_PEAK"])
        self.assertEqual("35", payload["config"]["CONNTRACK_MEMORY_PERCENT"])
        self.assertFalse(paths.conntrack_sysctl.exists())
        self.assertFalse(paths.conntrack_modprobe.exists())
        self.assertEqual([], adapter.run_calls)

    def test_build_parser_accepts_json_for_mutating_commands(self):
        parser = build_parser()
        args = parser.parse_args(["alias", "add", "--json", "VM_WEB", "192.168.10.20"])
        self.assertTrue(args.json)
        args = parser.parse_args(["config", "set", "--json", "PROTECTION_MODE", "nets"])
        self.assertTrue(args.json)
        args = parser.parse_args(["conntrack", "profile", "--json", "high"])
        self.assertTrue(args.json)
        args = parser.parse_args(["rules", "render", "--json"])
        self.assertTrue(args.json)

    def test_build_parser_rejects_removed_legacy_commands(self):
        parser = build_parser()
        for argv in (
            ["apply"],
            ["alias", "del", "VM_WEB"],
            ["port", "del", "tcp", "8080"],
            ["rpfilter", "strict"],
        ):
            with self.subTest(argv=argv), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parser.parse_args(argv)

    def test_main_json_error_uses_stratified_validation_exit_code(self):
        parser = SimpleNamespace(
            parse_args=lambda _argv=None: Namespace(
                command="dummy",
                json=True,
                etc_dir="/tmp/etc",
                prefix="/tmp/prefix",
                run_dir="/tmp/run",
                systemd_dir="/tmp/systemd",
                func=lambda _args: (_ for _ in ()).throw(ConfigValidationError("bad value")),
            )
        )
        out = io.StringIO()
        with patch("loha.cli.build_parser", return_value=parser), redirect_stdout(out):
            exit_code = main([])
        payload = json.loads(out.getvalue())
        self.assertEqual(3, exit_code)
        self.assertEqual(3, payload["error"]["exit_code"])
        self.assertEqual("validation_failed", payload["error"]["code"])
        self.assertEqual("validation", payload["error"]["category"])
        self.assertEqual("ConfigValidationError", payload["error"]["type"])

    def test_main_non_json_error_uses_stratified_lock_exit_code(self):
        parser = SimpleNamespace(
            parse_args=lambda _argv=None: Namespace(
                command="dummy",
                json=False,
                etc_dir="/tmp/etc",
                prefix="/tmp/prefix",
                run_dir="/tmp/run",
                systemd_dir="/tmp/systemd",
                func=lambda _args: (_ for _ in ()).throw(RulesLockError("busy")),
            )
        )
        out = io.StringIO()
        with patch("loha.cli.build_parser", return_value=parser), redirect_stdout(out):
            exit_code = main([])
        self.assertEqual(4, exit_code)
        self.assertIn("busy", out.getvalue())

    def test_config_set_enable_history_prints_status(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with patch("loha.cli._paths_from_args", return_value=paths), redirect_stdout(out):
            cmd_config_set(Namespace(key="enable_config_history", value="off"))
        self.assertIn('ENABLE_CONFIG_HISTORY="off"', paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("自动快照：已关闭", out.getvalue())

    def test_conntrack_status_uses_shared_report_output(self):
        report = ConntrackStatusReport(
            configured_mode="standard",
            expected_max=262144,
            expected_buckets=2048,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=True,
            modprobe_file_present=True,
            sysctl_matches_expected=True,
            modprobe_matches_expected=True,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="match",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_conntrack_status", return_value=report), redirect_stdout(out):
            cmd_conntrack_status(Namespace(etc_dir="/tmp/etc", prefix="/tmp/prefix", run_dir="/tmp/run", systemd_dir="/tmp/systemd"))
        rendered = out.getvalue()
        self.assertIn("Conntrack mode: standard", rendered)
        self.assertIn("Configured target: nf_conntrack_max=262144, nf_conntrack_buckets=2048", rendered)

    def test_conntrack_status_supports_json_output(self):
        report = ConntrackStatusReport(
            configured_mode="standard",
            expected_max=262144,
            expected_buckets=2048,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=True,
            modprobe_file_present=True,
            sysctl_matches_expected=True,
            modprobe_matches_expected=True,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="match",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_conntrack_status", return_value=report), redirect_stdout(out):
            exit_code = cmd_conntrack_status(
                Namespace(
                    json=True,
                    etc_dir="/tmp/etc",
                    prefix="/tmp/prefix",
                    run_dir="/tmp/run",
                    systemd_dir="/tmp/systemd",
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(0, exit_code)
        self.assertTrue(payload["ok"])
        self.assertEqual("standard", payload["conntrack"]["configured_mode"])
        self.assertEqual(262144, payload["conntrack"]["expected_max"])
        self.assertIn("matches runtime nf_conntrack_max=262144", payload["conntrack"]["runtime_description"])

    def test_conntrack_status_uses_runtime_locale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        report = ConntrackStatusReport(
            configured_mode="standard",
            expected_max=262144,
            expected_buckets=2048,
            expected_sysctl_content="",
            expected_modprobe_content="",
            sysctl_file_present=True,
            modprobe_file_present=True,
            sysctl_matches_expected=True,
            modprobe_matches_expected=True,
            runtime_max="262144",
            runtime_buckets="2048",
            runtime_state="match",
        )
        out = io.StringIO()
        with patch("loha.cli.collect_conntrack_status", return_value=report), redirect_stdout(out):
            cmd_conntrack_status(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("配置目标：nf_conntrack_max=262144，nf_conntrack_buckets=2048", rendered)
        self.assertIn("运行时：运行时 nf_conntrack_max=262144 与模式 standard 一致", rendered)

    def test_config_rollback_latest_reports_reload_hint(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        write_transaction(
            paths,
            config_text=paths.loha_conf.read_text(encoding="utf-8"),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\n",
            source="cli",
            reason="alias-add",
        )
        write_transaction(
            paths,
            config_text=paths.loha_conf.read_text(encoding="utf-8"),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\nALIAS\tVM_API\t192.0.2.20\n",
            source="cli",
            reason="alias-add",
        )
        out = io.StringIO()
        with redirect_stdout(out):
            cmd_config_rollback(
                Namespace(
                    selector="latest",
                    apply=False,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertIn("The latest configuration snapshot has been restored.", rendered)
        self.assertIn("Run `loha reload` to apply the restored configuration.", rendered)

    def test_config_rollback_apply_prints_reload_result(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        write_transaction(
            paths,
            config_text=paths.loha_conf.read_text(encoding="utf-8"),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\n",
            source="cli",
            reason="alias-add",
        )
        out = io.StringIO()
        with patch("loha.cli._service_reload", return_value="Rules have been applied to kernel and service state synced."):
            with redirect_stdout(out):
                cmd_config_rollback(
                    Namespace(
                        selector="latest",
                        apply=True,
                        etc_dir=str(paths.etc_dir),
                        prefix=str(paths.prefix),
                        run_dir=str(paths.run_dir),
                        systemd_dir=str(paths.systemd_unit_dir),
                    )
                )
        rendered = out.getvalue()
        self.assertIn("The latest configuration snapshot has been restored.", rendered)
        self.assertIn("Rules have been applied to kernel and service state synced.", rendered)

    def test_reload_uses_runtime_locale_and_systemctl_reload_path(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        adapter = ServiceAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), redirect_stdout(out):
            exit_code = cmd_reload(
                Namespace(
                    full=False,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(0, exit_code)
        self.assertEqual([("systemctl", "is-active", "--quiet", "loha.service")], adapter.run_calls)
        self.assertEqual([("reload", "loha.service")], adapter.systemctl_calls)
        self.assertIn("映射已成功热更新", out.getvalue())

    def test_reload_full_uses_systemctl_restart_path(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        adapter = ServiceAdapter()
        out = io.StringIO()
        with patch("loha.cli.SubprocessSystemAdapter", return_value=adapter), redirect_stdout(out):
            exit_code = cmd_reload(
                Namespace(
                    full=True,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(0, exit_code)
        self.assertEqual([], adapter.run_calls)
        self.assertEqual([("restart", "loha.service")], adapter.systemctl_calls)
        self.assertIn("Full ruleset initialized successfully", out.getvalue())

    def test_config_rollback_prints_rescue_dir_when_recovery_fails(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        out = io.StringIO()
        with patch("loha.cli.rollback_snapshot", side_effect=HistoryError("boom", rescue_dir=paths.etc_dir / "rescue")), redirect_stdout(out):
            exit_code = cmd_config_rollback(
                Namespace(
                    selector="latest",
                    apply=True,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(6, exit_code)
        self.assertIn("Rollback rescue files were kept in:", out.getvalue())

    def test_config_rollback_apply_restores_previous_files_when_reload_recovery_succeeds(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        base_config_text = paths.loha_conf.read_text(encoding="utf-8")
        base_rules_text = "ALIAS\tVM_WEB\t192.168.10.20\n"
        changed_config_text = render_canonical_text(
            normalize_mapping(
                {
                    "EXTERNAL_IFS": "eth0",
                    "PRIMARY_EXTERNAL_IF": "eth0",
                    "LISTEN_IPS": "203.0.113.10,198.51.100.20",
                    "DEFAULT_SNAT_IP": "198.51.100.20",
                    "LAN_IFS": "eth1",
                    "LAN_NETS": "192.168.10.0/24",
                    "PROTECTION_MODE": "backends",
                    "ENABLE_CONFIG_HISTORY": "on",
                }
            )
        )
        changed_rules_text = "ALIAS\tVM_WEB\t192.168.10.20\nALIAS\tVM_API\t192.0.2.20\n"
        write_transaction(paths, config_text=base_config_text, rules_text=base_rules_text, source="cli", reason="alias-add")
        write_transaction(paths, config_text=changed_config_text, rules_text=changed_rules_text, source="cli", reason="config-set")

        out = io.StringIO()
        with patch("loha.cli._service_reload", side_effect=[RuntimeError("boom"), "recovered current state"]), redirect_stdout(out):
            exit_code = cmd_config_rollback(
                Namespace(
                    selector="latest",
                    apply=True,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )

        rendered = out.getvalue()
        self.assertEqual(6, exit_code)
        self.assertIn("rollback apply failed; previous files were restored", rendered)
        self.assertNotIn("Rollback rescue files were kept in:", rendered)
        self.assertIn('DEFAULT_SNAT_IP="198.51.100.20"', paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("ALIAS\tVM_API\t192.0.2.20", paths.rules_conf.read_text(encoding="utf-8"))

    def test_config_rollback_latest_uses_checkpoint_message_after_first_rollback(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        write_transaction(
            paths,
            config_text=paths.loha_conf.read_text(encoding="utf-8"),
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\n",
            source="cli",
            reason="alias-add",
        )
        changed_config_text = render_canonical_text(
            normalize_mapping(
                {
                    "EXTERNAL_IFS": "eth0",
                    "PRIMARY_EXTERNAL_IF": "eth0",
                    "LISTEN_IPS": "203.0.113.10,198.51.100.20",
                    "DEFAULT_SNAT_IP": "198.51.100.20",
                    "LAN_IFS": "eth1",
                    "LAN_NETS": "192.168.10.0/24",
                    "PROTECTION_MODE": "backends",
                    "ENABLE_CONFIG_HISTORY": "on",
                }
            )
        )
        write_transaction(
            paths,
            config_text=changed_config_text,
            rules_text="ALIAS\tVM_WEB\t192.168.10.20\nALIAS\tVM_API\t192.0.2.20\n",
            source="cli",
            reason="config-set",
        )
        cmd_config_rollback(
            Namespace(
                selector="latest",
                apply=False,
                etc_dir=str(paths.etc_dir),
                prefix=str(paths.prefix),
                run_dir=str(paths.run_dir),
                systemd_dir=str(paths.systemd_unit_dir),
            )
        )

        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = cmd_config_rollback(
                Namespace(
                    selector="latest",
                    apply=False,
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(0, exit_code)
        rendered = out.getvalue()
        self.assertIn("The rollback checkpoint has been restored.", rendered)
        self.assertIn('DEFAULT_SNAT_IP="198.51.100.20"', paths.loha_conf.read_text(encoding="utf-8"))

    def test_doctor_prints_summary_line(self):
        out = io.StringIO()
        with patch("loha.cli.run_doctor", return_value=[]), redirect_stdout(out):
            exit_code = cmd_doctor(Namespace(etc_dir="/tmp/etc", prefix="/tmp/prefix", run_dir="/tmp/run", systemd_dir="/tmp/systemd"))
        self.assertEqual(0, exit_code)
        self.assertIn("Doctor summary: all checks passed", out.getvalue())

    def test_doctor_supports_json_output(self):
        out = io.StringIO()
        results = [
            DoctorResult(
                "fail",
                "Dependency check: missing nft",
                detail="detail",
                hint="hint",
                summary_key="doctor.dependency.missing",
                detail_key="doctor.detail.current_value",
                hint_key="doctor.hint.run_as_root",
                values={"binary": "nft"},
            )
        ]
        with patch("loha.cli.run_doctor", return_value=results), redirect_stdout(out):
            exit_code = cmd_doctor(
                Namespace(
                    json=True,
                    etc_dir="/tmp/etc",
                    prefix="/tmp/prefix",
                    run_dir="/tmp/run",
                    systemd_dir="/tmp/systemd",
                )
            )
        payload = json.loads(out.getvalue())
        self.assertEqual(1, exit_code)
        self.assertFalse(payload["ok"])
        self.assertEqual("report", payload["result"]["code"])
        self.assertEqual("doctor_report", payload["result"]["category"])
        self.assertEqual(1, payload["summary"]["fail"])
        self.assertEqual("fail", payload["results"][0]["level"])
        self.assertEqual("doctor.dependency.missing", payload["results"][0]["summary_key"])

    def test_doctor_summary_uses_runtime_locale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with patch("loha.cli.run_doctor", return_value=[]), redirect_stdout(out):
            exit_code = cmd_doctor(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(0, exit_code)
        self.assertIn("诊断总结：所有检查均已通过", out.getvalue())

    def test_doctor_result_lines_use_runtime_locale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        results = [
            DoctorResult(
                "warn",
                "Dependency check: missing nft",
                detail="current=0",
                summary_key="doctor.dependency.missing",
                summary_default="Dependency check: missing {binary}",
                detail_key="doctor.detail.current_value",
                detail_default="current={current}",
                values={"binary": "nft", "current": "0"},
            )
        ]
        with patch("loha.cli.run_doctor", return_value=results), redirect_stdout(out):
            exit_code = cmd_doctor(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        rendered = out.getvalue()
        self.assertEqual(0, exit_code)
        self.assertIn("[警告] 依赖检查：缺少 nft", rendered)
        self.assertIn("当前值=0", rendered)

    def test_resolve_editor_command_rejects_whitespace_wrapped_commands(self):
        with self.assertRaises(Exception):
            _resolve_editor_command("vim -f")

    def test_validate_rules_after_edit_uses_loader_check_only_path(self):
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
                "LOCALE": "zh_CN",
            }
        )
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.loha_conf.write_text(render_canonical_text(config), encoding="utf-8")
        paths.rules_conf.write_text(render_rules_text(type("Rules", (), {"aliases": (), "ports": ()})()), encoding="utf-8")
        runtime = _runtime_i18n(paths)
        with patch("loha.cli.LoaderService.apply", return_value="checked") as apply_mock:
            message = _validate_rules_after_edit(paths, runtime, RecordingAdapter())
        self.assertEqual("checked", message)
        apply_mock.assert_called_once_with(mode="full", check_only=True, runtime=runtime)

    def test_edit_rules_conf_validates_after_editor_returns(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        out = io.StringIO()
        with patch("loha.cli._resolve_editor_command", return_value="/usr/bin/test-editor"), patch(
            "loha.cli._validate_rules_after_edit",
            return_value="checked",
        ), redirect_stdout(out):
            exit_code = _edit_rules_conf(
                paths,
                runtime,
                adapter=RecordingAdapter(),
                run_editor=lambda argv, check=False: subprocess.CompletedProcess(argv, 0),
            )
        self.assertEqual(0, exit_code)
        rendered = out.getvalue()
        self.assertIn("Validating edited rules.conf...", rendered)
        self.assertIn("checked", rendered)
        self.assertIn("rules.conf validation passed.", rendered)

    def test_edit_rules_conf_reports_localized_rules_syntax_error_in_tui_flow(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        runtime = _runtime_i18n(paths)
        out = io.StringIO()
        with patch("loha.cli._resolve_editor_command", return_value="/usr/bin/test-editor"), patch(
            "loha.cli._validate_rules_after_edit",
            side_effect=RulesSyntaxError("line 3: PORT requires exactly 4 columns"),
        ), redirect_stdout(out):
            result = _run_menu_action(
                runtime,
                _edit_rules_conf,
                paths,
                runtime,
                adapter=RecordingAdapter(),
                run_editor=lambda argv, check=False: subprocess.CompletedProcess(argv, 0),
            )
        self.assertIsNone(result)
        rendered = out.getvalue()
        self.assertIn("rules.conf 校验失败", rendered)
        self.assertIn("第 3 行：PORT 需要正好 4 列", rendered)

    def test_main_rules_render_reports_localized_rules_syntax_error(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        paths.rules_conf.write_text("PORT\ttcp\t8080\tVM_WEB\n", encoding="utf-8")
        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = main(
                [
                    "--etc-dir",
                    str(paths.etc_dir),
                    "--prefix",
                    str(paths.prefix),
                    "--run-dir",
                    str(paths.run_dir),
                    "--systemd-dir",
                    str(paths.systemd_unit_dir),
                    "rules",
                    "render",
                ]
            )
        self.assertEqual(2, exit_code)
        self.assertIn("第 1 行：PORT 需要正好 4 列", out.getvalue())

    def test_edit_rules_conf_reports_editor_launch_failure(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        with patch("loha.cli._resolve_editor_command", return_value="/usr/bin/test-editor"), self.assertRaises(ApplyError):
            _edit_rules_conf(
                paths,
                runtime,
                adapter=RecordingAdapter(),
                run_editor=lambda argv, check=False: subprocess.CompletedProcess(argv, 3),
            )

    def test_confirm_rules_conf_edit_returns_false_on_enter(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        out = io.StringIO()
        prompts = []
        with redirect_stdout(out):
            self.assertFalse(_confirm_rules_conf_edit(runtime, input_func=lambda prompt: prompts.append(prompt) or ""))
        rendered = out.getvalue()
        self.assertIn("raw rules.conf editor", rendered)
        self.assertTrue(prompts)
        self.assertIn("Continue editing rules.conf? [y/N]", prompts[0])

    def test_confirm_rules_conf_edit_accepts_yes(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        with patch("builtins.input", return_value="y"):
            self.assertTrue(_confirm_rules_conf_edit(runtime))

    def test_interactive_auth_switch_loops_on_invalid_selection(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        runtime_paths = Paths(
            etc_dir=paths.etc_dir,
            run_dir=paths.run_dir,
            prefix=paths.prefix,
            systemd_unit_dir=paths.systemd_unit_dir,
        )
        out = io.StringIO()
        with patch("builtins.input", side_effect=["9", "2", "", "n"]), redirect_stdout(out):
            exit_code = _interactive_auth_switch(paths, _runtime_i18n(runtime_paths), adapter=RecordingAdapter())
        self.assertEqual(0, exit_code)
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('AUTH_MODE="label"', rendered)
        self.assertIn("Invalid option. Please enter 1 or 2.", out.getvalue())

    def test_interactive_auth_switch_can_switch_back_to_mark_via_shared_selected_plan(self):
        paths = self._cli_paths()
        paths.etc_dir.mkdir(parents=True, exist_ok=True)
        paths.rules_conf.write_text("", encoding="utf-8")
        paths.loha_conf.write_text(
            render_canonical_text(
                normalize_mapping(
                    {
                        "AUTH_MODE": "label",
                        "DNAT_MARK": "",
                        "DNAT_LABEL": "56",
                        "EXTERNAL_IFS": "eth0",
                        "PRIMARY_EXTERNAL_IF": "eth0",
                        "LISTEN_IPS": "203.0.113.10",
                        "DEFAULT_SNAT_IP": "203.0.113.10",
                        "LAN_IFS": "eth1",
                        "LAN_NETS": "192.168.10.0/24",
                        "PROTECTION_MODE": "backends",
                        "ENABLE_CONFIG_HISTORY": "on",
                        "LOCALE": "en_US",
                    }
                )
            ),
            encoding="utf-8",
        )
        runtime_paths = Paths(
            etc_dir=paths.etc_dir,
            run_dir=paths.run_dir,
            prefix=paths.prefix,
            systemd_unit_dir=paths.systemd_unit_dir,
        )
        out = io.StringIO()
        with patch("builtins.input", side_effect=["1", "", "n"]), redirect_stdout(out):
            exit_code = _interactive_auth_switch(paths, _runtime_i18n(runtime_paths), adapter=RecordingAdapter())
        self.assertEqual(0, exit_code)
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('AUTH_MODE="mark"', rendered)
        self.assertIn('DNAT_MARK="0x10000000"', rendered)
        self.assertIn("Dynamic detection unavailable.", out.getvalue())

    def test_interactive_auth_switch_can_reload_immediately(self):
        paths = self._cli_paths()
        self._write_config(paths, history_mode="on")
        runtime_paths = Paths(
            etc_dir=paths.etc_dir,
            run_dir=paths.run_dir,
            prefix=paths.prefix,
            systemd_unit_dir=paths.systemd_unit_dir,
        )
        out = io.StringIO()
        with patch("builtins.input", side_effect=["2", "", ""]), patch(
            "loha.cli._service_reload",
            return_value="full reload applied",
        ), redirect_stdout(out):
            exit_code = _interactive_auth_switch(paths, _runtime_i18n(runtime_paths), adapter=RecordingAdapter())
        self.assertEqual(0, exit_code)
        self.assertIn("full reload applied", out.getvalue())

    def test_cli_yes_no_prompt_retries_invalid_input(self):
        runtime = build_runtime_i18n_for_paths(None, requested_locale="en_US")
        answers = iter(["maybe", "y"])
        out = io.StringIO()
        with redirect_stdout(out):
            result = _prompt_yes_no(
                runtime,
                "history.rollback.apply_prompt",
                "Apply restored configuration immediately with `loha reload`? [y/N]",
                default=False,
                input_func=lambda _prompt="": next(answers),
            )
        self.assertTrue(result)
        self.assertIn("Invalid choice.", out.getvalue())

    def test_watch_mark_detection_reports_running_and_stopped_states(self):
        runtime = build_runtime_i18n_for_paths(None, requested_locale="en_US")
        current = SimpleNamespace(as_dict=lambda: {"AUTH_MODE": "label", "DNAT_MARK": "", "DNAT_LABEL": "56"})
        survey = SimpleNamespace(
            suggested_mark="0x40000000",
            available_marks=("0x40000000",),
            conflicting_marks=(),
            runtime_scan_available=True,
            static_conflicting_marks=(),
            runtime_conflicting_marks=(),
            static_conflict_samples=(),
            runtime_conflict_samples=(),
        )
        out = io.StringIO()
        with patch("loha.cli.survey_auth_mark_candidates", return_value=survey), redirect_stdout(out):
            result = _watch_mark_detection_interactive(
                Paths(),
                runtime,
                current,
                adapter=RecordingAdapter(),
                wait_for_stop=lambda _timeout: True,
            )
        self.assertEqual("0x40000000", result.suggested_mark)
        rendered = out.getvalue()
        self.assertIn("Dynamic ct mark conflict detection is running.", rendered)
        self.assertIn("Current suggested ct mark value: 0x40000000", rendered)
        self.assertIn("Dynamic ct mark conflict detection stopped.", rendered)

    def test_watch_mark_detection_reports_runtime_conflict_source_and_samples(self):
        runtime = build_runtime_i18n_for_paths(None, requested_locale="en_US")
        current = SimpleNamespace(as_dict=lambda: {"AUTH_MODE": "mark", "DNAT_MARK": "0x10000000", "DNAT_LABEL": ""})
        survey = SimpleNamespace(
            suggested_mark="0x10000000",
            available_marks=("0x10000000",),
            conflicting_marks=(
                "0x40000000",
                "0x20000000",
                "0x08000000",
            ),
            runtime_scan_available=True,
            static_conflicting_marks=(),
            runtime_conflicting_marks=(
                "0x40000000",
                "0x20000000",
                "0x08000000",
            ),
            static_conflict_samples=(),
            runtime_conflict_samples=("0x68000000",),
        )
        out = io.StringIO()
        with patch("loha.cli.survey_auth_mark_candidates", return_value=survey), redirect_stdout(out):
            _watch_mark_detection_interactive(
                Paths(),
                runtime,
                current,
                adapter=RecordingAdapter(),
                wait_for_stop=lambda _timeout: True,
            )
        rendered = out.getvalue()
        self.assertIn(
            "Detected candidate bits currently present in live conntrack marks: 30,29,27",
            rendered,
        )
        self.assertIn("Observed live conntrack mark values: 0x68000000", rendered)

    def test_detect_listener_conflicts_returns_full_conflict_set(self):
        adapter = RecordingAdapter()
        adapter.listeners = {("tcp", 80), ("tcp", 81), ("udp", 53)}
        self.assertEqual((80, 81), _detect_listener_conflicts(adapter, "tcp", "80-81"))
        self.assertEqual((53,), _detect_listener_conflicts(adapter, "udp", "53"))

    def test_menu_alias_retries_invalid_ipv4_in_place(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["name"] = args.name
            captured["ip"] = args.ip
            return 0

        with patch("loha.cli.cmd_alias_add", side_effect=fake_cmd), patch(
            "builtins.input",
            side_effect=["1", "vm_web", "not-an-ip", "192.168.10.20", "0"],
        ):
            _menu_alias(paths, runtime)
        self.assertEqual("VM_WEB", captured["name"])
        self.assertEqual("192.168.10.20", captured["ip"])

    def test_menu_add_port_can_continue_when_listener_scan_unavailable(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["force"] = args.force
            return 0

        with patch("loha.cli.SubprocessSystemAdapter", return_value=RecordingAdapter()), patch(
            "loha.cli.cmd_port_add",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["1", "8080", "192.168.10.2", "", "y", "0"],
        ):
            _menu_add_port(paths, runtime)
        self.assertTrue(captured["force"])

    def test_menu_add_port_retries_invalid_port_spec_in_place(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["orig"] = args.orig_port_spec
            captured["dest_port"] = args.dest_port_spec
            return 0

        with patch("loha.cli.SubprocessSystemAdapter", return_value=RecordingAdapter()), patch(
            "loha.cli.cmd_port_add",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["1", "bad", "8080", "192.168.10.2", "", "y", "0"],
        ):
            _menu_add_port(paths, runtime)
        self.assertEqual("8080", captured["orig"])
        self.assertEqual("8080", captured["dest_port"])

    def test_menu_config_history_can_toggle_and_exit(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        runtime = _runtime_i18n(paths)
        called = []

        def fake_history(args):
            called.append(args.subcommand)
            return 0

        with patch("loha.cli.cmd_config_history", side_effect=fake_history), patch(
            "builtins.input",
            side_effect=["1", "0"],
        ):
            _menu_config_history(paths, runtime)
        self.assertEqual(["disable"], called)

    def test_menu_wan_to_wan_updates_setting_and_exits(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["key"] = args.key
            captured["value"] = args.value
            return 0

        with patch(
            "loha.cli._load_or_default_config",
            return_value={"ENABLE_WAN_TO_WAN": "off"},
        ), patch(
            "loha.cli.cmd_config_set",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["1", "0"],
        ):
            _menu_wan_to_wan(paths, runtime)
        self.assertEqual("ENABLE_WAN_TO_WAN", captured["key"])
        self.assertEqual("on", captured["value"])

    def test_menu_tcpmss_clamp_skips_noop_changes(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        out = io.StringIO()

        with patch(
            "loha.cli._load_or_default_config",
            return_value={"ENABLE_TCPMSS_CLAMP": "on"},
        ), patch(
            "loha.cli.cmd_config_set",
        ) as fake_cmd, patch(
            "builtins.input",
            side_effect=["1", "0"],
        ), redirect_stdout(out):
            _menu_tcpmss_clamp(paths, runtime)
        self.assertFalse(fake_cmd.called)
        self.assertIn("Already applied.", out.getvalue())

    def test_menu_counter_mode_updates_setting_and_exits(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["key"] = args.key
            captured["value"] = args.value
            return 0

        with patch(
            "loha.cli._load_or_default_config",
            return_value={"COUNTER_MODE": "off"},
        ), patch(
            "loha.cli.cmd_config_set",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["2", "0"],
        ):
            _menu_counter_mode(paths, runtime)
        self.assertEqual("COUNTER_MODE", captured["key"])
        self.assertEqual("minimal", captured["value"])

    def test_menu_strict_validation_updates_toggle_and_exits(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["key"] = args.key
            captured["value"] = args.value
            return 0

        with patch(
            "loha.cli._load_or_default_config",
            return_value={
                "ENABLE_STRICT_LAN_VALIDATION": "off",
                "INTERNAL_IFS": "eth1",
                "LAN_IFS": "eth1",
                "TRUSTED_INTERNAL_NETS": "192.168.10.0/24",
                "LAN_NETS": "192.168.10.0/24",
            },
        ), patch(
            "loha.cli.cmd_config_set",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["1", "0"],
        ):
            _menu_strict_validation(paths, runtime)
        self.assertEqual("ENABLE_STRICT_LAN_VALIDATION", captured["key"])
        self.assertEqual("on", captured["value"])

    def test_menu_strict_validation_updates_internal_interfaces_and_exits(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["key"] = args.key
            captured["value"] = args.value
            return 0

        with patch(
            "loha.cli._load_or_default_config",
            return_value={
                "ENABLE_STRICT_LAN_VALIDATION": "off",
                "INTERNAL_IFS": "eth1",
                "LAN_IFS": "eth1",
                "TRUSTED_INTERNAL_NETS": "192.168.10.0/24",
                "LAN_NETS": "192.168.10.0/24",
            },
        ), patch(
            "loha.cli.cmd_config_set",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["3", "eth1,eth2", "0"],
        ):
            _menu_strict_validation(paths, runtime)
        self.assertEqual("INTERNAL_IFS", captured["key"])
        self.assertEqual("eth1,eth2", captured["value"])

    def test_menu_strict_validation_skips_noop_trusted_networks(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        out = io.StringIO()

        with patch(
            "loha.cli._load_or_default_config",
            return_value={
                "ENABLE_STRICT_LAN_VALIDATION": "off",
                "INTERNAL_IFS": "eth1",
                "LAN_IFS": "eth1",
                "TRUSTED_INTERNAL_NETS": "192.168.10.0/24",
                "LAN_NETS": "192.168.10.0/24",
            },
        ), patch(
            "loha.cli.cmd_config_set",
        ) as fake_cmd, patch(
            "builtins.input",
            side_effect=["4", "192.168.10.0/24", "0"],
        ), redirect_stdout(out):
            _menu_strict_validation(paths, runtime)
        self.assertFalse(fake_cmd.called)
        self.assertIn("Already applied.", out.getvalue())

    def test_menu_rpfilter_updates_mode_and_exits(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["mode"] = args.mode
            return 0

        with patch(
            "loha.cli._load_or_default_config",
            return_value={},
        ), patch(
            "loha.cli._collect_rpfilter_report",
            return_value=object(),
        ), patch(
            "loha.cli.format_rp_filter_status_lines",
            return_value=("rp_filter status",),
        ), patch(
            "loha.cli._rpfilter_selection_is_applied",
            return_value=False,
        ), patch(
            "loha.cli.cmd_rpfilter",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["2", "0"],
        ):
            _menu_rpfilter(paths, runtime)
        self.assertEqual("strict", captured["mode"])

    def test_menu_conntrack_profile_updates_setting_and_exits(self):
        paths = self._paths()
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["profile"] = args.profile
            return 0

        with patch(
            "loha.cli._load_or_default_config",
            return_value={
                "CONNTRACK_PEAK": "",
                "CONNTRACK_MEMORY_PERCENT": "",
                "CONNTRACK_TARGET_MAX": "",
            },
        ), patch(
            "loha.cli._collect_conntrack_report",
            return_value=object(),
        ), patch(
            "loha.cli.format_conntrack_status_lines",
            return_value=("conntrack status",),
        ), patch(
            "loha.cli._conntrack_selection_is_applied",
            return_value=False,
        ), patch(
            "loha.cli.cmd_conntrack_profile",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["2", "0"],
        ):
            _menu_conntrack(paths, runtime)
        self.assertEqual("conservative", captured["profile"])

    def test_menu_advanced_prints_shared_current_status_panel(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        runtime = _runtime_i18n(paths)
        out = io.StringIO()
        with patch(
            "loha.cli._build_advanced_status_lines",
            return_value=("Automatic snapshots: enabled", "External interface binding status: configured binding"),
        ), patch(
            "builtins.input",
            side_effect=["0"],
        ), redirect_stdout(out):
            _menu_advanced(paths, runtime)
        rendered = out.getvalue()
        self.assertIn("Advanced Settings", rendered)
        self.assertIn("Current Status", rendered)
        self.assertIn("Automatic snapshots: enabled", rendered)
        self.assertIn("External interface binding status: configured binding", rendered)
        self.assertIn("WAN-to-WAN Forwarding", rendered)
        self.assertIn("Strict Internal Source Validation", rendered)

    def test_menu_conntrack_retries_memory_percent_above_max(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        runtime = _runtime_i18n(paths)
        captured = {}

        def fake_cmd(args):
            captured["peak"] = args.peak
            captured["memory_percent"] = args.memory_percent
            return 0

        with patch("loha.cli.cmd_conntrack_auto", side_effect=fake_cmd), patch(
            "builtins.input",
            side_effect=["5", "12000", "95", "35", "0"],
        ):
            _menu_conntrack(paths, runtime)
        self.assertEqual(12000, captured["peak"])
        self.assertEqual(35, captured["memory_percent"])

    def test_main_menu_language_switch_uses_interactive_selector(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        captured = {}

        def fake_cmd(args):
            captured["key"] = args.key
            captured["value"] = args.value
            return 0

        with patch("loha.cli.select_locale_interactive", return_value="zh_CN"), patch(
            "loha.cli.cmd_config_set",
            side_effect=fake_cmd,
        ), patch(
            "builtins.input",
            side_effect=["9", "0"],
        ):
            _interactive_menu(paths)
        self.assertEqual("LOCALE", captured["key"])
        self.assertEqual("zh_CN", captured["value"])

    def test_main_menu_non_english_language_entry_shows_bilingual_label(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with patch("builtins.input", side_effect=["0"]), redirect_stdout(out):
            _interactive_menu(paths)
        self.assertIn("切换语言 / Change Language", out.getvalue())

    def test_main_menu_title_is_fixed_and_includes_version(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with patch("builtins.input", side_effect=["0"]), redirect_stdout(out):
            _interactive_menu(paths)
        rendered = out.getvalue()
        self.assertIn(f"LOHA Port Forwarder v{__version__}", rendered)
        self.assertNotIn("LOHA 端口转发器", rendered)

    def test_main_menu_rendered_rules_label_clarifies_current_config_preview(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with patch("builtins.input", side_effect=["0"]), redirect_stdout(out):
            _interactive_menu(paths)
        self.assertIn("预览当前配置渲染的 nft 规则", out.getvalue())

    def test_main_menu_reload_passes_runtime_to_service_reload(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on", locale="zh_CN")
        out = io.StringIO()
        with patch("loha.cli._service_reload", return_value="ok") as reload_mock, patch(
            "builtins.input",
            side_effect=["5", "0"],
        ), redirect_stdout(out):
            _interactive_menu(paths)
        self.assertEqual("zh_CN", reload_mock.call_args.kwargs["runtime"].locale)
        self.assertIn("ok", out.getvalue())

    def test_main_menu_rendered_rules_renders_fresh_output_even_if_debug_snapshot_is_stale(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        paths.run_dir.mkdir(parents=True, exist_ok=True)
        paths.debug_ruleset_file.write_text("stale snapshot\n", encoding="utf-8")
        rendered = SimpleNamespace(full_ruleset="table ip loha_port_forwarder {\n  # fresh\n}\n")
        out = io.StringIO()
        with patch("loha.cli.LoaderService.render", return_value=rendered), patch(
            "builtins.input",
            side_effect=["7", "0"],
        ), redirect_stdout(out):
            _interactive_menu(paths)
        shown = out.getvalue()
        self.assertIn(rendered.full_ruleset, shown)
        self.assertNotIn("stale snapshot", shown)

    def test_config_wizard_can_jump_from_summary_to_gateway_section_and_save(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        inputs = [
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "5",
            "1",
            "",
            "",
            "",
            "",
            "",
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("loha.cli.SubprocessSystemAdapter", return_value=RecordingAdapter()):
                exit_code = cmd_config_wizard(
                    Namespace(
                        etc_dir=str(paths.etc_dir),
                        prefix=str(paths.prefix),
                        run_dir=str(paths.run_dir),
                        systemd_dir=str(paths.systemd_unit_dir),
                    )
                )
        self.assertEqual(0, exit_code)
        rendered = paths.loha_conf.read_text(encoding="utf-8")
        self.assertIn('ENABLE_EGRESS_SNAT="on"', rendered)
        self.assertIn('EGRESS_NETS="192.168.10.0/24"', rendered)

    def test_config_wizard_cancel_returns_zero_without_rewriting_config(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        original = paths.loha_conf.read_text(encoding="utf-8")
        out = io.StringIO()
        with patch(
            "loha.cli.run_config_wizard_flow",
            side_effect=KeyboardInterrupt("wizard cancelled"),
        ), redirect_stdout(out):
            exit_code = cmd_config_wizard(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(0, exit_code)
        self.assertEqual(original, paths.loha_conf.read_text(encoding="utf-8"))
        self.assertIn("The configuration wizard was cancelled.", out.getvalue())

    def test_config_wizard_materializes_toggle_shortcuts_when_loading_initial_config(self):
        paths = self._paths()
        self._write_config(paths, history_mode="on")
        rendered = paths.loha_conf.read_text(encoding="utf-8").replace('ENABLE_HAIRPIN="on"', 'ENABLE_HAIRPIN="auto"')
        paths.loha_conf.write_text(rendered, encoding="utf-8")
        captured = {}

        def fake_flow(*_args, **kwargs):
            captured["initial"] = kwargs["initial"]
            raise KeyboardInterrupt("wizard cancelled")

        with patch("loha.cli.run_config_wizard_flow", side_effect=fake_flow):
            exit_code = cmd_config_wizard(
                Namespace(
                    etc_dir=str(paths.etc_dir),
                    prefix=str(paths.prefix),
                    run_dir=str(paths.run_dir),
                    systemd_dir=str(paths.systemd_unit_dir),
                )
            )
        self.assertEqual(0, exit_code)
        self.assertEqual("on", captured["initial"]["ENABLE_HAIRPIN"])


if __name__ == "__main__":
    unittest.main()
