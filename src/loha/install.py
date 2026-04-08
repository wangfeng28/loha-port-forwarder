import argparse
import socket
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

from .config_access import load_management_config
from .config import normalize_mapping, render_canonical_text, recommended_config
from .constants import LOHA_NFT_TABLE_NAME
from .control_tx import commit_desired_state, control_file_lock, remove_runtime_state, update_runtime_state
from .exceptions import ApplyError, LohaError
from .history import capture_snapshot_if_enabled
from .i18n import (
    RuntimeI18N,
    build_runtime_i18n,
    pick_locale,
    read_first_config_value,
    render_localized_message,
    render_localized_messages,
    resolve_locale_directory,
    runtime_template,
    runtime_translate,
    select_locale_interactive,
)
from .input_parsing import InputValidationError, parse_yes_no
from .models import CanonicalConfig, InstallStepResult, LocalizedMessage, MenuOption, Paths, RuntimeStateSnapshot
from .precheck import count_level, has_failures, run_install_prechecks
from .runtime_binding import sync_runtime_binding_state, sync_toggle_shortcut_state
from .rules import load_rules, render_rules_text
from .system import SubprocessSystemAdapter, SystemAdapter
from .system_features import apply_system_feature_files
from .wizard import prompt_menu_single, prompt_summary_action, run_config_wizard_flow


UPSTREAM_FIREWALL_UNITS = (
    "firewalld.service",
    "ufw.service",
    "nftables.service",
    "netfilter-persistent.service",
    "iptables.service",
    "ip6tables.service",
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _copy_tree(src: Path, dst: Path, *, dry_run: bool, i18n: Optional[RuntimeI18N] = None) -> None:
    if dry_run:
        if i18n is None:
            print(f"[dry-run] copy {src} -> {dst}")
        else:
            print(_t(i18n, "install.dry_run.copy", "[dry-run] copy {src} -> {dst}", src=src, dst=dst))
        return
    if dst.exists():
        _remove_path(dst, dry_run=False, i18n=i18n)
    shutil.copytree(src, dst)


def _write_text(path: Path, text: str, *, dry_run: bool, i18n: Optional[RuntimeI18N] = None) -> None:
    if dry_run:
        if i18n is None:
            print(f"[dry-run] write {path}")
        else:
            print(_t(i18n, "install.dry_run.write", "[dry-run] write {path}", path=path))
        print(text.rstrip())
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _ensure_directory(path: Path, *, dry_run: bool, i18n: Optional[RuntimeI18N] = None) -> None:
    if dry_run:
        if i18n is None:
            print(f"[dry-run] mkdir -p {path}")
        else:
            print(_t(i18n, "install.dry_run.mkdir", "[dry-run] mkdir -p {path}", path=path))
        return
    path.mkdir(parents=True, exist_ok=True)


def _remove_path(path: Path, *, dry_run: bool, i18n: Optional[RuntimeI18N] = None) -> None:
    if dry_run:
        if i18n is None:
            print(f"[dry-run] remove {path}")
        else:
            print(_t(i18n, "install.dry_run.remove", "[dry-run] remove {path}", path=path))
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
        return
    if path.exists() or path.is_symlink():
        path.unlink()


def _remove_file(path: Path, *, dry_run: bool, i18n: Optional[RuntimeI18N] = None) -> None:
    _remove_path(path, dry_run=dry_run, i18n=i18n)


def _touch_file(path: Path, *, dry_run: bool, i18n: Optional[RuntimeI18N] = None) -> None:
    if dry_run:
        if i18n is None:
            print(f"[dry-run] touch {path}")
        else:
            print(_t(i18n, "install.dry_run.touch", "[dry-run] touch {path}", path=path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def _service_unit(paths: Paths, *, upstream_target: str = "network.target") -> str:
    lines = [
        "[Unit]",
        "Description=LOHA Port Forwarder (nftables engine)",
        "After=network.target",
    ]
    if upstream_target and upstream_target != "network.target":
        lines.append(f"After={upstream_target}")
    lines.extend(
        [
            "",
            "[Service]",
            "Type=oneshot",
            "RuntimeDirectory=loha",
            "RuntimeDirectoryMode=0755",
            "ExecStartPre=/bin/sleep 0.2",
            f"ExecStart={paths.loader_wrapper} full",
            f"ExecReload={paths.loader_wrapper} reload",
            "RemainAfterExit=yes",
            "Restart=on-failure",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    return "\n".join(lines)


def _t(i18n: RuntimeI18N, key: str, default: str, **values) -> str:
    return runtime_translate(i18n, key, default, **values)


def _template(i18n: RuntimeI18N, key: str, default: str) -> str:
    return runtime_template(i18n, key, default)


def _render_messages(i18n: RuntimeI18N, messages: Sequence[LocalizedMessage]) -> Tuple[str, ...]:
    return render_localized_messages(messages, i18n)


def _render_message(i18n: RuntimeI18N, message: LocalizedMessage) -> str:
    return render_localized_message(message, i18n)


def _stdin_supports_interaction() -> bool:
    stream = sys.stdin
    if stream is None or not hasattr(stream, "isatty"):
        return False
    try:
        return bool(stream.isatty())
    except OSError:
        return False


def _reconnect_stdin_to_tty() -> bool:
    try:
        tty_stream = open("/dev/tty", "r", encoding=getattr(sys.stdin, "encoding", None) or "utf-8", errors="replace")
    except OSError:
        return False
    sys.stdin = tty_stream
    return True


def _prepare_interactive_stdin(*, non_interactive: bool, runtime: RuntimeI18N) -> None:
    if non_interactive or _stdin_supports_interaction():
        return
    if _reconnect_stdin_to_tty():
        return
    raise LohaError(
        _t(
            runtime,
            "common.interactive_stdin_required",
            "Interactive prompts require a terminal for input. Re-run this command from a terminal, or add --non-interactive.",
        )
    )


def _step_ok() -> InstallStepResult:
    return InstallStepResult(ok=True)


def _step_error(key: str, default: str, **values) -> InstallStepResult:
    return InstallStepResult(ok=False, error=LocalizedMessage(key, default, values=values))


@dataclass(frozen=True)
class _InstallRecoveryEntry:
    path: Path
    backup_path: Optional[Path]
    existed: bool
    is_dir: bool


@dataclass(frozen=True)
class _InstallServiceState:
    unit_name: str
    systemctl_available: bool
    service_enabled: bool
    service_active: bool


@dataclass(frozen=True)
class _InstallRecoveryState:
    temp_dir: Path
    entries: Tuple[_InstallRecoveryEntry, ...]
    service_state: _InstallServiceState


def _print_error(i18n: RuntimeI18N, message: LocalizedMessage) -> None:
    print(_t(i18n, "common.error", "ERROR: {message}", message=_render_message(i18n, message)))


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _install_recovery_targets(paths: Paths) -> Tuple[Path, ...]:
    return (
        paths.etc_dir,
        paths.cli_wrapper,
        paths.loader_wrapper,
        paths.package_root,
        paths.share_dir,
        paths.service_unit,
        paths.run_dir,
        paths.forwarding_sysctl,
        paths.conntrack_sysctl,
        paths.conntrack_modprobe,
    )


def _copy_recovery_target(src: Path, dst: Path) -> bool:
    if src.is_dir() and not src.is_symlink():
        shutil.copytree(src, dst, symlinks=True)
        return True
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst, follow_symlinks=False)
    return False


def _capture_install_service_state(paths: Paths, adapter: SystemAdapter) -> _InstallServiceState:
    unit_name = paths.service_unit.name
    if not adapter.command_exists("systemctl"):
        return _InstallServiceState(
            unit_name=unit_name,
            systemctl_available=False,
            service_enabled=False,
            service_active=False,
        )
    if not _path_exists(paths.service_unit):
        return _InstallServiceState(
            unit_name=unit_name,
            systemctl_available=True,
            service_enabled=False,
            service_active=False,
        )
    return _InstallServiceState(
        unit_name=unit_name,
        systemctl_available=True,
        service_enabled=adapter.run(["systemctl", "is-enabled", unit_name], check=False).returncode == 0,
        service_active=adapter.run(["systemctl", "is-active", "--quiet", unit_name], check=False).returncode == 0,
    )


def _capture_install_recovery_state(paths: Paths, adapter: SystemAdapter) -> _InstallRecoveryState:
    temp_dir = Path(tempfile.mkdtemp(prefix="loha-install-recovery-"))
    entries = []
    for index, target in enumerate(_install_recovery_targets(paths)):
        existed = _path_exists(target)
        backup_path = None
        is_dir = False
        if existed:
            backup_path = temp_dir / str(index)
            is_dir = _copy_recovery_target(target, backup_path)
        entries.append(
            _InstallRecoveryEntry(
                path=target,
                backup_path=backup_path,
                existed=existed,
                is_dir=is_dir,
            )
        )
    return _InstallRecoveryState(
        temp_dir=temp_dir,
        entries=tuple(entries),
        service_state=_capture_install_service_state(paths, adapter),
    )


def _discard_install_recovery_state(state: Optional[_InstallRecoveryState]) -> None:
    if state is None:
        return
    shutil.rmtree(state.temp_dir, ignore_errors=True)


def _restore_install_recovery_state(state: _InstallRecoveryState) -> None:
    errors = []
    for entry in state.entries:
        try:
            _remove_path(entry.path, dry_run=False)
            if entry.existed and entry.backup_path is not None:
                if entry.is_dir:
                    shutil.copytree(entry.backup_path, entry.path, symlinks=True)
                else:
                    entry.path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(entry.backup_path, entry.path, follow_symlinks=False)
        except Exception as exc:
            errors.append(f"{entry.path}: {exc}")
    _discard_install_recovery_state(state)
    if errors:
        raise ApplyError("; ".join(errors))


def _resync_recovered_system_feature_runtime(adapter: SystemAdapter) -> None:
    if not adapter.command_exists("sysctl"):
        raise ApplyError("Missing 'sysctl' command")
    result = adapter.run(["sysctl", "--system"], check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "sysctl --system failed"
        raise ApplyError(detail)


def _run_recovery_systemctl(adapter: SystemAdapter, action: str, unit: str = "") -> None:
    try:
        adapter.systemctl(action, unit)
    except Exception as exc:
        command = "systemctl " + action + (f" {unit}" if unit else "")
        raise ApplyError(f"{command}: {exc}") from exc


def _resync_recovered_service_runtime(
    adapter: SystemAdapter,
    service_state: _InstallServiceState,
    *,
    restore_activation_state: bool,
) -> None:
    if not service_state.systemctl_available:
        raise ApplyError("Missing 'systemctl' command")
    if restore_activation_state:
        _run_recovery_systemctl(adapter, "stop", service_state.unit_name)
        _run_recovery_systemctl(adapter, "disable", service_state.unit_name)
    _run_recovery_systemctl(adapter, "daemon-reload")
    if service_state.service_enabled:
        _run_recovery_systemctl(adapter, "enable", service_state.unit_name)
    if service_state.service_active:
        _run_recovery_systemctl(adapter, "restart", service_state.unit_name)


def _recover_failed_install(
    state: Optional[_InstallRecoveryState],
    *,
    adapter: Optional[SystemAdapter] = None,
    i18n: RuntimeI18N,
    reload_sysctl_runtime: bool = False,
    reload_systemd_manager: bool = False,
    restore_service_runtime: bool = False,
) -> None:
    if state is None:
        return
    try:
        _restore_install_recovery_state(state)
        if reload_sysctl_runtime:
            if adapter is None:
                raise ApplyError("Missing system adapter for sysctl recovery")
            _resync_recovered_system_feature_runtime(adapter)
        if reload_systemd_manager or restore_service_runtime:
            if adapter is None:
                raise ApplyError("Missing system adapter for service recovery")
            _resync_recovered_service_runtime(
                adapter,
                state.service_state,
                restore_activation_state=restore_service_runtime,
            )
    except Exception as exc:
        _print_error(
            i18n,
            LocalizedMessage(
                "install.recovery.failed",
                "Install recovery failed: {error}",
                values={"error": str(exc)},
            ),
        )
        return
    print(_t(i18n, "install.recovery.completed", "Install recovery completed; partial changes were rolled back."))


def _candidate_config_paths(paths: Paths) -> Tuple[Path, ...]:
    return (Path.cwd() / "loha.conf", paths.loha_conf)


def _systemd_unit_exists(adapter: SystemAdapter, unit: str) -> bool:
    if not adapter.command_exists("systemctl"):
        return False
    result = adapter.run(["systemctl", "show", "--property=LoadState", "--value", unit], check=False)
    state = result.stdout.strip()
    return bool(state and state != "not-found")


def _systemd_unit_active_or_enabled(adapter: SystemAdapter, unit: str) -> bool:
    if not adapter.command_exists("systemctl"):
        return False
    for action in ("is-active", "is-enabled"):
        result = adapter.run(["systemctl", action, "--quiet", unit], check=False)
        if result.returncode == 0:
            return True
    return False


def _pve_nftables_backend_enabled(adapter: SystemAdapter, host_fw_path: Path) -> bool:
    if not host_fw_path.exists():
        return False
    in_options = False
    for raw_line in adapter.read_text(host_fw_path).splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[OPTIONS]":
            in_options = True
            continue
        if line.startswith("[") and line.endswith("]"):
            in_options = False
            continue
        if in_options and line == "nftables: 1":
            return True
    return False


def detect_upstream_firewall_target(
    adapter: SystemAdapter,
    *,
    pve_nodes_dir: Path = Path("/etc/pve/nodes"),
) -> str:
    node_name = socket.gethostname().split(".", 1)[0]
    is_pve_host = adapter.command_exists("pveversion") or pve_nodes_dir.is_dir()
    if is_pve_host:
        host_fw_path = pve_nodes_dir / node_name / "host.fw"
        if _pve_nftables_backend_enabled(adapter, host_fw_path):
            if _systemd_unit_exists(adapter, "proxmox-firewall.service"):
                return "proxmox-firewall.service"
        elif _systemd_unit_exists(adapter, "pve-firewall.service"):
            return "pve-firewall.service"

    for unit in UPSTREAM_FIREWALL_UNITS:
        if _systemd_unit_active_or_enabled(adapter, unit):
            return unit
    for unit in UPSTREAM_FIREWALL_UNITS:
        if _systemd_unit_exists(adapter, unit):
            return unit
    return "network.target"


def _build_install_i18n(paths: Paths, *, non_interactive: bool, input_func=input) -> RuntimeI18N:
    locale_dir = resolve_locale_directory(paths)
    requested = read_first_config_value("LOCALE", _candidate_config_paths(paths))
    runtime = build_runtime_i18n(locale_dir, requested_locale=requested)
    if non_interactive:
        return runtime
    selected = select_locale_interactive(
        runtime,
        recommended_locale=pick_locale(runtime.catalogs, runtime.locale, runtime.default_locale),
        input_func=input_func,
    )
    if selected == runtime.locale:
        return runtime
    return build_runtime_i18n(locale_dir, requested_locale=selected)


def _probe_install_initial_state(base: CanonicalConfig, adapter: SystemAdapter) -> CanonicalConfig:
    state = base.as_dict()
    external_candidates = tuple(item for item in adapter.default_ipv4_ifaces() if item)
    primary_external = state.get("PRIMARY_EXTERNAL_IF") or (external_candidates[0] if external_candidates else "")
    if primary_external:
        state["PRIMARY_EXTERNAL_IF"] = primary_external
        state["EXTERNAL_IFS"] = state.get("EXTERNAL_IFS") or primary_external

    if primary_external and not state.get("LISTEN_IPS"):
        listen_ips = adapter.global_ipv4s(primary_external)
        if listen_ips:
            state["LISTEN_IPS"] = ",".join(listen_ips)
            state["DEFAULT_SNAT_IP"] = state.get("DEFAULT_SNAT_IP") or listen_ips[0]

    interfaces = tuple(item for item in adapter.list_interfaces() if item and item != "lo")
    if not state.get("LAN_IFS"):
        lan_candidates = tuple(candidate for candidate in interfaces if candidate != primary_external)
        if lan_candidates:
            preferred = next((candidate for candidate in lan_candidates if adapter.ipv4_networks(candidate)), lan_candidates[0])
            state["LAN_IFS"] = preferred
    if state.get("LAN_IFS") and not state.get("LAN_NETS"):
        first_lan = state["LAN_IFS"].split(",", 1)[0].strip()
        lan_nets = adapter.ipv4_networks(first_lan)
        if lan_nets:
            state["LAN_NETS"] = ",".join(lan_nets)

    return CanonicalConfig(state)


def _confirm_yes_no(
    prompt: str,
    *,
    input_func=None,
    default: bool = True,
    i18n: Optional[RuntimeI18N] = None,
) -> bool:
    input_func = input_func or input
    while True:
        raw = input_func(prompt)
        try:
            return parse_yes_no(raw, default=default)
        except InputValidationError:
            print(_t(i18n, "common.invalid_choice", "Invalid choice."))


def _select_install_import_path(
    paths: Paths,
    *,
    non_interactive: bool,
    i18n: RuntimeI18N,
    input_func=input,
) -> Optional[Path]:
    repo_config, system_config = _candidate_config_paths(paths)
    candidates = []
    seen = set()
    for label, path in (("repo", repo_config), ("system", system_config)):
        if not path.exists():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        candidates.append((label, path))
    if not candidates:
        return None
    if non_interactive:
        return candidates[0][1]
    selection = prompt_menu_single(
        _t(i18n, "install.import.title", "Import Existing Configuration"),
        _t(i18n, "install.import.description", "Choose which existing configuration to start from."),
        tuple(
            [
                MenuOption(
                    str(index),
                    _t(
                        i18n,
                        f"install.import.option.{label}",
                        "{label}: {path}",
                        label=label,
                        path=path,
                    ),
                    str(index),
                )
                for index, (label, path) in enumerate(candidates, start=1)
            ]
            + [
                MenuOption(
                    "0",
                    _t(i18n, "install.import.fresh", "Start from recommended defaults"),
                    "0",
                )
            ]
        ),
        default_value="1",
        input_func=input_func,
        i18n=i18n,
        allow_cancel=False,
        prompt_key="install.import.prompt_default",
        prompt_default="Choice (press Enter for {default_token})",
    )
    if selection == "0":
        return None
    return candidates[int(selection, 10) - 1][1]


def _choose_install_initial_config(
    paths: Paths,
    *,
    non_interactive: bool,
    adapter: SystemAdapter,
    i18n: RuntimeI18N,
    input_func=input,
) -> CanonicalConfig:
    selected = _select_install_import_path(
        paths,
        non_interactive=non_interactive,
        i18n=i18n,
        input_func=input_func,
    )
    if selected is not None:
        loaded, _notices = load_management_config(selected, adapter)
        state = loaded.as_dict()
        state["LOCALE"] = i18n.locale
        return CanonicalConfig(state)

    base = recommended_config()
    state = base.as_dict()
    state["LOCALE"] = i18n.locale
    return _probe_install_initial_state(CanonicalConfig(state), adapter)


def _resolve_install_config(
    paths: Paths,
    *,
    non_interactive: bool,
    adapter: SystemAdapter,
    i18n: RuntimeI18N,
    initial: CanonicalConfig,
    initial_stage: str,
    input_func=input,
) -> Tuple[CanonicalConfig, bool, Tuple[LocalizedMessage, ...]]:
    if non_interactive:
        state = initial.as_dict()
        state = sync_toggle_shortcut_state(state)
        state, notices = sync_runtime_binding_state(state, adapter, only_if_shortcuts=True)
        return normalize_mapping(state, materialize_defaults=True), False, notices
    outcome = run_config_wizard_flow(
        adapter,
        initial=initial,
        input_func=input_func,
        i18n=i18n,
        initial_stage=initial_stage,
        show_summary=False,
        surface="installer",
        paths=paths,
    )
    state = outcome.config.as_dict()
    state["LOCALE"] = i18n.locale
    return normalize_mapping(state), outcome.advanced_checked, outcome.persist_notices


def _confirm_install_execution(
    config: CanonicalConfig,
    i18n: RuntimeI18N,
    *,
    advanced_checked: bool,
    persist_notices: Sequence[LocalizedMessage] = (),
    input_func=input,
) -> str:
    return prompt_summary_action(
        config,
        advanced_checked=advanced_checked,
        i18n=i18n,
        input_func=input_func,
        footer_lines=_render_messages(i18n, tuple(persist_notices))
        + (f"{_t(i18n, 'install.summary.fields.locale', 'Language')}: {i18n.locale_name()}",),
        title_key="install.summary.title",
        title_default="Install Summary",
        description_key="install.summary.description",
        description_default="Review the planned installation and choose how to proceed.",
        option_key_prefix="install.summary.options",
        confirm_default="Confirm and install",
    )


def _run_interactive_prechecks(
    adapter: SystemAdapter,
    *,
    repo_root: Path,
    i18n: RuntimeI18N,
    non_interactive: bool,
    dry_run: bool,
    input_func=input,
) -> bool:
    results = run_install_prechecks(adapter, repo_root=repo_root, dry_run=dry_run)
    print()
    print(_t(i18n, "install.precheck.title", "Install Prechecks"))
    for result in results:
        message = i18n.t(result.message_key, result.default_message, **result.values)
        level = _t(i18n, f"doctor.level.{result.level}", result.level.upper())
        print(f"  [{level}] {message}")
    fail_count = count_level(results, "fail")
    warn_count = count_level(results, "warn")
    if has_failures(results):
        print(_t(i18n, "install.precheck.fail_summary", "Prechecks failed: {count}", count=fail_count))
        if not non_interactive:
            input_func(_t(i18n, "install.precheck.exit_prompt", "Press Enter to exit") + ": ")
        return False
    if warn_count:
        print(_t(i18n, "install.precheck.warn_summary", "Prechecks completed with {count} warning(s)", count=warn_count))
    else:
        print(_t(i18n, "install.precheck.all_pass", "All install prechecks passed."))
    return True


def _apply_install_system_features(
    paths: Paths,
    config: CanonicalConfig,
    adapter: SystemAdapter,
    *,
    dry_run: bool,
    i18n: Optional[RuntimeI18N] = None,
) -> InstallStepResult:
    try:
        apply_system_feature_files(
            paths,
            config,
            write_text=lambda path, text: _write_text(path, text, dry_run=dry_run, i18n=i18n),
            remove_path=lambda path: _remove_file(path, dry_run=dry_run, i18n=i18n),
        )
    except Exception as exc:
        return _step_error(
            "install.system_features.file_apply_failed",
            "Failed to write install system-feature files: {error}",
            error=str(exc),
        )
    if dry_run:
        if i18n is None:
            print("[dry-run] sysctl --system")
        else:
            print(_t(i18n, "install.dry_run.sysctl", "[dry-run] sysctl --system"))
        return _step_ok()
    if not adapter.command_exists("sysctl"):
        return _step_error(
            "install.system_features.sysctl_missing",
            "Install cannot apply system-feature runtime state because `sysctl` is unavailable.",
        )
    result = adapter.run(["sysctl", "--system"], check=False)
    if result.returncode != 0:
        return _step_error(
            "install.system_features.sysctl_failed",
            "Install system-feature apply failed during `sysctl --system`: {error}",
            error=result.stderr.strip() or result.stdout.strip() or "sysctl --system failed",
        )
    return _step_ok()


def _activate_install_service(
    paths: Paths,
    adapter: SystemAdapter,
    *,
    dry_run: bool,
    i18n: Optional[RuntimeI18N] = None,
) -> InstallStepResult:
    unit_name = paths.service_unit.name
    if dry_run:
        if i18n is None:
            print("[dry-run] systemctl daemon-reload")
            print(f"[dry-run] systemctl enable {unit_name}")
            print(f"[dry-run] systemctl restart {unit_name}")
        else:
            print(_t(i18n, "install.dry_run.daemon_reload", "[dry-run] systemctl daemon-reload"))
            print(_t(i18n, "install.dry_run.enable", "[dry-run] systemctl enable {unit}", unit=unit_name))
            print(_t(i18n, "install.dry_run.restart", "[dry-run] systemctl restart {unit}", unit=unit_name))
        return _step_ok()
    if not adapter.command_exists("systemctl"):
        return _step_error(
            "install.service.systemctl_missing",
            "Install cannot activate loha.service because `systemctl` is unavailable.",
        )
    for action, unit in (("daemon-reload", ""), ("enable", unit_name), ("restart", unit_name)):
        try:
            adapter.systemctl(action, unit)
        except Exception as exc:
            command = "systemctl " + action + (f" {unit}" if unit else "")
            return _step_error(
                "install.service.action_failed",
                "Install service activation failed during `{command}`: {error}",
                command=command,
                error=str(exc),
            )
    return _step_ok()


def _capture_preinstall_snapshot(
    paths: Paths,
    *,
    dry_run: bool,
    i18n: Optional[RuntimeI18N] = None,
) -> InstallStepResult:
    if dry_run:
        return _step_ok()
    try:
        capture_snapshot_if_enabled(paths, source="installer", reason="install-apply")
    except Exception as exc:
        return _step_error(
            "install.history.write_failed",
            "Install snapshot write failed: {error}",
            error=str(exc),
        )
    return _step_ok()


def _persist_install_state(
    paths: Paths,
    *,
    config: CanonicalConfig,
    rules_text: str,
    assume_locked: bool = False,
) -> Tuple[InstallStepResult, int]:
    try:
        revision = commit_desired_state(
            paths,
            config_text=render_canonical_text(config),
            rules_text=rules_text,
            source="installer",
            reason="install-apply",
            capture_history=False,
            assume_locked=assume_locked,
            extra_pending_actions=("install_sync",),
        ).revision
    except Exception as exc:
        return (
            _step_error(
                "install.history.write_failed",
                "Install snapshot write failed: {error}",
                error=str(exc),
            ),
            0,
        )
    return _step_ok(), revision


def _update_install_runtime_sync_state(
    paths: Paths,
    *,
    desired_revision: int = 0,
    install_pending: bool,
    sysctl_pending: Optional[bool] = None,
    last_error: Optional[str] = None,
    assume_locked: bool = False,
) -> None:
    def _transform(current: RuntimeStateSnapshot) -> RuntimeStateSnapshot:
        pending_actions = [action for action in current.pending_actions if action not in {"install_sync", "sysctl_sync"}]
        if install_pending:
            pending_actions.append("install_sync")
        if sysctl_pending is None:
            if "sysctl_sync" in current.pending_actions:
                pending_actions.append("sysctl_sync")
        elif sysctl_pending:
            pending_actions.append("sysctl_sync")
        return RuntimeStateSnapshot(
            desired_revision=desired_revision or current.desired_revision,
            applied_revision=current.applied_revision,
            last_apply_mode=current.last_apply_mode,
            last_apply_status=current.last_apply_status,
            last_error=current.last_error if last_error is None else last_error,
            pending_actions=tuple(dict.fromkeys(pending_actions)),
            updated_at_epoch=int(time.time()),
        )

    update_runtime_state(paths, _transform, assume_locked=assume_locked)


def _mark_install_runtime_sync_failure(
    paths: Paths,
    *,
    desired_revision: int,
    error: str,
    sysctl_pending: bool = False,
    assume_locked: bool = False,
) -> None:
    _update_install_runtime_sync_state(
        paths,
        desired_revision=desired_revision,
        install_pending=True,
        sysctl_pending=sysctl_pending,
        last_error=error,
        assume_locked=assume_locked,
    )


def _clear_install_runtime_sync(
    paths: Paths,
    *,
    desired_revision: int = 0,
    assume_locked: bool = False,
) -> None:
    _update_install_runtime_sync_state(
        paths,
        desired_revision=desired_revision,
        install_pending=False,
        sysctl_pending=False,
        last_error="",
        assume_locked=assume_locked,
    )


def _deploy_install_files(
    paths: Paths,
    *,
    repo_root: Path,
    upstream_target: str,
    dry_run: bool,
    i18n: RuntimeI18N,
) -> InstallStepResult:
    try:
        for directory in (
            paths.etc_dir,
            paths.history_dir,
            paths.cli_wrapper.parent,
            paths.loader_wrapper.parent,
            paths.package_root.parent,
            paths.share_dir,
            paths.locale_dir.parent,
            paths.systemd_unit_dir,
        ):
            _ensure_directory(directory, dry_run=dry_run, i18n=i18n)
        _touch_file(paths.rules_conf, dry_run=dry_run, i18n=i18n)
        _copy_tree(repo_root / "src" / "loha", paths.package_root / "loha", dry_run=dry_run, i18n=i18n)
        _copy_tree(repo_root / "locales", paths.locale_dir, dry_run=dry_run, i18n=i18n)
        _write_text(
            paths.cli_wrapper,
            "#!/bin/sh\n"
            f'export PYTHONPATH="{paths.package_root}${{PYTHONPATH:+:$PYTHONPATH}}"\n'
            'exec "${PYTHON:-python3}" -m loha.cli "$@"\n',
            dry_run=dry_run,
            i18n=i18n,
        )
        _write_text(
            paths.loader_wrapper,
            "#!/bin/sh\n"
            f'export PYTHONPATH="{paths.package_root}${{PYTHONPATH:+:$PYTHONPATH}}"\n'
            'exec "${PYTHON:-python3}" -m loha.loader "$@"\n',
            dry_run=dry_run,
            i18n=i18n,
        )
        if not dry_run:
            paths.cli_wrapper.chmod(0o755)
            paths.loader_wrapper.chmod(0o755)
        _write_text(
            paths.service_unit,
            _service_unit(paths, upstream_target=upstream_target),
            dry_run=dry_run,
            i18n=i18n,
        )
    except Exception as exc:
        return _step_error(
            "install.deploy.failed",
            "Install filesystem deployment failed: {error}",
            error=str(exc),
        )
    return _step_ok()


def _run_runtime_cleanup_command(adapter: SystemAdapter, argv: Sequence[str]) -> Optional[str]:
    if not argv:
        return None
    command_text = " ".join(argv)
    try:
        result = adapter.run(argv, check=False)
    except Exception as exc:
        return f"{command_text}: {exc}"
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        return f"{command_text}: {detail}"
    return None


def _remove_installation_payload(
    paths: Paths,
    *,
    dry_run: bool,
    i18n: RuntimeI18N,
    remove_run_dir: bool = True,
) -> InstallStepResult:
    try:
        targets = [
            paths.cli_wrapper,
            paths.loader_wrapper,
            paths.package_root,
            paths.share_dir,
            paths.service_unit,
        ]
        if remove_run_dir:
            targets.append(paths.run_dir)
        for target in targets:
            _remove_path(target, dry_run=dry_run, i18n=i18n)
    except Exception as exc:
        return _step_error(
            "install.uninstall.remove_failed",
            "Failed to remove installed LOHA files: {error}",
            error=str(exc),
        )
    return _step_ok()


def _remove_uninstall_data(
    paths: Paths,
    *,
    remove_config_data: bool,
    remove_system_tuning: bool,
    dry_run: bool,
    i18n: RuntimeI18N,
) -> InstallStepResult:
    try:
        if remove_config_data:
            _remove_path(paths.etc_dir, dry_run=dry_run, i18n=i18n)
        elif _path_exists(paths.etc_dir):
            preserved_names = {"loha.conf", "rules.conf", "history"}
            for child in tuple(paths.etc_dir.iterdir()):
                if child.name in preserved_names:
                    continue
                _remove_path(child, dry_run=dry_run, i18n=i18n)
            if not dry_run and not any(paths.etc_dir.iterdir()):
                _remove_path(paths.etc_dir, dry_run=False, i18n=i18n)
        if remove_system_tuning:
            for target in (paths.forwarding_sysctl, paths.conntrack_sysctl, paths.conntrack_modprobe):
                _remove_path(target, dry_run=dry_run, i18n=i18n)
    except Exception as exc:
        return _step_error(
            "install.uninstall.remove_failed",
            "Failed to remove installed LOHA files: {error}",
            error=str(exc),
        )
    return _step_ok()


def _sync_uninstall_runtime(
    paths: Paths,
    adapter: SystemAdapter,
    *,
    dry_run: bool,
    i18n: RuntimeI18N,
) -> InstallStepResult:
    unit_name = paths.service_unit.name
    if dry_run:
        print(_t(i18n, "install.dry_run.stop", "[dry-run] systemctl stop {unit}", unit=unit_name))
        print(_t(i18n, "install.dry_run.disable", "[dry-run] systemctl disable {unit}", unit=unit_name))
        for command in adapter.nft_table_reset_commands("ip", LOHA_NFT_TABLE_NAME):
            print(_t(i18n, "install.dry_run.nft_destroy", f"[dry-run] nft {command}"))
        print(_t(i18n, "install.dry_run.daemon_reload", "[dry-run] systemctl daemon-reload"))
        print(_t(i18n, "install.dry_run.sysctl", "[dry-run] sysctl --system"))
        return _step_ok()

    failures = []

    systemctl_available = adapter.command_exists("systemctl")
    if systemctl_available:
        for argv in (
            ["systemctl", "stop", unit_name],
            ["systemctl", "disable", unit_name],
        ):
            error = _run_runtime_cleanup_command(adapter, argv)
            if error:
                failures.append(error)
    else:
        failures.append("Missing 'systemctl' command")

    if adapter.command_exists("nft"):
        try:
            commands = adapter.nft_table_reset_commands("ip", LOHA_NFT_TABLE_NAME)
        except Exception as exc:
            failures.append(f"nft table reset probe failed: {exc}")
        else:
            for command in commands:
                error = _run_runtime_cleanup_command(adapter, ["nft", *command.split()])
                if error:
                    failures.append(error)
    else:
        failures.append("Missing 'nft' command")

    if adapter.command_exists("sysctl"):
        error = _run_runtime_cleanup_command(adapter, ["sysctl", "--system"])
        if error:
            failures.append(error)
    else:
        failures.append("Missing 'sysctl' command")

    if systemctl_available:
        error = _run_runtime_cleanup_command(adapter, ["systemctl", "daemon-reload"])
        if error:
            failures.append(error)

    if failures:
        return _step_error(
            "install.uninstall.runtime_cleanup_failed",
            "Uninstall runtime cleanup failed: {error}",
            error="; ".join(failures),
        )
    return _step_ok()


def cmd_install(args) -> int:
    paths = Paths(
        etc_dir=Path(args.etc_dir) if args.etc_dir else Paths().etc_dir,
        prefix=Path(args.prefix) if args.prefix else Paths().prefix,
        run_dir=Path(args.run_dir) if args.run_dir else Paths().run_dir,
        systemd_unit_dir=Path(args.systemd_dir) if args.systemd_dir else Paths().systemd_unit_dir,
    )
    adapter = SubprocessSystemAdapter()
    i18n = _build_install_i18n(paths, non_interactive=args.non_interactive)
    if not _run_interactive_prechecks(
        adapter,
        repo_root=_repo_root(),
        i18n=i18n,
        non_interactive=args.non_interactive,
        dry_run=args.dry_run,
    ):
        return 1
    initial = _choose_install_initial_config(
        paths,
        non_interactive=args.non_interactive,
        adapter=adapter,
        i18n=i18n,
    )
    stage = "network"
    advanced_checked = False
    persist_notices: Tuple[LocalizedMessage, ...] = ()
    while True:
        try:
            config, advanced_checked, persist_notices = _resolve_install_config(
                paths,
                non_interactive=args.non_interactive,
                adapter=adapter,
                i18n=i18n,
                initial=initial,
                initial_stage=stage,
            )
        except KeyboardInterrupt:
            print(_t(i18n, "install.cancelled", "Installation was cancelled before applying changes."))
            return 0
        if args.non_interactive:
            break
        action = _confirm_install_execution(
            config,
            i18n,
            advanced_checked=advanced_checked,
            persist_notices=persist_notices,
        )
        if action == "confirm":
            break
        if action == "cancel":
            print(_t(i18n, "install.cancelled", "Installation was cancelled before applying changes."))
            return 0
        initial = config
        stage = action

    rules = load_rules(paths.rules_conf)
    if args.dry_run:
        print(_t(i18n, "install.dry_run.notice", "[dry-run] filesystem changes were not applied"))
    repo_root = _repo_root()
    upstream_target = detect_upstream_firewall_target(adapter)
    print(_t(i18n, "install.upstream_fw", "Detected upstream firewall target: {target}", target=upstream_target))
    snapshot_result = _capture_preinstall_snapshot(paths, dry_run=args.dry_run, i18n=i18n)
    if not snapshot_result.ok:
        _print_error(i18n, snapshot_result.error)
        return 1
    recovery_state = None
    if not args.dry_run:
        try:
            recovery_state = _capture_install_recovery_state(paths, adapter)
        except Exception as exc:
            _print_error(
                i18n,
                LocalizedMessage(
                    "install.recovery.prepare_failed",
                    "Install recovery preparation failed: {error}",
                    values={"error": str(exc)},
                ),
            )
            return 1
    desired_revision = 0
    install_error = None
    recover_install_kwargs = None
    try:
        with control_file_lock(paths):
            deploy_result = _deploy_install_files(
                paths,
                repo_root=repo_root,
                upstream_target=upstream_target,
                dry_run=args.dry_run,
                i18n=i18n,
            )
            if not deploy_result.ok:
                install_error = deploy_result.error
                recover_install_kwargs = {}
            elif not args.dry_run:
                persist_result, desired_revision = _persist_install_state(
                    paths,
                    config=config,
                    rules_text=render_rules_text(rules),
                    assume_locked=True,
                )
                if not persist_result.ok:
                    install_error = persist_result.error
                    recover_install_kwargs = {}
                else:
                    system_feature_result = _apply_install_system_features(
                        paths,
                        config,
                        adapter,
                        dry_run=args.dry_run,
                        i18n=i18n,
                    )
                    if not system_feature_result.ok:
                        install_error = system_feature_result.error
                        _mark_install_runtime_sync_failure(
                            paths,
                            desired_revision=desired_revision,
                            error=system_feature_result.error.render(),
                            sysctl_pending=system_feature_result.error is not None
                            and system_feature_result.error.message_key == "install.system_features.sysctl_failed",
                            assume_locked=True,
                        )
                        recover_install_kwargs = {
                            "reload_sysctl_runtime": system_feature_result.error is not None
                            and system_feature_result.error.message_key == "install.system_features.sysctl_failed",
                        }
            else:
                system_feature_result = _apply_install_system_features(
                    paths,
                    config,
                    adapter,
                    dry_run=args.dry_run,
                    i18n=i18n,
                )
                if not system_feature_result.ok:
                    install_error = system_feature_result.error
                    recover_install_kwargs = {}
        if install_error is not None:
            _print_error(i18n, install_error)
            _recover_failed_install(
                recovery_state,
                adapter=adapter,
                i18n=i18n,
                **(recover_install_kwargs or {}),
            )
            return 1
        activation_result = _activate_install_service(paths, adapter, dry_run=args.dry_run, i18n=i18n)
        if not activation_result.ok:
            _print_error(i18n, activation_result.error)
            activation_command = ""
            if activation_result.error is not None:
                activation_command = str(activation_result.error.values.get("command", ""))
            if not args.dry_run and activation_result.error is not None:
                with control_file_lock(paths):
                    _mark_install_runtime_sync_failure(
                        paths,
                        desired_revision=desired_revision,
                        error=activation_result.error.render(),
                        assume_locked=True,
                    )
            _recover_failed_install(
                recovery_state,
                adapter=adapter,
                i18n=i18n,
                reload_sysctl_runtime=True,
                reload_systemd_manager=activation_result.error is not None
                and activation_result.error.message_key == "install.service.action_failed",
                restore_service_runtime=activation_result.error is not None
                and activation_result.error.message_key == "install.service.action_failed"
                and activation_command == f"systemctl restart {paths.service_unit.name}",
            )
            return 1
        if not args.dry_run:
            with control_file_lock(paths):
                _clear_install_runtime_sync(paths, desired_revision=desired_revision, assume_locked=True)
        print(_t(i18n, "install.completed", "Installation files are in place."))
        return 0
    finally:
        _discard_install_recovery_state(recovery_state)


def cmd_uninstall(args) -> int:
    paths = Paths(
        etc_dir=Path(args.etc_dir) if args.etc_dir else Paths().etc_dir,
        prefix=Path(args.prefix) if args.prefix else Paths().prefix,
        run_dir=Path(args.run_dir) if args.run_dir else Paths().run_dir,
        systemd_unit_dir=Path(args.systemd_dir) if args.systemd_dir else Paths().systemd_unit_dir,
    )
    i18n = _build_install_i18n(paths, non_interactive=True)
    adapter = SubprocessSystemAdapter()
    non_interactive = bool(getattr(args, "non_interactive", False))
    purge = bool(getattr(args, "purge", False))
    dry_run = bool(getattr(args, "dry_run", False))
    remove_config_data = purge
    remove_system_tuning = purge
    if purge:
        if not non_interactive:
            if not _confirm_yes_no(
                _t(
                    i18n,
                    "install.uninstall.purge_prompt",
                    "Permanently delete all LOHA files, including {path}, history snapshots, and kernel tuning files ({nat}, {conntrack}, {modprobe})? [y/N]: ",
                    path=paths.etc_dir,
                    nat=paths.forwarding_sysctl,
                    conntrack=paths.conntrack_sysctl,
                    modprobe=paths.conntrack_modprobe,
                ),
                input_func=input,
                default=False,
                i18n=i18n,
            ):
                print(_t(i18n, "common.cancelled", "Cancelled."))
                return 1
    else:
        if not non_interactive:
            if not _confirm_yes_no(
                _t(i18n, "install.uninstall.prompt", "Uninstall LOHA from this system? [y/N]: "),
                input_func=input,
                default=False,
                i18n=i18n,
            ):
                print(_t(i18n, "common.cancelled", "Cancelled."))
                return 1
            remove_config_data = _confirm_yes_no(
                _t(
                    i18n,
                    "install.uninstall.data_prompt",
                    "Delete all user configuration data ({path})? [y/N]: ",
                    path=paths.etc_dir,
                ),
                input_func=input,
                default=False,
                i18n=i18n,
            )
            remove_system_tuning = _confirm_yes_no(
                _t(
                    i18n,
                    "install.uninstall.system_tuning_prompt",
                    "Remove kernel network tuning parameters ({nat}, {conntrack}, {modprobe})? [y/N]: ",
                    nat=paths.forwarding_sysctl,
                    conntrack=paths.conntrack_sysctl,
                    modprobe=paths.conntrack_modprobe,
                ),
                input_func=input,
                default=False,
                i18n=i18n,
            )
    if dry_run:
        payload_result = _remove_installation_payload(paths, dry_run=True, i18n=i18n, remove_run_dir=False)
        if not payload_result.ok:
            _print_error(i18n, payload_result.error)
            return 1
        data_result = _remove_uninstall_data(
            paths,
            remove_config_data=remove_config_data,
            remove_system_tuning=remove_system_tuning,
            dry_run=True,
            i18n=i18n,
        )
        if not data_result.ok:
            _print_error(i18n, data_result.error)
            return 1
        for runtime_file in (paths.control_state_file, paths.debug_ruleset_file, paths.runtime_state_file):
            _remove_path(runtime_file, dry_run=True, i18n=i18n)
        runtime_result = _sync_uninstall_runtime(paths, adapter, dry_run=True, i18n=i18n)
        if not runtime_result.ok:
            _print_error(i18n, runtime_result.error)
            return 1
        _remove_path(paths.run_dir, dry_run=True, i18n=i18n)
        print(_t(i18n, "install.dry_run.notice", "[dry-run] filesystem changes were not applied"))
        return 0
    with control_file_lock(paths):
        _update_install_runtime_sync_state(
            paths,
            install_pending=True,
            assume_locked=True,
        )
        payload_result = _remove_installation_payload(paths, dry_run=False, i18n=i18n, remove_run_dir=False)
        if not payload_result.ok:
            if payload_result.error is not None:
                _mark_install_runtime_sync_failure(
                    paths,
                    desired_revision=0,
                    error=payload_result.error.render(),
                    assume_locked=True,
                )
            _print_error(i18n, payload_result.error)
            return 1
        data_result = _remove_uninstall_data(
            paths,
            remove_config_data=remove_config_data,
            remove_system_tuning=remove_system_tuning,
            dry_run=False,
            i18n=i18n,
        )
        if not data_result.ok:
            if data_result.error is not None:
                _mark_install_runtime_sync_failure(
                    paths,
                    desired_revision=0,
                    error=data_result.error.render(),
                    assume_locked=True,
                )
            _print_error(i18n, data_result.error)
            return 1
        for runtime_file in (paths.control_state_file, paths.debug_ruleset_file):
            _remove_path(runtime_file, dry_run=False, i18n=i18n)
    runtime_result = _sync_uninstall_runtime(paths, adapter, dry_run=False, i18n=i18n)
    if not runtime_result.ok:
        if runtime_result.error is not None:
            with control_file_lock(paths):
                _mark_install_runtime_sync_failure(
                    paths,
                    desired_revision=0,
                    error=runtime_result.error.render(),
                    assume_locked=True,
                )
            _print_error(i18n, runtime_result.error)
        return 1
    with control_file_lock(paths):
        remove_runtime_state(paths, assume_locked=True)
    _remove_path(paths.run_dir, dry_run=False, i18n=i18n)
    print(_t(i18n, "install.uninstall.completed", "LOHA has been removed from the system."))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loha-install")
    parser.add_argument("--etc-dir")
    parser.add_argument("--prefix")
    parser.add_argument("--run-dir")
    parser.add_argument("--systemd-dir")
    parser.add_argument("-y", "--non-interactive", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--purge", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths(
        etc_dir=Path(args.etc_dir) if args.etc_dir else Paths().etc_dir,
        prefix=Path(args.prefix) if args.prefix else Paths().prefix,
        run_dir=Path(args.run_dir) if args.run_dir else Paths().run_dir,
        systemd_unit_dir=Path(args.systemd_dir) if args.systemd_dir else Paths().systemd_unit_dir,
    )
    runtime = build_runtime_i18n(resolve_locale_directory(paths), requested_locale=read_first_config_value("LOCALE", _candidate_config_paths(paths)))
    try:
        _prepare_interactive_stdin(non_interactive=bool(getattr(args, "non_interactive", False)), runtime=runtime)
        return cmd_uninstall(args) if args.uninstall else cmd_install(args)
    except KeyboardInterrupt:
        print(_t(runtime, "common.cancelled", "Cancelled."))
        return 130
    except LohaError as exc:
        print(_t(runtime, "common.error", "ERROR: {message}", message=str(exc)))
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
