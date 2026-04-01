from dataclasses import dataclass
from typing import Callable, List, Optional

from .config import load_config
from .constants import LOHA_NFT_TABLE_NAME
from .exceptions import ApplyError, ConfigSyntaxError, ConfigValidationError, RulesSyntaxError, RulesValidationError
from .loader import LoaderService
from .models import DoctorResult, Paths
from .runtime_binding import runtime_binding_doctor_results
from .rules import load_rules
from .system import SubprocessSystemAdapter, SystemAdapter
from .system_features import (
    collect_conntrack_status,
    collect_rp_filter_status,
    conntrack_doctor_results,
    rp_filter_doctor_results,
    rp_filter_runtime_sysctl_results,
)


@dataclass(frozen=True)
class _SystemdState:
    systemctl_available: bool
    unit_exists: bool
    service_enabled: Optional[bool] = None
    service_active: Optional[bool] = None


def _doctor_result(
    level: str,
    summary_key: str,
    summary_default: str,
    *,
    detail: str = "",
    detail_key: str = "",
    detail_default: str = "",
    hint: str = "",
    hint_key: str = "",
    hint_default: str = "",
    **values,
) -> DoctorResult:
    rendered_detail = detail_default.format(**values) if detail_default else detail
    rendered_hint = hint_default.format(**values) if hint_default else hint
    return DoctorResult(
        level=level,
        summary=summary_default.format(**values),
        detail=rendered_detail,
        hint=rendered_hint,
        summary_key=summary_key,
        summary_default=summary_default,
        detail_key=detail_key,
        detail_default=detail_default,
        hint_key=hint_key,
        hint_default=hint_default,
        values=dict(values),
    )


def format_doctor_result_lines(
    result: DoctorResult,
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> List[str]:
    def _tr(key: str, default: str) -> str:
        if translate is None:
            return default
        return translate(key, default)

    lines = [f"[{_tr(f'doctor.level.{result.level}', result.level.upper())}] {result.render_summary(translate)}"]
    detail = result.render_detail(translate)
    hint = result.render_hint(translate)
    if detail:
        lines.append(f"  {detail}")
    if hint:
        lines.append(f"  {hint}")
    return lines


def summarize_doctor_results(
    results: List[DoctorResult],
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> str:
    def _tr(key: str, default: str) -> str:
        if translate is None:
            return default
        return translate(key, default)

    fail_count = sum(1 for result in results if result.level == "fail")
    warn_count = sum(1 for result in results if result.level == "warn")
    if fail_count:
        return _tr("doctor.summary.fail_warn", "Doctor summary: {fail_count} fail, {warn_count} warn").format(
            fail_count=fail_count,
            warn_count=warn_count,
        )
    if warn_count:
        return _tr("doctor.summary.warn_only", "Doctor summary: 0 fail, {warn_count} warn").format(
            warn_count=warn_count
        )
    return _tr("doctor.summary.all_pass", "Doctor summary: all checks passed")


def _collect_systemd_state(paths: Paths, adapter: SystemAdapter) -> _SystemdState:
    systemctl_available = adapter.command_exists("systemctl")
    unit_exists = paths.service_unit.exists()
    if not systemctl_available:
        return _SystemdState(systemctl_available=False, unit_exists=unit_exists)
    if not unit_exists:
        return _SystemdState(systemctl_available=True, unit_exists=False)
    enabled = adapter.run(["systemctl", "is-enabled", paths.service_unit.stem], check=False).returncode == 0
    active = adapter.run(["systemctl", "is-active", "--quiet", paths.service_unit.stem], check=False).returncode == 0
    return _SystemdState(
        systemctl_available=True,
        unit_exists=True,
        service_enabled=enabled,
        service_active=active,
    )


def _systemd_doctor_results(paths: Paths, adapter: SystemAdapter, *, state: Optional[_SystemdState] = None) -> List[DoctorResult]:
    state = state or _collect_systemd_state(paths, adapter)
    results: List[DoctorResult] = []
    if not state.systemctl_available:
        return [
            _doctor_result(
                "fail",
                "doctor.systemd.missing_systemctl",
                "Systemd check: missing systemctl",
            )
        ]
    if not state.unit_exists:
        return [
            _doctor_result(
                "fail",
                "doctor.systemd.missing_unit_file",
                "Systemd check: missing unit file {unit}",
                unit=paths.service_unit.name,
            )
        ]

    results.append(
        _doctor_result(
            "pass",
            "doctor.systemd.unit_file_exists",
            "Systemd check: unit file {unit} exists",
            unit=paths.service_unit.name,
        )
    )
    if state.service_enabled:
        results.append(_doctor_result("pass", "doctor.systemd.service_enabled", "Systemd check: loha service is enabled"))
    else:
        results.append(
            _doctor_result("warn", "doctor.systemd.service_not_enabled", "Systemd check: loha service is not enabled")
        )

    if state.service_active:
        results.append(_doctor_result("pass", "doctor.systemd.service_active", "Systemd check: loha service is active"))
    else:
        results.append(
            _doctor_result("warn", "doctor.systemd.service_not_active", "Systemd check: loha service is not active")
        )
    return results


def _looks_like_missing_nft_table(detail: str) -> bool:
    lowered = detail.lower()
    return any(token in lowered for token in ("no such file or directory", "not found", "does not exist"))


def _nft_runtime_doctor_results(
    config,
    adapter: SystemAdapter,
    *,
    systemd_state: Optional[_SystemdState] = None,
) -> List[DoctorResult]:
    results: List[DoctorResult] = []
    if not adapter.command_exists("nft"):
        return [_doctor_result("fail", "doctor.nft.missing_binary", "nft runtime check: missing nft")]

    table = adapter.run(["nft", "list", "table", "ip", LOHA_NFT_TABLE_NAME], check=False)
    if table.returncode != 0:
        detail = table.stderr.strip() or table.stdout.strip()
        lowered = detail.lower()
        if "permission denied" in lowered or "operation not permitted" in lowered:
            return [
                _doctor_result(
                    "warn",
                    "doctor.nft.inspect_permission_denied",
                    f"nft runtime check: unable to inspect live {LOHA_NFT_TABLE_NAME} table without elevated privileges",
                    detail=detail,
                    hint_key="doctor.hint.run_as_root",
                    hint_default="Re-run `loha doctor` as root to inspect live nft runtime state.",
                )
            ]
        if _looks_like_missing_nft_table(detail):
            if systemd_state is not None and systemd_state.systemctl_available and not systemd_state.unit_exists:
                return [
                    _doctor_result(
                        "pass",
                        "doctor.nft.table_absent_service_missing",
                        f"nft runtime check: live {LOHA_NFT_TABLE_NAME} table is absent because loha.service is not installed",
                    )
                ]
            if systemd_state is not None and systemd_state.systemctl_available and systemd_state.service_active is False:
                return [
                    _doctor_result(
                        "pass",
                        "doctor.nft.table_absent_service_inactive",
                        f"nft runtime check: live {LOHA_NFT_TABLE_NAME} table is absent because loha service is not active",
                    )
                ]
            if systemd_state is not None and systemd_state.service_active is True:
                return [
                    _doctor_result(
                        "fail",
                        "doctor.nft.table_missing_while_active",
                        f"nft runtime check: loha service is active but live {LOHA_NFT_TABLE_NAME} table is absent",
                        detail=detail,
                        hint_key="doctor.hint.nft_table_restore",
                        hint_default="Run `loha reload` or inspect `systemctl status loha` to restore the live table.",
                    )
                ]
            return [
                _doctor_result(
                    "warn",
                    "doctor.nft.table_absent_unknown",
                    f"nft runtime check: live {LOHA_NFT_TABLE_NAME} table is absent",
                    detail=detail,
                    hint_key="doctor.hint.nft_table_absent",
                    hint_default="Inspect loha.service state and run `loha reload` if the service should be active.",
                )
            ]
        return [
            _doctor_result(
                "warn",
                "doctor.nft.inspect_unavailable",
                f"nft runtime check: unable to inspect live {LOHA_NFT_TABLE_NAME} table",
                detail=detail,
                hint_key="doctor.hint.nft_inspect_unavailable",
                hint_default="Ensure the nft command can inspect the live ruleset in this environment.",
            )
        ]

    table_text = table.stdout
    results.append(
        _doctor_result("pass", "doctor.nft.table_present", f"nft runtime check: live {LOHA_NFT_TABLE_NAME} table is present")
    )
    if "map dnat_rules" in table_text:
        results.append(_doctor_result("pass", "doctor.nft.dnat_map_present", "nft runtime check: dnat_rules map is present"))
    else:
        results.append(_doctor_result("fail", "doctor.nft.dnat_map_missing", "nft runtime check: dnat_rules map is missing"))

    expected_auth = "ct label" if config["AUTH_MODE"] == "label" else "ct mark"
    if expected_auth in table_text:
        results.append(
            _doctor_result(
                "pass",
                "doctor.nft.auth_mode_match",
                "nft runtime check: the configured authorization mode ({auth_mode}) is reflected in the live table",
                auth_mode=config["AUTH_MODE"],
            )
        )
    else:
        results.append(
            _doctor_result(
                "fail",
                "doctor.nft.auth_mode_mismatch",
                "nft runtime check: live table auth mode does not match loha.conf",
                detail_key="doctor.detail.expected_token",
                detail_default="expected token={token}",
                token=expected_auth,
            )
        )
    return results


def _listener_conflict_results(rules, adapter: SystemAdapter) -> List[DoctorResult]:
    listeners = adapter.scan_listeners()
    if listeners is None:
        return [
            _doctor_result(
                "warn",
                "doctor.listener.scan_unavailable",
                "Listener conflict check: listener scan unavailable",
                hint_key="doctor.hint.listener_scan_unavailable",
                hint_default="Install `ss` and run with enough privileges to inspect local listeners.",
            )
        ]

    conflicts = []
    for record in rules.ports:
        for port in range(record.listen.start, record.listen.end + 1):
            if (record.proto.lower(), port) in listeners:
                conflicts.append(f"{record.proto.lower()} {port}")

    if conflicts:
        return [
            _doctor_result(
                "warn",
                "doctor.listener.conflict",
                "Listener conflict check: local listeners overlap with exposed ports",
                detail_key="doctor.listener.conflict_detail",
                detail_default="{conflicts}",
                conflicts=", ".join(conflicts),
            )
        ]
    return [
        _doctor_result(
            "pass",
            "doctor.listener.no_conflict",
            "Listener conflict check: no local listener conflicts detected",
        )
    ]


def run_doctor(paths: Optional[Paths] = None, adapter: Optional[SystemAdapter] = None) -> List[DoctorResult]:
    paths = paths or Paths()
    adapter = adapter or SubprocessSystemAdapter()
    results: List[DoctorResult] = []

    for binary in ("python3", "nft", "ip"):
        if adapter.command_exists(binary):
            results.append(
                _doctor_result(
                    "pass",
                    "doctor.dependency.available",
                    "Dependency check: {binary} is available",
                    binary=binary,
                )
            )
        else:
            results.append(
                _doctor_result(
                    "fail",
                    "doctor.dependency.missing",
                    "Dependency check: missing {binary}",
                    binary=binary,
                )
            )

    try:
        config = load_config(paths.loha_conf)
        results.append(_doctor_result("pass", "doctor.config.valid", "Config check: loha.conf is valid"))
    except (FileNotFoundError, ConfigSyntaxError, ConfigValidationError) as exc:
        results.append(_doctor_result("fail", "doctor.config.invalid", "Config check: loha.conf is invalid", detail=str(exc)))
        return results

    try:
        rules = load_rules(paths.rules_conf)
        results.append(_doctor_result("pass", "doctor.rules.valid", "Rules check: rules.conf is valid"))
    except (FileNotFoundError, RulesSyntaxError, RulesValidationError) as exc:
        results.append(_doctor_result("fail", "doctor.rules.invalid", "Rules check: rules.conf is invalid", detail=str(exc)))
        return results

    systemd_state = _collect_systemd_state(paths, adapter)
    results.extend(_systemd_doctor_results(paths, adapter, state=systemd_state))

    rp_filter_report = collect_rp_filter_status(paths, config, adapter)
    conntrack_report = collect_conntrack_status(paths, config, adapter)
    results.extend(rp_filter_runtime_sysctl_results(rp_filter_report))

    results.extend(_nft_runtime_doctor_results(config, adapter, systemd_state=systemd_state))
    results.extend(_listener_conflict_results(rules, adapter))
    results.extend(runtime_binding_doctor_results(config.as_dict(), adapter))

    service = LoaderService(paths=paths, adapter=adapter)
    try:
        service.render()
        results.append(_doctor_result("pass", "doctor.renderer.pass", "Renderer check: rules render successfully"))
    except Exception as exc:
        results.append(_doctor_result("fail", "doctor.renderer.fail", "Renderer check: rules render failed", detail=str(exc)))

    results.extend(rp_filter_doctor_results(rp_filter_report))
    results.extend(conntrack_doctor_results(conntrack_report))

    return results
