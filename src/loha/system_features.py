from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from .constants import CONNTRACK_PROFILE_SPECS
from .i18n import translate_text
from .models import CanonicalConfig, ConntrackStatusReport, DoctorResult, RPFilterStatusReport
from .system import SystemAdapter

def _doctor_result(
    level: str,
    summary_key: str,
    summary_default: str,
    *,
    detail: str = "",
    detail_key: str = "",
    detail_default: str = "",
    **values,
) -> DoctorResult:
    return DoctorResult(
        level=level,
        summary=summary_default.format(**values),
        detail=detail_default.format(**values) if detail_default else detail,
        summary_key=summary_key,
        summary_default=summary_default,
        detail_key=detail_key,
        detail_default=detail_default,
        values=dict(values),
    )


def rp_filter_apply_mode(mode: str) -> str:
    normalized = mode.strip().lower()
    if normalized == "system":
        return "write_ip_forward_only"
    if normalized == "strict":
        return "write_strict"
    if normalized == "loose_scoped":
        return "write_loose_scoped"
    if normalized == "loose_global":
        return "write_loose_global"
    raise ValueError(f"unsupported RP_FILTER_MODE: {mode}")


def rp_filter_target_ifaces(config: CanonicalConfig) -> Tuple[str, ...]:
    values = []
    seen = set()
    for name in [config["PRIMARY_EXTERNAL_IF"], *[item for item in config["LAN_IFS"].split(",") if item]]:
        if name and name not in seen:
            seen.add(name)
            values.append(name)
    return tuple(values)


def render_forwarding_sysctl_content(config: CanonicalConfig) -> str:
    mode = rp_filter_apply_mode(config["RP_FILTER_MODE"])
    lines = ["net.ipv4.ip_forward = 1"]
    if mode == "write_ip_forward_only":
        return "\n".join(lines) + "\n"
    value = "1" if mode == "write_strict" else "2"
    if mode == "write_loose_global":
        lines.append("net.ipv4.conf.all.rp_filter = 2")
        lines.append("net.ipv4.conf.default.rp_filter = 2")
    for iface in rp_filter_target_ifaces(config):
        lines.append(f"net.ipv4.conf.{iface}.rp_filter = {value}")
    return "\n".join(lines) + "\n"


def conntrack_profile_spec(mode: str) -> Dict[str, int]:
    return dict(CONNTRACK_PROFILE_SPECS[mode])


def conntrack_effective_target(config: CanonicalConfig) -> Tuple[int, int]:
    mode = config["CONNTRACK_MODE"]
    if mode in CONNTRACK_PROFILE_SPECS:
        spec = CONNTRACK_PROFILE_SPECS[mode]
        return spec["target_max"], spec["buckets"]
    if mode == "custom":
        target = int(config["CONNTRACK_TARGET_MAX"])
        return target, max(128, target // 128)
    if mode == "auto":
        peak = int(config["CONNTRACK_PEAK"])
        memory_percent = int(config["CONNTRACK_MEMORY_PERCENT"])
        target = max(32768, peak * 2)
        buckets = max(256, target // max(32, min(128, memory_percent)))
        return target, buckets
    return 0, 0


def render_conntrack_sysctl_content(config: CanonicalConfig) -> str:
    if config["CONNTRACK_MODE"] == "system":
        return ""
    target, buckets = conntrack_effective_target(config)
    return "\n".join(
        [
            f"net.netfilter.nf_conntrack_max = {target}",
            f"net.netfilter.nf_conntrack_buckets = {buckets}",
        ]
    ) + "\n"


def render_conntrack_modprobe_content(config: CanonicalConfig) -> str:
    if config["CONNTRACK_MODE"] == "system":
        return ""
    _, buckets = conntrack_effective_target(config)
    return "\n".join(
        [
            "# Managed by LOHA - Persist conntrack hashsize on module load",
            f"options nf_conntrack hashsize={buckets}",
        ]
    ) + "\n"


def apply_rp_filter_files(
    paths,
    config: CanonicalConfig,
    *,
    write_text: Callable[[Path, str], None],
) -> None:
    write_text(paths.forwarding_sysctl, render_forwarding_sysctl_content(config))


def apply_conntrack_files(
    paths,
    config: CanonicalConfig,
    *,
    write_text: Callable[[Path, str], None],
    remove_path: Callable[[Path], None],
) -> None:
    sysctl_content = render_conntrack_sysctl_content(config)
    modprobe_content = render_conntrack_modprobe_content(config)
    if sysctl_content:
        write_text(paths.conntrack_sysctl, sysctl_content)
        write_text(paths.conntrack_modprobe, modprobe_content)
        return
    remove_path(paths.conntrack_sysctl)
    remove_path(paths.conntrack_modprobe)


def apply_system_feature_files(
    paths,
    config: CanonicalConfig,
    *,
    write_text: Callable[[Path, str], None],
    remove_path: Callable[[Path], None],
) -> None:
    apply_rp_filter_files(paths, config, write_text=write_text)
    apply_conntrack_files(paths, config, write_text=write_text, remove_path=remove_path)


def _parse_sysctl_text(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _read_optional_text(adapter: SystemAdapter, path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return adapter.read_text(path)
    except Exception:
        return ""


def _read_optional_value(adapter: SystemAdapter, path: Path) -> str:
    return _read_optional_text(adapter, path).strip()


def _extract_rp_filter_values(entries: Mapping[str, str]) -> Tuple[str, str, Dict[str, str]]:
    iface_values: Dict[str, str] = {}
    for key, value in entries.items():
        if not key.startswith("net.ipv4.conf.") or not key.endswith(".rp_filter"):
            continue
        iface = key[len("net.ipv4.conf.") : -len(".rp_filter")]
        if iface in {"all", "default"}:
            continue
        iface_values[iface] = value
    return (
        entries.get("net.ipv4.conf.default.rp_filter", ""),
        entries.get("net.ipv4.conf.all.rp_filter", ""),
        iface_values,
    )


def _detect_rp_filter_mode(default_value: str, all_value: str, iface_values: Mapping[str, str]) -> str:
    iface_count = len(iface_values)
    if iface_count == 0 and not default_value and not all_value:
        return "runtime_only"
    if default_value == "2" and all_value == "2":
        if iface_count == 0 or all(value == "2" for value in iface_values.values()):
            return "loose_global"
    if default_value == "1" and all_value == "1":
        if iface_count == 0 or all(value == "1" for value in iface_values.values()):
            return "strict"
    if not default_value and not all_value:
        if iface_count > 0 and all(value == "1" for value in iface_values.values()):
            return "strict"
        if iface_count > 0 and all(value == "2" for value in iface_values.values()):
            return "loose_scoped"
    return "custom"


def _format_rp_filter_effective(all_value: str, iface_value: str) -> str:
    if all_value.isdigit() and iface_value.isdigit():
        return str(max(int(all_value), int(iface_value)))
    return "N/A"


def format_rp_filter_scope(
    target_ifaces: Iterable[str],
    default_value: str,
    all_value: str,
    iface_values: Mapping[str, str],
) -> str:
    left = f"default={default_value or 'unset'}, all={all_value or 'unset'}"
    rendered_ifaces = []
    for iface in target_ifaces:
        value = iface_values.get(iface, "unset")
        effective = _format_rp_filter_effective(all_value, value)
        rendered_ifaces.append(f"{iface}={value}(eff={effective})")
    right = ", ".join(rendered_ifaces) if rendered_ifaces else "interfaces=none"
    return f"{left}; {right}"


def describe_rp_filter_source(
    report: RPFilterStatusReport,
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> str:
    if report.configured_mode == "system":
        if report.file_present and report.file_mode != "runtime_only":
            return translate_text(
                translate,
                "system_feature.rpfilter.source.system_still_managed",
                "Existing LOHA-managed sysctl content still drives rp_filter even though system mode is configured.",
            )
        return translate_text(
            translate,
            "system_feature.rpfilter.source.system_clean",
            "No LOHA-managed rp_filter values are required in system mode; LOHA only ensures ip_forward=1.",
        )
    if not report.file_present:
        return translate_text(
            translate,
            "system_feature.rpfilter.source.missing_file",
            "Expected LOHA-managed rp_filter sysctl file is missing.",
        )
    if report.file_matches_expected:
        return translate_text(
            translate,
            "system_feature.rpfilter.source.file_match",
            "LOHA-managed rp_filter sysctl file matches configured mode {mode}.",
            mode=report.configured_mode,
        )
    return translate_text(
        translate,
        "system_feature.rpfilter.source.file_mismatch",
        "LOHA-managed rp_filter sysctl file is present but currently resolves to {mode}.",
        mode=report.file_mode,
    )


def describe_rp_filter_runtime(
    report: RPFilterStatusReport,
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> str:
    scope = format_rp_filter_scope(
        report.target_ifaces,
        report.runtime_default_value,
        report.runtime_all_value,
        report.runtime_iface_values,
    )
    if report.runtime_state == "system":
        return translate_text(
            translate,
            "system_feature.rpfilter.runtime.system",
            "system mode is configured and runtime rp_filter is not LOHA-managed (current={current}; {scope})",
            current=report.runtime_mode,
            scope=scope,
        )
    if report.runtime_state == "system_managed":
        return translate_text(
            translate,
            "system_feature.rpfilter.runtime.system_managed",
            "configured as system, but runtime rp_filter is still LOHA-managed (current={current}; {scope})",
            current=report.runtime_mode,
            scope=scope,
        )
    if report.runtime_state == "match":
        return translate_text(
            translate,
            "system_feature.rpfilter.runtime.match",
            "matches the configured rp_filter mode (current={current}; {scope})",
            current=report.runtime_mode,
            scope=scope,
        )
    if report.runtime_state == "no_file":
        return translate_text(
            translate,
            "system_feature.rpfilter.runtime.no_file",
            "configured mode cannot be enforced because the LOHA-managed sysctl file is missing (current={current}; {scope})",
            current=report.runtime_mode,
            scope=scope,
        )
    return translate_text(
        translate,
        "system_feature.rpfilter.runtime.mismatch",
        "does not match the configured rp_filter mode (current={current}; {scope})",
        current=report.runtime_mode,
        scope=scope,
    )


def describe_conntrack_runtime(
    report: ConntrackStatusReport,
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> str:
    if report.runtime_state == "system":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.system",
            "system mode; LOHA does not manage conntrack",
        )
    if report.runtime_state == "system_managed":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.system_managed",
            "configured as system, but LOHA-managed conntrack config files are still present",
        )
    if report.runtime_state == "component_missing":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.component_missing",
            "configured as {mode}, but conntrack tuning components are unavailable",
            mode=report.configured_mode,
        )
    if report.runtime_state == "expected_unavailable":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.expected_unavailable",
            "configured as {mode}, but the expected runtime target could not be derived",
            mode=report.configured_mode,
        )
    if report.runtime_state == "match":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.match",
            "matches runtime nf_conntrack_max={runtime_max} for mode {mode}",
            runtime_max=report.runtime_max,
            mode=report.configured_mode,
        )
    if report.runtime_state == "bucket_mismatch":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.bucket_mismatch",
            "runtime nf_conntrack_max matches mode {mode}, but nf_conntrack_buckets={runtime_buckets} "
            "(expected {expected_buckets})",
            mode=report.configured_mode,
            runtime_buckets=report.runtime_buckets,
            expected_buckets=report.expected_buckets,
        )
    if report.runtime_state == "mismatch":
        return translate_text(
            translate,
            "system_feature.conntrack.runtime.mismatch",
            "configured as {mode}, but runtime nf_conntrack_max={runtime_max} (expected {expected_max})",
            mode=report.configured_mode,
            runtime_max=report.runtime_max or "N/A",
            expected_max=report.expected_max,
        )
    return report.runtime_state


def collect_rp_filter_status(
    paths,
    config: CanonicalConfig,
    adapter: SystemAdapter,
    *,
    runtime_paths: Mapping[str, Path] = None,
) -> RPFilterStatusReport:
    runtime_paths = runtime_paths or {}
    target_ifaces = rp_filter_target_ifaces(config)
    expected_file_content = render_forwarding_sysctl_content(config)
    file_text = _read_optional_text(adapter, paths.forwarding_sysctl)
    file_present = bool(file_text) or paths.forwarding_sysctl.exists()
    file_entries = _parse_sysctl_text(file_text)
    file_default, file_all, file_ifaces = _extract_rp_filter_values(file_entries)
    file_mode = _detect_rp_filter_mode(file_default, file_all, file_ifaces) if file_present else "missing"

    conf_base = runtime_paths.get("conf_base", Path("/proc/sys/net/ipv4/conf"))
    runtime_ip_forward = _read_optional_value(
        adapter,
        runtime_paths.get("ip_forward", Path("/proc/sys/net/ipv4/ip_forward")),
    )
    runtime_default_value = _read_optional_value(adapter, runtime_paths.get("default", conf_base / "default" / "rp_filter"))
    runtime_all_value = _read_optional_value(adapter, runtime_paths.get("all", conf_base / "all" / "rp_filter"))
    runtime_iface_values: Dict[str, str] = {}
    for iface in target_ifaces:
        value = _read_optional_value(adapter, conf_base / iface / "rp_filter")
        if value:
            runtime_iface_values[iface] = value
    runtime_mode = _detect_rp_filter_mode(runtime_default_value, runtime_all_value, runtime_iface_values)

    configured_mode = config["RP_FILTER_MODE"]
    if configured_mode == "system":
        runtime_state = "system_managed" if file_present and file_mode != "runtime_only" else "system"
    elif not file_present:
        runtime_state = "no_file"
    elif runtime_mode == configured_mode:
        runtime_state = "match"
    else:
        runtime_state = "mismatch"

    return RPFilterStatusReport(
        configured_mode=configured_mode,
        target_ifaces=target_ifaces,
        expected_file_content=expected_file_content,
        file_present=file_present,
        file_matches_expected=file_present and file_text == expected_file_content,
        file_mode=file_mode,
        runtime_ip_forward=runtime_ip_forward,
        runtime_default_value=runtime_default_value,
        runtime_all_value=runtime_all_value,
        runtime_iface_values=runtime_iface_values,
        runtime_mode=runtime_mode,
        runtime_state=runtime_state,
    )


def collect_conntrack_status(
    paths,
    config: CanonicalConfig,
    adapter: SystemAdapter,
    *,
    runtime_paths: Mapping[str, Path] = None,
) -> ConntrackStatusReport:
    runtime_paths = runtime_paths or {}
    expected_max, expected_buckets = conntrack_effective_target(config)
    expected_sysctl_content = render_conntrack_sysctl_content(config)
    expected_modprobe_content = render_conntrack_modprobe_content(config)

    sysctl_text = _read_optional_text(adapter, paths.conntrack_sysctl)
    modprobe_text = _read_optional_text(adapter, paths.conntrack_modprobe)
    sysctl_file_present = bool(sysctl_text) or paths.conntrack_sysctl.exists()
    modprobe_file_present = bool(modprobe_text) or paths.conntrack_modprobe.exists()

    runtime_max = _read_optional_value(
        adapter,
        runtime_paths.get("max", Path("/proc/sys/net/netfilter/nf_conntrack_max")),
    )
    runtime_buckets = _read_optional_value(
        adapter,
        runtime_paths.get("buckets", Path("/proc/sys/net/netfilter/nf_conntrack_buckets")),
    )

    configured_mode = config["CONNTRACK_MODE"]
    if configured_mode == "system":
        runtime_state = "system_managed" if sysctl_file_present or modprobe_file_present else "system"
    elif not sysctl_file_present or not modprobe_file_present:
        runtime_state = "component_missing"
    elif sysctl_text != expected_sysctl_content or modprobe_text != expected_modprobe_content:
        runtime_state = "component_mismatch"
    elif not expected_max:
        runtime_state = "expected_unavailable"
    elif runtime_max.isdigit() and int(runtime_max) == expected_max:
        if runtime_buckets.isdigit() and int(runtime_buckets) != expected_buckets:
            runtime_state = "bucket_mismatch"
        else:
            runtime_state = "match"
    else:
        runtime_state = "mismatch"

    return ConntrackStatusReport(
        configured_mode=configured_mode,
        expected_max=expected_max,
        expected_buckets=expected_buckets,
        expected_sysctl_content=expected_sysctl_content,
        expected_modprobe_content=expected_modprobe_content,
        sysctl_file_present=sysctl_file_present,
        modprobe_file_present=modprobe_file_present,
        sysctl_matches_expected=sysctl_file_present and sysctl_text == expected_sysctl_content,
        modprobe_matches_expected=modprobe_file_present and modprobe_text == expected_modprobe_content,
        runtime_max=runtime_max,
        runtime_buckets=runtime_buckets,
        runtime_state=runtime_state,
    )


def format_rp_filter_status_lines(
    report: RPFilterStatusReport,
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> List[str]:
    lines = [
        translate_text(
            translate,
            "system_feature.rpfilter.status.mode_line",
            "rp_filter mode: {mode}",
            mode=report.configured_mode,
        )
    ]
    lines.append(
        translate_text(
            translate,
            "system_feature.rpfilter.status.current_scope",
            "Current scope: {scope}",
            scope=format_rp_filter_scope(
                report.target_ifaces,
                report.runtime_default_value,
                report.runtime_all_value,
                report.runtime_iface_values,
            ),
        )
    )
    lines.append(
        translate_text(
            translate,
            "system_feature.rpfilter.status.effective_hint",
            "Effective hint: effective rp_filter is max(all, iface) per interface.",
        )
    )
    lines.append(
        translate_text(
            translate,
            "system_feature.rpfilter.status.source",
            "Source: {source}",
            source=describe_rp_filter_source(report, translate=translate),
        )
    )
    lines.append(
        translate_text(
            translate,
            "system_feature.rpfilter.status.runtime",
            "Runtime: {runtime}",
            runtime=describe_rp_filter_runtime(report, translate=translate),
        )
    )
    return lines


def format_conntrack_status_lines(
    report: ConntrackStatusReport,
    *,
    translate: Optional[Callable[[str, str], str]] = None,
) -> List[str]:
    lines = [
        translate_text(
            translate,
            "system_feature.conntrack.status.mode_line",
            "Conntrack mode: {mode}",
            mode=report.configured_mode,
        )
    ]
    if report.configured_mode != "system":
        lines.append(
            translate_text(
                translate,
                "system_feature.conntrack.status.configured_target",
                "Configured target: nf_conntrack_max={target_max}, nf_conntrack_buckets={buckets}",
                target_max=report.expected_max,
                buckets=report.expected_buckets,
            )
        )
    source_bits = []
    if report.sysctl_file_present:
        source_bits.append(translate_text(translate, "system_feature.conntrack.status.source_sysctl", "sysctl file present"))
    if report.modprobe_file_present:
        source_bits.append(translate_text(translate, "system_feature.conntrack.status.source_modprobe", "modprobe file present"))
    if not source_bits:
        source_bits.append(
            translate_text(translate, "system_feature.conntrack.status.source_none", "no LOHA-managed tuning files present")
        )
    lines.append(
        translate_text(
            translate,
            "system_feature.conntrack.status.source",
            "Source: {source}",
            source=", ".join(source_bits),
        )
    )
    runtime_bits = [f"nf_conntrack_max={report.runtime_max or 'N/A'}"]
    if report.runtime_buckets:
        runtime_bits.append(f"nf_conntrack_buckets={report.runtime_buckets}")
    lines.append(
        translate_text(
            translate,
            "system_feature.conntrack.status.current_runtime",
            "Current runtime: {runtime}",
            runtime=", ".join(runtime_bits),
        )
    )
    lines.append(
        translate_text(
            translate,
            "system_feature.conntrack.status.runtime",
            "Runtime: {runtime}",
            runtime=describe_conntrack_runtime(report, translate=translate),
        )
    )
    return lines


def rp_filter_runtime_sysctl_results(report: RPFilterStatusReport) -> List[DoctorResult]:
    results: List[DoctorResult] = []
    if report.runtime_ip_forward == "1":
        results.append(
            _doctor_result(
                "pass",
                "doctor.runtime_sysctl.ip_forward_ok",
                "Runtime sysctl check: net.ipv4.ip_forward=1",
            )
        )
    elif report.runtime_ip_forward:
        results.append(
            _doctor_result(
                "warn",
                "doctor.runtime_sysctl.ip_forward_not_one",
                "Runtime sysctl check: net.ipv4.ip_forward is not 1",
                detail_key="doctor.detail.current_value",
                detail_default="current={current}",
                current=report.runtime_ip_forward,
            )
        )
    else:
        results.append(
            _doctor_result(
                "warn",
                "doctor.runtime_sysctl.ip_forward_unavailable",
                "Runtime sysctl check: unable to read net.ipv4.ip_forward",
            )
        )

    if report.runtime_all_value in {"0", "1", "2"}:
        results.append(
            _doctor_result(
                "pass",
                "doctor.runtime_sysctl.rp_all_ok",
                "Runtime sysctl check: net.ipv4.conf.all.rp_filter={current}",
                current=report.runtime_all_value,
            )
        )
    else:
        results.append(
            _doctor_result(
                "warn",
                "doctor.runtime_sysctl.rp_all_unavailable",
                "Runtime sysctl check: net.ipv4.conf.all.rp_filter is unavailable or unexpected",
                detail_key="doctor.detail.current_value",
                detail_default="current={current}",
                current=report.runtime_all_value or "N/A",
            )
        )

    if report.runtime_default_value in {"0", "1", "2"}:
        results.append(
            _doctor_result(
                "pass",
                "doctor.runtime_sysctl.rp_default_ok",
                "Runtime sysctl check: net.ipv4.conf.default.rp_filter={current}",
                current=report.runtime_default_value,
            )
        )
    else:
        results.append(
            _doctor_result(
                "warn",
                "doctor.runtime_sysctl.rp_default_unavailable",
                "Runtime sysctl check: net.ipv4.conf.default.rp_filter is unavailable or unexpected",
                detail_key="doctor.detail.current_value",
                detail_default="current={current}",
                current=report.runtime_default_value or "N/A",
            )
        )
    return results


def rp_filter_doctor_results(report: RPFilterStatusReport) -> List[DoctorResult]:
    results: List[DoctorResult] = []
    if report.configured_mode == "system":
        if report.file_present and report.file_mode != "runtime_only":
            results.append(
                _doctor_result(
                    "warn",
                    "doctor.rpfilter.config.system_still_managed",
                    "rp_filter config check: RP_FILTER_MODE=system but LOHA-managed rp_filter lines are still present",
                    detail_key="doctor.detail.detected_file_mode",
                    detail_default="detected_file_mode={mode}",
                    mode=report.file_mode,
                )
            )
        else:
            results.append(
                _doctor_result(
                    "pass",
                    "doctor.rpfilter.config.system_coherent",
                    "rp_filter config check: system mode is coherent",
                )
            )
    else:
        if not report.file_present:
            results.append(
                _doctor_result(
                    "warn",
                    "doctor.rpfilter.config.file_missing",
                    "rp_filter config check: expected LOHA-managed sysctl file is missing",
                )
            )
        elif not report.file_matches_expected:
            results.append(
                _doctor_result(
                    "warn",
                    "doctor.rpfilter.config.file_mismatch",
                    "rp_filter config check: current sysctl file does not match RP_FILTER_MODE",
                    detail_key="doctor.detail.detected_file_mode",
                    detail_default="detected_file_mode={mode}",
                    mode=report.file_mode,
                )
            )
        else:
            results.append(
                _doctor_result(
                    "pass",
                    "doctor.rpfilter.config.file_match",
                    "rp_filter config check: current sysctl file matches RP_FILTER_MODE",
                )
            )

    if report.runtime_state in {"system", "match"}:
        results.append(
            _doctor_result(
                "pass",
                "doctor.rpfilter.runtime.coherent",
                "rp_filter runtime check: effective runtime state is coherent",
                detail=format_rp_filter_scope(
                    report.target_ifaces,
                    report.runtime_default_value,
                    report.runtime_all_value,
                    report.runtime_iface_values,
                ),
            )
        )
    elif report.runtime_state == "system_managed":
        results.append(
            _doctor_result(
                "warn",
                "doctor.rpfilter.runtime.system_managed",
                "rp_filter runtime check: system mode is configured but rp_filter is still LOHA-managed",
                detail_key="doctor.detail.current_mode",
                detail_default="current={mode}",
                mode=report.runtime_mode,
            )
        )
    elif report.runtime_state == "no_file":
        results.append(
            _doctor_result(
                "warn",
                "doctor.rpfilter.runtime.no_file",
                "rp_filter runtime check: configured mode cannot be enforced because the sysctl file is missing",
            )
        )
    else:
        results.append(
            _doctor_result(
                "warn",
                "doctor.rpfilter.runtime.mismatch",
                "rp_filter runtime check: effective runtime state does not match RP_FILTER_MODE",
                detail_key="doctor.rpfilter.runtime.mismatch_detail",
                detail_default="configured={configured} current={current}",
                configured=report.configured_mode,
                current=report.runtime_mode,
            )
        )
    return results


def conntrack_doctor_results(report: ConntrackStatusReport) -> List[DoctorResult]:
    results: List[DoctorResult] = []
    if report.configured_mode == "system":
        if report.sysctl_file_present or report.modprobe_file_present:
            results.append(
                _doctor_result(
                    "warn",
                    "doctor.conntrack.config.system_still_managed",
                    "Conntrack config check: CONNTRACK_MODE=system but LOHA-managed conntrack files are still present",
                )
            )
        else:
            results.append(
                _doctor_result(
                    "pass",
                    "doctor.conntrack.config.system_coherent",
                    "Conntrack config check: system mode is coherent",
                )
            )
        return results

    if not report.sysctl_file_present or not report.modprobe_file_present:
        results.append(
            _doctor_result(
                "warn",
                "doctor.conntrack.config.files_missing",
                "Conntrack config check: LOHA-managed conntrack tuning files are missing",
                detail_key="doctor.conntrack.config.files_missing_detail",
                detail_default="sysctl={sysctl} modprobe={modprobe}",
                sysctl="present" if report.sysctl_file_present else "missing",
                modprobe="present" if report.modprobe_file_present else "missing",
            )
        )
    elif not report.sysctl_matches_expected or not report.modprobe_matches_expected:
        results.append(
            _doctor_result(
                "warn",
                "doctor.conntrack.config.files_mismatch",
                "Conntrack config check: LOHA-managed conntrack tuning files do not match the configured target",
            )
        )
    else:
        results.append(
            _doctor_result(
                "pass",
                "doctor.conntrack.config.files_present",
                "Conntrack config check: {mode} mode files are present",
                mode=report.configured_mode,
            )
        )

    if not report.runtime_max:
        results.append(
            _doctor_result(
                "warn",
                "doctor.conntrack.runtime.unavailable",
                "Conntrack runtime check: unable to read nf_conntrack_max",
            )
        )
    elif not report.runtime_max.isdigit():
        results.append(
            _doctor_result(
                "warn",
                "doctor.conntrack.runtime.non_numeric",
                "Conntrack runtime check: nf_conntrack_max is not numeric",
                detail_key="doctor.detail.current_value",
                detail_default="current={current}",
                current=report.runtime_max,
            )
        )
    elif int(report.runtime_max) != report.expected_max:
        results.append(
            _doctor_result(
                "warn",
                "doctor.conntrack.runtime.max_mismatch",
                "Conntrack runtime check: nf_conntrack_max differs from the configured target",
                detail_key="doctor.conntrack.runtime.max_mismatch_detail",
                detail_default="runtime={runtime} expected={expected}",
                runtime=report.runtime_max,
                expected=report.expected_max,
            )
        )
    elif report.runtime_buckets.isdigit() and int(report.runtime_buckets) != report.expected_buckets:
        results.append(
            _doctor_result(
                "warn",
                "doctor.conntrack.runtime.buckets_mismatch",
                "Conntrack runtime check: nf_conntrack_buckets differs from the configured target",
                detail_key="doctor.conntrack.runtime.buckets_mismatch_detail",
                detail_default="runtime={runtime} expected={expected}",
                runtime=report.runtime_buckets,
                expected=report.expected_buckets,
            )
        )
    else:
        detail = f"nf_conntrack_max={report.runtime_max}"
        if report.runtime_buckets:
            detail += f" nf_conntrack_buckets={report.runtime_buckets}"
        results.append(
            _doctor_result(
                "pass",
                "doctor.conntrack.runtime.match",
                "Conntrack runtime check: runtime values match the configured target",
                detail=detail,
            )
        )
    return results
