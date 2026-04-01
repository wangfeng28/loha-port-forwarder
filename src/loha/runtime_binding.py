import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Mapping, Tuple

from .config import join_csv, normalize_toggle, parse_csv, trim_spaces, validate_iface, validate_ipv4
from .constants import DEFAULT_CONFIG_VALUES
from .exceptions import ApplyError
from .models import DoctorResult, LocalizedMessage
from .system import SystemAdapter


@dataclass(frozen=True)
class ExternalBindingResolution:
    external_ifs: str
    primary_external_if: str
    origin: str


@dataclass(frozen=True)
class ListenerBindingResolution:
    listen_ips: str
    default_snat_ip: str
    origin: str


@dataclass(frozen=True)
class RuntimeBindingResolution:
    external: ExternalBindingResolution
    listener: ListenerBindingResolution

    @property
    def values(self) -> Dict[str, str]:
        return {
            "EXTERNAL_IFS": self.external.external_ifs,
            "PRIMARY_EXTERNAL_IF": self.external.primary_external_if,
            "LISTEN_IPS": self.listener.listen_ips,
            "DEFAULT_SNAT_IP": self.listener.default_snat_ip,
        }


@dataclass(frozen=True)
class BindingStatusDescription:
    status: str
    message_key: str
    message_default: str
    note_key: str = ""
    note_default: str = ""


def _binding_result(
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


def _first_csv_value(csv_text: str) -> str:
    return next((item.strip() for item in csv_text.split(",") if item.strip()), "")


TOGGLE_SHORTCUT_DEFAULTS = {
    "ENABLE_HAIRPIN": DEFAULT_CONFIG_VALUES["ENABLE_HAIRPIN"],
    "ENABLE_WAN_TO_WAN": DEFAULT_CONFIG_VALUES["ENABLE_WAN_TO_WAN"],
    "ENABLE_TCPMSS_CLAMP": DEFAULT_CONFIG_VALUES["ENABLE_TCPMSS_CLAMP"],
}


def materialize_toggle_shortcut(raw_value: str, default_value: str) -> str:
    raw = trim_spaces(raw_value)
    if not raw:
        return default_value
    normalized = normalize_toggle(raw, allow_auto=True)
    if normalized == "auto":
        return default_value
    return normalized


def sync_toggle_shortcut_state(state: Mapping[str, str]) -> Dict[str, str]:
    updated = dict(state)
    for key, default_value in TOGGLE_SHORTCUT_DEFAULTS.items():
        updated[key] = materialize_toggle_shortcut(updated.get(key, ""), default_value)
    return updated


def detect_binding_status(binding_kind: str, configured_value: str) -> str:
    normalized = trim_spaces(configured_value).lower()
    if binding_kind not in {"external", "listen"}:
        raise ValueError(f"unsupported binding kind: {binding_kind}")
    if not normalized:
        return "unset"
    if normalized == "auto":
        return "compatible_auto"
    try:
        items = parse_csv(normalized, kind="iface" if binding_kind == "external" else "ipv4")
    except Exception:
        return "invalid"
    if binding_kind == "external" and len(items) > 1:
        return "out_of_scope_multi"
    if len(items) > 1:
        return "compatible_multiple"
    return "compatible"


def describe_binding_status(binding_kind: str, configured_value: str) -> BindingStatusDescription:
    status = detect_binding_status(binding_kind, configured_value)
    mapping = {
        ("external", "unset"): BindingStatusDescription(
            "unset",
            "runtime_binding.status.unset",
            "not set",
        ),
        ("listen", "unset"): BindingStatusDescription(
            "unset",
            "runtime_binding.status.unset",
            "not set",
        ),
        ("external", "compatible"): BindingStatusDescription(
            "compatible",
            "runtime_binding.status.external_single",
            "compatible now via the configured single-interface binding",
        ),
        ("external", "compatible_auto"): BindingStatusDescription(
            "compatible_auto",
            "runtime_binding.status.external_auto",
            "compatible now when exactly one default IPv4 egress interface can be resolved",
            "runtime_binding.note.external_auto",
            "If the main routing table has multiple default IPv4 routes, set the external interface binding manually instead of using auto.",
        ),
        ("external", "out_of_scope_multi"): BindingStatusDescription(
            "out_of_scope_multi",
            "runtime_binding.status.external_multi_out_of_scope",
            "out of scope: only one external interface is supported",
        ),
        ("listen", "compatible"): BindingStatusDescription(
            "compatible",
            "runtime_binding.status.listen_single",
            "compatible now via the configured external IP list used for exposure",
        ),
        ("listen", "compatible_auto"): BindingStatusDescription(
            "compatible_auto",
            "runtime_binding.status.listen_auto",
            "compatible now via the current primary external interface addresses",
            "runtime_binding.note.listen_auto",
            "Exposure address binding in auto mode resolves external IPv4 addresses from the primary external interface at runtime.",
        ),
        ("listen", "compatible_multiple"): BindingStatusDescription(
            "compatible_multiple",
            "runtime_binding.status.listen_multiple",
            "compatible now via the configured external IP list used for exposure",
        ),
        ("external", "invalid"): BindingStatusDescription(
            "invalid",
            "runtime_binding.status.invalid_external",
            "External interface binding is invalid",
        ),
        ("listen", "invalid"): BindingStatusDescription(
            "invalid",
            "runtime_binding.status.invalid_listen",
            "Exposure address binding is invalid",
        ),
    }
    return mapping[(binding_kind, status)]


def runtime_binding_summary_lines(
    state: Mapping[str, str],
    *,
    translate: Callable[[str, str], str],
) -> List[str]:
    external = describe_binding_status("external", state.get("EXTERNAL_IFS", ""))
    listen = describe_binding_status("listen", state.get("LISTEN_IPS", ""))
    lines = [
        f"{translate('wizard.summary.fields.external_runtime', 'External interface binding')}: "
        f"{translate(external.message_key, external.message_default)}",
        f"{translate('wizard.summary.fields.listen_runtime', 'Exposure address binding')}: "
        f"{translate(listen.message_key, listen.message_default)}",
    ]
    if external.note_key:
        lines.append(translate(external.note_key, external.note_default))
    if listen.note_key:
        lines.append(translate(listen.note_key, listen.note_default))
    return lines


def _extract_csv_from_parentheses(detail: str) -> str:
    match = re.search(r"\(([^)]+)\)", detail)
    if match is None:
        return ""
    return match.group(1).strip()


def _extract_interface_after_colon(detail: str) -> str:
    if ":" not in detail:
        return ""
    return detail.rsplit(":", 1)[1].strip()


def _parse_listener_boundary_error(detail: str) -> Tuple[str, str]:
    match = re.search(r"PRIMARY_EXTERNAL_IF \(([^)]+)\): (.+)$", detail)
    if match is None:
        return "", ""
    return match.group(1).strip(), match.group(2).strip()


def resolve_external_binding(state: Mapping[str, str], adapter: SystemAdapter) -> ExternalBindingResolution:
    configured_external = trim_spaces(state.get("EXTERNAL_IFS", ""))
    primary_external = trim_spaces(state.get("PRIMARY_EXTERNAL_IF", ""))
    origin = "configured"

    if configured_external.lower() == "auto":
        origin = "auto"
        if primary_external:
            validate_iface(primary_external)
            configured_external = primary_external
        else:
            probed_ifaces = tuple(item for item in adapter.default_ipv4_ifaces() if item)
            if not probed_ifaces:
                raise ApplyError(
                    "EXTERNAL_IFS=auto could not find any default IPv4 egress interface in the main routing table. "
                    "Set PRIMARY_EXTERNAL_IF or EXTERNAL_IFS explicitly."
                )
            if len(probed_ifaces) > 1:
                raise ApplyError(
                    "EXTERNAL_IFS=auto found multiple default IPv4 egress interfaces in the main routing table "
                    f"({','.join(probed_ifaces)}). Set PRIMARY_EXTERNAL_IF or EXTERNAL_IFS explicitly."
                )
            primary_external = probed_ifaces[0]
            configured_external = primary_external
    elif configured_external:
        configured_external = join_csv(parse_csv(configured_external, kind="iface"))
    elif primary_external:
        validate_iface(primary_external)
        configured_external = primary_external
    else:
        raise ApplyError("External interface binding is incomplete. Set PRIMARY_EXTERNAL_IF or EXTERNAL_IFS.")

    external_values = parse_csv(configured_external, kind="iface")
    if len(external_values) > 1:
        raise ApplyError(
            "The current single-external product boundary only supports one external interface. "
            "Multi-external configs remain out of scope."
        )
    if not primary_external:
        if len(external_values) != 1:
            raise ApplyError("PRIMARY_EXTERNAL_IF is required when EXTERNAL_IFS contains multiple interfaces.")
        primary_external = external_values[0]
    else:
        validate_iface(primary_external)
    if primary_external not in external_values:
        raise ApplyError("PRIMARY_EXTERNAL_IF must be included in EXTERNAL_IFS when both are set.")

    return ExternalBindingResolution(
        external_ifs=join_csv(external_values),
        primary_external_if=primary_external,
        origin=origin,
    )


def resolve_listener_binding(
    state: Mapping[str, str],
    adapter: SystemAdapter,
    external: ExternalBindingResolution,
) -> ListenerBindingResolution:
    configured_listen = trim_spaces(state.get("LISTEN_IPS", ""))
    default_snat = trim_spaces(state.get("DEFAULT_SNAT_IP", ""))
    origin = "configured"

    if configured_listen.lower() == "auto":
        origin = "auto"
        listen_candidates = tuple(item for item in adapter.global_ipv4s(external.primary_external_if) if item)
        if not listen_candidates:
            raise ApplyError(
                "LISTEN_IPS=auto could not resolve any global IPv4 on primary WAN interface: "
                f"{external.primary_external_if}"
            )
        configured_listen = ",".join(listen_candidates)
        if not default_snat:
            default_snat = listen_candidates[0]
    elif configured_listen:
        configured_listen = join_csv(parse_csv(configured_listen, kind="ipv4"))
    elif default_snat:
        validate_ipv4(default_snat)
        configured_listen = default_snat
    else:
        raise ApplyError("Listener address binding is incomplete. Set DEFAULT_SNAT_IP or LISTEN_IPS.")

    listen_values = parse_csv(configured_listen, kind="ipv4")
    if not default_snat:
        if len(listen_values) != 1:
            raise ApplyError("DEFAULT_SNAT_IP is required when LISTEN_IPS contains multiple addresses.")
        default_snat = listen_values[0]
    else:
        default_snat = validate_ipv4(default_snat)
    if default_snat not in listen_values:
        raise ApplyError("DEFAULT_SNAT_IP must be included in LISTEN_IPS when both are set.")
    iface_ips = set(adapter.global_ipv4s(external.primary_external_if))
    invalid = [ip for ip in listen_values if ip not in iface_ips]
    if invalid:
        raise ApplyError(
            "In the current single-external product boundary, LISTEN_IPS must belong to PRIMARY_EXTERNAL_IF "
            f"({external.primary_external_if}): {', '.join(invalid)}"
        )

    return ListenerBindingResolution(
        listen_ips=join_csv(listen_values),
        default_snat_ip=default_snat,
        origin=origin,
    )


def resolve_runtime_binding(state: Mapping[str, str], adapter: SystemAdapter) -> RuntimeBindingResolution:
    external = resolve_external_binding(state, adapter)
    listener = resolve_listener_binding(state, adapter, external)
    return RuntimeBindingResolution(external=external, listener=listener)


def materialize_runtime_binding_values(state: Mapping[str, str], adapter: SystemAdapter) -> Dict[str, str]:
    return resolve_runtime_binding(state, adapter).values


def sync_runtime_binding_state(
    state: Mapping[str, str],
    adapter: SystemAdapter,
    *,
    only_if_shortcuts: bool = False,
) -> Tuple[Dict[str, str], Tuple[LocalizedMessage, ...]]:
    updated = dict(state)
    raw_external = trim_spaces(updated.get("EXTERNAL_IFS", "")).lower()
    raw_listen = trim_spaces(updated.get("LISTEN_IPS", "")).lower()
    if only_if_shortcuts and raw_external != "auto" and raw_listen != "auto":
        return updated, ()
    resolution = resolve_runtime_binding(updated, adapter)
    notices = tuple(runtime_binding_persist_notices(updated, resolution))
    updated.update(resolution.values)
    return updated, notices


def runtime_binding_persist_notices(
    raw_state: Mapping[str, str],
    resolution: RuntimeBindingResolution,
) -> List[LocalizedMessage]:
    notices: List[LocalizedMessage] = []
    raw_external = trim_spaces(raw_state.get("EXTERNAL_IFS", "")).lower()
    raw_listen = trim_spaces(raw_state.get("LISTEN_IPS", "")).lower()
    if raw_external == "auto":
        notices.append(
            LocalizedMessage(
                "runtime_binding.notice.external_auto_materialized",
                "EXTERNAL_IFS=auto was resolved to {value} before saving; loha.conf will store that resolved value.",
                values={"value": resolution.external.external_ifs},
            )
        )
    if raw_listen == "auto":
        notices.append(
            LocalizedMessage(
                "runtime_binding.notice.listen_auto_materialized",
                "LISTEN_IPS=auto was resolved to {value} before saving; loha.conf will store that resolved value.",
                values={"value": resolution.listener.listen_ips},
            )
        )
    return notices


def runtime_binding_doctor_results(state: Mapping[str, str], adapter: SystemAdapter) -> List[DoctorResult]:
    results: List[DoctorResult] = []
    raw_external = trim_spaces(state.get("EXTERNAL_IFS", ""))
    raw_listen = trim_spaces(state.get("LISTEN_IPS", ""))

    try:
        external = resolve_external_binding(state, adapter)
    except Exception as exc:
        detail = str(exc)
        if raw_external.lower() == "auto":
            interfaces = _extract_csv_from_parentheses(detail)
            if interfaces:
                results.append(
                    _binding_result(
                        "fail",
                        "doctor.runtime_binding.external_auto_multi",
                        "Runtime binding check: EXTERNAL_IFS=auto found multiple default IPv4 egress interfaces ({interfaces})",
                        interfaces=interfaces,
                        hint_key="doctor.runtime_binding.external_auto_hint",
                        hint_default="Set PRIMARY_EXTERNAL_IF or EXTERNAL_IFS manually.",
                    )
                )
                if raw_listen.lower() == "auto":
                    results.append(
                        _binding_result(
                            "fail",
                            "doctor.runtime_binding.listener_auto_blocked_by_external_auto",
                            "Runtime binding check: LISTEN_IPS=auto cannot resolve safely because EXTERNAL_IFS=auto sees multiple default egress interfaces ({interfaces})",
                            interfaces=interfaces,
                            hint_key="doctor.runtime_binding.listener_auto_blocked_hint",
                            hint_default="Set PRIMARY_EXTERNAL_IF / EXTERNAL_IFS and LISTEN_IPS manually.",
                        )
                    )
                return results
            if "could not find any default IPv4 egress interface" in detail:
                return [
                    _binding_result(
                        "fail",
                        "doctor.runtime_binding.external_auto_missing",
                        "Runtime binding check: EXTERNAL_IFS=auto could not resolve any default IPv4 egress interface",
                        hint_key="doctor.runtime_binding.external_auto_hint",
                        hint_default="Set PRIMARY_EXTERNAL_IF or EXTERNAL_IFS manually.",
                    )
                ]
        return [
            _binding_result(
                "fail",
                "doctor.runtime_binding.external_invalid",
                "Runtime binding check: external binding is invalid",
                detail=detail,
            )
        ]

    if external.origin == "auto":
        results.append(
            _binding_result(
                "pass",
                "doctor.runtime_binding.external_auto_resolved",
                "Runtime binding check: EXTERNAL_IFS=auto resolves to primary external interface {interface}",
                detail_key="doctor.runtime_binding.external_auto_detail",
                detail_default="materialized EXTERNAL_IFS={value}",
                hint_key="runtime_binding.note.external_auto",
                hint_default="If the main routing table has multiple default IPv4 routes, set EXTERNAL_IFS manually instead of using auto.",
                interface=external.primary_external_if,
                value=external.external_ifs,
            )
        )
    else:
        results.append(
            _binding_result(
                "pass",
                "doctor.runtime_binding.external_explicit",
                "Runtime binding check: external binding uses configured values",
                detail_key="doctor.runtime_binding.external_explicit_detail",
                detail_default="EXTERNAL_IFS={external_ifs} PRIMARY_EXTERNAL_IF={primary_external_if}",
                external_ifs=external.external_ifs,
                primary_external_if=external.primary_external_if,
            )
        )

    try:
        listener = resolve_listener_binding(state, adapter, external)
    except Exception as exc:
        detail = str(exc)
        if raw_listen.lower() == "auto" and "could not resolve any global IPv4 on primary WAN interface:" in detail:
            interface = _extract_interface_after_colon(detail)
            results.append(
                _binding_result(
                    "fail",
                    "doctor.runtime_binding.listener_auto_missing",
                    "Runtime binding check: LISTEN_IPS=auto could not resolve any global IPv4 on primary external interface {interface}",
                    interface=interface,
                    hint_key="doctor.runtime_binding.listener_auto_hint",
                    hint_default="Assign a global IPv4 to the primary WAN interface, or set LISTEN_IPS manually.",
                )
            )
            return results
        interface, invalid_ips = _parse_listener_boundary_error(detail)
        if interface and invalid_ips:
            results.append(
                _binding_result(
                    "fail",
                    "doctor.runtime_binding.listener_outside_primary",
                    "Runtime binding check: LISTEN_IPS ({ips}) contains addresses outside the primary external interface ({interface})",
                    ips=join_csv(parse_csv(invalid_ips, kind="ipv4")),
                    interface=interface,
                    hint_key="doctor.runtime_binding.listener_outside_primary_hint",
                    hint_default="Keep LISTEN_IPS on PRIMARY_EXTERNAL_IF, or revisit the external binding selection.",
                )
            )
            return results
        results.append(
            _binding_result(
                "fail",
                "doctor.runtime_binding.listener_invalid",
                "Runtime binding check: listener binding is invalid",
                detail=detail,
            )
        )
        return results

    if listener.origin == "auto":
        results.append(
            _binding_result(
                "pass",
                "doctor.runtime_binding.listener_auto_resolved",
                "Runtime binding check: LISTEN_IPS=auto resolves on primary external interface {interface} ({listen_ips})",
                interface=external.primary_external_if,
                listen_ips=listener.listen_ips,
                detail_key="doctor.runtime_binding.listener_auto_detail",
                detail_default="DEFAULT_SNAT_IP={default_snat_ip}",
                hint_key="runtime_binding.note.listen_auto",
                hint_default="LISTEN_IPS=auto will resolve external IPv4 addresses used for exposure from PRIMARY_EXTERNAL_IF at runtime.",
                default_snat_ip=listener.default_snat_ip,
            )
        )
    else:
        results.append(
            _binding_result(
                "pass",
                "doctor.runtime_binding.listener_explicit",
                "Runtime binding check: listener binding uses configured values",
                detail_key="doctor.runtime_binding.listener_explicit_detail",
                detail_default="LISTEN_IPS={listen_ips} DEFAULT_SNAT_IP={default_snat_ip}",
                listen_ips=listener.listen_ips,
                default_snat_ip=listener.default_snat_ip,
            )
        )
    return results
