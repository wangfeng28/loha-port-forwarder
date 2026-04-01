from typing import Callable, Dict, List, Optional, Sequence, Tuple

from .auth import plan_auth_mode_switch
from .config import normalize_integer_value, normalize_mapping, parse_csv, recommended_config, validate_iface
from .exceptions import ApplyError, ConfigValidationError
from .i18n import RuntimeI18N, render_localized_messages, runtime_translate
from .input_parsing import InputValidationError, parse_menu_indices
from .models import CanonicalConfig, LocalizedMessage, MenuOption, WizardOutcome
from .runtime_binding import runtime_binding_summary_lines, sync_runtime_binding_state, sync_toggle_shortcut_state
from .steps import STEPS
from .system import SystemAdapter


RECOMMENDED_ADVANCED = {
    "AUTH_MODE": "mark",
    "ENABLE_WAN_TO_WAN": "off",
    "ENABLE_TCPMSS_CLAMP": "off",
    "COUNTER_MODE": "minimal",
    "ENABLE_STRICT_LAN_VALIDATION": "off",
    "RP_FILTER_MODE": "system",
    "CONNTRACK_MODE": "system",
    "CONNTRACK_TARGET_MAX": "",
    "CONNTRACK_PEAK": "",
    "CONNTRACK_MEMORY_PERCENT": "",
}

WIZARD_CANCEL_TOKENS = {"0", "cancel", "quit", "q"}


def _t(i18n: Optional[RuntimeI18N], key: str, default: str, **values) -> str:
    return runtime_translate(i18n, key, default, **values)


def _render_messages(messages: Sequence[LocalizedMessage], i18n: Optional[RuntimeI18N]) -> Tuple[str, ...]:
    return render_localized_messages(messages, i18n)


def _read_wizard_input(
    prompt: str,
    *,
    input_func: Callable[[str], str],
    allow_cancel: bool = True,
) -> str:
    raw = input_func(prompt)
    normalized = raw.strip()
    if allow_cancel and normalized.lower() in WIZARD_CANCEL_TOKENS:
        raise KeyboardInterrupt("wizard cancelled")
    return normalized


def _csv_items(value: str) -> Tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _ordered_unique_values(*groups: Sequence[str]) -> Tuple[str, ...]:
    ordered: List[str] = []
    seen = set()
    for group in groups:
        for value in group:
            if not value or value in seen:
                continue
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)


def _looks_like_menu_selection(raw: str) -> bool:
    return all(char.isdigit() or char == "," or char.isspace() for char in raw)


def _step_title(step_id: str, i18n: Optional[RuntimeI18N]) -> str:
    step = STEPS[step_id]
    return _t(i18n, f"wizard.steps.{step_id}.title", step.title)


def _step_description(step_id: str, i18n: Optional[RuntimeI18N]) -> str:
    step = STEPS[step_id]
    return _t(i18n, f"wizard.steps.{step_id}.description", step.description)


def _step_options(step_id: str, i18n: Optional[RuntimeI18N]) -> Tuple[MenuOption, ...]:
    step = STEPS[step_id]
    localized: List[MenuOption] = []
    for option in step.options:
        option_key = option.value.replace("-", "_")
        label = _t(
            i18n,
            f"wizard.steps.{step_id}.options.{option_key}",
            option.label,
        )
        localized.append(MenuOption(option.token, label, option.value, option.recommended))
    return tuple(localized)


def build_summary(
    config: CanonicalConfig,
    *,
    advanced_checked: bool = False,
    i18n: Optional[RuntimeI18N] = None,
) -> List[Tuple[str, List[str]]]:
    sections: List[Tuple[str, List[str]]] = []
    network_lines = [
        f"{_t(i18n, 'wizard.summary.fields.external_interface', 'External interface')}: {config['PRIMARY_EXTERNAL_IF']}",
        f"{_t(i18n, 'wizard.summary.fields.listen_ips', 'External IPv4 addresses used for exposure')}: {config['LISTEN_IPS']}",
        f"{_t(i18n, 'wizard.summary.fields.default_snat_ip', 'Primary external IP')}: {config['DEFAULT_SNAT_IP']}",
        f"{_t(i18n, 'wizard.summary.fields.lan_ifs', 'Internal interfaces')}: {config['LAN_IFS']}",
        f"{_t(i18n, 'wizard.summary.fields.lan_nets', 'Internal networks')}: {config['LAN_NETS']}",
    ]
    network_lines.extend(
        runtime_binding_summary_lines(
            config.as_dict(),
            translate=lambda key, default: _t(i18n, key, default),
        )
    )
    sections.append(
        (
            _t(i18n, "wizard.summary.sections.network", "Network Topology"),
            network_lines,
        )
    )

    protection_line = {
        "backends": _t(
            i18n,
            "wizard.summary.protection.backends",
            "Protection scope: exposed backends only",
        ),
        "nets": _t(
            i18n,
            "wizard.summary.protection.nets",
            "Protection scope: user-specified protected networks",
        ),
        "both": _t(
            i18n,
            "wizard.summary.protection.both",
            "Protection scope: exposed backends and user-specified protected networks",
        ),
    }[config["PROTECTION_MODE"]]
    exposure_lines = [
        protection_line,
        f"{_t(i18n, 'wizard.summary.fields.hairpin', 'Hairpin NAT')}: "
        f"{_t(i18n, f'common.state.{config['ENABLE_HAIRPIN']}', config['ENABLE_HAIRPIN'])}",
    ]
    if config["PROTECTION_MODE"] in {"nets", "both"}:
        exposure_lines.insert(
            1,
            f"{_t(i18n, 'wizard.summary.fields.protected_nets', 'Protected networks')}: {config['PROTECTED_NETS']}",
        )
    sections.append((_t(i18n, "wizard.summary.sections.exposure", "Exposure and Protection"), exposure_lines))

    if config["ENABLE_EGRESS_SNAT"] == "off":
        sections.append(
            (
                _t(i18n, "wizard.summary.sections.egress", "Default Egress NAT"),
                [_t(i18n, "wizard.summary.egress.disabled", "Managed by LOHA: disabled")],
            )
        )
    else:
        sections.append(
            (
                _t(i18n, "wizard.summary.sections.egress", "Default Egress NAT"),
                [
                    _t(i18n, "wizard.summary.egress.enabled", "Managed by LOHA: enabled"),
                    f"{_t(i18n, 'wizard.summary.fields.egress_nets', 'Networks')}: {config['EGRESS_NETS']}",
                    f"{_t(i18n, 'wizard.summary.fields.egress_ip', 'Default egress source IP')}: {config['DEFAULT_SNAT_IP']}",
                ],
            )
        )

    advanced_lines: List[str] = []
    changed = {key for key, value in RECOMMENDED_ADVANCED.items() if config[key] != value}
    if not changed:
        advanced_lines.append(
            _t(
                i18n,
                "wizard.summary.advanced.recommended_checked"
                if advanced_checked
                else "wizard.summary.advanced.recommended",
                "Advanced settings: checked, kept recommended values"
                if advanced_checked
                else "Advanced settings: using recommended values",
            )
        )
    else:
        labels = {
            "AUTH_MODE": _t(i18n, "wizard.summary.fields.auth_mode", "Authorization marking"),
            "ENABLE_WAN_TO_WAN": _t(i18n, "wizard.summary.fields.enable_wan_to_wan", "WAN-to-WAN forwarding"),
            "ENABLE_TCPMSS_CLAMP": _t(i18n, "wizard.summary.fields.enable_tcpmss_clamp", "Automatic TCP MSS adjustment"),
            "COUNTER_MODE": _t(i18n, "wizard.summary.fields.counter_mode", "Rule counters"),
            "ENABLE_STRICT_LAN_VALIDATION": _t(
                i18n,
                "wizard.summary.fields.enable_strict_lan_validation",
                "Strict internal source validation",
            ),
            "INTERNAL_IFS": _t(i18n, "wizard.summary.fields.internal_ifs", "Interfaces to validate"),
            "TRUSTED_INTERNAL_NETS": _t(
                i18n,
                "wizard.summary.fields.trusted_internal_nets",
                "Trusted source networks",
            ),
            "RP_FILTER_MODE": _t(i18n, "wizard.summary.fields.rp_filter_mode", "rp_filter handling"),
            "CONNTRACK_MODE": _t(i18n, "wizard.summary.fields.conntrack_mode", "Connection capacity tuning"),
            "CONNTRACK_TARGET_MAX": _t(
                i18n,
                "wizard.summary.fields.conntrack_target_max",
                "Maximum concurrent connections",
            ),
            "CONNTRACK_PEAK": _t(i18n, "wizard.summary.fields.conntrack_peak", "Estimated peak concurrent connections"),
            "CONNTRACK_MEMORY_PERCENT": _t(
                i18n,
                "wizard.summary.fields.conntrack_memory_percent",
                "Memory share for connection tracking",
            ),
        }
        for key, label in labels.items():
            include = key in changed
            if key in {"INTERNAL_IFS", "TRUSTED_INTERNAL_NETS"} and config["ENABLE_STRICT_LAN_VALIDATION"] == "on":
                include = True
            if include and config[key]:
                advanced_lines.append(f"{label}: {config[key]}")
    sections.append((_t(i18n, "wizard.summary.sections.advanced", "Advanced Settings"), advanced_lines))
    return sections


def print_summary(
    config: CanonicalConfig,
    *,
    advanced_checked: bool = False,
    i18n: Optional[RuntimeI18N] = None,
    output_func: Callable[[str], None] = print,
) -> None:
    for title, lines in build_summary(config, advanced_checked=advanced_checked, i18n=i18n):
        output_func(title)
        for line in lines:
            output_func(f"  {line}")
        output_func("")


def _prompt_menu_single(
    title: str,
    description: str,
    options: Sequence[MenuOption],
    *,
    default_value: Optional[str],
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
    allow_cancel: bool = True,
    prompt_key: str = "wizard.prompt.menu_default",
    prompt_default: str = "Enter a number to choose, or press Enter for {default_token}",
) -> str:
    print(title)
    print(description)
    recommended = next((option for option in options if option.recommended), options[0])
    for option in options:
        suffix = ""
        if option.recommended:
            suffix = f" {_t(i18n, 'wizard.option.recommended', '(recommended)')}"
        print(f" {option.token}. {option.label}{suffix}")
    default_token = next((option.token for option in options if option.value == default_value), recommended.token)
    while True:
        raw = _read_wizard_input(
            _t(
                i18n,
                prompt_key,
                prompt_default,
                default_token=default_token,
            )
            + ": ",
            input_func=input_func,
            allow_cancel=allow_cancel,
        )
        if not raw:
            raw = default_token
        chosen = next((option for option in options if option.token == raw), None)
        if chosen:
            return chosen.value
        print(_t(i18n, "common.invalid_choice", "Invalid choice."))


def prompt_menu_single(
    title: str,
    description: str,
    options: Sequence[MenuOption],
    *,
    default_value: Optional[str],
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
    allow_cancel: bool = True,
    prompt_key: str = "wizard.prompt.menu_default",
    prompt_default: str = "Enter a number to choose, or press Enter for {default_token}",
) -> str:
    return _prompt_menu_single(
        title,
        description,
        options,
        default_value=default_value,
        input_func=input_func,
        i18n=i18n,
        allow_cancel=allow_cancel,
        prompt_key=prompt_key,
        prompt_default=prompt_default,
    )


def _materialize_runtime_binding_shortcuts(
    state: Dict[str, str],
    *,
    adapter: SystemAdapter,
) -> Tuple[Dict[str, str], Tuple[LocalizedMessage, ...]]:
    state = sync_toggle_shortcut_state(state)
    return sync_runtime_binding_state(state, adapter, only_if_shortcuts=True)


def _gateway_settings_active(state: Dict[str, str]) -> bool:
    return any(
        (
            state.get("ENABLE_EGRESS_SNAT", "off") == "on",
            state.get("ENABLE_STRICT_LAN_VALIDATION", "off") == "on",
            state.get("RP_FILTER_MODE", "system") != "system",
            state.get("CONNTRACK_MODE", "system") != "system",
        )
    )


def prompt_summary_action(
    config: CanonicalConfig,
    *,
    advanced_checked: bool = False,
    i18n: Optional[RuntimeI18N] = None,
    input_func: Callable[[str], str] = input,
    footer_lines: Sequence[str] = (),
    title_key: str = "wizard.confirm.title",
    title_default: str = "Confirm Configuration",
    description_key: str = "wizard.confirm.description",
    description_default: str = "Choose how to proceed.",
    option_key_prefix: str = "wizard.confirm.options",
    confirm_default: str = "Confirm",
    actions: Optional[Sequence[MenuOption]] = None,
) -> str:
    print_summary(
        config,
        advanced_checked=advanced_checked,
        i18n=i18n,
        output_func=print,
    )
    for line in footer_lines:
        print(f"  {line}")
    if actions is None:
        actions = (
            MenuOption(
                "1",
                _t(i18n, f"{option_key_prefix}.confirm", confirm_default),
                "confirm",
                recommended=True,
            ),
            MenuOption(
                "2",
                _t(i18n, f"{option_key_prefix}.network", "Back to network topology"),
                "network",
            ),
            MenuOption(
                "3",
                _t(i18n, f"{option_key_prefix}.exposure", "Back to exposure and protection"),
                "exposure",
            ),
            MenuOption(
                "4",
                _t(i18n, f"{option_key_prefix}.egress", "Back to default egress NAT"),
                "egress",
            ),
            MenuOption(
                "5",
                _t(i18n, f"{option_key_prefix}.advanced", "Back to advanced settings"),
                "advanced",
            ),
            MenuOption(
                "0",
                _t(i18n, f"{option_key_prefix}.cancel", "Cancel"),
                "cancel",
            ),
        )
    return _prompt_menu_single(
        _t(i18n, title_key, title_default),
        _t(i18n, description_key, description_default),
        actions,
        default_value="confirm",
        input_func=input_func,
        i18n=i18n,
        allow_cancel=False,
    )


def _prompt_menu_multi(
    title: str,
    description: str,
    candidates: Sequence[str],
    *,
    default_values: Sequence[str],
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
) -> str:
    print(title)
    print(description)
    for index, candidate in enumerate(candidates, start=1):
        suffix = ""
        if candidate in default_values:
            suffix = f" {_t(i18n, 'wizard.option.current', '(current)')}"
        print(f" {index}. {candidate}{suffix}")
    default_display = ",".join(default_values)
    while True:
        prompt = _t(
            i18n,
            "wizard.prompt.multi_default",
            "Enter comma-separated numbers ({default_display})",
            default_display=default_display or "-",
        )
        if not default_values:
            prompt = _t(i18n, "wizard.prompt.multi", "Enter comma-separated numbers")
        raw = _read_wizard_input(prompt + ": ", input_func=input_func, allow_cancel=True)
        if not raw and default_values:
            return ",".join(default_values)
        try:
            selected = [candidates[index] for index in parse_menu_indices(raw, size=len(candidates), allow_multiple=True)]
        except InputValidationError:
            print(_t(i18n, "wizard.error.invalid_multi_selection", "Invalid selection."))
            continue
        if not selected:
            print(_t(i18n, "wizard.error.required_selection", "At least one value is required."))
            continue
        return ",".join(selected)


def _prompt_text(
    title: str,
    description: str,
    *,
    default_value: Optional[str],
    placeholder: str,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
    validator: Optional[Callable[[str], str]] = None,
) -> str:
    print(title)
    print(description)
    return _prompt_text_value(
        default_value=default_value,
        placeholder=placeholder,
        input_func=input_func,
        i18n=i18n,
        validator=validator,
    )


def _prompt_text_value(
    *,
    default_value: Optional[str],
    placeholder: str,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
    validator: Optional[Callable[[str], str]] = None,
) -> str:
    while True:
        prompt = placeholder
        if default_value:
            prompt = _t(
                i18n,
                "wizard.prompt.text_default",
                "{placeholder} [{default_value}]",
                placeholder=placeholder,
                default_value=default_value,
            )
        raw = _read_wizard_input(prompt + ": ", input_func=input_func, allow_cancel=True)
        if raw:
            if validator is None:
                return raw
            try:
                return validator(raw)
            except ConfigValidationError as exc:
                print(_t(i18n, "common.error", "ERROR: {message}", message=str(exc)))
                continue
        if default_value:
            if validator is None:
                return default_value
            try:
                return validator(default_value)
            except ConfigValidationError as exc:
                print(_t(i18n, "common.error", "ERROR: {message}", message=str(exc)))
                continue
        print(_t(i18n, "wizard.error.required_value", "A value is required."))


def _prompt_candidates_or_text_multi(
    title: str,
    description: str,
    candidates: Sequence[str],
    *,
    default_values: Sequence[str],
    placeholder: str,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
    text_validator: Optional[Callable[[str], str]] = None,
) -> str:
    print(title)
    print(description)
    menu_values = _ordered_unique_values(default_values, candidates)
    for index, candidate in enumerate(menu_values, start=1):
        suffix = ""
        if candidate in default_values:
            suffix = f" {_t(i18n, 'wizard.option.current', '(current)')}"
        print(f" {index}. {candidate}{suffix}")
    default_display = ",".join(default_values)
    while True:
        prompt = _t(
            i18n,
            "wizard.prompt.multi_or_manual_default",
            "Enter comma-separated menu numbers, or enter values directly ({default_display})",
            default_display=default_display or "-",
        )
        if not default_values:
            prompt = _t(
                i18n,
                "wizard.prompt.multi_or_manual",
                "Enter comma-separated menu numbers, or enter values directly",
            )
        raw = _read_wizard_input(prompt + ": ", input_func=input_func, allow_cancel=True)
        if not raw:
            if default_values:
                return ",".join(default_values)
            print(_t(i18n, "wizard.error.required_selection", "At least one value is required."))
            continue
        if _looks_like_menu_selection(raw):
            try:
                selected = [menu_values[index] for index in parse_menu_indices(raw, size=len(menu_values), allow_multiple=True)]
            except InputValidationError:
                print(_t(i18n, "wizard.error.invalid_multi_selection", "Invalid selection."))
                continue
            if not selected:
                print(_t(i18n, "wizard.error.required_selection", "At least one value is required."))
                continue
            return ",".join(selected)
        if text_validator is not None:
            try:
                return text_validator(raw)
            except ConfigValidationError as exc:
                print(_t(i18n, "common.error", "ERROR: {message}", message=str(exc)))
                continue
        print(_t(i18n, "wizard.error.invalid_multi_selection", "Invalid selection."))
        continue


def _validate_iface_text(value: str) -> str:
    return validate_iface(value)


def _validate_iface_csv(value: str) -> str:
    return ",".join(parse_csv(value, kind="iface"))


def _validate_ipv4_csv(value: str) -> str:
    return ",".join(parse_csv(value, kind="ipv4"))


def _validate_cidr_csv(value: str) -> str:
    return ",".join(parse_csv(value, kind="cidr"))


def _validate_positive_integer(value: str) -> str:
    return normalize_integer_value(value, "wizard_integer")


def _validate_conntrack_memory_percent(value: str) -> str:
    return normalize_integer_value(value, "CONNTRACK_MEMORY_PERCENT", minimum=1, maximum=90)


def _probe_defaults(adapter: SystemAdapter, state: Dict[str, str]) -> Dict[str, Sequence[str]]:
    external_candidates = tuple(item for item in adapter.default_ipv4_ifaces() if item)
    interfaces = tuple(item for item in adapter.list_interfaces() if item and item != "lo")
    selected_external = state.get("PRIMARY_EXTERNAL_IF") or (external_candidates[0] if external_candidates else "")
    listen_candidates = adapter.global_ipv4s(selected_external) if selected_external else ()
    lan_candidates = tuple(candidate for candidate in interfaces if candidate != selected_external)
    default_lan_ifs = _csv_items(state.get("LAN_IFS", ""))
    if not default_lan_ifs and lan_candidates:
        preferred = next((candidate for candidate in lan_candidates if adapter.ipv4_networks(candidate)), lan_candidates[0])
        default_lan_ifs = (preferred,)
    detected_lan_nets: List[str] = []
    for iface in default_lan_ifs:
        for network in adapter.ipv4_networks(iface):
            if network not in detected_lan_nets:
                detected_lan_nets.append(network)
    return {
        "external_candidates": external_candidates or interfaces,
        "listen_candidates": listen_candidates,
        "lan_candidates": lan_candidates,
        "default_lan_ifs": default_lan_ifs,
        "default_lan_nets": tuple(detected_lan_nets),
    }


def _detected_lan_nets(adapter: SystemAdapter, lan_ifs: str) -> Tuple[str, ...]:
    detected: List[str] = []
    for iface in _csv_items(lan_ifs):
        for network in adapter.ipv4_networks(iface):
            if network not in detected:
                detected.append(network)
    return tuple(detected)


def _run_network_section(
    state: Dict[str, str],
    *,
    adapter: SystemAdapter,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
) -> None:
    probes = _probe_defaults(adapter, state)
    previous_external = state.get("PRIMARY_EXTERNAL_IF") or state.get("EXTERNAL_IFS", "")
    previous_lan_ifs = state.get("LAN_IFS", "")
    external_candidates = tuple(probes["external_candidates"])
    if external_candidates:
        external_value = _prompt_menu_single(
            _step_title("external_ifs", i18n),
            _step_description("external_ifs", i18n),
            tuple(
                MenuOption(str(index), value, value, recommended=index == 1)
                for index, value in enumerate(external_candidates, start=1)
            ),
            default_value=state.get("PRIMARY_EXTERNAL_IF") or (external_candidates[0] if external_candidates else None),
            input_func=input_func,
            i18n=i18n,
        )
    else:
        external_value = _prompt_text(
            _step_title("external_ifs", i18n),
            _t(i18n, "wizard.external_interface.manual", "Enter the external interface name."),
            default_value=state.get("PRIMARY_EXTERNAL_IF") or None,
            placeholder=_t(i18n, "wizard.placeholder.interface", "interface"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_iface_text,
        )
    state["EXTERNAL_IFS"] = external_value
    state["PRIMARY_EXTERNAL_IF"] = external_value

    listen_candidates = tuple(adapter.global_ipv4s(external_value)) if external_value else ()
    existing_listen_values = list(_csv_items(state.get("LISTEN_IPS", "")))
    if external_value != previous_external and listen_candidates:
        listen_defaults = list(listen_candidates)
    else:
        listen_defaults = existing_listen_values or list(listen_candidates)
    if listen_candidates:
        state["LISTEN_IPS"] = _prompt_candidates_or_text_multi(
            _step_title("listen_ips", i18n),
            _step_description("listen_ips", i18n),
            listen_candidates,
            default_values=listen_defaults,
            placeholder=_t(i18n, "wizard.placeholder.ipv4_csv", "ipv4,ipv4"),
            input_func=input_func,
            i18n=i18n,
            text_validator=_validate_ipv4_csv,
        )
    else:
        listen_default = state.get("LISTEN_IPS") or ",".join(probes["listen_candidates"])
        state["LISTEN_IPS"] = _prompt_text(
            _step_title("listen_ips", i18n),
            _step_description("listen_ips", i18n),
            default_value=listen_default or None,
            placeholder=_t(i18n, "wizard.placeholder.ipv4_csv", "ipv4,ipv4"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_ipv4_csv,
        )
    listen_values = list(_csv_items(state["LISTEN_IPS"]))
    if len(listen_values) > 1:
        state["DEFAULT_SNAT_IP"] = _prompt_menu_single(
            _step_title("default_snat_ip", i18n),
            _step_description("default_snat_ip", i18n),
            tuple(
                MenuOption(str(index), value, value, recommended=index == 1)
                for index, value in enumerate(listen_values, start=1)
            ),
            default_value=state.get("DEFAULT_SNAT_IP") or listen_values[0],
            input_func=input_func,
            i18n=i18n,
        )
    else:
        state["DEFAULT_SNAT_IP"] = listen_values[0]

    lan_candidates = tuple(item for item in adapter.list_interfaces() if item and item not in {"lo", external_value})
    existing_lans = [iface for iface in _csv_items(state.get("LAN_IFS", "")) if iface in lan_candidates]
    if lan_candidates:
        preferred_lans = [candidate for candidate in lan_candidates if adapter.ipv4_networks(candidate)]
        fallback_lans = preferred_lans[:1] or [lan_candidates[0]]
    else:
        fallback_lans = []
    default_lans = existing_lans or fallback_lans
    if lan_candidates:
        state["LAN_IFS"] = _prompt_menu_multi(
            _step_title("lan_ifs", i18n),
            _step_description("lan_ifs", i18n),
            lan_candidates,
            default_values=default_lans,
            input_func=input_func,
            i18n=i18n,
        )
    else:
        state["LAN_IFS"] = _prompt_text(
            _step_title("lan_ifs", i18n),
            _t(i18n, "wizard.internal_interfaces.manual", "Enter one or more internal interfaces, separated by commas."),
            default_value=state.get("LAN_IFS") or None,
            placeholder=_t(i18n, "wizard.placeholder.iface_csv", "iface,iface"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_iface_csv,
        )

    lan_net_candidates = _detected_lan_nets(adapter, state["LAN_IFS"])
    existing_lan_nets = list(_csv_items(state.get("LAN_NETS", "")))
    if state["LAN_IFS"] != previous_lan_ifs and lan_net_candidates:
        lan_net_defaults = list(lan_net_candidates)
    else:
        lan_net_defaults = existing_lan_nets or list(lan_net_candidates)
    if lan_net_candidates:
        state["LAN_NETS"] = _prompt_candidates_or_text_multi(
            _step_title("lan_nets", i18n),
            _step_description("lan_nets", i18n),
            lan_net_candidates,
            default_values=lan_net_defaults,
            placeholder=_t(i18n, "wizard.placeholder.cidr_csv", "cidr,cidr"),
            input_func=input_func,
            i18n=i18n,
            text_validator=_validate_cidr_csv,
        )
    else:
        lan_net_default = state.get("LAN_NETS") or ",".join(probes["default_lan_nets"])
        state["LAN_NETS"] = _prompt_text(
            _step_title("lan_nets", i18n),
            _step_description("lan_nets", i18n),
            default_value=lan_net_default or None,
            placeholder=_t(i18n, "wizard.placeholder.cidr_csv", "cidr,cidr"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_cidr_csv,
        )


def _run_exposure_section(
    state: Dict[str, str],
    *,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
) -> None:
    state["PROTECTION_MODE"] = _prompt_menu_single(
        _step_title("protection_mode", i18n),
        _step_description("protection_mode", i18n),
        _step_options("protection_mode", i18n),
        default_value=state.get("PROTECTION_MODE") or "backends",
        input_func=input_func,
        i18n=i18n,
    )
    if state["PROTECTION_MODE"] in {"nets", "both"}:
        state["PROTECTED_NETS"] = _prompt_text(
            _step_title("protected_nets", i18n),
            _step_description("protected_nets", i18n),
            default_value=state.get("PROTECTED_NETS") or state.get("LAN_NETS") or None,
            placeholder=_t(i18n, "wizard.placeholder.cidr_csv", "cidr,cidr"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_cidr_csv,
        )
    else:
        state["PROTECTED_NETS"] = ""
    state["ENABLE_HAIRPIN"] = _prompt_menu_single(
        _step_title("enable_hairpin", i18n),
        _step_description("enable_hairpin", i18n),
        _step_options("enable_hairpin", i18n),
        default_value=state.get("ENABLE_HAIRPIN") or "on",
        input_func=input_func,
        i18n=i18n,
    )


def _run_forwarding_section(
    state: Dict[str, str],
    *,
    adapter: SystemAdapter,
    paths=None,
    notices: Optional[List[str]] = None,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
) -> None:
    notices = notices if notices is not None else []
    while True:
        requested_mode = _prompt_menu_single(
            _step_title("auth_mode", i18n),
            _step_description("auth_mode", i18n),
            _step_options("auth_mode", i18n),
            default_value=state.get("AUTH_MODE") or "mark",
            input_func=input_func,
            i18n=i18n,
        )
        try:
            plan = plan_auth_mode_switch(state, requested_mode, paths=paths, adapter=adapter)
        except (ApplyError, ConfigValidationError) as exc:
            print(str(exc))
            continue
        state["AUTH_MODE"] = plan.auth_mode
        state["DNAT_MARK"] = plan.dnat_mark
        state["DNAT_LABEL"] = plan.dnat_label
        for warning in plan.warnings:
            if warning not in notices:
                notices.append(warning)
        break
    state["ENABLE_WAN_TO_WAN"] = _prompt_menu_single(
        _step_title("enable_wan_to_wan", i18n),
        _step_description("enable_wan_to_wan", i18n),
        _step_options("enable_wan_to_wan", i18n),
        default_value=state.get("ENABLE_WAN_TO_WAN") or "off",
        input_func=input_func,
        i18n=i18n,
    )
    state["ENABLE_TCPMSS_CLAMP"] = _prompt_menu_single(
        _step_title("enable_tcpmss_clamp", i18n),
        _step_description("enable_tcpmss_clamp", i18n),
        _step_options("enable_tcpmss_clamp", i18n),
        default_value=state.get("ENABLE_TCPMSS_CLAMP") or "off",
        input_func=input_func,
        i18n=i18n,
    )
    state["COUNTER_MODE"] = _prompt_menu_single(
        _step_title("counter_mode", i18n),
        _step_description("counter_mode", i18n),
        _step_options("counter_mode", i18n),
        default_value=state.get("COUNTER_MODE") or "minimal",
        input_func=input_func,
        i18n=i18n,
    )


def _run_gateway_section(
    state: Dict[str, str],
    *,
    include_egress: bool,
    include_system_integration: bool = True,
    input_func: Callable[[str], str],
    i18n: Optional[RuntimeI18N],
) -> None:
    if include_egress:
        state["ENABLE_EGRESS_SNAT"] = _prompt_menu_single(
            _step_title("enable_egress_snat", i18n),
            _step_description("enable_egress_snat", i18n),
            _step_options("enable_egress_snat", i18n),
            default_value=state.get("ENABLE_EGRESS_SNAT") or "off",
            input_func=input_func,
            i18n=i18n,
        )
        if state["ENABLE_EGRESS_SNAT"] == "on":
            state["EGRESS_NETS"] = _prompt_text(
                _step_title("egress_nets", i18n),
                _step_description("egress_nets", i18n),
                default_value=state.get("EGRESS_NETS") or state.get("LAN_NETS") or None,
                placeholder=_t(i18n, "wizard.placeholder.cidr_csv", "cidr,cidr"),
                input_func=input_func,
                i18n=i18n,
                validator=_validate_cidr_csv,
            )
        else:
            state["EGRESS_NETS"] = ""

    if not include_system_integration:
        return

    state["ENABLE_STRICT_LAN_VALIDATION"] = _prompt_menu_single(
        _step_title("enable_strict_validation", i18n),
        _step_description("enable_strict_validation", i18n),
        _step_options("enable_strict_validation", i18n),
        default_value=state.get("ENABLE_STRICT_LAN_VALIDATION") or "off",
        input_func=input_func,
        i18n=i18n,
    )
    if state["ENABLE_STRICT_LAN_VALIDATION"] == "on":
        lan_candidates = tuple(item for item in _csv_items(state["LAN_IFS"]))
        state["INTERNAL_IFS"] = _prompt_menu_multi(
            _step_title("internal_ifs", i18n),
            _step_description("internal_ifs", i18n),
            lan_candidates,
            default_values=list(_csv_items(state.get("INTERNAL_IFS", ""))) or list(lan_candidates),
            input_func=input_func,
            i18n=i18n,
        )
        state["TRUSTED_INTERNAL_NETS"] = _prompt_text(
            _step_title("trusted_internal_nets", i18n),
            _step_description("trusted_internal_nets", i18n),
            default_value=state.get("TRUSTED_INTERNAL_NETS") or state.get("LAN_NETS") or None,
            placeholder=_t(i18n, "wizard.placeholder.cidr_csv", "cidr,cidr"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_cidr_csv,
        )
    else:
        state["INTERNAL_IFS"] = ""
        state["TRUSTED_INTERNAL_NETS"] = ""

    state["RP_FILTER_MODE"] = _prompt_menu_single(
        _step_title("rp_filter_mode", i18n),
        _step_description("rp_filter_mode", i18n),
        _step_options("rp_filter_mode", i18n),
        default_value=state.get("RP_FILTER_MODE") or "system",
        input_func=input_func,
        i18n=i18n,
    )
    state["CONNTRACK_MODE"] = _prompt_menu_single(
        _step_title("conntrack_mode", i18n),
        _step_description("conntrack_mode", i18n),
        _step_options("conntrack_mode", i18n),
        default_value=state.get("CONNTRACK_MODE") or "system",
        input_func=input_func,
        i18n=i18n,
    )
    if state["CONNTRACK_MODE"] == "auto":
        state["CONNTRACK_PEAK"] = _prompt_text(
            _step_title("conntrack_peak", i18n),
            _step_description("conntrack_peak", i18n),
            default_value=state.get("CONNTRACK_PEAK") or None,
            placeholder=_t(i18n, "wizard.placeholder.integer", "integer"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_positive_integer,
        )
        state["CONNTRACK_MEMORY_PERCENT"] = _prompt_text(
            _step_title("conntrack_memory_percent", i18n),
            _step_description("conntrack_memory_percent", i18n),
            default_value=state.get("CONNTRACK_MEMORY_PERCENT") or "35",
            placeholder=_t(i18n, "wizard.placeholder.integer", "integer"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_conntrack_memory_percent,
        )
        state["CONNTRACK_TARGET_MAX"] = ""
    elif state["CONNTRACK_MODE"] == "custom":
        state["CONNTRACK_TARGET_MAX"] = _prompt_text(
            _step_title("conntrack_target_max", i18n),
            _step_description("conntrack_target_max", i18n),
            default_value=state.get("CONNTRACK_TARGET_MAX") or None,
            placeholder=_t(i18n, "wizard.placeholder.integer", "integer"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_positive_integer,
        )
        state["CONNTRACK_MEMORY_PERCENT"] = _prompt_text(
            _step_title("conntrack_memory_percent", i18n),
            _step_description("conntrack_memory_percent", i18n),
            default_value=state.get("CONNTRACK_MEMORY_PERCENT") or "35",
            placeholder=_t(i18n, "wizard.placeholder.integer", "integer"),
            input_func=input_func,
            i18n=i18n,
            validator=_validate_conntrack_memory_percent,
        )
        state["CONNTRACK_PEAK"] = ""
    else:
        state["CONNTRACK_TARGET_MAX"] = ""
        state["CONNTRACK_PEAK"] = ""
        state["CONNTRACK_MEMORY_PERCENT"] = ""


def run_config_wizard_flow(
    adapter: SystemAdapter,
    *,
    initial: Optional[CanonicalConfig] = None,
    input_func: Callable[[str], str] = input,
    i18n: Optional[RuntimeI18N] = None,
    initial_stage: str = "network",
    show_summary: bool = True,
    surface: str = "installer",
    paths=None,
) -> WizardOutcome:
    if surface not in {"installer", "cli"}:
        raise ValueError(f"unsupported wizard surface: {surface}")
    state = (initial or recommended_config()).as_dict()
    state, persist_notices = _materialize_runtime_binding_shortcuts(state, adapter=adapter)
    summary_notices: List[LocalizedMessage] = list(persist_notices)
    advanced_checked = False
    stage = initial_stage
    while True:
        if stage == "network":
            _run_network_section(state, adapter=adapter, input_func=input_func, i18n=i18n)
            stage = "exposure"
            continue

        if stage == "exposure":
            _run_exposure_section(state, input_func=input_func, i18n=i18n)
            stage = "forwarding" if surface == "cli" else "egress"
            continue

        if stage == "forwarding":
            _run_forwarding_section(
                state,
                adapter=adapter,
                paths=paths,
                notices=summary_notices,
                input_func=input_func,
                i18n=i18n,
            )
            stage = _prompt_menu_single(
                _t(i18n, "wizard.gateway.title", "Advanced Gateway Settings"),
                _t(i18n, "wizard.gateway.description", "Review gateway-facing NAT and system-integration settings."),
                (
                    MenuOption(
                        "1",
                        _t(i18n, "wizard.gateway.options.configure", "Configure now"),
                        "gateway",
                        recommended=_gateway_settings_active(state),
                    ),
                    MenuOption(
                        "2",
                        _t(i18n, "wizard.gateway.options.skip", "Skip for now"),
                        "summary",
                        recommended=not _gateway_settings_active(state),
                    ),
                ),
                default_value="gateway" if _gateway_settings_active(state) else "summary",
                input_func=input_func,
                i18n=i18n,
            )
            continue

        if stage == "egress":
            _run_gateway_section(
                state,
                include_egress=True,
                include_system_integration=False,
                input_func=input_func,
                i18n=i18n,
            )
            stage = "advanced" if surface == "installer" else "summary"
            continue

        if stage == "gateway":
            print(_t(i18n, "wizard.gateway.title", "Advanced Gateway Settings"))
            description = _t(
                i18n,
                "wizard.gateway.description",
                "Review gateway-facing NAT and system-integration settings.",
            )
            if description:
                print(description)
            _run_gateway_section(
                state,
                include_egress=True,
                include_system_integration=True,
                input_func=input_func,
                i18n=i18n,
            )
            stage = "summary"
            continue

        if stage == "advanced":
            advanced_checked = True
            choice = _prompt_menu_single(
                _t(i18n, "wizard.advanced.title", "Advanced Settings"),
                _t(
                    i18n,
                    "wizard.advanced.description",
                    "Use the recommended advanced settings, or adjust them manually.",
                ),
                (
                    MenuOption(
                        "1",
                        _t(i18n, "wizard.advanced.options.recommended", "Use recommended settings"),
                        "recommended",
                        recommended=True,
                    ),
                    MenuOption(
                        "2",
                        _t(i18n, "wizard.advanced.options.manual", "Adjust manually"),
                        "manual",
                    ),
                ),
                default_value="recommended",
                input_func=input_func,
                i18n=i18n,
            )
            if choice == "recommended":
                state.update(RECOMMENDED_ADVANCED)
                state["INTERNAL_IFS"] = ""
                state["TRUSTED_INTERNAL_NETS"] = ""
                stage = "summary"
                continue

            _run_forwarding_section(
                state,
                adapter=adapter,
                paths=paths,
                notices=summary_notices,
                input_func=input_func,
                i18n=i18n,
            )
            _run_gateway_section(
                state,
                include_egress=False,
                include_system_integration=True,
                input_func=input_func,
                i18n=i18n,
            )
            stage = "summary"
            continue

        if stage == "summary":
            config = normalize_mapping(state)
            outcome = WizardOutcome(
                config=config,
                advanced_checked=advanced_checked,
                persist_notices=tuple(summary_notices),
            )
            if not show_summary:
                return outcome
            if surface == "cli":
                action = prompt_summary_action(
                    config,
                    advanced_checked=advanced_checked,
                    i18n=i18n,
                    input_func=input_func,
                    footer_lines=_render_messages(summary_notices, i18n),
                    title_key="wizard.cli_confirm.title",
                    title_default="Save Configuration",
                    description_key="wizard.cli_confirm.description",
                    description_default="Review the configuration and choose how to proceed.",
                    option_key_prefix="wizard.cli_confirm.options",
                    confirm_default="Save configuration",
                    actions=(
                        MenuOption(
                            "1",
                            _t(i18n, "wizard.cli_confirm.options.confirm", "Save configuration"),
                            "confirm",
                            recommended=True,
                        ),
                        MenuOption(
                            "2",
                            _t(i18n, "wizard.cli_confirm.options.network", "Back to network topology"),
                            "network",
                        ),
                        MenuOption(
                            "3",
                            _t(i18n, "wizard.cli_confirm.options.exposure", "Back to exposure and protection"),
                            "exposure",
                        ),
                        MenuOption(
                            "4",
                            _t(i18n, "wizard.cli_confirm.options.forwarding", "Back to forwarding settings"),
                            "forwarding",
                        ),
                        MenuOption(
                            "5",
                            _t(i18n, "wizard.cli_confirm.options.gateway", "Back to advanced gateway settings"),
                            "gateway",
                        ),
                        MenuOption(
                            "0",
                            _t(i18n, "wizard.cli_confirm.options.cancel", "Cancel"),
                            "cancel",
                        ),
                    ),
                )
            else:
                action = prompt_summary_action(
                    config,
                    advanced_checked=advanced_checked,
                    i18n=i18n,
                    input_func=input_func,
                    footer_lines=_render_messages(summary_notices, i18n),
                )
            if action == "confirm":
                return outcome
            if action == "cancel":
                raise KeyboardInterrupt("configuration cancelled")
            stage = action
def run_config_wizard(
    adapter: SystemAdapter,
    *,
    initial: Optional[CanonicalConfig] = None,
    input_func: Callable[[str], str] = input,
    i18n: Optional[RuntimeI18N] = None,
    surface: str = "installer",
) -> CanonicalConfig:
    return run_config_wizard_flow(
        adapter,
        initial=initial,
        input_func=input_func,
        i18n=i18n,
        initial_stage="network",
        show_summary=True,
        surface=surface,
    ).config
