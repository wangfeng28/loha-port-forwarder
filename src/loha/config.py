from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .constants import (
    AUTH_MARK_CANDIDATE_BITS,
    AUTH_MODES,
    CONFIG_KEYS,
    CONNTRACK_MODES,
    COUNTER_MODES,
    DEFAULT_CONFIG_VALUES,
    DEFAULT_DNAT_LABEL,
    DEFAULT_DNAT_MARK,
    DEFAULT_LOCALE,
    LIST_FIELDS,
    PROTECTION_MODES,
    RP_FILTER_MODES,
    TOGGLE_KEYS,
)
from .exceptions import ConfigSyntaxError, ConfigValidationError
from .models import CanonicalConfig


KEY_LINE_RE = re.compile(r'^([A-Z][A-Z0-9_]*)="((?:[^"\\]|\\.)*)"$')
IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")


def trim_spaces(value: str) -> str:
    return value.strip()


def validate_ipv4(value: str) -> str:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ConfigValidationError(f"invalid IPv4 value: {value}") from exc
    return value


def normalize_cidr(value: str) -> str:
    try:
        network = ipaddress.IPv4Network(value, strict=False)
    except ValueError as exc:
        raise ConfigValidationError(f"invalid IPv4 CIDR: {value}") from exc
    return f"{network.network_address}/{network.prefixlen}"


def validate_iface(value: str) -> str:
    if not IFACE_RE.match(value):
        raise ConfigValidationError(f"invalid interface name: {value}")
    return value


def normalize_toggle(value: str, allow_auto: bool = False) -> str:
    raw = trim_spaces(value).lower()
    if allow_auto and raw == "auto":
        return "auto"
    if raw in {"1", "true", "yes", "on"}:
        return "on"
    if raw in {"0", "false", "no", "off", ""}:
        return "off"
    raise ConfigValidationError(f"invalid toggle value: {value}")


def normalize_counter_mode(value: str) -> str:
    raw = trim_spaces(value).lower() or DEFAULT_CONFIG_VALUES["COUNTER_MODE"]
    if raw not in COUNTER_MODES:
        raise ConfigValidationError("COUNTER_MODE must be one of: off/minimal/all")
    return raw


def normalize_conntrack_mode(value: str) -> str:
    raw = trim_spaces(value).lower() or DEFAULT_CONFIG_VALUES["CONNTRACK_MODE"]
    if raw not in CONNTRACK_MODES:
        raise ConfigValidationError(
            "CONNTRACK_MODE must be one of: system/conservative/standard/high/auto/custom"
        )
    return raw


def normalize_rp_filter_mode(value: str) -> str:
    raw = trim_spaces(value).lower()
    if raw in {"", "system"}:
        return "system"
    if raw in {"1", "strict"}:
        return "strict"
    if raw in {"2", "loose", "scoped", "loose-scoped", "loose_scoped"}:
        return "loose_scoped"
    if raw in {"global", "loose-global", "loose_global", "global-loose", "global_loose", "all"}:
        return "loose_global"
    raise ConfigValidationError(
        "RP_FILTER_MODE must be one of: system/strict/loose_scoped/loose_global"
    )


def normalize_auth_mode(value: str) -> str:
    raw = trim_spaces(value).lower() or DEFAULT_CONFIG_VALUES["AUTH_MODE"]
    if raw not in AUTH_MODES:
        raise ConfigValidationError("AUTH_MODE must be one of: mark/label")
    return raw


def parse_csv(
    raw: str,
    *,
    kind: str,
    allow_empty: bool = False,
) -> Tuple[str, ...]:
    text = trim_spaces(raw)
    if not text:
        if allow_empty:
            return ()
        raise ConfigValidationError(f"{kind} list must not be empty")
    items = [trim_spaces(item) for item in text.split(",")]
    if any(not item for item in items):
        raise ConfigValidationError(f"{kind} list contains an empty item")
    seen = set()
    normalized: List[str] = []
    for item in items:
        if kind == "iface":
            item = validate_iface(item)
        elif kind == "ipv4":
            item = validate_ipv4(item)
        elif kind == "cidr":
            item = normalize_cidr(item)
        else:
            raise AssertionError(f"unknown csv kind: {kind}")
        if item in seen:
            raise ConfigValidationError(f"{kind} list contains duplicate item: {item}")
        seen.add(item)
        normalized.append(item)
    return tuple(normalized)


def join_csv(values: Sequence[str]) -> str:
    return ",".join(values)


def _decode_quoted_value(raw: str) -> str:
    decoded: List[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            decoded.append(char)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            raise ConfigSyntaxError("dangling escape in quoted value")
        next_char = raw[index]
        if next_char not in {'"', "\\"}:
            raise ConfigSyntaxError("only \\\" and \\\\ escapes are allowed")
        decoded.append(next_char)
        index += 1
    return "".join(decoded)


def _escape_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def parse_canonical_text(text: str) -> OrderedDict[str, str]:
    parsed: "OrderedDict[str, str]" = OrderedDict()
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.rstrip("\r")
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if line != trimmed:
            raise ConfigSyntaxError(
                f"line {lineno}: leading or trailing spaces are not allowed in canonical config lines"
            )
        if trimmed.startswith("export "):
            raise ConfigSyntaxError(
                f'line {lineno}: export KEY=... is not allowed; expected KEY="VALUE"'
            )
        match = KEY_LINE_RE.match(trimmed)
        if not match:
            raise ConfigSyntaxError(
                f'line {lineno}: invalid canonical syntax; expected KEY="VALUE"'
            )
        key, raw_value = match.groups()
        if key not in CONFIG_KEYS:
            raise ConfigSyntaxError(f"line {lineno}: unsupported config key: {key}")
        if key in parsed:
            raise ConfigSyntaxError(f"line {lineno}: duplicate config key: {key}")
        parsed[key] = _decode_quoted_value(raw_value)
    return parsed


def _normalize_mark(value: str) -> str:
    raw = trim_spaces(value or DEFAULT_DNAT_MARK)
    if not raw:
        raise ConfigValidationError("DNAT_MARK must not be empty when AUTH_MODE=mark")
    if raw.lower().startswith("0x"):
        mark_value = int(raw, 16)
    else:
        mark_value = int(raw, 10)
    if mark_value <= 0 or mark_value & (mark_value - 1):
        raise ConfigValidationError("DNAT_MARK must be a single-bit integer")
    valid_marks = {1 << bit for bit in AUTH_MARK_CANDIDATE_BITS}
    if mark_value not in valid_marks:
        raise ConfigValidationError("DNAT_MARK must use a candidate auth bit in bit22-bit30")
    return f"0x{mark_value:08X}"


def _normalize_label(value: str) -> str:
    raw = trim_spaces(value or DEFAULT_DNAT_LABEL)
    if not raw.isdigit():
        raise ConfigValidationError("DNAT_LABEL must be an integer in [1, 127]")
    number = int(raw, 10)
    if number < 1 or number > 127:
        raise ConfigValidationError("DNAT_LABEL must be an integer in [1, 127]")
    return str(number)


def normalize_integer_value(value: str, key: str, minimum: int = 1, maximum: Optional[int] = None) -> str:
    raw = trim_spaces(value)
    if not raw:
        return ""
    if not raw.isdigit():
        raise ConfigValidationError(f"{key} must be a positive integer")
    number = int(raw, 10)
    if number < minimum:
        raise ConfigValidationError(f"{key} must be >= {minimum}")
    if maximum is not None and number > maximum:
        raise ConfigValidationError(f"{key} must be <= {maximum}")
    return str(number)


def recommended_config() -> CanonicalConfig:
    values = {key: "" for key in CONFIG_KEYS}
    values.update(DEFAULT_CONFIG_VALUES)
    values["AUTH_MODE"] = "mark"
    values["DNAT_MARK"] = DEFAULT_DNAT_MARK
    values["DNAT_LABEL"] = ""
    return CanonicalConfig(values)


def normalize_mapping(mapping: Mapping[str, str], *, materialize_defaults: bool = True) -> CanonicalConfig:
    values = {key: trim_spaces(mapping.get(key, DEFAULT_CONFIG_VALUES.get(key, ""))) for key in CONFIG_KEYS}
    for key, default in DEFAULT_CONFIG_VALUES.items():
        values[key] = trim_spaces(mapping.get(key, default))

    if values["EXTERNAL_IFS"].lower() == "auto":
        raise ConfigValidationError("EXTERNAL_IFS=auto is an input shortcut and must not be persisted")
    if values["LISTEN_IPS"].lower() == "auto":
        raise ConfigValidationError("LISTEN_IPS=auto is an input shortcut and must not be persisted")

    external_ifs = parse_csv(values["EXTERNAL_IFS"], kind="iface")
    if len(external_ifs) > 1:
        raise ConfigValidationError(
            "The current single-external product boundary only supports one external interface. "
            "Multi-external configs remain out of scope."
        )
    primary_external_if = validate_iface(values["PRIMARY_EXTERNAL_IF"] or external_ifs[0] if len(external_ifs) == 1 else values["PRIMARY_EXTERNAL_IF"])
    if primary_external_if not in external_ifs:
        raise ConfigValidationError("PRIMARY_EXTERNAL_IF must be included in EXTERNAL_IFS")

    listen_ips = parse_csv(values["LISTEN_IPS"], kind="ipv4")
    if values["DEFAULT_SNAT_IP"]:
        default_snat_ip = validate_ipv4(values["DEFAULT_SNAT_IP"])
    elif len(listen_ips) == 1:
        default_snat_ip = listen_ips[0]
    else:
        raise ConfigValidationError("DEFAULT_SNAT_IP is required when LISTEN_IPS contains multiple addresses")
    if default_snat_ip not in listen_ips:
        raise ConfigValidationError("DEFAULT_SNAT_IP must be included in LISTEN_IPS")

    lan_ifs = parse_csv(values["LAN_IFS"], kind="iface")
    lan_nets = parse_csv(values["LAN_NETS"], kind="cidr")

    protection_mode = (values["PROTECTION_MODE"] or DEFAULT_CONFIG_VALUES["PROTECTION_MODE"]).lower()
    if protection_mode not in PROTECTION_MODES:
        raise ConfigValidationError("PROTECTION_MODE must be one of: backends/nets/both")
    protected_nets = parse_csv(values["PROTECTED_NETS"], kind="cidr", allow_empty=True)
    if materialize_defaults and protection_mode in {"nets", "both"} and not protected_nets:
        protected_nets = lan_nets
    if protection_mode in {"nets", "both"} and not protected_nets:
        raise ConfigValidationError("PROTECTED_NETS must not be empty when PROTECTION_MODE=nets|both")
    if protection_mode == "backends":
        protected_nets = ()

    auth_mode = normalize_auth_mode(values["AUTH_MODE"])
    if auth_mode == "mark":
        dnat_mark = _normalize_mark(values["DNAT_MARK"])
        dnat_label = ""
    else:
        dnat_mark = ""
        dnat_label = _normalize_label(values["DNAT_LABEL"])

    enable_hairpin = normalize_toggle(values["ENABLE_HAIRPIN"], allow_auto=False)
    enable_wan_to_wan = normalize_toggle(values["ENABLE_WAN_TO_WAN"], allow_auto=False)
    enable_egress_snat = normalize_toggle(values["ENABLE_EGRESS_SNAT"], allow_auto=False)
    enable_tcpmss_clamp = normalize_toggle(values["ENABLE_TCPMSS_CLAMP"], allow_auto=False)
    enable_strict = normalize_toggle(values["ENABLE_STRICT_LAN_VALIDATION"], allow_auto=False)
    enable_config_history = normalize_toggle(values["ENABLE_CONFIG_HISTORY"], allow_auto=False)

    egress_nets = parse_csv(values["EGRESS_NETS"], kind="cidr", allow_empty=True)
    if materialize_defaults and enable_egress_snat == "on" and not egress_nets:
        egress_nets = lan_nets
    if enable_egress_snat == "on" and not egress_nets:
        raise ConfigValidationError("EGRESS_NETS must not be empty when ENABLE_EGRESS_SNAT=on")
    if enable_egress_snat == "off":
        egress_nets = ()

    internal_ifs = parse_csv(values["INTERNAL_IFS"], kind="iface", allow_empty=True)
    trusted_internal_nets = parse_csv(values["TRUSTED_INTERNAL_NETS"], kind="cidr", allow_empty=True)
    if materialize_defaults and enable_strict == "on" and not internal_ifs:
        internal_ifs = lan_ifs
    if materialize_defaults and enable_strict == "on" and not trusted_internal_nets:
        trusted_internal_nets = lan_nets
    if enable_strict == "on":
        if not internal_ifs:
            raise ConfigValidationError("INTERNAL_IFS must not be empty when ENABLE_STRICT_LAN_VALIDATION=on")
        if not trusted_internal_nets:
            raise ConfigValidationError(
                "TRUSTED_INTERNAL_NETS must not be empty when ENABLE_STRICT_LAN_VALIDATION=on"
            )
    else:
        internal_ifs = ()
        trusted_internal_nets = ()

    counter_mode = normalize_counter_mode(values["COUNTER_MODE"])
    rp_filter_mode = normalize_rp_filter_mode(values["RP_FILTER_MODE"])
    conntrack_mode = normalize_conntrack_mode(values["CONNTRACK_MODE"])
    conntrack_target_max = normalize_integer_value(values["CONNTRACK_TARGET_MAX"], "CONNTRACK_TARGET_MAX")
    conntrack_peak = normalize_integer_value(values["CONNTRACK_PEAK"], "CONNTRACK_PEAK")
    conntrack_memory_percent = normalize_integer_value(
        values["CONNTRACK_MEMORY_PERCENT"], "CONNTRACK_MEMORY_PERCENT", minimum=1, maximum=90
    )
    if conntrack_mode == "auto":
        if not conntrack_peak:
            raise ConfigValidationError("CONNTRACK_PEAK must not be empty when CONNTRACK_MODE=auto")
        if not conntrack_memory_percent:
            raise ConfigValidationError(
                "CONNTRACK_MEMORY_PERCENT must not be empty when CONNTRACK_MODE=auto"
            )
        conntrack_target_max = ""
    elif conntrack_mode == "custom":
        if not conntrack_target_max:
            raise ConfigValidationError(
                "CONNTRACK_TARGET_MAX must not be empty when CONNTRACK_MODE=custom"
            )
        if not conntrack_memory_percent:
            raise ConfigValidationError(
                "CONNTRACK_MEMORY_PERCENT must not be empty when CONNTRACK_MODE=custom"
            )
        conntrack_peak = ""
    else:
        conntrack_target_max = ""
        conntrack_peak = ""
        conntrack_memory_percent = ""

    locale_value = values["LOCALE"] or DEFAULT_LOCALE

    normalized = {
        "EXTERNAL_IFS": join_csv(external_ifs),
        "PRIMARY_EXTERNAL_IF": primary_external_if,
        "LISTEN_IPS": join_csv(listen_ips),
        "DEFAULT_SNAT_IP": default_snat_ip,
        "LAN_IFS": join_csv(lan_ifs),
        "LAN_NETS": join_csv(lan_nets),
        "PROTECTION_MODE": protection_mode,
        "PROTECTED_NETS": join_csv(protected_nets),
        "AUTH_MODE": auth_mode,
        "DNAT_MARK": dnat_mark,
        "DNAT_LABEL": dnat_label,
        "ENABLE_HAIRPIN": enable_hairpin,
        "ENABLE_WAN_TO_WAN": enable_wan_to_wan,
        "ENABLE_EGRESS_SNAT": enable_egress_snat,
        "EGRESS_NETS": join_csv(egress_nets),
        "ENABLE_TCPMSS_CLAMP": enable_tcpmss_clamp,
        "ENABLE_STRICT_LAN_VALIDATION": enable_strict,
        "INTERNAL_IFS": join_csv(internal_ifs),
        "TRUSTED_INTERNAL_NETS": join_csv(trusted_internal_nets),
        "COUNTER_MODE": counter_mode,
        "ENABLE_CONFIG_HISTORY": enable_config_history,
        "RP_FILTER_MODE": rp_filter_mode,
        "CONNTRACK_MODE": conntrack_mode,
        "CONNTRACK_TARGET_MAX": conntrack_target_max,
        "CONNTRACK_PEAK": conntrack_peak,
        "CONNTRACK_MEMORY_PERCENT": conntrack_memory_percent,
        "LOCALE": locale_value,
    }
    return CanonicalConfig(normalized)


def render_canonical_text(config: CanonicalConfig) -> str:
    lines = []
    for key in CONFIG_KEYS:
        lines.append(f'{key}="{_escape_value(config.get(key, ""))}"')
    return "\n".join(lines) + "\n"


def load_config(path: Path) -> CanonicalConfig:
    text = path.read_text(encoding="utf-8")
    parsed = parse_canonical_text(text)
    return normalize_mapping(parsed, materialize_defaults=False)
