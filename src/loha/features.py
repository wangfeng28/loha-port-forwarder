from typing import Dict, Iterable, List

from .constants import CONNTRACK_PROFILE_SPECS, DEFAULT_CONFIG_VALUES
from .models import CanonicalConfig, FeatureDefinition


FEATURES: Dict[str, FeatureDefinition] = {
    "hairpin": FeatureDefinition(
        feature_id="hairpin",
        title="Hairpin NAT",
        category="render-only",
        config_keys=("ENABLE_HAIRPIN",),
        default_config={"ENABLE_HAIRPIN": "on"},
    ),
    "wan_to_wan": FeatureDefinition(
        feature_id="wan_to_wan",
        title="WAN-to-WAN",
        category="render-only",
        config_keys=("ENABLE_WAN_TO_WAN",),
        default_config={"ENABLE_WAN_TO_WAN": "off"},
    ),
    "tcpmss_clamp": FeatureDefinition(
        feature_id="tcpmss_clamp",
        title="TCP MSS Clamp",
        category="render-only",
        config_keys=("ENABLE_TCPMSS_CLAMP",),
        default_config={"ENABLE_TCPMSS_CLAMP": "off"},
    ),
    "counters": FeatureDefinition(
        feature_id="counters",
        title="Counters",
        category="render-only",
        config_keys=("COUNTER_MODE",),
        default_config={"COUNTER_MODE": "minimal"},
    ),
    "protected_nets": FeatureDefinition(
        feature_id="protected_nets",
        title="Protected Networks",
        category="config+render",
        config_keys=("PROTECTION_MODE", "PROTECTED_NETS"),
        default_config={"PROTECTION_MODE": "backends", "PROTECTED_NETS": ""},
    ),
    "egress_snat": FeatureDefinition(
        feature_id="egress_snat",
        title="Default Egress SNAT",
        category="config+render",
        config_keys=("ENABLE_EGRESS_SNAT", "EGRESS_NETS"),
        default_config={"ENABLE_EGRESS_SNAT": "off", "EGRESS_NETS": ""},
    ),
    "strict_internal_validation": FeatureDefinition(
        feature_id="strict_internal_validation",
        title="Strict Internal Source Validation",
        category="config+render",
        config_keys=("ENABLE_STRICT_LAN_VALIDATION", "INTERNAL_IFS", "TRUSTED_INTERNAL_NETS"),
        default_config={
            "ENABLE_STRICT_LAN_VALIDATION": "off",
            "INTERNAL_IFS": "",
            "TRUSTED_INTERNAL_NETS": "",
        },
    ),
    "rp_filter": FeatureDefinition(
        feature_id="rp_filter",
        title="rp_filter",
        category="system-integration",
        config_keys=("RP_FILTER_MODE",),
        default_config={"RP_FILTER_MODE": "system"},
    ),
    "conntrack": FeatureDefinition(
        feature_id="conntrack",
        title="conntrack",
        category="system-integration",
        config_keys=(
            "CONNTRACK_MODE",
            "CONNTRACK_TARGET_MAX",
            "CONNTRACK_PEAK",
            "CONNTRACK_MEMORY_PERCENT",
        ),
        default_config={
            "CONNTRACK_MODE": "system",
            "CONNTRACK_TARGET_MAX": "",
            "CONNTRACK_PEAK": "",
            "CONNTRACK_MEMORY_PERCENT": "",
        },
    ),
}


def feature_defaults() -> Dict[str, str]:
    defaults = dict(DEFAULT_CONFIG_VALUES)
    for feature in FEATURES.values():
        defaults.update(feature.default_config)
    return defaults


def summarize_feature(config: CanonicalConfig, feature_id: str) -> str:
    if feature_id == "hairpin":
        return f"Hairpin NAT: {'enabled' if config['ENABLE_HAIRPIN'] == 'on' else 'disabled'}"
    if feature_id == "wan_to_wan":
        return f"WAN-to-WAN: {'enabled' if config['ENABLE_WAN_TO_WAN'] == 'on' else 'disabled'}"
    if feature_id == "tcpmss_clamp":
        return f"TCP MSS Clamp: {'enabled' if config['ENABLE_TCPMSS_CLAMP'] == 'on' else 'disabled'}"
    if feature_id == "counters":
        return f"Counters: {config['COUNTER_MODE']}"
    if feature_id == "protected_nets":
        mode = config["PROTECTION_MODE"]
        if mode == "backends":
            return "Protection scope: exposed backends only"
        if mode == "nets":
            return f"Protection scope: user-specified protected networks ({config['PROTECTED_NETS']})"
        return f"Protection scope: exposed backends and user-specified protected networks ({config['PROTECTED_NETS']})"
    if feature_id == "egress_snat":
        if config["ENABLE_EGRESS_SNAT"] == "off":
            return "Default egress NAT: disabled"
        return f"Default egress NAT: enabled for {config['EGRESS_NETS']}"
    if feature_id == "strict_internal_validation":
        if config["ENABLE_STRICT_LAN_VALIDATION"] == "off":
            return "Strict internal source validation: disabled"
        return (
            "Strict internal source validation: "
            f"{config['INTERNAL_IFS']} / {config['TRUSTED_INTERNAL_NETS']}"
        )
    if feature_id == "rp_filter":
        return f"rp_filter: {config['RP_FILTER_MODE']}"
    if feature_id == "conntrack":
        mode = config["CONNTRACK_MODE"]
        if mode in CONNTRACK_PROFILE_SPECS:
            return f"Conntrack: {mode} profile"
        if mode == "auto":
            return (
                "Conntrack: auto plan "
                f"(peak={config['CONNTRACK_PEAK']}, memory={config['CONNTRACK_MEMORY_PERCENT']}%)"
            )
        if mode == "custom":
            return (
                "Conntrack: custom plan "
                f"(max={config['CONNTRACK_TARGET_MAX']}, memory={config['CONNTRACK_MEMORY_PERCENT']}%)"
            )
        return "Conntrack: system-managed"
    raise KeyError(feature_id)
