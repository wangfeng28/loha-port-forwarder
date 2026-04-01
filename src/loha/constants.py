from pathlib import Path


CONFIG_KEYS = (
    "EXTERNAL_IFS",
    "PRIMARY_EXTERNAL_IF",
    "LISTEN_IPS",
    "DEFAULT_SNAT_IP",
    "LAN_IFS",
    "LAN_NETS",
    "PROTECTION_MODE",
    "PROTECTED_NETS",
    "AUTH_MODE",
    "DNAT_MARK",
    "DNAT_LABEL",
    "ENABLE_HAIRPIN",
    "ENABLE_WAN_TO_WAN",
    "ENABLE_EGRESS_SNAT",
    "EGRESS_NETS",
    "ENABLE_TCPMSS_CLAMP",
    "ENABLE_STRICT_LAN_VALIDATION",
    "INTERNAL_IFS",
    "TRUSTED_INTERNAL_NETS",
    "COUNTER_MODE",
    "ENABLE_CONFIG_HISTORY",
    "RP_FILTER_MODE",
    "CONNTRACK_MODE",
    "CONNTRACK_TARGET_MAX",
    "CONNTRACK_PEAK",
    "CONNTRACK_MEMORY_PERCENT",
    "LOCALE",
)

LIST_FIELDS = {
    "EXTERNAL_IFS",
    "LISTEN_IPS",
    "LAN_IFS",
    "LAN_NETS",
    "PROTECTED_NETS",
    "EGRESS_NETS",
    "INTERNAL_IFS",
    "TRUSTED_INTERNAL_NETS",
}

TOGGLE_KEYS = {
    "ENABLE_HAIRPIN",
    "ENABLE_WAN_TO_WAN",
    "ENABLE_EGRESS_SNAT",
    "ENABLE_TCPMSS_CLAMP",
    "ENABLE_STRICT_LAN_VALIDATION",
    "ENABLE_CONFIG_HISTORY",
}

CONFIG_SOURCE_OF_TRUTH_KEYS = (
    "EXTERNAL_IFS",
    "PRIMARY_EXTERNAL_IF",
    "LISTEN_IPS",
    "DEFAULT_SNAT_IP",
    "LAN_IFS",
    "LAN_NETS",
    "PROTECTION_MODE",
    "PROTECTED_NETS",
    "AUTH_MODE",
    "DNAT_MARK",
    "DNAT_LABEL",
    "ENABLE_HAIRPIN",
    "ENABLE_WAN_TO_WAN",
    "ENABLE_EGRESS_SNAT",
    "EGRESS_NETS",
    "ENABLE_TCPMSS_CLAMP",
    "ENABLE_STRICT_LAN_VALIDATION",
    "INTERNAL_IFS",
    "TRUSTED_INTERNAL_NETS",
    "COUNTER_MODE",
    "ENABLE_CONFIG_HISTORY",
    "RP_FILTER_MODE",
    "CONNTRACK_MODE",
    "CONNTRACK_TARGET_MAX",
    "CONNTRACK_PEAK",
    "CONNTRACK_MEMORY_PERCENT",
    "LOCALE",
)

PROTECTION_MODES = {"backends", "nets", "both"}
AUTH_MODES = {"mark", "label"}
COUNTER_MODES = {"off", "minimal", "all"}
RP_FILTER_MODES = {"system", "strict", "loose_scoped", "loose_global"}
CONNTRACK_MODES = {"system", "conservative", "standard", "high", "auto", "custom"}

AUTH_MARK_CANDIDATE_BITS = (30, 29, 28, 27, 26, 25, 24, 23, 22)
DEFAULT_DNAT_MARK = "0x10000000"
DEFAULT_DNAT_LABEL = "56"
DEFAULT_LOCALE = "en_US"
LOHA_NFT_TABLE_NAME = "loha_port_forwarder"
LOHA_CT_LABEL_PROBE_TABLE_NAME = "loha_ct_label_probe"

DEFAULT_CONFIG_VALUES = {
    "AUTH_MODE": "mark",
    "DNAT_MARK": DEFAULT_DNAT_MARK,
    "DNAT_LABEL": "",
    "ENABLE_HAIRPIN": "on",
    "ENABLE_WAN_TO_WAN": "off",
    "ENABLE_EGRESS_SNAT": "off",
    "ENABLE_TCPMSS_CLAMP": "off",
    "ENABLE_STRICT_LAN_VALIDATION": "off",
    "COUNTER_MODE": "minimal",
    "ENABLE_CONFIG_HISTORY": "on",
    "RP_FILTER_MODE": "system",
    "CONNTRACK_MODE": "system",
    "CONNTRACK_TARGET_MAX": "",
    "CONNTRACK_PEAK": "",
    "CONNTRACK_MEMORY_PERCENT": "",
    "PROTECTION_MODE": "backends",
    "PROTECTED_NETS": "",
    "EGRESS_NETS": "",
    "INTERNAL_IFS": "",
    "TRUSTED_INTERNAL_NETS": "",
    "LOCALE": DEFAULT_LOCALE,
}

CONNTRACK_PROFILE_SPECS = {
    "conservative": {"target_max": 65536, "buckets": 512},
    "standard": {"target_max": 262144, "buckets": 2048},
    "high": {"target_max": 1048576, "buckets": 8192},
}

HISTORY_LIMIT = 5
HISTORY_WINDOW_SECONDS = 600

LITERAL_TOKENS = (
    "EXTERNAL_IFS",
    "PRIMARY_EXTERNAL_IF",
    "LISTEN_IPS",
    "DEFAULT_SNAT_IP",
    "LAN_IFS",
    "LAN_NETS",
    "PROTECTION_MODE",
    "PROTECTED_NETS",
    "ENABLE_EGRESS_SNAT",
    "EGRESS_NETS",
    "ENABLE_STRICT_LAN_VALIDATION",
    "INTERNAL_IFS",
    "TRUSTED_INTERNAL_NETS",
    "AUTH_MODE",
    "CONNTRACK_MODE",
    "ct mark",
    "ct label",
    "rp_filter",
    "conntrack",
    "nftables",
    "systemd",
    "reload --full",
)

DEFAULT_SERVICE_NAME = "loha.service"

REPO_ROOT = Path(__file__).resolve().parents[2]
