import hashlib
from typing import Dict, Iterable, List, Sequence, Tuple

from .constants import LOHA_NFT_TABLE_NAME
from .exceptions import RulesValidationError
from .models import CanonicalConfig, RenderContext, RenderedRuleset, RulesFile


def _iface_set(csv: str) -> str:
    items = [item for item in csv.split(",") if item]
    return "{ " + ", ".join(f'"{item}"' for item in items) + " }"


def _cidr_set(csv: str) -> str:
    items = [item for item in csv.split(",") if item]
    return "{ " + ", ".join(items) + " }"


def _ipv4_set(csv: str) -> str:
    items = [item for item in csv.split(",") if item]
    return "{ " + ", ".join(items) + " }"


def _dnat_elements(config: CanonicalConfig, rules: RulesFile) -> Tuple[List[str], List[str]]:
    alias_map = rules.alias_map()
    dnat_elements: List[str] = []
    protected_backends: List[str] = []
    seen_backends = set()
    seen_dnat_targets: Dict[Tuple[str, int], Tuple[str, int]] = {}
    for record in rules.ports:
        destination_ip = alias_map.get(record.destination, record.destination)
        for offset in range(record.listen.length):
            listen_port = record.listen.start + offset
            destination_port = record.destination_port.start + offset
            key = (record.proto, listen_port)
            value = (destination_ip, destination_port)
            previous = seen_dnat_targets.get(key)
            if previous is not None:
                if previous == value:
                    continue
                previous_ip, previous_port = previous
                raise RulesValidationError(
                    f"render would generate duplicate dnat_rules key "
                    f"({record.proto} . {listen_port}) for conflicting targets "
                    f"({previous_ip} . {previous_port} vs {destination_ip} . {destination_port})"
                )
            seen_dnat_targets[key] = value
            dnat_elements.append(
                f"        {record.proto} . {listen_port} : "
                f"{destination_ip} . {destination_port},"
            )
        if destination_ip not in seen_backends:
            protected_backends.append(f"        {destination_ip},")
            seen_backends.add(destination_ip)
    return dnat_elements, protected_backends


def _render_auth_authorize(config: CanonicalConfig) -> str:
    if config["AUTH_MODE"] == "mark":
        return "\n".join(
            [
                "    # Pre-authorize by setting the dedicated auth bit",
                "    ct mark set ct mark or $DNAT_MARK",
            ]
        )
    return "\n".join(
        [
            "    # Pre-authorize by setting the dedicated auth label bit",
            "    ct label set $DNAT_LABEL",
        ]
    )


def _render_auth_lookup() -> str:
    return "\n".join(
        [
            "    # Fast map forwarding (single lookup; exit the chain on success)",
            "    dnat to meta l4proto . th dport map @dnat_rules",
        ]
    )


def _render_auth_miss_cleanup(config: CanonicalConfig) -> str:
    if config["AUTH_MODE"] == "mark":
        return "\n".join(
            [
                "    # Clear the auth bit on miss (prevent mark leakage into downstream checks)",
                "    ct mark set ct mark and $DNAT_MARK_CLEAR_MASK",
            ]
        )
    return "\n".join(
        [
            "    # Miss cleanup for label mode is enforced downstream via ct status dnat gating;",
            "    # ct label set is append-only and cannot roll a dedicated label bit back to zero.",
        ]
    )


def _forward_accept_predicate(config: CanonicalConfig) -> str:
    if config["AUTH_MODE"] == "mark":
        return "ct status dnat ct mark & $DNAT_MARK != 0"
    return "ct status dnat ct label $DNAT_LABEL"


def _postrouting_auth_match(config: CanonicalConfig) -> str:
    if config["AUTH_MODE"] == "mark":
        return "ct mark & $DNAT_MARK != 0"
    return "ct status dnat ct label $DNAT_LABEL"


def _protection_miss_expr(config: CanonicalConfig) -> str:
    if config["AUTH_MODE"] == "mark":
        return " ct mark & $DNAT_MARK == 0"
    return ""


def _counter_drop(config: CanonicalConfig) -> str:
    return "counter" if config["COUNTER_MODE"] in {"minimal", "all"} else ""


def _counter_accept(config: CanonicalConfig) -> str:
    return "counter" if config["COUNTER_MODE"] == "all" else ""


def _render_forward_features_pre(config: CanonicalConfig) -> str:
    if config["ENABLE_TCPMSS_CLAMP"] != "on":
        return ""
    return "\n".join(
        [
            "    # Optional TCP MSS clamping: fixes PMTU black holes on WAN egress",
            "    meta l4proto tcp ip saddr $LAN_NETS oifname $PRIMARY_EXTERNAL_IF tcp flags syn tcp option maxseg size set rt mtu",
        ]
    )


def _render_forward_features_post(config: CanonicalConfig) -> str:
    if config["ENABLE_STRICT_LAN_VALIDATION"] != "on":
        return ""
    return "\n".join(
        [
            "    # Optional strict internal validation: drop packets arriving on configured internal interfaces with unexpected source subnets",
            "    iifname $INTERNAL_IFS ip saddr != $TRUSTED_INTERNAL_NETS __COUNTER_DROP__ drop",
        ]
    )


def _render_postrouting(config: CanonicalConfig) -> str:
    parts: List[str] = []
    if config["ENABLE_EGRESS_SNAT"] == "on":
        source_set = "$LAN_NETS" if config["EGRESS_NETS"] == config["LAN_NETS"] else "$EGRESS_NETS"
        parts.append("    # 3.1 Regular LAN Internet access -> primary WAN egress NAT")
        parts.append(f"    ip saddr {source_set} oifname $PRIMARY_EXTERNAL_IF snat to $DEFAULT_SNAT_IP")
    if config["ENABLE_HAIRPIN"] == "on":
        parts.append("    # 3.2 Hairpin NAT (LAN loopback): allow LAN hosts to reach LAN services via the WAN IP")
        parts.append(
            f"    ip saddr $LAN_NETS ip daddr $LAN_NETS oifname != $PRIMARY_EXTERNAL_IF {_postrouting_auth_match(config)} masquerade"
        )
    if config["ENABLE_WAN_TO_WAN"] == "on":
        parts.append("    # 3.3 WAN-to-WAN (WAN mapped to WAN): primary-WAN triangle-routing support")
        parts.append(
            f"    iifname $EXTERNAL_IFS oifname $PRIMARY_EXTERNAL_IF {_postrouting_auth_match(config)} masquerade"
        )
    return "\n".join(parts)


def _render_protection_rules(config: CanonicalConfig) -> str:
    lines = ["    # [Security Barrier 2] Final block: drop unauthorized traffic attempting to route from WAN into LAN"]
    miss = _protection_miss_expr(config)
    counter = _counter_drop(config)
    counter_suffix = f" {counter}" if counter else ""
    if config["PROTECTION_MODE"] in {"backends", "both"}:
        lines.append(
            f"    iifname $EXTERNAL_IFS ip daddr @protected_backend_hosts{miss}{counter_suffix} drop".replace("  ", " ").replace("  ", " ")
        )
    if config["PROTECTION_MODE"] in {"nets", "both"}:
        lines.append(
            f"    iifname $EXTERNAL_IFS ip daddr $PROTECTED_NETS{miss}{counter_suffix} drop".replace("  ", " ").replace("  ", " ")
        )
    return "\n".join(lines)


def _elements_block(elements: Sequence[str]) -> str:
    if not elements:
        return ""
    return "        elements = {\n" + "\n".join(elements) + "\n        }"


def _render_ruleset_text(
    define_lines: Sequence[str],
    *,
    dnat_block: str,
    listen_block: str,
    protected_block: str,
    port_forwarding_body: str,
    postrouting_body: str,
    forward_features_pre: str,
    forward_features_post: str,
    forward_allow_rule: str,
    protection_rules: str,
) -> str:
    return f"""#!/usr/sbin/nft -f
destroy table ip {LOHA_NFT_TABLE_NAME}
{chr(10).join(define_lines)}

table ip {LOHA_NFT_TABLE_NAME} {{
    map dnat_rules {{
        type inet_proto . inet_service : ipv4_addr . inet_service
{dnat_block}
    }}

    set listen_ips {{
        type ipv4_addr
{listen_block}
    }}

    set protected_backend_hosts {{
        type ipv4_addr
{protected_block}
    }}

    chain port_forwarding {{
{port_forwarding_body}
    }}

    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr @listen_ips jump port_forwarding
    }}

    chain output {{
        type nat hook output priority dstnat; policy accept;
        ip daddr @listen_ips jump port_forwarding
    }}

    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
{postrouting_body}
    }}

    chain forward {{
        type filter hook forward priority filter - 5; policy accept;
        ct state invalid drop
{forward_features_pre}
        ct state established,related accept
        iifname $LAN_IFS ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
        iifname $EXTERNAL_IFS ip saddr $LAN_NETS __COUNTER_DROP__ drop
{forward_features_post}
{forward_allow_rule}
        iifname $LAN_IFS ip saddr $LAN_NETS oifname $PRIMARY_EXTERNAL_IF accept
{protection_rules}
    }}
}}
"""


def render_ruleset(context: RenderContext) -> RenderedRuleset:
    config = context.config
    rules = context.rules
    dnat_elements, protected_backend_hosts = _dnat_elements(config, rules)
    listen_elements = [f"        {ip}," for ip in config["LISTEN_IPS"].split(",") if ip]

    define_lines = [
        f'define PRIMARY_EXTERNAL_IF = "{config["PRIMARY_EXTERNAL_IF"]}"',
        f"define EXTERNAL_IFS = {_iface_set(config['EXTERNAL_IFS'])}",
        f"define DEFAULT_SNAT_IP = {config['DEFAULT_SNAT_IP']}",
        f"define LAN_IFS = {_iface_set(config['LAN_IFS'])}",
        f"define LAN_NETS = {_cidr_set(config['LAN_NETS'])}",
    ]
    if config["INTERNAL_IFS"]:
        define_lines.append(f"define INTERNAL_IFS = {_iface_set(config['INTERNAL_IFS'])}")
    if config["TRUSTED_INTERNAL_NETS"]:
        define_lines.append(f"define TRUSTED_INTERNAL_NETS = {_cidr_set(config['TRUSTED_INTERNAL_NETS'])}")
    if config["EGRESS_NETS"] and config["EGRESS_NETS"] != config["LAN_NETS"]:
        define_lines.append(f"define EGRESS_NETS = {_cidr_set(config['EGRESS_NETS'])}")
    if config["PROTECTED_NETS"]:
        define_lines.append(f"define PROTECTED_NETS = {_cidr_set(config['PROTECTED_NETS'])}")
    if config["AUTH_MODE"] == "mark":
        mark_value = int(config["DNAT_MARK"], 16)
        clear_mask = (~mark_value) & 0xFFFFFFFF
        define_lines.append(f"define DNAT_MARK = {config['DNAT_MARK']}")
        define_lines.append(f"define DNAT_MARK_CLEAR_MASK = 0x{clear_mask:08X}")
    else:
        define_lines.append(f"define DNAT_LABEL = {config['DNAT_LABEL']}")

    port_forwarding_body = "\n".join(
        [
            _render_auth_authorize(config),
            _render_auth_lookup(),
            _render_auth_miss_cleanup(config),
        ]
    )
    forward_features_pre = _render_forward_features_pre(config)
    forward_features_post = _render_forward_features_post(config)
    postrouting_body = _render_postrouting(config)
    forward_allow_counter = _counter_accept(config)
    forward_allow_rule = (
        "    # [Traffic Allow 1] Allow legitimate mapped traffic that carries LOHA auth state\n"
        f"    {_forward_accept_predicate(config)}"
        f"{' ' + forward_allow_counter if forward_allow_counter else ''} accept"
    )
    protection_rules = _render_protection_rules(config)

    skeleton = _render_ruleset_text(
        define_lines,
        dnat_block=_elements_block(dnat_elements),
        listen_block=_elements_block(listen_elements),
        protected_block=_elements_block(protected_backend_hosts),
        port_forwarding_body=port_forwarding_body,
        postrouting_body=postrouting_body,
        forward_features_pre=forward_features_pre,
        forward_features_post=forward_features_post,
        forward_allow_rule=forward_allow_rule,
        protection_rules=protection_rules,
    ).replace("__COUNTER_DROP__", _counter_drop(config))
    control_plane_template = _render_ruleset_text(
        define_lines,
        dnat_block="",
        listen_block="",
        protected_block="",
        port_forwarding_body=port_forwarding_body,
        postrouting_body=postrouting_body,
        forward_features_pre=forward_features_pre,
        forward_features_post=forward_features_post,
        forward_allow_rule=forward_allow_rule,
        protection_rules=protection_rules,
    ).replace("__COUNTER_DROP__", _counter_drop(config))
    template_checksum = hashlib.sha256(control_plane_template.encode("utf-8")).hexdigest()
    control_state = "\n".join(
        [
            f"EXTERNAL_IFS={config['EXTERNAL_IFS']}",
            f"LAN_IFS={config['LAN_IFS']}",
            f"LAN_NETS={config['LAN_NETS']}",
            f"INTERNAL_IFS={config['INTERNAL_IFS']}",
            f"TRUSTED_INTERNAL_NETS={config['TRUSTED_INTERNAL_NETS']}",
            f"AUTH_MODE={config['AUTH_MODE']}",
            f"DNAT_MARK={config['DNAT_MARK']}",
            f"DNAT_LABEL={config['DNAT_LABEL']}",
            f"ENABLE_TCPMSS_CLAMP={config['ENABLE_TCPMSS_CLAMP']}",
            f"ENABLE_HAIRPIN={config['ENABLE_HAIRPIN']}",
            f"ENABLE_WAN_TO_WAN={config['ENABLE_WAN_TO_WAN']}",
            f"ENABLE_EGRESS_SNAT={config['ENABLE_EGRESS_SNAT']}",
            f"EGRESS_NETS={config['EGRESS_NETS']}",
            f"ENABLE_STRICT_LAN_VALIDATION={config['ENABLE_STRICT_LAN_VALIDATION']}",
            f"COUNTER_MODE={config['COUNTER_MODE']}",
            f"PROTECTION_MODE={config['PROTECTION_MODE']}",
            f"PROTECTED_NETS={config['PROTECTED_NETS']}",
            f"CORE_TEMPLATE_CHECKSUM={template_checksum}",
        ]
    )

    map_update_lines = define_lines + [
        f"flush map ip {LOHA_NFT_TABLE_NAME} dnat_rules",
        f"flush set ip {LOHA_NFT_TABLE_NAME} listen_ips",
        f"flush set ip {LOHA_NFT_TABLE_NAME} protected_backend_hosts",
    ]
    if dnat_elements:
        map_update_lines.extend([f"add element ip {LOHA_NFT_TABLE_NAME} dnat_rules {{", *dnat_elements, "}"])
    if listen_elements:
        map_update_lines.extend([f"add element ip {LOHA_NFT_TABLE_NAME} listen_ips {{", *listen_elements, "}"])
    if protected_backend_hosts:
        map_update_lines.extend(
            [f"add element ip {LOHA_NFT_TABLE_NAME} protected_backend_hosts {{", *protected_backend_hosts, "}"]
        )
    return RenderedRuleset(
        full_ruleset=skeleton,
        map_update="\n".join(map_update_lines) + "\n",
        control_state=control_state,
        template_checksum=template_checksum,
    )
