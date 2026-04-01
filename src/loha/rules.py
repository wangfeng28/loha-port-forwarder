import ipaddress
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .exceptions import RulesSyntaxError, RulesValidationError
from .models import AliasRecord, PortRecord, PortSpec, RulesFile


ALIAS_RE = re.compile(r"^(HOST|VM)_[A-Za-z0-9_]+$")


def validate_alias_name(value: str) -> str:
    if not ALIAS_RE.match(value):
        raise RulesValidationError("alias names must start with HOST_ or VM_")
    return value


def validate_ipv4(value: str) -> str:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise RulesValidationError(f"invalid IPv4 value: {value}") from exc
    return value


def validate_proto(value: str) -> str:
    proto = value.lower()
    if proto not in {"tcp", "udp"}:
        raise RulesValidationError("protocol must be tcp or udp")
    return proto


def parse_port_spec(text: str, *, allow_plus: bool) -> PortSpec:
    raw = text.strip()
    if raw.isdigit():
        port = int(raw, 10)
        if 1 <= port <= 65535:
            return PortSpec(port, port)
        raise RulesValidationError("port must be within 1..65535")
    if "-" in raw:
        start_text, end_text = raw.split("-", 1)
        if not start_text.isdigit() or not end_text.isdigit():
            raise RulesValidationError(f"invalid port range: {text}")
        start = int(start_text, 10)
        end = int(end_text, 10)
        if not (1 <= start < end <= 65535):
            raise RulesValidationError(f"invalid port range: {text}")
        return PortSpec(start, end)
    if allow_plus and "+" in raw:
        start_text, offset_text = raw.split("+", 1)
        if not start_text.isdigit() or not offset_text.isdigit():
            raise RulesValidationError(f"invalid +offset port syntax: {text}")
        start = int(start_text, 10)
        end = start + int(offset_text, 10)
        if not (1 <= start < end <= 65535):
            raise RulesValidationError(f"invalid +offset port syntax: {text}")
        return PortSpec(start, end)
    raise RulesValidationError(f"invalid port syntax: {text}")


def _validate_port_shapes(listen: PortSpec, destination: PortSpec) -> None:
    if listen.is_range and not destination.is_range:
        raise RulesValidationError(
            "original listening port is a range, so destination port must also be a range"
        )
    if not listen.is_range and destination.is_range:
        raise RulesValidationError(
            "original listening port is a single port, so destination port must also be a single port"
        )
    if listen.is_range and destination.is_range and listen.length != destination.length:
        raise RulesValidationError("destination port range length must match original range length")


def parse_rules_text(text: str) -> RulesFile:
    aliases: List[AliasRecord] = []
    ports: List[PortRecord] = []
    alias_map: Dict[str, str] = {}
    seen_proto_specs: List[Tuple[str, PortSpec, int]] = []

    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        line = line.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        kind = parts[0]
        if kind == "ALIAS":
            if len(parts) != 3:
                raise RulesSyntaxError(f"line {lineno}: ALIAS requires exactly 2 columns")
            name = validate_alias_name(parts[1])
            ip = validate_ipv4(parts[2])
            if name in alias_map:
                raise RulesValidationError(f"line {lineno}: duplicate alias {name}")
            alias_map[name] = ip
            aliases.append(AliasRecord(name, ip))
            continue
        if kind == "PORT":
            if len(parts) != 5:
                raise RulesSyntaxError(f"line {lineno}: PORT requires exactly 4 columns")
            proto = validate_proto(parts[1])
            listen = parse_port_spec(parts[2], allow_plus=False)
            destination = parts[3]
            if destination.startswith(("HOST_", "VM_")):
                validate_alias_name(destination)
                if destination not in alias_map:
                    raise RulesValidationError(f"line {lineno}: alias ({destination}) does not exist")
            else:
                validate_ipv4(destination)
            destination_port = parse_port_spec(parts[4], allow_plus=False)
            _validate_port_shapes(listen, destination_port)
            for seen_proto, seen_spec, seen_lineno in seen_proto_specs:
                if seen_proto == proto and seen_spec.overlaps(listen):
                    raise RulesValidationError(
                        f"line {lineno}: original listening port/range ({listen.canonical}) overlaps "
                        f"with line {seen_lineno} ({proto} {seen_spec.canonical})"
                    )
            seen_proto_specs.append((proto, listen, lineno))
            ports.append(PortRecord(proto, listen, destination, destination_port))
            continue
        raise RulesSyntaxError(f"line {lineno}: unknown rule type ({kind})")

    return RulesFile(tuple(aliases), tuple(ports))


def render_rules_text(rules: RulesFile) -> str:
    lines: List[str] = []
    for alias in rules.aliases:
        lines.append(f"ALIAS\t{alias.name}\t{alias.ip}")
    for record in rules.ports:
        lines.append(
            f"PORT\t{record.proto}\t{record.listen.canonical}\t"
            f"{record.destination}\t{record.destination_port.canonical}"
        )
    return ("\n".join(lines) + "\n") if lines else ""


def load_rules(path: Path) -> RulesFile:
    if not path.exists():
        return RulesFile()
    return parse_rules_text(path.read_text(encoding="utf-8"))


def add_alias(rules: RulesFile, name: str, ip: str) -> RulesFile:
    name = validate_alias_name(name)
    ip = validate_ipv4(ip)
    alias_map = rules.alias_map()
    alias_map[name] = ip
    aliases = [AliasRecord(alias, alias_ip) for alias, alias_ip in sorted(alias_map.items())]
    return RulesFile(tuple(aliases), rules.ports)


def remove_alias(rules: RulesFile, name: str) -> RulesFile:
    remaining_aliases = tuple(alias for alias in rules.aliases if alias.name != name)
    if len(remaining_aliases) == len(rules.aliases):
        raise RulesValidationError(f"alias not found: {name}")
    for port in rules.ports:
        if port.destination == name:
            raise RulesValidationError(f"alias {name} is still referenced by a PORT rule")
    return RulesFile(remaining_aliases, rules.ports)


def add_port_rule(
    rules: RulesFile,
    proto: str,
    listen_spec: str,
    destination: str,
    destination_spec: Optional[str] = None,
) -> RulesFile:
    proto = validate_proto(proto)
    listen = parse_port_spec(listen_spec, allow_plus=True)
    if destination.startswith(("HOST_", "VM_")):
        validate_alias_name(destination)
        if destination not in rules.alias_map():
            raise RulesValidationError(f"alias ({destination}) does not exist")
    else:
        validate_ipv4(destination)
    destination_port = parse_port_spec(destination_spec or listen_spec, allow_plus=True)
    _validate_port_shapes(listen, destination_port)
    for record in rules.ports:
        if record.proto == proto and record.listen.overlaps(listen):
            raise RulesValidationError(
                f"original listening port/range ({listen.canonical}) overlaps with existing "
                f"rule ({record.proto} {record.listen.canonical})"
            )
    ports = list(rules.ports)
    ports.append(PortRecord(proto, listen, destination, destination_port))
    ports.sort(key=lambda record: (record.proto, record.listen.start, record.listen.end, record.destination))
    return RulesFile(rules.aliases, tuple(ports))


def remove_port_rule(rules: RulesFile, proto: str, listen_spec: str) -> RulesFile:
    proto = validate_proto(proto)
    listen = parse_port_spec(listen_spec, allow_plus=True)
    remaining = tuple(
        record for record in rules.ports if not (record.proto == proto and record.listen == listen)
    )
    if len(remaining) == len(rules.ports):
        raise RulesValidationError(f"port rule not found: {proto} {listen.canonical}")
    return RulesFile(rules.aliases, remaining)


def prune_port_rules(
    rules: RulesFile,
    *,
    destination: Optional[str] = None,
    proto: Optional[str] = None,
    range_spec: Optional[str] = None,
) -> RulesFile:
    if not any([destination, proto, range_spec]):
        raise RulesValidationError("port prune requires at least one filter")
    range_value = parse_port_spec(range_spec, allow_plus=True) if range_spec else None
    remaining: List[PortRecord] = []
    removed = 0
    for record in rules.ports:
        matches = True
        if destination is not None and record.destination != destination:
            matches = False
        if proto is not None and record.proto != validate_proto(proto):
            matches = False
        if range_value is not None and not range_value.contains(record.listen):
            matches = False
        if matches:
            removed += 1
        else:
            remaining.append(record)
    if removed == 0:
        raise RulesValidationError("no rules matched the prune filters")
    return RulesFile(rules.aliases, tuple(remaining))
