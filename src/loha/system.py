import re
import shutil
import subprocess
from ipaddress import IPv4Interface
from pathlib import Path
from typing import Iterable, Optional, Sequence, Set, Tuple

from .exceptions import ApplyError


VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_version_tuple(text: str) -> Tuple[int, ...]:
    match = VERSION_RE.search(text)
    if not match:
        return ()
    return tuple(int(group or "0", 10) for group in match.groups())


class SystemAdapter:
    def command_exists(self, name: str) -> bool:
        raise NotImplementedError

    def run(self, argv: Sequence[str], *, input_text: str = "", check: bool = True) -> subprocess.CompletedProcess:
        raise NotImplementedError

    def default_ipv4_ifaces(self) -> Tuple[str, ...]:
        raise NotImplementedError

    def list_interfaces(self) -> Tuple[str, ...]:
        raise NotImplementedError

    def global_ipv4s(self, interface: str) -> Tuple[str, ...]:
        raise NotImplementedError

    def ipv4_networks(self, interface: str) -> Tuple[str, ...]:
        raise NotImplementedError

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        raise NotImplementedError

    def systemctl(self, action: str, unit: str = "") -> None:
        raise NotImplementedError

    def scan_listeners(self) -> Optional[Set[Tuple[str, int]]]:
        raise NotImplementedError

    def read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def write_text_atomic(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(path.name + ".tmp")
        temp_path.write_text(text, encoding="utf-8")
        temp_path.replace(path)

    def nft_version(self) -> Tuple[int, ...]:
        if not self.command_exists("nft"):
            return ()
        result = self.run(["nft", "--version"], check=False)
        version_text = result.stdout.strip() or result.stderr.strip()
        return _parse_version_tuple(version_text)

    def nft_supports_destroy(self, *, family: str = "ip", table: str = "__loha_destroy_probe__") -> bool:
        if not self.command_exists("nft"):
            return False
        result = self.run(
            ["nft", "-c", "-f", "-"],
            input_text=f"destroy table {family} {table}\n",
            check=False,
        )
        return result.returncode == 0

    def nft_table_exists(self, family: str, table: str) -> bool:
        if not self.command_exists("nft"):
            return False
        result = self.run(["nft", "list", "table", family, table], check=False)
        return result.returncode == 0

    def nft_table_reset_commands(self, family: str, table: str) -> Tuple[str, ...]:
        if self.nft_supports_destroy(family=family, table=table):
            return (f"destroy table {family} {table}",)
        if self.nft_table_exists(family, table):
            return (f"delete table {family} {table}",)
        return ()


class SubprocessSystemAdapter(SystemAdapter):
    def command_exists(self, name: str) -> bool:
        return shutil.which(name) is not None

    def run(self, argv: Sequence[str], *, input_text: str = "", check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            list(argv),
            input=input_text,
            text=True,
            capture_output=True,
            check=check,
        )

    def default_ipv4_ifaces(self) -> Tuple[str, ...]:
        if not self.command_exists("ip"):
            raise ApplyError("Missing 'ip' command; cannot probe default IPv4 interface")
        result = self.run(["ip", "-4", "route", "show", "table", "main", "default"], check=False)
        seen = []
        seen_set = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            for index, part in enumerate(parts):
                if part == "dev" and index + 1 < len(parts):
                    iface = parts[index + 1]
                    if iface not in seen_set:
                        seen.append(iface)
                        seen_set.add(iface)
                    break
        return tuple(seen)

    def list_interfaces(self) -> Tuple[str, ...]:
        if not self.command_exists("ip"):
            raise ApplyError("Missing 'ip' command; cannot list interfaces")
        result = self.run(["ip", "-o", "link", "show"], check=False)
        seen = []
        seen_set = set()
        for line in result.stdout.splitlines():
            if ":" not in line:
                continue
            try:
                name = line.split(":", 2)[1].strip()
            except IndexError:
                continue
            if "@" in name:
                name = name.split("@", 1)[0]
            if name not in seen_set:
                seen.append(name)
                seen_set.add(name)
        return tuple(seen)

    def global_ipv4s(self, interface: str) -> Tuple[str, ...]:
        if not self.command_exists("ip"):
            raise ApplyError("Missing 'ip' command; cannot probe interface addresses")
        result = self.run(["ip", "-o", "-4", "addr", "show", "dev", interface, "scope", "global"], check=False)
        values = []
        for line in result.stdout.splitlines():
            if " inet " not in line:
                continue
            raw = line.split(" inet ", 1)[1].split("/", 1)[0].strip()
            if raw:
                values.append(raw)
        return tuple(values)

    def ipv4_networks(self, interface: str) -> Tuple[str, ...]:
        if not self.command_exists("ip"):
            raise ApplyError("Missing 'ip' command; cannot probe interface networks")
        result = self.run(["ip", "-o", "-4", "addr", "show", "dev", interface], check=False)
        values = []
        seen = set()
        for line in result.stdout.splitlines():
            if " inet " not in line:
                continue
            raw = line.split(" inet ", 1)[1].split()[0].strip()
            try:
                network = IPv4Interface(raw).network
            except ValueError:
                continue
            canonical = f"{network.network_address}/{network.prefixlen}"
            if canonical not in seen:
                seen.add(canonical)
                values.append(canonical)
        return tuple(values)

    def nft_apply(self, ruleset: str, *, check_only: bool = False) -> None:
        if not self.command_exists("nft"):
            raise ApplyError("Missing 'nft' command")
        command = ["nft", "-f", "-"]
        if check_only:
            command = ["nft", "-c", "-f", "-"]
        result = self.run(command, input_text=ruleset, check=False)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip() or "nft apply failed"
            raise ApplyError(stderr)

    def systemctl(self, action: str, unit: str = "") -> None:
        if not self.command_exists("systemctl"):
            raise ApplyError("Missing 'systemctl' command")
        command = ["systemctl", action]
        if unit:
            command.append(unit)
        result = self.run(command, check=False)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip() or f"systemctl {action} failed"
            raise ApplyError(stderr)

    def scan_listeners(self) -> Optional[Set[Tuple[str, int]]]:
        if not self.command_exists("ss"):
            return None
        result = self.run(["ss", "-Hlnptu"], check=False)
        if result.returncode != 0:
            return None
        listeners: Set[Tuple[str, int]] = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            endpoint = parts[4]
            if ":" not in endpoint:
                continue
            port_text = endpoint.rsplit(":", 1)[1]
            if port_text.isdigit():
                listeners.add((proto, int(port_text, 10)))
        return listeners
