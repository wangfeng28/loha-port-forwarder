import os
import platform
import re
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .constants import LOHA_CT_LABEL_PROBE_TABLE_NAME
from .models import PrecheckResult
from .system import SystemAdapter


REQUIRED_COMMANDS = ("python3", "ip", "nft", "sysctl", "systemctl")
REQUIRED_ASSETS = (
    "src/loha/install.py",
    "src/loha/cli.py",
    "src/loha/loader.py",
    "locales/en_US.toml",
    "locales/zh_CN.toml",
)
KERNEL_MIN_VERSION = (5, 6)
NFT_MIN_VERSION = (0, 9, 4)
VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
CT_LABEL_CHECK_RULESET = f"""table inet {LOHA_CT_LABEL_PROBE_TABLE_NAME} {{
    chain c {{
        ct label set 1
        ct label 1 accept
    }}
}}
"""


def _parse_version_tuple(text: str) -> Tuple[int, ...]:
    match = VERSION_RE.search(text)
    if not match:
        return ()
    return tuple(int(group or "0", 10) for group in match.groups())


def _version_gte(found: Sequence[int], minimum: Sequence[int]) -> bool:
    if not found:
        return False
    width = max(len(found), len(minimum))
    left = tuple(found) + (0,) * (width - len(found))
    right = tuple(minimum) + (0,) * (width - len(minimum))
    return left >= right


def _result(level: str, key: str, default_message: str, **values: str) -> PrecheckResult:
    return PrecheckResult(level=level, message_key=key, default_message=default_message, values=dict(values))


def count_level(results: Sequence[PrecheckResult], level: str) -> int:
    return sum(1 for result in results if result.level == level)


def has_failures(results: Sequence[PrecheckResult]) -> bool:
    return count_level(results, "fail") > 0


def _supports_ct_label(adapter: SystemAdapter) -> bool:
    if not adapter.command_exists("nft"):
        return False
    result = adapter.run(["nft", "-c", "-f", "-"], input_text=CT_LABEL_CHECK_RULESET, check=False)
    return result.returncode == 0


def run_install_prechecks(
    adapter: SystemAdapter,
    *,
    repo_root: Path,
    is_root: Optional[bool] = None,
    kernel_release: Optional[str] = None,
    dry_run: bool = False,
) -> List[PrecheckResult]:
    results: List[PrecheckResult] = []
    is_root = os.geteuid() == 0 if is_root is None else is_root
    kernel_release = kernel_release or platform.release()
    missing_required_dependency = False

    results.append(
        _result(
            "pass" if is_root else "fail",
            "install.precheck.root_ok" if is_root else "install.precheck.root_fail",
            "Running as root" if is_root else "Installer must run as root",
        )
    )

    for name in REQUIRED_COMMANDS:
        level = "pass" if adapter.command_exists(name) else "fail"
        if level == "fail":
            missing_required_dependency = True
        results.append(
            _result(
                level,
                "install.precheck.dep_ok" if level == "pass" else "install.precheck.dep_missing",
                "Dependency: {name} found" if level == "pass" else "Dependency: {name} missing",
                name=name,
            )
        )

    for relative_path in REQUIRED_ASSETS:
        path = repo_root / relative_path
        level = "pass" if path.exists() else "fail"
        results.append(
            _result(
                level,
                "install.precheck.asset_ok" if level == "pass" else "install.precheck.asset_missing",
                "Asset: {path} found" if level == "pass" else "Asset: {path} missing",
                path=relative_path,
            )
        )

    kernel_version = _parse_version_tuple(kernel_release)
    if _version_gte(kernel_version, KERNEL_MIN_VERSION):
        results.append(
            _result(
                "pass",
                "install.precheck.kernel_ok",
                "Kernel: {version} meets >= 5.6",
                version=kernel_release,
            )
        )
    else:
        results.append(
            _result(
                "fail",
                "install.precheck.kernel_low",
                "Kernel: {version} is below 5.6",
                version=kernel_release or "unknown",
            )
        )

    if not missing_required_dependency and adapter.command_exists("nft"):
        result = adapter.run(["nft", "--version"], check=False)
        version_text = result.stdout.strip() or result.stderr.strip()
        nft_version = _parse_version_tuple(version_text)
        if _version_gte(nft_version, NFT_MIN_VERSION):
            results.append(
                _result(
                    "pass",
                    "install.precheck.nft_ok",
                    "nftables: {version} meets >= 0.9.4",
                    version=version_text or "available",
                )
            )
        elif version_text:
            results.append(
                _result(
                    "fail",
                    "install.precheck.nft_low",
                    "nftables: {version} is below 0.9.4",
                    version=version_text,
                )
            )
        else:
            results.append(
                _result(
                    "fail",
                    "install.precheck.nft_unknown",
                    "nftables: unable to determine version",
                )
            )

    if not missing_required_dependency and adapter.command_exists("systemctl"):
        result = adapter.run(["systemctl", "list-unit-files"], check=False)
        if result.returncode == 0:
            results.append(
                _result(
                    "pass",
                    "install.precheck.systemd_ok",
                    "systemd: unit-file listing succeeded",
                )
            )
        else:
            results.append(
                _result(
                    "fail",
                    "install.precheck.systemd_fail",
                    "systemd: unable to query unit files",
                )
            )

    if not missing_required_dependency and adapter.command_exists("nft"):
        if _supports_ct_label(adapter):
            results.append(
                _result(
                    "pass",
                    "install.precheck.ct_label_ok",
                    "nftables supports ct label",
                )
            )
        else:
            results.append(
                _result(
                    "warn",
                    "install.precheck.ct_label_warn",
                    "nftables ct label check failed; label mode may be unavailable",
                )
            )

    if dry_run:
        results.append(
            _result(
                "pass",
                "install.precheck.dry_run",
                "Dry-run mode: installation changes will not be applied",
            )
        )

    return results
