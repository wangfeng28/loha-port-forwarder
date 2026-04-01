from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Paths:
    etc_dir: Path = Path("/etc/loha")
    prefix: Path = Path("/usr/local")
    run_dir: Path = Path("/run/loha")
    systemd_unit_dir: Path = Path("/etc/systemd/system")

    @property
    def loha_conf(self) -> Path:
        return self.etc_dir / "loha.conf"

    @property
    def rules_conf(self) -> Path:
        return self.etc_dir / "rules.conf"

    @property
    def history_dir(self) -> Path:
        return self.etc_dir / "history"

    @property
    def rollback_checkpoint_dir(self) -> Path:
        return self.history_dir / "_rollback_checkpoint"

    @property
    def forwarding_sysctl(self) -> Path:
        return Path("/etc/sysctl.d/90-loha-forwarding.conf")

    @property
    def conntrack_sysctl(self) -> Path:
        return Path("/etc/sysctl.d/90-loha-conntrack.conf")

    @property
    def conntrack_modprobe(self) -> Path:
        return Path("/etc/modprobe.d/loha-conntrack.conf")

    @property
    def service_unit(self) -> Path:
        return self.systemd_unit_dir / "loha.service"

    @property
    def loader_wrapper(self) -> Path:
        return self.prefix / "libexec" / "loha" / "loader.sh"

    @property
    def cli_wrapper(self) -> Path:
        return self.prefix / "bin" / "loha"

    @property
    def package_root(self) -> Path:
        return self.prefix / "lib" / "loha-port-forwarder"

    @property
    def share_dir(self) -> Path:
        return self.prefix / "share" / "loha"

    @property
    def locale_dir(self) -> Path:
        return self.share_dir / "locales"

    @property
    def control_state_file(self) -> Path:
        return self.run_dir / "control_plane.state"

    @property
    def debug_ruleset_file(self) -> Path:
        return self.run_dir / "loha_debug.nft"


@dataclass(frozen=True)
class PortSpec:
    start: int
    end: int

    @property
    def is_range(self) -> bool:
        return self.start != self.end

    @property
    def length(self) -> int:
        return self.end - self.start + 1

    @property
    def canonical(self) -> str:
        if self.start == self.end:
            return str(self.start)
        return f"{self.start}-{self.end}"

    def contains(self, other: "PortSpec") -> bool:
        return self.start <= other.start and self.end >= other.end

    def overlaps(self, other: "PortSpec") -> bool:
        return self.start <= other.end and other.start <= self.end


@dataclass(frozen=True)
class AliasRecord:
    name: str
    ip: str


@dataclass(frozen=True)
class PortRecord:
    proto: str
    listen: PortSpec
    destination: str
    destination_port: PortSpec


@dataclass(frozen=True)
class RulesFile:
    aliases: Tuple[AliasRecord, ...] = ()
    ports: Tuple[PortRecord, ...] = ()

    def alias_map(self) -> Dict[str, str]:
        return {record.name: record.ip for record in self.aliases}


@dataclass(frozen=True)
class CanonicalConfig:
    values: Dict[str, str]

    def get(self, key: str, default: str = "") -> str:
        return self.values.get(key, default)

    def __getitem__(self, key: str) -> str:
        return self.values[key]

    def items(self):
        return self.values.items()

    def as_dict(self) -> Dict[str, str]:
        return dict(self.values)


@dataclass(frozen=True)
class RenderContext:
    config: CanonicalConfig
    rules: RulesFile


@dataclass(frozen=True)
class RenderedRuleset:
    full_ruleset: str
    map_update: str
    control_state: str
    template_checksum: str


@dataclass(frozen=True)
class DoctorResult:
    level: str
    summary: str
    detail: str = ""
    hint: str = ""
    summary_key: str = ""
    summary_default: str = ""
    detail_key: str = ""
    detail_default: str = ""
    hint_key: str = ""
    hint_default: str = ""
    values: Dict[str, object] = field(default_factory=dict)

    def _render_text(
        self,
        *,
        key: str,
        default: str,
        fallback: str,
        translate: Optional[Callable[[str, str], str]] = None,
    ) -> str:
        template = default or fallback
        if key and translate is not None:
            template = translate(key, template)
        if not self.values:
            return template
        return template.format(**self.values)

    def render_summary(self, translate: Optional[Callable[[str, str], str]] = None) -> str:
        return self._render_text(
            key=self.summary_key,
            default=self.summary_default,
            fallback=self.summary,
            translate=translate,
        )

    def render_detail(self, translate: Optional[Callable[[str, str], str]] = None) -> str:
        return self._render_text(
            key=self.detail_key,
            default=self.detail_default,
            fallback=self.detail,
            translate=translate,
        )

    def render_hint(self, translate: Optional[Callable[[str, str], str]] = None) -> str:
        return self._render_text(
            key=self.hint_key,
            default=self.hint_default,
            fallback=self.hint,
            translate=translate,
        )


@dataclass(frozen=True)
class PrecheckResult:
    level: str
    message_key: str
    default_message: str
    values: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class LocalizedMessage:
    message_key: str
    default_message: str
    values: Dict[str, object] = field(default_factory=dict)

    def render(self, translate: Optional[Callable[[str, str], str]] = None) -> str:
        template = self.default_message if translate is None else translate(self.message_key, self.default_message)
        return template.format(**self.values)


@dataclass(frozen=True)
class InstallStepResult:
    ok: bool
    error: Optional[LocalizedMessage] = None


@dataclass(frozen=True)
class WizardOutcome:
    config: CanonicalConfig
    advanced_checked: bool = False
    persist_notices: Tuple[LocalizedMessage, ...] = ()


@dataclass(frozen=True)
class HistoryEntry:
    path: Path
    created_at_epoch: int
    updated_at_epoch: int
    source: str
    reason: str
    config_hash: str
    rules_hash: str


@dataclass(frozen=True)
class RollbackOutcome:
    entry: HistoryEntry
    apply_message: str = ""
    rescue_dir: Optional[Path] = None
    restored_from: str = "snapshot"


@dataclass(frozen=True)
class ConfigUpdateResult:
    config: CanonicalConfig
    notices: Tuple[LocalizedMessage, ...] = ()


@dataclass(frozen=True)
class RPFilterStatusReport:
    configured_mode: str
    target_ifaces: Tuple[str, ...]
    expected_file_content: str
    file_present: bool
    file_matches_expected: bool
    file_mode: str
    runtime_ip_forward: str
    runtime_default_value: str
    runtime_all_value: str
    runtime_iface_values: Dict[str, str] = field(default_factory=dict)
    runtime_mode: str = "runtime_only"
    runtime_state: str = "unknown"


@dataclass(frozen=True)
class ConntrackStatusReport:
    configured_mode: str
    expected_max: int
    expected_buckets: int
    expected_sysctl_content: str
    expected_modprobe_content: str
    sysctl_file_present: bool
    modprobe_file_present: bool
    sysctl_matches_expected: bool
    modprobe_matches_expected: bool
    runtime_max: str
    runtime_buckets: str
    runtime_state: str


@dataclass(frozen=True)
class FeatureDefinition:
    feature_id: str
    title: str
    category: str
    config_keys: Tuple[str, ...]
    default_config: Dict[str, str]


@dataclass(frozen=True)
class MenuOption:
    token: str
    label: str
    value: str
    recommended: bool = False


@dataclass(frozen=True)
class StepDefinition:
    step_id: str
    config_key: str
    title: str
    description: str
    input_kind: str
    options: Tuple[MenuOption, ...] = ()
    visible_when: Tuple[Tuple[str, Sequence[str]], ...] = ()
    default_from: Optional[str] = None


@dataclass(frozen=True)
class LocaleCatalog:
    locale: str
    fallback: str
    messages: Dict[str, str]
    display_name: str = ""
    glossary: Dict[str, str] = field(default_factory=dict)
    literal_tokens: Tuple[str, ...] = ()
    required_terms: Dict[str, str] = field(default_factory=dict)
    forbidden_substrings: Tuple[str, ...] = ()
