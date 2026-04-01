import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Set, Tuple

from .config import normalize_auth_mode
from .constants import (
    AUTH_MARK_CANDIDATE_BITS,
    DEFAULT_DNAT_LABEL,
    DEFAULT_DNAT_MARK,
    LOHA_CT_LABEL_PROBE_TABLE_NAME,
    LOHA_NFT_TABLE_NAME,
)
from .exceptions import ApplyError, ConfigValidationError
from .models import LocalizedMessage
from .system import SystemAdapter


HEX_RE = re.compile(r"0x[0-9A-Fa-f]+|\b\d+\b")
CONNTRACK_MARK_RE = re.compile(r"\bmark=([^\s]+)")
LABEL_RE = re.compile(r"\b(?:ct\s+label\s+set|ct\s+label|DNAT_LABEL=|define\s+DNAT_LABEL\s*=)\s*(\d+)\b")
MARK_CONTEXT_RE = re.compile(r"\b(?:ct\s+mark|meta\s+mark|DNAT_MARK|define\s+DNAT_MARK)\b")
LOHA_OWNED_TABLE_RE = re.compile(
    rf"^\s*table\s+\S+\s+(?:{re.escape(LOHA_NFT_TABLE_NAME)}|{re.escape(LOHA_CT_LABEL_PROBE_TABLE_NAME)})\b"
)


@dataclass(frozen=True)
class AuthModePlan:
    auth_mode: str
    dnat_mark: str
    dnat_label: str
    changed: bool
    message: LocalizedMessage
    reload_hint: Optional[LocalizedMessage]
    warnings: Tuple[LocalizedMessage, ...] = ()


@dataclass(frozen=True)
class AuthMarkSurvey:
    suggested_mark: str
    available_marks: Tuple[str, ...]
    conflicting_marks: Tuple[str, ...]
    runtime_scan_available: bool
    static_conflicting_marks: Tuple[str, ...] = ()
    runtime_conflicting_marks: Tuple[str, ...] = ()
    static_conflict_samples: Tuple[str, ...] = ()
    runtime_conflict_samples: Tuple[str, ...] = ()


def _normalize_current_mark_for_plan(current_mode: str, current_mark: str) -> str:
    if current_mode != "mark" or not current_mark:
        return ""
    try:
        return _normalize_mark_value(current_mark)
    except ConfigValidationError:
        return ""


def _normalize_current_label_for_plan(current_mode: str, current_label: str) -> str:
    if current_mode != "label" or not current_label:
        return ""
    try:
        return _normalize_label_value(current_label)
    except ConfigValidationError:
        return ""


def _compose_auth_mode_plan(
    state: Mapping[str, str],
    requested: str,
    *,
    dnat_mark: str = "",
    dnat_label: str = "",
    warnings: Sequence[LocalizedMessage] = (),
) -> AuthModePlan:
    current_mode = normalize_auth_mode(state.get("AUTH_MODE", "mark"))
    current_mark = (state.get("DNAT_MARK", "") or "").strip()
    current_label = (state.get("DNAT_LABEL", "") or "").strip()
    warning_values = tuple(warnings)

    if requested == "label":
        chosen_label = _normalize_label_value(dnat_label or DEFAULT_DNAT_LABEL)
        current_label_normalized = _normalize_current_label_for_plan(current_mode, current_label)
        changed = current_mode != "label" or current_label_normalized != chosen_label
        return AuthModePlan(
            auth_mode="label",
            dnat_mark="",
            dnat_label=chosen_label,
            changed=changed,
            message=LocalizedMessage(
                "auth.plan.switched_label" if changed else "auth.plan.already_label",
                "Authorization mode switched to ct label (label value {value})."
                if changed
                else "Authorization mode is already ct label (label value {value}).",
                values={"value": chosen_label},
            ),
            reload_hint=(
                LocalizedMessage(
                    "auth.plan.reload_hint",
                    "Run `loha reload --full` to apply the authorization mode change.",
                )
                if changed
                else None
            ),
            warnings=warning_values,
        )

    chosen_mark = _normalize_mark_value(dnat_mark or DEFAULT_DNAT_MARK)
    current_mark_normalized = _normalize_current_mark_for_plan(current_mode, current_mark)
    changed = current_mode != "mark" or current_mark_normalized != chosen_mark
    return AuthModePlan(
        auth_mode="mark",
        dnat_mark=chosen_mark,
        dnat_label="",
        changed=changed,
        message=LocalizedMessage(
            "auth.plan.switched_mark" if changed else "auth.plan.already_mark",
            "Authorization mode switched to ct mark (mark value {value})."
            if changed
            else "Authorization mode is already ct mark (mark value {value}).",
            values={"value": chosen_mark},
        ),
        reload_hint=(
            LocalizedMessage(
                "auth.plan.reload_hint",
                "Run `loha reload --full` to apply the authorization mode change.",
            )
            if changed
            else None
        ),
        warnings=warning_values,
    )


def _normalize_mark_value(value: str) -> str:
    raw = (value or DEFAULT_DNAT_MARK).strip()
    try:
        mark_value = int(raw, 16 if raw.lower().startswith("0x") else 10)
    except ValueError as exc:
        raise ConfigValidationError("DNAT_MARK must be a single-bit integer") from exc
    if mark_value <= 0 or mark_value & (mark_value - 1):
        raise ConfigValidationError("DNAT_MARK must be a single-bit integer")
    valid_marks = {1 << bit for bit in AUTH_MARK_CANDIDATE_BITS}
    if mark_value not in valid_marks:
        raise ConfigValidationError("DNAT_MARK must use a candidate auth bit in bit22-bit30")
    return f"0x{mark_value:08X}"


def _normalize_label_value(value: str) -> str:
    raw = (value or DEFAULT_DNAT_LABEL).strip()
    if not raw.isdigit():
        raise ConfigValidationError("DNAT_LABEL must be an integer in [1, 127]")
    label = int(raw, 10)
    if not (1 <= label <= 127):
        raise ConfigValidationError("DNAT_LABEL must be an integer in [1, 127]")
    return str(label)


def normalize_mark_candidate(value: str) -> str:
    return _normalize_mark_value(value)


def normalize_label_candidate(value: str) -> str:
    return _normalize_label_value(value)


def mark_candidate_order(current_mark: str = "") -> Tuple[str, ...]:
    ordered = []
    seen = set()
    if current_mark:
        try:
            normalized_current = _normalize_mark_value(current_mark)
        except ConfigValidationError:
            normalized_current = ""
        if normalized_current and normalized_current not in seen:
            ordered.append(normalized_current)
            seen.add(normalized_current)
    for candidate in [DEFAULT_DNAT_MARK, *[f"0x{1 << bit:08X}" for bit in AUTH_MARK_CANDIDATE_BITS]]:
        if candidate not in seen:
            ordered.append(candidate)
            seen.add(candidate)
    return tuple(ordered)


def _candidate_marks_from_int(value: int) -> Set[str]:
    candidates: Set[str] = set()
    for bit in AUTH_MARK_CANDIDATE_BITS:
        mark_value = 1 << bit
        if value & mark_value:
            candidates.add(f"0x{mark_value:08X}")
    return candidates


def _canonical_mark_sample(value: int) -> str:
    return f"0x{value:08X}"


def _strip_loha_owned_tables(text: str) -> str:
    lines = []
    skip_depth = 0
    for line in text.splitlines():
        if skip_depth:
            skip_depth += line.count("{") - line.count("}")
            if skip_depth <= 0:
                skip_depth = 0
            continue
        if LOHA_OWNED_TABLE_RE.match(line):
            skip_depth = line.count("{") - line.count("}")
            if skip_depth <= 0:
                skip_depth = 0
            continue
        lines.append(line)
    return "\n".join(lines)


def _scan_text_sources(paths, adapter: Optional[SystemAdapter]) -> Sequence[str]:
    sources = []
    if adapter is not None and adapter.command_exists("nft"):
        result = adapter.run(["nft", "list", "ruleset"], check=False)
        if result.returncode == 0 and result.stdout:
            filtered = _strip_loha_owned_tables(result.stdout)
            if filtered.strip():
                sources.append(filtered)
    return tuple(sources)


def _scan_runtime_mark_tokens(adapter: Optional[SystemAdapter]) -> Tuple[Sequence[str], bool]:
    if adapter is None:
        return (), False
    proc_path = Path("/proc/net/nf_conntrack")
    try:
        proc_text = adapter.read_text(proc_path)
    except Exception:
        proc_text = ""
    if proc_text:
        return tuple(CONNTRACK_MARK_RE.findall(proc_text)), True
    if adapter.command_exists("conntrack"):
        result = adapter.run(["conntrack", "-L", "-o", "extended"], check=False)
        if result.returncode == 0 and result.stdout:
            return tuple(CONNTRACK_MARK_RE.findall(result.stdout)), True
    return (), False


def _normalized_ignored_marks(ignored_marks: Iterable[str]) -> Set[str]:
    ignored = set()
    for candidate in ignored_marks:
        if not candidate:
            continue
        try:
            ignored.add(_normalize_mark_value(candidate))
        except ConfigValidationError:
            continue
    return ignored


def _scan_static_auth_marks(
    paths,
    adapter: Optional[SystemAdapter],
    *,
    ignored: Set[str],
) -> Tuple[Set[str], Tuple[str, ...]]:
    used: Set[str] = set()
    samples = []
    seen_samples = set()
    for text in _scan_text_sources(paths, adapter):
        for line in text.splitlines():
            if not MARK_CONTEXT_RE.search(line):
                continue
            line_used = False
            sample_values = []
            for match in HEX_RE.finditer(line):
                token = match.group(0)
                try:
                    value = int(token, 16 if token.lower().startswith("0x") else 10)
                except ValueError:
                    continue
                token_prefix = line[: match.start()].lower()
                if re.search(r"\band\s*$", token_prefix):
                    raw_candidates = {
                        f"0x{1 << bit:08X}" for bit in AUTH_MARK_CANDIDATE_BITS if not (value & (1 << bit))
                    }
                else:
                    raw_candidates = _candidate_marks_from_int(value)
                normalized_candidates = {normalized for normalized in raw_candidates if normalized not in ignored}
                if not normalized_candidates:
                    continue
                used.update(normalized_candidates)
                sample = _canonical_mark_sample(value)
                if sample not in sample_values:
                    sample_values.append(sample)
                line_used = True
            if line_used:
                for sample in sample_values:
                    if sample not in seen_samples:
                        seen_samples.add(sample)
                        samples.append(sample)
    return used, tuple(samples)


def _scan_runtime_auth_marks(
    adapter: Optional[SystemAdapter],
    *,
    ignored: Set[str],
) -> Tuple[Set[str], Tuple[str, ...], bool]:
    used: Set[str] = set()
    samples = []
    seen_samples = set()
    runtime_tokens, runtime_scan_available = _scan_runtime_mark_tokens(adapter)
    for candidate in runtime_tokens:
        try:
            value = int(candidate, 16 if candidate.lower().startswith("0x") else 10)
        except ValueError:
            continue
        normalized_candidates = {
            normalized for normalized in _candidate_marks_from_int(value) if normalized not in ignored
        }
        if not normalized_candidates:
            continue
        used.update(normalized_candidates)
        sample = _canonical_mark_sample(value)
        if sample not in seen_samples:
            seen_samples.add(sample)
            samples.append(sample)
    return used, tuple(samples), runtime_scan_available


def used_auth_marks(
    paths,
    adapter: Optional[SystemAdapter] = None,
    *,
    ignored_marks: Iterable[str] = (),
) -> Set[str]:
    ignored = _normalized_ignored_marks(ignored_marks)
    static_used, _static_samples = _scan_static_auth_marks(paths, adapter, ignored=ignored)
    runtime_used, _runtime_samples, _runtime_scan_available = _scan_runtime_auth_marks(adapter, ignored=ignored)
    return static_used | runtime_used


def used_auth_labels(
    paths,
    adapter: Optional[SystemAdapter] = None,
    *,
    ignored_labels: Iterable[str] = (),
) -> Set[str]:
    used: Set[str] = set()
    ignored = set()
    for candidate in ignored_labels:
        if not candidate:
            continue
        try:
            ignored.add(_normalize_label_value(candidate))
        except ConfigValidationError:
            continue
    for text in _scan_text_sources(paths, adapter):
        for match in LABEL_RE.findall(text):
            try:
                normalized = _normalize_label_value(match)
            except ConfigValidationError:
                continue
            if normalized not in ignored:
                used.add(normalized)
    return used


def probe_ct_label_support(adapter: Optional[SystemAdapter]) -> Optional[bool]:
    if adapter is None or not adapter.command_exists("nft"):
        return None
    result = adapter.run(
        ["nft", "-c", "-f", "-"],
        input_text=(
            f"table inet {LOHA_CT_LABEL_PROBE_TABLE_NAME} {{\n"
            "    chain input {\n"
            "        type filter hook input priority 0; policy accept;\n"
            "        ct label set 1\n"
            "    }\n"
            "}\n"
        ),
        check=False,
    )
    return result.returncode == 0


def survey_auth_mark_candidates(
    state: Mapping[str, str],
    *,
    paths=None,
    adapter: Optional[SystemAdapter] = None,
) -> AuthMarkSurvey:
    current_mode = normalize_auth_mode(state.get("AUTH_MODE", "mark"))
    current_mark = (state.get("DNAT_MARK", "") or "").strip() if current_mode == "mark" else ""
    ordered = mark_candidate_order(current_mark)
    ignored = _normalized_ignored_marks((current_mark,) if current_mark else ())
    static_conflicts = set()
    static_samples: Tuple[str, ...] = ()
    if paths is not None:
        static_conflicts, static_samples = _scan_static_auth_marks(paths, adapter, ignored=ignored)
    runtime_conflicts, runtime_samples, runtime_scan_available = _scan_runtime_auth_marks(adapter, ignored=ignored)
    conflicts = static_conflicts | runtime_conflicts
    if not runtime_samples and not runtime_scan_available:
        runtime_scan_available = False
    available = tuple(candidate for candidate in ordered if candidate not in conflicts)
    suggested = available[0] if available else (ordered[0] if ordered else DEFAULT_DNAT_MARK)
    conflicting = tuple(candidate for candidate in ordered if candidate in conflicts)
    return AuthMarkSurvey(
        suggested_mark=suggested,
        available_marks=available,
        conflicting_marks=conflicting,
        runtime_scan_available=runtime_scan_available,
        static_conflicting_marks=tuple(candidate for candidate in ordered if candidate in static_conflicts),
        runtime_conflicting_marks=tuple(candidate for candidate in ordered if candidate in runtime_conflicts),
        static_conflict_samples=static_samples,
        runtime_conflict_samples=runtime_samples,
    )


def _pick_mark(current_mark: str, used_marks: Iterable[str]) -> str:
    used = set(used_marks)
    if current_mark:
        try:
            normalized = _normalize_mark_value(current_mark)
        except ConfigValidationError:
            normalized = ""
        if normalized and normalized not in used:
            return normalized
    candidate_order = [DEFAULT_DNAT_MARK] + [
        f"0x{1 << bit:08X}" for bit in AUTH_MARK_CANDIDATE_BITS if f"0x{1 << bit:08X}" != DEFAULT_DNAT_MARK
    ]
    for candidate in candidate_order:
        if candidate not in used:
            return candidate
    raise ApplyError("no available DNAT_MARK candidate remains in bit22-bit30")


def _pick_label(current_label: str, used_labels: Iterable[str]) -> str:
    used = set(used_labels)
    if current_label:
        try:
            normalized = _normalize_label_value(current_label)
        except ConfigValidationError:
            normalized = ""
        if normalized and normalized not in used:
            return normalized
    for candidate in [DEFAULT_DNAT_LABEL, *[str(number) for number in range(57, 128)], *[str(number) for number in range(1, 56)]]:
        if candidate not in used:
            return candidate
    raise ApplyError("no available DNAT_LABEL candidate remains in [1, 127]")


def plan_auth_mode_switch(
    state: Mapping[str, str],
    requested_mode: str,
    *,
    paths=None,
    adapter: Optional[SystemAdapter] = None,
) -> AuthModePlan:
    requested = normalize_auth_mode(requested_mode)
    current_mode = normalize_auth_mode(state.get("AUTH_MODE", "mark"))
    current_mark = (state.get("DNAT_MARK", "") or "").strip()
    current_label = (state.get("DNAT_LABEL", "") or "").strip()
    warnings = []

    if requested == "label":
        label_probe = probe_ct_label_support(adapter)
        if label_probe is False:
            warnings.append(
                LocalizedMessage(
                    "auth.warning.label_probe_failed",
                    "ct label capability probe failed in current environment; later reload may fail.",
                )
            )
        chosen_label = _pick_label(
            current_label if current_mode == "label" else "",
            used_auth_labels(
                paths,
                adapter,
                ignored_labels=(current_label,) if current_mode == "label" else (),
            ) if paths is not None else (),
        )
        return _compose_auth_mode_plan(state, requested, dnat_label=chosen_label, warnings=tuple(warnings))

    chosen_mark = _pick_mark(
        current_mark if current_mode == "mark" else "",
        used_auth_marks(
            paths,
            adapter,
            ignored_marks=(current_mark,) if current_mode == "mark" else (),
        )
        if paths is not None
        else (),
    )
    return _compose_auth_mode_plan(state, requested, dnat_mark=chosen_mark)


def plan_selected_auth_mode_switch(
    state: Mapping[str, str],
    requested_mode: str,
    *,
    selected_mark: str = "",
    selected_label: str = "",
    paths=None,
    adapter: Optional[SystemAdapter] = None,
) -> AuthModePlan:
    requested = normalize_auth_mode(requested_mode)
    baseline = plan_auth_mode_switch(state, requested, paths=paths, adapter=adapter)
    if requested == "label":
        return _compose_auth_mode_plan(
            state,
            requested,
            dnat_label=selected_label or baseline.dnat_label,
            warnings=baseline.warnings,
        )
    return _compose_auth_mode_plan(
        state,
        requested,
        dnat_mark=selected_mark or baseline.dnat_mark,
        warnings=baseline.warnings,
    )
