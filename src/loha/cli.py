from __future__ import annotations

import argparse
import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
from dataclasses import is_dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from .auth import (
    normalize_label_candidate,
    plan_auth_mode_switch,
    plan_selected_auth_mode_switch,
    survey_auth_mark_candidates,
    used_auth_labels,
)
from .config_access import normalize_management_state, parse_management_config_text
from .constants import CONFIG_KEYS
from .config import (
    join_csv,
    normalize_counter_mode,
    normalize_integer_value,
    normalize_mapping,
    normalize_toggle,
    parse_csv,
    recommended_config,
    render_canonical_text,
)
from .control_tx import (
    build_desired_snapshot_from_texts,
    commit_desired_state,
    control_file_lock,
    inspect_control_plane_status,
    read_desired_state,
    read_desired_texts,
    read_runtime_state,
    update_runtime_state,
    write_runtime_state,
)
from .config_view import build_config_show_sections, build_runtime_integration_lines
from .doctor import format_doctor_result_lines, run_doctor, summarize_doctor_results
from .exceptions import (
    ApplyError,
    ControlLockError,
    ControlStateError,
    ConfigSyntaxError,
    ConfigValidationError,
    HistoryError,
    RulesLockError,
    RulesSyntaxError,
    RulesValidationError,
)
from .history import history_enabled, list_snapshots, load_rollback_checkpoint, rollback_snapshot, write_transaction
from .i18n import (
    RuntimeI18N,
    build_runtime_i18n_for_paths,
    render_localized_message,
    render_localized_messages,
    select_locale_interactive,
    runtime_template,
    runtime_translate,
)
from .input_parsing import InputValidationError, parse_yes_no
from .loader import LoaderService
from .models import ConfigUpdateResult, LocalizedMessage, Paths, RuntimeStateSnapshot
from .runtime_binding import describe_binding_status, sync_runtime_binding_state, sync_toggle_shortcut_state
from .rules import (
    add_alias,
    add_port_rule,
    load_rules,
    parse_port_spec,
    prune_port_rules,
    remove_alias,
    remove_port_rule,
    render_rules_text,
    validate_alias_name,
    validate_ipv4,
)
from .rules_tx import mutate_rules_transaction, rules_file_lock
from .system import SubprocessSystemAdapter
from .system_features import (
    apply_conntrack_files,
    apply_rp_filter_files,
    collect_conntrack_status,
    collect_rp_filter_status,
    describe_conntrack_runtime,
    describe_rp_filter_runtime,
    describe_rp_filter_source,
    format_conntrack_status_lines,
    format_rp_filter_status_lines,
    render_conntrack_modprobe_content,
    render_conntrack_sysctl_content,
    render_forwarding_sysctl_content,
)
from .version import __version__
from .wizard import print_summary, run_config_wizard_flow


EXIT_CODE_GENERIC_ERROR = 1
EXIT_CODE_USAGE_OR_SYNTAX = 2
EXIT_CODE_VALIDATION = 3
EXIT_CODE_LOCK = 4
EXIT_CODE_APPLY = 5
EXIT_CODE_HISTORY = 6
EXIT_CODE_CANCELLED = 130


_RULES_LINE_RE = re.compile(r"^line (?P<lineno>\d+): (?P<detail>.+)$")
_RULES_DUPLICATE_ALIAS_RE = re.compile(r"^duplicate alias (?P<name>\S+)$")
_RULES_ALIAS_MISSING_RE = re.compile(r"^alias \((?P<name>[^)]+)\) does not exist$")
_RULES_OVERLAP_WITH_LINE_RE = re.compile(
    r"^original listening port/range \((?P<listen>[^)]+)\) overlaps with line "
    r"(?P<seen_lineno>\d+) \((?P<proto>\S+) (?P<seen_listen>[^)]+)\)$"
)
_RULES_UNKNOWN_TYPE_RE = re.compile(r"^unknown rule type \((?P<kind>[^)]+)\)$")
_RULES_INVALID_IPV4_RE = re.compile(r"^invalid IPv4 value: (?P<value>.+)$")
_RULES_INVALID_PORT_RANGE_RE = re.compile(r"^invalid port range: (?P<text>.+)$")
_RULES_INVALID_PORT_OFFSET_RE = re.compile(r"^invalid \+offset port syntax: (?P<text>.+)$")
_RULES_ALIAS_NOT_FOUND_RE = re.compile(r"^alias not found: (?P<name>\S+)$")
_RULES_ALIAS_REFERENCED_RE = re.compile(r"^alias (?P<name>\S+) is still referenced by a PORT rule$")
_RULES_PORT_RULE_NOT_FOUND_RE = re.compile(r"^port rule not found: (?P<proto>\S+) (?P<listen>.+)$")


def _paths_from_args(args) -> Paths:
    base = Paths()
    return Paths(
        etc_dir=Path(args.etc_dir) if getattr(args, "etc_dir", None) else base.etc_dir,
        prefix=Path(args.prefix) if getattr(args, "prefix", None) else base.prefix,
        run_dir=Path(args.run_dir) if getattr(args, "run_dir", None) else base.run_dir,
        systemd_unit_dir=Path(args.systemd_dir) if getattr(args, "systemd_dir", None) else base.systemd_unit_dir,
    )


def _load_or_default_config(
    paths: Paths,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    assume_locked: bool = False,
):
    if paths.loha_conf.exists():
        adapter = adapter or SubprocessSystemAdapter()
        config_text, _rules_text = read_desired_texts(paths, assume_locked=assume_locked)
        config, _notices = normalize_management_state(parse_management_config_text(config_text), adapter)
        return config
    return recommended_config()


def _load_management_config_or_default(
    paths: Paths,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    assume_locked: bool = False,
):
    adapter = adapter or SubprocessSystemAdapter()
    if not paths.loha_conf.exists():
        return recommended_config(), ()
    config_text, _rules_text = read_desired_texts(paths, assume_locked=assume_locked)
    return normalize_management_state(parse_management_config_text(config_text), adapter)


def _resolve_config_key(raw_key: str) -> str:
    candidate = raw_key.strip().upper().replace("-", "_")
    if candidate not in CONFIG_KEYS:
        raise ConfigValidationError(f"unsupported config key: {raw_key}")
    return candidate


def _service_reload(
    paths: Paths,
    *,
    full: bool,
    adapter: Optional[SubprocessSystemAdapter] = None,
    runtime: Optional[RuntimeI18N] = None,
) -> str:
    result = _service_reload_result(paths, full=full, adapter=adapter, runtime=runtime)
    return result["message"]


def _service_reload_result(
    paths: Paths,
    *,
    full: bool,
    adapter: Optional[SubprocessSystemAdapter] = None,
    runtime: Optional[RuntimeI18N] = None,
):
    adapter = adapter or SubprocessSystemAdapter()
    unit_name = paths.service_unit.name
    requested_mode = "full" if full else "reload"
    if full:
        adapter.systemctl("restart", unit_name)
    else:
        if not adapter.command_exists("systemctl"):
            raise ApplyError("Missing 'systemctl' command")
        status = adapter.run(["systemctl", "is-active", "--quiet", unit_name], check=False)
        if status.returncode != 0:
            stderr = status.stderr.strip() or status.stdout.strip() or f"{unit_name} is not active"
            raise ApplyError(stderr)
        adapter.systemctl("reload", unit_name)
    control_plane = inspect_control_plane_status(paths)
    effective_mode = control_plane.last_apply_mode or requested_mode
    message = LocalizedMessage(
        "loader.apply.full" if effective_mode == "full" else "loader.apply.reload",
        "Full ruleset initialized successfully." if effective_mode == "full" else "Mappings hot-swapped successfully.",
    )
    return {
        "message": _render_message(runtime, message) if runtime is not None else message.render(),
        "requested_mode": requested_mode,
        "effective_mode": effective_mode,
        "desired_revision": control_plane.desired_revision,
        "applied_revision": control_plane.applied_revision,
        "runtime_synced": control_plane.runtime_synced,
        "pending_actions": list(control_plane.pending_actions),
    }


def _load_rules_or_empty(paths: Paths, *, assume_locked: bool = False):
    del assume_locked
    return load_rules(paths.rules_conf)


def _menu_args(paths: Paths, **kwargs) -> argparse.Namespace:
    values = {
        "etc_dir": str(paths.etc_dir),
        "prefix": str(paths.prefix),
        "run_dir": str(paths.run_dir),
        "systemd_dir": str(paths.systemd_unit_dir),
    }
    values.update(kwargs)
    return argparse.Namespace(**values)


def _format_mark_bit(mark_value: str) -> str:
    number = int(mark_value, 16 if mark_value.lower().startswith("0x") else 10)
    return str(number.bit_length() - 1)


def _format_mark_samples(values, *, limit: int = 5) -> str:
    items = tuple(values)
    if not items:
        return ""
    preview = ", ".join(items[:limit])
    if len(items) > limit:
        return f"{preview}, ..."
    return preview


def _print_mark_conflict_details(runtime: RuntimeI18N, survey) -> None:
    static_conflicts = tuple(getattr(survey, "static_conflicting_marks", ()))
    runtime_conflicts = tuple(getattr(survey, "runtime_conflicting_marks", ()))

    if static_conflicts:
        bits = ",".join(_format_mark_bit(mark) for mark in static_conflicts)
        print(
            _t(
                runtime,
                "auth.mark_conflict_bits_static",
                "Detected candidate bits already referenced by non-LOHA nft/config state: {bits}",
                bits=bits,
            )
        )
        samples = _format_mark_samples(getattr(survey, "static_conflict_samples", ()))
        if samples:
            print(
                _t(
                    runtime,
                    "auth.mark_conflict_samples_static",
                    "Observed non-LOHA static mark values: {values}",
                    values=samples,
                )
            )

    if runtime_conflicts:
        bits = ",".join(_format_mark_bit(mark) for mark in runtime_conflicts)
        print(
            _t(
                runtime,
                "auth.mark_conflict_bits_runtime",
                "Detected candidate bits currently present in live conntrack marks: {bits}",
                bits=bits,
            )
        )
        samples = _format_mark_samples(getattr(survey, "runtime_conflict_samples", ()))
        if samples:
            print(
                _t(
                    runtime,
                    "auth.mark_conflict_samples_runtime",
                    "Observed live conntrack mark values: {values}",
                    values=samples,
                )
            )

    if not static_conflicts and not runtime_conflicts and getattr(survey, "conflicting_marks", ()):
        bits = ",".join(_format_mark_bit(mark) for mark in survey.conflicting_marks)
        print(_t(runtime, "auth.mark_conflict_bits", "Detected conflict bits: {bits}", bits=bits))


def _mutate_rules(
    paths: Paths,
    *,
    source: str,
    reason: str,
    mutate: Callable,
):
    config = _load_or_default_config(paths)
    return mutate_rules_transaction(
        paths,
        config=config,
        source=source,
        reason=reason,
        mutate=mutate,
    )


def _runtime_i18n(paths: Paths) -> RuntimeI18N:
    return build_runtime_i18n_for_paths(paths)


def _t(runtime: RuntimeI18N, key: str, default: str, **values) -> str:
    return runtime_translate(runtime, key, default, **values)


def _template(runtime: RuntimeI18N, key: str, default: str) -> str:
    return runtime_template(runtime, key, default)


def _render_message(runtime: RuntimeI18N, message: LocalizedMessage) -> str:
    return render_localized_message(message, runtime)


def _render_messages(runtime: RuntimeI18N, messages: Iterable[LocalizedMessage]):
    return render_localized_messages(messages, runtime)


def _jsonable(value):
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {
            name: _jsonable(getattr(value, name))
            for name in value.__dataclass_fields__
        }
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def _emit_json(payload) -> None:
    print(json.dumps(_jsonable(payload), indent=2, sort_keys=True))


def _error_category_for_exit_code(exit_code: int) -> str:
    if exit_code == EXIT_CODE_USAGE_OR_SYNTAX:
        return "syntax"
    if exit_code == EXIT_CODE_VALIDATION:
        return "validation"
    if exit_code == EXIT_CODE_LOCK:
        return "lock"
    if exit_code == EXIT_CODE_APPLY:
        return "apply"
    if exit_code == EXIT_CODE_HISTORY:
        return "history"
    if exit_code == EXIT_CODE_CANCELLED:
        return "cancelled"
    return "internal"


def _error_code_for_exit_code(exit_code: int) -> str:
    if exit_code == EXIT_CODE_USAGE_OR_SYNTAX:
        return "invalid_request"
    if exit_code == EXIT_CODE_VALIDATION:
        return "validation_failed"
    if exit_code == EXIT_CODE_LOCK:
        return "lock_conflict"
    if exit_code == EXIT_CODE_APPLY:
        return "apply_failed"
    if exit_code == EXIT_CODE_HISTORY:
        return "history_failed"
    if exit_code == EXIT_CODE_CANCELLED:
        return "cancelled"
    return "unexpected_failure"


def _result_code_for_category(category: str) -> str:
    if category.endswith("_update"):
        return "update"
    if category.endswith("_check"):
        return "check"
    if category.endswith("_render"):
        return "render"
    if category.endswith("_status"):
        return "status"
    if category == "reload":
        return "reload"
    if category == "rollback":
        return "rollback"
    if category == "state_summary":
        return "summary"
    if category == "config_show":
        return "show"
    if category == "history_show":
        return "show"
    if category == "doctor_report":
        return "report"
    return "result"


def _json_result_payload(category: str, **payload):
    body = {
        "result": {
            "code": _result_code_for_category(category),
            "category": category,
        }
    }
    body.update(payload)
    return body


def _json_error_payload(message: str, *, error_type: str, exit_code: int):
    return {
        "ok": False,
        "error": {
            "code": _error_code_for_exit_code(exit_code),
            "category": _error_category_for_exit_code(exit_code),
            "type": error_type,
            "message": message,
            "exit_code": exit_code,
        },
    }


def _exit_code_for_exception(exc: Exception) -> int:
    if isinstance(exc, (ConfigSyntaxError, RulesSyntaxError)):
        return EXIT_CODE_USAGE_OR_SYNTAX
    if isinstance(exc, (ConfigValidationError, RulesValidationError, InputValidationError)):
        return EXIT_CODE_VALIDATION
    if isinstance(exc, (RulesLockError, ControlLockError)):
        return EXIT_CODE_LOCK
    if isinstance(exc, (ApplyError, ControlStateError)):
        return EXIT_CODE_APPLY
    if isinstance(exc, HistoryError):
        return EXIT_CODE_HISTORY
    return EXIT_CODE_GENERIC_ERROR


def _read_path_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _localize_rules_error_detail(runtime: Optional[RuntimeI18N], detail: str) -> str:
    if runtime is None:
        return detail
    if detail == "ALIAS requires exactly 2 columns":
        return _t(runtime, "rules.error.alias_columns", "ALIAS requires exactly 2 columns")
    if detail == "PORT requires exactly 4 columns":
        return _t(runtime, "rules.error.port_columns", "PORT requires exactly 4 columns")
    match = _RULES_DUPLICATE_ALIAS_RE.match(detail)
    if match:
        return _t(runtime, "rules.error.duplicate_alias", "duplicate alias {name}", name=match.group("name"))
    match = _RULES_ALIAS_MISSING_RE.match(detail)
    if match:
        return _t(runtime, "rules.error.alias_missing", "alias ({name}) does not exist", name=match.group("name"))
    match = _RULES_OVERLAP_WITH_LINE_RE.match(detail)
    if match:
        return _t(
            runtime,
            "rules.error.overlap_with_line",
            "original listening port/range ({listen}) overlaps with line {seen_lineno} ({proto} {seen_listen})",
            listen=match.group("listen"),
            seen_lineno=match.group("seen_lineno"),
            proto=match.group("proto"),
            seen_listen=match.group("seen_listen"),
        )
    match = _RULES_UNKNOWN_TYPE_RE.match(detail)
    if match:
        return _t(runtime, "rules.error.unknown_type", "unknown rule type ({kind})", kind=match.group("kind"))
    if detail == "alias names must start with HOST_ or VM_":
        return _t(runtime, "rules.error.alias_name_prefix", "alias names must start with HOST_ or VM_")
    match = _RULES_INVALID_IPV4_RE.match(detail)
    if match:
        return _t(runtime, "rules.error.invalid_ipv4", "invalid IPv4 value: {value}", value=match.group("value"))
    if detail == "protocol must be tcp or udp":
        return _t(runtime, "rules.error.invalid_proto", "protocol must be tcp or udp")
    if detail == "port must be within 1..65535":
        return _t(runtime, "rules.error.port_range", "port must be within 1..65535")
    match = _RULES_INVALID_PORT_RANGE_RE.match(detail)
    if match:
        return _t(runtime, "rules.error.invalid_port_range", "invalid port range: {text}", text=match.group("text"))
    match = _RULES_INVALID_PORT_OFFSET_RE.match(detail)
    if match:
        return _t(
            runtime,
            "rules.error.invalid_port_offset",
            "invalid +offset port syntax: {text}",
            text=match.group("text"),
        )
    if detail == "original listening port is a range, so destination port must also be a range":
        return _t(
            runtime,
            "rules.error.destination_range_required",
            "original listening port is a range, so destination port must also be a range",
        )
    if detail == "original listening port is a single port, so destination port must also be a single port":
        return _t(
            runtime,
            "rules.error.destination_single_required",
            "original listening port is a single port, so destination port must also be a single port",
        )
    if detail == "destination port range length must match original range length":
        return _t(
            runtime,
            "rules.error.destination_range_length",
            "destination port range length must match original range length",
        )
    match = _RULES_ALIAS_NOT_FOUND_RE.match(detail)
    if match:
        return _t(runtime, "rules.error.alias_not_found", "alias not found: {name}", name=match.group("name"))
    match = _RULES_ALIAS_REFERENCED_RE.match(detail)
    if match:
        return _t(
            runtime,
            "rules.error.alias_referenced",
            "alias {name} is still referenced by a PORT rule",
            name=match.group("name"),
        )
    match = _RULES_PORT_RULE_NOT_FOUND_RE.match(detail)
    if match:
        return _t(
            runtime,
            "rules.error.port_rule_not_found",
            "port rule not found: {proto} {listen}",
            proto=match.group("proto"),
            listen=match.group("listen"),
        )
    if detail == "port prune requires at least one filter":
        return _t(runtime, "rules.error.port_prune_filter", "port prune requires at least one filter")
    if detail == "no rules matched the prune filters":
        return _t(runtime, "rules.error.port_prune_none", "no rules matched the prune filters")
    return detail


def _localized_exception_message(runtime: Optional[RuntimeI18N], exc: Exception) -> str:
    message = str(exc)
    if runtime is None:
        return message
    if isinstance(exc, (RulesSyntaxError, RulesValidationError)):
        match = _RULES_LINE_RE.match(message)
        if match:
            detail = _localize_rules_error_detail(runtime, match.group("detail"))
            return _t(
                runtime,
                "rules.error.line_detail",
                "line {lineno}: {detail}",
                lineno=match.group("lineno"),
                detail=detail,
            )
        return _localize_rules_error_detail(runtime, message)
    return message


def _format_plain_error(runtime: Optional[RuntimeI18N], exc: Exception) -> str:
    message = _localized_exception_message(runtime, exc)
    exit_code = _exit_code_for_exception(exc)
    if exit_code == EXIT_CODE_LOCK:
        return _t(
            runtime,
            "common.error_with_code",
            "ERROR [{code}]: {message}",
            code=_error_code_for_exit_code(exit_code),
            message=message,
        )
    return _t(runtime, "common.error", "ERROR: {message}", message=message)


def _preview_text_artifact(path: Path, content: str, *, empty_means_remove: bool = False):
    current = _read_path_text(path)
    if content == "" and empty_means_remove:
        return {
            "path": str(path),
            "action": "remove",
            "would_change": path.exists(),
            "content": "",
        }
    return {
        "path": str(path),
        "action": "write",
        "would_change": current != content,
        "content": content,
    }


def _preview_transaction_artifacts(paths: Paths, *, config_text: str, rules_text: str):
    return {
        "loha_conf": _preview_text_artifact(paths.loha_conf, config_text),
        "rules_conf": _preview_text_artifact(paths.rules_conf, rules_text),
    }


def _preview_config_side_effect_artifacts(paths: Paths, config, *, changed_keys):
    artifacts = {}
    should_sync_sysctl = False
    if "RP_FILTER_MODE" in changed_keys:
        artifacts["forwarding_sysctl"] = _preview_text_artifact(
            paths.forwarding_sysctl,
            render_forwarding_sysctl_content(config),
        )
        should_sync_sysctl = should_sync_sysctl or artifacts["forwarding_sysctl"]["would_change"]
    if changed_keys & {"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"}:
        artifacts["conntrack_sysctl"] = _preview_text_artifact(
            paths.conntrack_sysctl,
            render_conntrack_sysctl_content(config),
            empty_means_remove=True,
        )
        artifacts["conntrack_modprobe"] = _preview_text_artifact(
            paths.conntrack_modprobe,
            render_conntrack_modprobe_content(config),
            empty_means_remove=True,
        )
        should_sync_sysctl = should_sync_sysctl or artifacts["conntrack_sysctl"]["would_change"]
        should_sync_sysctl = should_sync_sysctl or artifacts["conntrack_modprobe"]["would_change"]
    return artifacts, {"sysctl_system": should_sync_sysctl}


def _artifacts_would_change(artifacts) -> bool:
    return any(item["would_change"] for item in artifacts.values())


def _check_message(runtime: RuntimeI18N, *, would_change: bool) -> str:
    if would_change:
        return _t(
            runtime,
            "common.check.would_change",
            "Check mode: changes would be applied, but nothing was written.",
        )
    return _t(
        runtime,
        "common.check.no_change",
        "Check mode: no changes would be needed.",
    )


def _print_check_result(runtime: RuntimeI18N, *, would_change: bool) -> None:
    print(_check_message(runtime, would_change=would_change))


def _plan_rules_mutation(
    paths: Paths,
    *,
    mutate: Callable,
):
    config = _load_or_default_config(paths)
    rules = _load_rules_or_empty(paths)
    updated_rules = mutate(rules)
    artifacts = _preview_transaction_artifacts(
        paths,
        config_text=render_canonical_text(config),
        rules_text=render_rules_text(updated_rules),
    )
    return config, updated_rules, artifacts


def _apply_rules_mutation(
    paths: Paths,
    *,
    source: str,
    reason: str,
    mutate: Callable,
):
    with control_file_lock(paths):
        if paths.loha_conf.exists():
            config = _load_or_default_config(paths, assume_locked=True)
            current = load_rules(paths.rules_conf)
        else:
            config = recommended_config()
            current = load_rules(paths.rules_conf)
        updated_rules = mutate(current)
        artifacts = _preview_transaction_artifacts(
            paths,
            config_text=render_canonical_text(config),
            rules_text=render_rules_text(updated_rules),
        )
        changed = _artifacts_would_change(artifacts)
        if changed:
            commit_desired_state(
                paths,
                config_text=render_canonical_text(config),
                rules_text=render_rules_text(updated_rules),
                source=source,
                reason=reason,
                assume_locked=True,
            )
        return config, updated_rules, artifacts, changed


def _run_standard_rules_mutation_command(
    paths: Paths,
    runtime: RuntimeI18N,
    *,
    mutate: Callable,
    reason: str,
    source: str = "cli",
    json_enabled: bool = False,
    check_only: bool = False,
) -> int:
    if check_only:
        config, rules, artifacts = _plan_rules_mutation(
            paths,
            mutate=mutate,
        )
        changed = _artifacts_would_change(artifacts)
        if json_enabled:
            _emit_json(
                _json_check_payload(
                    category="rules_check",
                    config=config,
                    would_change=changed,
                    artifacts=artifacts,
                    rules=rules,
                )
            )
            return 0
        _print_check_result(runtime, would_change=changed)
        return 0
    config, rules, artifacts, changed = _apply_rules_mutation(
        paths,
        source=source,
        reason=reason,
        mutate=mutate,
    )
    if json_enabled:
        _emit_json(
            _json_rules_update_payload(
                category="rules_update",
                config=config,
                rules=rules,
                changed=changed,
                artifacts=artifacts,
            )
        )
    return 0


def _json_port_spec(spec):
    return {
        "start": spec.start,
        "end": spec.end,
        "length": spec.length,
        "is_range": spec.is_range,
        "canonical": spec.canonical,
    }


def _json_rules_payload(rules):
    return {
        "aliases": [
            {
                "name": alias.name,
                "ip": alias.ip,
            }
            for alias in rules.aliases
        ],
        "ports": [
            {
                "proto": record.proto,
                "listen": _json_port_spec(record.listen),
                "destination": record.destination,
                "destination_port": _json_port_spec(record.destination_port),
            }
            for record in rules.ports
        ],
    }


def _json_localized_message(message: LocalizedMessage):
    payload = _jsonable(message)
    payload["rendered"] = message.render()
    return payload


def _json_doctor_result(result):
    return {
        "level": result.level,
        "summary_key": result.summary_key,
        "summary": result.render_summary(),
        "detail_key": result.detail_key,
        "detail": result.render_detail(),
        "hint_key": result.hint_key,
        "hint": result.render_hint(),
        "values": _jsonable(result.values),
    }


def _json_binding_status_payload(binding_kind: str, configured_value: str):
    description = describe_binding_status(binding_kind, configured_value)
    payload = _jsonable(description)
    payload["configured_value"] = configured_value
    return payload


def _json_rpfilter_report_payload(report):
    payload = _jsonable(report)
    payload["source_description"] = describe_rp_filter_source(report)
    payload["runtime_description"] = describe_rp_filter_runtime(report)
    return payload


def _json_conntrack_report_payload(report):
    payload = _jsonable(report)
    payload["runtime_description"] = describe_conntrack_runtime(report)
    return payload


def _json_list_payload(config, rules):
    return _json_result_payload(
        "state_summary",
        ok=True,
        summary={
            "primary_external_if": config["PRIMARY_EXTERNAL_IF"],
            "listen_ips": parse_csv(config["LISTEN_IPS"], kind="ipv4"),
            "lan_nets": parse_csv(config["LAN_NETS"], kind="cidr"),
        },
        rules=_json_rules_payload(rules),
    )


def _json_config_show_payload(
    paths: Paths,
    config,
    notices: Iterable[LocalizedMessage],
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
):
    adapter = adapter or SubprocessSystemAdapter()
    rpfilter_report = collect_rp_filter_status(paths, config, adapter)
    conntrack_report = collect_conntrack_status(paths, config, adapter)
    return _json_result_payload(
        "config_show",
        ok=True,
        config=config.as_dict(),
        runtime={
            "external_binding": _json_binding_status_payload("external", config["EXTERNAL_IFS"]),
            "listen_binding": _json_binding_status_payload("listen", config["LISTEN_IPS"]),
            "rp_filter": _json_rpfilter_report_payload(rpfilter_report),
            "conntrack": _json_conntrack_report_payload(conntrack_report),
        },
        control_plane=_json_control_plane_payload(paths),
        notices=[_json_localized_message(message) for message in notices],
    )


def _json_doctor_payload(results, *, exit_code: int):
    fail_count = sum(1 for result in results if result.level == "fail")
    warn_count = sum(1 for result in results if result.level == "warn")
    pass_count = sum(1 for result in results if result.level == "pass")
    return _json_result_payload(
        "doctor_report",
        ok=exit_code == 0,
        summary={
            "text": summarize_doctor_results(results),
            "exit_code": exit_code,
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
        },
        results=[_json_doctor_result(result) for result in results],
    )


def _json_control_plane_payload(paths: Paths):
    status = inspect_control_plane_status(paths)
    return {
        "desired_revision": status.desired_revision,
        "applied_revision": status.applied_revision,
        "runtime_synced": status.runtime_synced,
        "pending_actions": list(status.pending_actions),
        "last_apply_mode": status.last_apply_mode,
        "last_apply_status": status.last_apply_status,
        "last_error": status.last_error,
        "manifest_present": status.manifest_present,
        "pending_txn_present": status.pending_txn_present,
        "state_mismatch": status.state_mismatch,
    }


def _json_reload_payload(result):
    return _json_result_payload(
        "reload",
        ok=True,
        requested_mode=result["requested_mode"],
        effective_mode=result["effective_mode"],
        desired_revision=result["desired_revision"],
        applied_revision=result["applied_revision"],
        runtime_synced=result["runtime_synced"],
        pending_actions=result["pending_actions"],
    )


def _json_history_status_payload(paths: Paths):
    return _json_result_payload(
        "history_status",
        ok=True,
        enabled=history_enabled(paths),
        current_revision=_json_control_plane_payload(paths)["desired_revision"],
        snapshot_count=len(list_snapshots(paths)),
        has_rollback_checkpoint=load_rollback_checkpoint(paths) is not None,
    )


def _json_history_show_payload(paths: Paths):
    snapshots = list_snapshots(paths)
    checkpoint = load_rollback_checkpoint(paths)
    return _json_result_payload(
        "history_show",
        ok=True,
        current_revision=_json_control_plane_payload(paths)["desired_revision"],
        snapshots=[
            {
                "index": index,
                "created_at_epoch": entry.created_at_epoch,
                "source": entry.source,
                "reason": entry.reason,
                "config_hash": entry.config_hash,
                "rules_hash": entry.rules_hash,
            }
            for index, entry in enumerate(snapshots, start=1)
        ],
        rollback_checkpoint=(
            {
                "created_at_epoch": checkpoint.created_at_epoch,
                "source": checkpoint.source,
                "reason": checkpoint.reason,
                "config_hash": checkpoint.config_hash,
                "rules_hash": checkpoint.rules_hash,
            }
            if checkpoint is not None
            else None
        ),
    )


def _json_rollback_payload(paths: Paths, *, selector: str, outcome, apply_message: str = ""):
    control_plane = _json_control_plane_payload(paths)
    payload = _json_result_payload(
        "rollback",
        ok=True,
        selector=selector,
        restored_from=outcome.restored_from,
        desired_revision=control_plane["desired_revision"],
        applied_revision=control_plane["applied_revision"],
        runtime_synced=control_plane["runtime_synced"],
        pending_actions=control_plane["pending_actions"],
    )
    if apply_message:
        payload["apply_message"] = apply_message
    return payload


def _json_config_update_payload(
    paths: Paths,
    result: ConfigUpdateResult,
    *,
    category="config_update",
    changed_keys,
    changed=None,
    artifacts=None,
    actions=None,
    adapter: Optional[SubprocessSystemAdapter] = None,
):
    adapter = adapter or SubprocessSystemAdapter()
    changed_keys = set(changed_keys)
    payload = _json_result_payload(
        category,
        ok=True,
        config=result.config.as_dict(),
        changed=bool(changed) if changed is not None else None,
        changed_keys=sorted(changed_keys),
        artifacts=artifacts or {},
        actions=actions or {},
        notices=[_json_localized_message(message) for message in result.notices],
    )
    if "RP_FILTER_MODE" in changed_keys:
        payload["rp_filter"] = _json_rpfilter_report_payload(
            collect_rp_filter_status(paths, result.config, adapter)
        )
    if changed_keys & {"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"}:
        payload["conntrack"] = _json_conntrack_report_payload(
            collect_conntrack_status(paths, result.config, adapter)
        )
    if payload["changed"] is None:
        payload.pop("changed")
    if not payload["artifacts"]:
        payload.pop("artifacts")
    if not payload["actions"]:
        payload.pop("actions")
    return payload


def _json_rules_update_payload(*, category="rules_update", config, rules, changed: bool, artifacts):
    return _json_result_payload(
        category,
        ok=True,
        changed=changed,
        config=config.as_dict() if hasattr(config, "as_dict") else config,
        rules=_json_rules_payload(rules),
        artifacts=artifacts,
    )


def _json_check_payload(
    *,
    category="config_check",
    config,
    would_change: bool,
    artifacts,
    actions=None,
    notices=(),
    warnings=(),
    changed_keys=(),
    rules=None,
):
    payload = _json_result_payload(
        category,
        ok=True,
        check=True,
        would_change=would_change,
        config=config.as_dict() if hasattr(config, "as_dict") else config,
        artifacts=artifacts,
        actions=actions or {},
        changed_keys=sorted(changed_keys),
        notices=[_json_localized_message(message) for message in notices],
        warnings=[_json_localized_message(message) for message in warnings],
    )
    if rules is not None:
        payload["rules"] = _json_rules_payload(rules)
    if not payload["warnings"]:
        payload.pop("warnings")
    return payload


def _config_key_label(raw_key: str) -> str:
    return raw_key.strip().lower().replace("-", "_")


def _resolve_config_update(
    paths: Paths,
    updates,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    assume_locked: bool = False,
):
    adapter = adapter or SubprocessSystemAdapter()
    base_config, base_notices = _load_management_config_or_default(paths, adapter=adapter, assume_locked=assume_locked)
    state = base_config.as_dict()
    changed_keys = set()
    notices = list(base_notices)
    for key, value in updates.items():
        canonical_key = _resolve_config_key(key)
        state[canonical_key] = value
        changed_keys.add(canonical_key)
    state = sync_toggle_shortcut_state(state)
    if changed_keys & {"EXTERNAL_IFS", "PRIMARY_EXTERNAL_IF", "LISTEN_IPS", "DEFAULT_SNAT_IP"}:
        state, runtime_notices = sync_runtime_binding_state(state, adapter)
        notices.extend(runtime_notices)
    config = normalize_mapping(state)
    return ConfigUpdateResult(config=config, notices=tuple(notices)), changed_keys


def _plan_config_update(
    paths: Paths,
    updates,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    assume_locked: bool = False,
):
    adapter = adapter or SubprocessSystemAdapter()
    result, changed_keys = _resolve_config_update(paths, updates, adapter=adapter, assume_locked=assume_locked)
    rules = _load_rules_or_empty(paths, assume_locked=assume_locked)
    transaction_artifacts = _preview_transaction_artifacts(
        paths,
        config_text=render_canonical_text(result.config),
        rules_text=render_rules_text(rules),
    )
    side_effect_artifacts, actions = _preview_config_side_effect_artifacts(
        paths,
        result.config,
        changed_keys=changed_keys,
    )
    actions["sysctl_system"] = actions["sysctl_system"] and adapter.command_exists("sysctl")
    artifacts = {**transaction_artifacts, **side_effect_artifacts}
    return result, changed_keys, rules, transaction_artifacts, side_effect_artifacts, actions, artifacts


def _plan_config_normalize(
    paths: Paths,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    assume_locked: bool = False,
):
    adapter = adapter or SubprocessSystemAdapter()
    config_text, _rules_text = read_desired_texts(paths, assume_locked=assume_locked)
    state = parse_management_config_text(config_text)
    config, notices = normalize_management_state(state, adapter)
    rules = _load_rules_or_empty(paths, assume_locked=assume_locked)
    transaction_artifacts = _preview_transaction_artifacts(
        paths,
        config_text=render_canonical_text(config),
        rules_text=render_rules_text(rules),
    )
    changed_keys = {
        key
        for key in set(state) | set(config.as_dict())
        if state.get(key, "") != config.as_dict().get(key, "")
    }
    return (
        ConfigUpdateResult(config=config, notices=tuple(notices)),
        changed_keys,
        rules,
        transaction_artifacts,
    )


def _auth_check_message(runtime: RuntimeI18N, plan) -> str:
    if plan.auth_mode == "label":
        if plan.changed:
            return _t(
                runtime,
                "auth.plan.check_switch_label",
                "Check mode: AUTH_MODE would switch to ct label (label value {value}).",
                value=plan.dnat_label,
            )
        return _t(
            runtime,
            "auth.plan.check_already_label",
            "Check mode: AUTH_MODE is already ct label (label value {value}); no changes would be needed.",
            value=plan.dnat_label,
        )
    if plan.changed:
        return _t(
            runtime,
            "auth.plan.check_switch_mark",
            "Check mode: AUTH_MODE would switch to ct mark (mark value {value}).",
            value=plan.dnat_mark,
        )
    return _t(
        runtime,
        "auth.plan.check_already_mark",
        "Check mode: AUTH_MODE is already ct mark (mark value {value}); no changes would be needed.",
        value=plan.dnat_mark,
    )


def _print_config_command_invalid(runtime: RuntimeI18N, exc: Exception) -> None:
    print(_t(runtime, "config.command.invalid", "loha.conf is invalid for this command."))
    print(_t(runtime, "config.command.detail", "Detail: {message}", message=_localized_exception_message(runtime, exc)))


def _print_config_get_invalid(runtime: RuntimeI18N, raw_key: str, exc: Exception) -> None:
    print(
        _t(
            runtime,
            "config.get.invalid_current",
            "The current value of {key_name} in loha.conf is invalid.",
            key_name=_config_key_label(raw_key),
        )
    )
    print(_t(runtime, "config.get.detail", "Detail: {message}", message=_localized_exception_message(runtime, exc)))


def _build_advanced_status_lines(
    paths: Paths,
    runtime: RuntimeI18N,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
):
    adapter = adapter or SubprocessSystemAdapter()
    lines = [
        _t(
            runtime,
            "history.menu.status",
            "Automatic snapshots: {status}",
            status=_history_status_text(paths, runtime),
        )
    ]
    try:
        config, _notices = _load_management_config_or_default(paths, adapter=adapter)
    except (ConfigSyntaxError, ConfigValidationError) as exc:
        lines.append(_t(runtime, "config.command.invalid", "loha.conf is invalid for this command."))
        lines.append(
            _t(
                runtime,
                "config.command.detail",
                "Detail: {message}",
                message=_localized_exception_message(runtime, exc),
            )
        )
        return tuple(lines)
    lines.extend(
        build_runtime_integration_lines(
            paths,
            config,
            adapter,
            translate=lambda key, default, **values: _t(runtime, key, default, **values),
            template=lambda key, default: _template(runtime, key, default),
        )
    )
    return tuple(lines)


def _print_menu_error(runtime: RuntimeI18N, exc: Exception) -> None:
    print(_format_plain_error(runtime, exc))


def _run_menu_action(runtime: RuntimeI18N, func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        print(_t(runtime, "common.cancelled", "Cancelled."))
        return None
    except Exception as exc:
        _print_menu_error(runtime, exc)
        return None


def cmd_version(_args) -> int:
    print(__version__)
    return 0


def cmd_list(args) -> int:
    paths = _paths_from_args(args)
    config = _load_or_default_config(paths)
    rules = _load_rules_or_empty(paths)
    if getattr(args, "json", False):
        _emit_json(_json_list_payload(config, rules))
        return 0
    runtime = _runtime_i18n(paths)
    print(_t(runtime, "list.title", "LOHA summary"))
    print(f"  {_t(runtime, 'list.external_interface', 'External interface')}: {config['PRIMARY_EXTERNAL_IF']}")
    print(
        f"  {_t(runtime, 'list.listen_ips', 'External IPv4 addresses used for exposure')}: {config['LISTEN_IPS']}"
    )
    print(f"  {_t(runtime, 'list.lan_nets', 'Internal networks')}: {config['LAN_NETS']}")
    print(_t(runtime, "list.aliases", "Aliases"))
    if rules.aliases:
        for alias in rules.aliases:
            print(f"  {alias.name} -> {alias.ip}")
    else:
        print(f"  {_t(runtime, 'list.none', '(none)')}")
    print(_t(runtime, "list.ports", "Ports"))
    if rules.ports:
        for record in rules.ports:
            print(
                f"  {record.proto} {record.listen.canonical} -> {record.destination}:{record.destination_port.canonical}"
            )
    else:
        print(f"  {_t(runtime, 'list.none', '(none)')}")
    return 0


def cmd_alias_add(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_rules_mutation_command(
        paths,
        runtime,
        reason="alias-add",
        mutate=lambda current: add_alias(current, args.name, args.ip),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_alias_rm(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_rules_mutation_command(
        paths,
        runtime,
        reason="alias-rm",
        mutate=lambda current: remove_alias(current, args.name),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_port_add(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    adapter = SubprocessSystemAdapter()

    def _mutation(current):
        if not args.force:
            conflicts = _detect_listener_conflicts(adapter, args.proto, args.orig_port_spec)
            if conflicts is None:
                raise RulesValidationError("listener scan unavailable; use --force to override")
            if conflicts:
                raise RulesValidationError(
                    f"listener conflict detected on {args.proto.lower()} {','.join(str(port) for port in conflicts)}; use --force to override"
                )
        return add_port_rule(
            current,
            args.proto,
            args.orig_port_spec,
            args.dest_addr,
            args.dest_port_spec,
        )

    return _run_standard_rules_mutation_command(
        paths,
        runtime,
        reason="port-add",
        mutate=_mutation,
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_port_rm(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_rules_mutation_command(
        paths,
        runtime,
        reason="port-rm",
        mutate=lambda current: remove_port_rule(current, args.proto, args.orig_port_spec),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_port_prune(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_rules_mutation_command(
        paths,
        runtime,
        reason="port-prune",
        mutate=lambda current: prune_port_rules(
            current,
            destination=args.dest,
            proto=args.proto,
            range_spec=args.range,
        ),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_reload(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    result = _service_reload_result(paths, full=args.full, runtime=runtime)
    if getattr(args, "json", False):
        _emit_json(_json_reload_payload(result))
        return 0
    print(result["message"])
    return 0


def cmd_doctor(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    results = run_doctor(paths=paths)
    exit_code = 0
    for result in results:
        if result.level == "fail":
            exit_code = 1
    if getattr(args, "json", False):
        _emit_json(_json_doctor_payload(results, exit_code=exit_code))
        return exit_code
    for result in results:
        for line in format_doctor_result_lines(result, translate=lambda key, default: _template(runtime, key, default)):
            print(line)
    print(summarize_doctor_results(results, translate=lambda key, default: _template(runtime, key, default)))
    return exit_code


def cmd_config_show(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    adapter = SubprocessSystemAdapter()
    try:
        config, notices = _load_management_config_or_default(paths, adapter=adapter)
    except (ConfigSyntaxError, ConfigValidationError) as exc:
        if getattr(args, "json", False):
            exit_code = _exit_code_for_exception(exc)
            _emit_json(_json_error_payload(str(exc), error_type=exc.__class__.__name__, exit_code=exit_code))
            return exit_code
        _print_config_command_invalid(runtime, exc)
        return _exit_code_for_exception(exc)
    if getattr(args, "json", False):
        _emit_json(_json_config_show_payload(paths, config, notices, adapter=adapter))
        return 0
    print(_t(runtime, "config.show.title", "Current Core Configuration"))
    print_summary(config, i18n=runtime)
    sections = build_config_show_sections(
        paths,
        config,
        adapter,
        translate=lambda key, default, **values: _t(runtime, key, default, **values),
        template=lambda key, default: _template(runtime, key, default),
    )
    for title, lines in sections:
        print(title)
        for line in lines:
            print(f"  {line}")
        print("")
    for notice in _render_messages(runtime, notices):
        print(notice)
    return 0


def cmd_config_get(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    key = _resolve_config_key(args.key)
    try:
        config, _notices = _load_management_config_or_default(paths)
    except (ConfigSyntaxError, ConfigValidationError) as exc:
        _print_config_get_invalid(runtime, args.key, exc)
        return _exit_code_for_exception(exc)
    print(config[key])
    return 0


def _write_config_only(paths: Paths, config, reason: str) -> None:
    with control_file_lock(paths):
        if paths.loha_conf.exists():
            _config_text, rules_text = read_desired_texts(paths, assume_locked=True)
        else:
            rules_text = render_rules_text(load_rules(paths.rules_conf))
        commit_desired_state(
            paths,
            config_text=render_canonical_text(config),
            rules_text=rules_text,
            source="cli",
            reason=reason,
            assume_locked=True,
        )


def _write_plain_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(text, encoding="utf-8")
    temp_path.replace(path)


def _prompt_text_with_default(
    runtime: RuntimeI18N,
    key: str,
    default_text: str,
    *,
    default_value: str = "",
) -> str:
    prompt = _t(runtime, key, default_text)
    if default_value:
        prompt = f"{prompt} [{default_value}]"
    raw = input(prompt + ": ").strip()
    return raw or default_value


def _prompt_validated_text(
    runtime: RuntimeI18N,
    key: str,
    default_text: str,
    *,
    default_value: str = "",
    validator: Optional[Callable[[str], str]] = None,
    input_func: Optional[Callable[[str], str]] = None,
    allow_empty: bool = False,
) -> str:
    input_func = input_func or input
    while True:
        prompt = _t(runtime, key, default_text)
        if default_value:
            prompt = f"{prompt} [{default_value}]"
        raw = input_func(prompt + ": ").strip() or default_value
        if not raw:
            if allow_empty:
                return ""
            print(_t(runtime, "wizard.error.required_value", "A value is required."))
            continue
        if validator is None:
            return raw
        try:
            return validator(raw)
        except (ConfigValidationError, RulesValidationError) as exc:
            print(_format_plain_error(runtime, exc))


def _prompt_positive_int(
    runtime: RuntimeI18N,
    key: str,
    default_text: str,
    *,
    validation_key: str = "VALUE",
    default_value: str = "",
    minimum: int = 1,
    maximum: Optional[int] = None,
) -> int:
    normalized = _prompt_validated_text(
        runtime,
        key,
        default_text,
        default_value=default_value,
        validator=lambda raw: normalize_integer_value(
            raw,
            validation_key,
            minimum=minimum,
            maximum=maximum,
        ),
    )
    return int(normalized, 10)


def _prompt_yes_no(
    runtime: RuntimeI18N,
    key: str,
    default_text: str,
    *,
    default: bool,
    input_func: Optional[Callable[[str], str]] = None,
    **values,
) -> bool:
    input_func = input_func or input
    default_hint = "Y/n" if default else "y/N"
    while True:
        raw = input_func(_t(runtime, key, default_text, **values) + f": ").strip()
        try:
            return parse_yes_no(raw, default=default)
        except InputValidationError:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _prompt_submenu_choice(runtime: RuntimeI18N) -> str:
    return input(
        _t(
            runtime,
            "menu.prompt.enter_back",
            "Enter a number to choose, or press Enter to go back",
        )
        + ": "
    ).strip()


def _normalize_iface_csv_text(value: str) -> str:
    return join_csv(parse_csv(value, kind="iface"))


def _normalize_cidr_csv_text(value: str) -> str:
    return join_csv(parse_csv(value, kind="cidr"))


def _toggle_status_text(runtime: RuntimeI18N, value: str) -> str:
    normalized = normalize_toggle(value, allow_auto=False)
    return _t(runtime, f"common.state.{normalized}", normalized.title())


def _counter_mode_text(runtime: RuntimeI18N, value: str) -> str:
    normalized = normalize_counter_mode(value)
    return _t(
        runtime,
        f"wizard.steps.counter_mode.options.{normalized}",
        {
            "off": "Off",
            "minimal": "Minimal (important rules only)",
            "all": "All rules",
        }[normalized],
    )


def _change_language_menu_label(runtime: RuntimeI18N) -> str:
    english = "Change Language"
    localized = _t(runtime, "menu.main.change_language", english)
    if runtime.locale.split("_", 1)[0] == "en" or localized == english:
        return english
    return f"{localized} / {english}"


def _menu_change_language(paths: Paths, runtime: RuntimeI18N) -> None:
    locale = select_locale_interactive(
        runtime,
        recommended_locale=runtime.locale,
        title_key="menu.language.title",
        title_default="LOHA Language",
        description_key="menu.language.description",
        description_default="Choose the LOHA interface language.",
        prompt_key="menu.language.prompt",
        prompt_default="Enter number or locale code (press Enter for {recommended})",
    )
    if locale == runtime.locale:
        return
    _run_menu_action(
        runtime,
        cmd_config_set,
        _menu_args(paths, key="LOCALE", value=locale),
    )


def _validate_alias_name_text(value: str) -> str:
    return validate_alias_name(value.strip().upper())


def _validate_port_spec_text(value: str) -> str:
    return parse_port_spec(value, allow_plus=True).canonical


def _validate_destination_text(value: str) -> str:
    candidate = value.strip()
    alias_candidate = candidate.upper()
    if alias_candidate.startswith(("HOST_", "VM_")):
        return validate_alias_name(alias_candidate)
    return validate_ipv4(candidate)


def _collect_rpfilter_report(paths: Paths, adapter: Optional[SubprocessSystemAdapter] = None):
    adapter = adapter or SubprocessSystemAdapter()
    return collect_rp_filter_status(paths, _load_or_default_config(paths), adapter)


def _collect_conntrack_report(paths: Paths, adapter: Optional[SubprocessSystemAdapter] = None):
    adapter = adapter or SubprocessSystemAdapter()
    return collect_conntrack_status(paths, _load_or_default_config(paths), adapter)


def _print_rpfilter_report(paths: Paths, config, runtime: RuntimeI18N, *, adapter: Optional[SubprocessSystemAdapter] = None) -> None:
    adapter = adapter or SubprocessSystemAdapter()
    report = collect_rp_filter_status(paths, config, adapter)
    for line in format_rp_filter_status_lines(report, translate=lambda key, default: _template(runtime, key, default)):
        print(line)


def _print_conntrack_report(paths: Paths, config, runtime: RuntimeI18N, *, adapter: Optional[SubprocessSystemAdapter] = None) -> None:
    adapter = adapter or SubprocessSystemAdapter()
    report = collect_conntrack_status(paths, config, adapter)
    for line in format_conntrack_status_lines(report, translate=lambda key, default: _template(runtime, key, default)):
        print(line)


def _print_config_update_followup(
    paths: Paths,
    config,
    runtime: RuntimeI18N,
    *,
    changed_keys,
    adapter: Optional[SubprocessSystemAdapter] = None,
) -> None:
    changed_keys = set(changed_keys)
    if "ENABLE_CONFIG_HISTORY" in changed_keys:
        print(_t(runtime, "history.command.status", "Automatic snapshots: {status}", status=_history_status_text(paths, runtime)))
    if "RP_FILTER_MODE" in changed_keys:
        _print_rpfilter_report(paths, config, runtime, adapter=adapter)
    if changed_keys & {"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"}:
        _print_conntrack_report(paths, config, runtime, adapter=adapter)


def _detect_listener_conflicts(adapter: SubprocessSystemAdapter, proto: str, listen_spec: str):
    listeners = adapter.scan_listeners()
    if listeners is None:
        return None
    listen = parse_port_spec(listen_spec, allow_plus=True)
    conflicts = []
    for port in range(listen.start, listen.end + 1):
        if (proto.lower(), port) in listeners:
            conflicts.append(port)
    return tuple(conflicts)


def _rpfilter_selection_is_applied(config, report, selected_mode: str) -> bool:
    return selected_mode == config["RP_FILTER_MODE"] and report.runtime_state in {"system", "match"}


def _conntrack_selection_is_applied(
    config,
    report,
    *,
    mode: str,
    target_max: str = "",
    peak: str = "",
    memory_percent: str = "",
) -> bool:
    if config["CONNTRACK_MODE"] != mode:
        return False
    if mode == "auto":
        if config["CONNTRACK_PEAK"] != peak or config["CONNTRACK_MEMORY_PERCENT"] != memory_percent:
            return False
    elif mode == "custom":
        if config["CONNTRACK_TARGET_MAX"] != target_max or config["CONNTRACK_MEMORY_PERCENT"] != memory_percent:
            return False
    return report.runtime_state in {"system", "match"}


def _resolve_editor_command(editor_raw: str = "") -> str:
    candidate = (editor_raw or os.environ.get("EDITOR", "") or "nano").strip()
    if not candidate:
        candidate = "nano"
    if " " in candidate:
        raise ApplyError(f"invalid editor command: {candidate}")
    if "/" in candidate:
        if os.access(candidate, os.X_OK):
            return candidate
    else:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise ApplyError(f"editor not found: {candidate}")


def _validate_rules_after_edit(
    paths: Paths,
    runtime: Optional[RuntimeI18N] = None,
    adapter: Optional[SubprocessSystemAdapter] = None,
    *,
    rules_text: Optional[str] = None,
) -> str:
    adapter = adapter or SubprocessSystemAdapter()
    service = LoaderService(paths=paths, adapter=adapter)
    if rules_text is None:
        return service.apply(mode="full", check_only=True, runtime=runtime)
    config_text, _rules_text = read_desired_texts(paths)
    staged_snapshot = build_desired_snapshot_from_texts(
        config_text,
        rules_text,
    )
    return service.apply(mode="full", check_only=True, runtime=runtime, snapshot=staged_snapshot)


def _edit_rules_conf(
    paths: Paths,
    runtime: RuntimeI18N,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    run_editor=subprocess.run,
    ) -> int:
    adapter = adapter or SubprocessSystemAdapter()
    try:
        editor = _resolve_editor_command()
    except ApplyError as exc:
        message = str(exc)
        if message.startswith("invalid editor command:"):
            raise ApplyError(_t(runtime, "menu.edit.editor_invalid", "EDITOR must resolve to a single executable path or name."))
        if message.startswith("editor not found:"):
            editor_name = message.split(":", 1)[1].strip()
            raise ApplyError(_t(runtime, "menu.edit.editor_missing", "Editor not found: {editor}", editor=editor_name))
        raise
    current_config_text = ""
    current_rules_text = _read_path_text(paths.rules_conf)
    if paths.loha_conf.exists():
        current_config_text, current_rules_text = read_desired_texts(paths)
    stage_dir = paths.txn_dir / f"raw-edit-{time.time_ns()}"
    staged_rules = stage_dir / "rules.conf"
    try:
        stage_dir.mkdir(parents=True, exist_ok=True)
        staged_rules.write_text(current_rules_text, encoding="utf-8")
        launched = run_editor([editor, str(staged_rules)], check=False)
        if getattr(launched, "returncode", 0) != 0:
            raise ApplyError(
                _t(
                    runtime,
                    "menu.edit.launch_fail",
                    "Editor exited with status {code}: {editor}",
                    code=str(getattr(launched, "returncode", 1)),
                    editor=editor,
                )
            )
        edited_rules_text = staged_rules.read_text(encoding="utf-8")
        print(_t(runtime, "menu.edit.validating", "Validating edited rules.conf..."))
        try:
            validation_message = _validate_rules_after_edit(paths, runtime, adapter, rules_text=edited_rules_text)
        except Exception:
            print(_t(runtime, "menu.edit.fail", "rules.conf validation failed."))
            raise
        if validation_message:
            print(validation_message)
        if edited_rules_text != current_rules_text:
            with control_file_lock(paths):
                live_config_text = current_config_text
                if paths.loha_conf.exists():
                    live_config_text, _live_rules_text = read_desired_texts(paths, assume_locked=True)
                commit_desired_state(
                    paths,
                    config_text=live_config_text if live_config_text else render_canonical_text(recommended_config()),
                    rules_text=edited_rules_text,
                    source="cli",
                    reason="raw-rules-edit",
                    assume_locked=True,
                )
        print(_t(runtime, "menu.edit.pass", "rules.conf validation passed."))
        return 0
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)


def _confirm_rules_conf_edit(
    runtime: RuntimeI18N,
    *,
    input_func: Optional[Callable[[str], str]] = None,
    output_func: Callable[[str], None] = print,
) -> bool:
    input_func = input_func or input
    output_func(
        _t(
            runtime,
            "menu.edit.warning_intro",
            "This opens the raw rules.conf editor and is intended for advanced users.",
        )
    )
    output_func(
        _t(
            runtime,
            "menu.edit.warning_recommendation",
            "For routine changes, prefer the alias and port menus.",
        )
    )
    output_func(
        _t(
            runtime,
            "menu.edit.warning_validation",
            "LOHA will validate rules.conf after the editor exits.",
        )
    )
    while True:
        raw = input_func(
            _t(
                runtime,
                "menu.edit.continue_prompt",
                "Continue editing rules.conf? [y/N]",
            )
            + ": "
        ).strip()
        try:
            return parse_yes_no(raw, default=False)
        except InputValidationError:
            output_func(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _prompt_label_value_interactive(
    paths: Paths,
    runtime: RuntimeI18N,
    current,
    adapter: Optional[SubprocessSystemAdapter] = None,
) -> str:
    adapter = adapter or SubprocessSystemAdapter()
    current_label = (current.get("DNAT_LABEL", "") or "").strip()
    default_label = plan_auth_mode_switch(current.as_dict(), "label", paths=paths, adapter=adapter).dnat_label
    while True:
        raw = _prompt_text_with_default(
            runtime,
            "auth.label_prompt",
            "Enter ct label value",
            default_value=default_label,
        )
        try:
            label_value = normalize_label_candidate(raw)
        except Exception:
            print(_t(runtime, "auth.label_range_error", "The ct label value must be an integer in [1, 127]."))
            continue
        conflicts = used_auth_labels(
            paths,
            adapter=adapter,
            ignored_labels=(current_label,) if current["AUTH_MODE"] == "label" else (),
        )
        if label_value in conflicts:
            print(
                _t(
                    runtime,
                    "auth.label_conflict",
                    "Label value {value} conflicts with existing nft rules. Choose another value.",
                    value=label_value,
                )
            )
            continue
        return label_value


def _prompt_mark_choice_interactive(
    paths: Paths,
    runtime: RuntimeI18N,
    current,
    adapter: Optional[SubprocessSystemAdapter] = None,
) -> str:
    adapter = adapter or SubprocessSystemAdapter()
    while True:
        survey = _watch_mark_detection_interactive(
            paths,
            runtime,
            current,
            adapter=adapter,
        )
        if survey.conflicting_marks:
            _print_mark_conflict_details(runtime, survey)
        if survey.suggested_mark in survey.conflicting_marks:
            print(
                _t(
                    runtime,
                    "auth.mark_conflict_detected",
                    "LOHA detected a ct mark conflict when using {mark}. Choose another candidate to continue.",
                    mark=survey.suggested_mark,
                )
            )
        else:
            print(
                _t(
                    runtime,
                    "auth.mark_watch_hint",
                    "Dynamic detection stopped. Current suggested ct mark value is {mark}. Press Enter to apply it, or choose another action.",
                    mark=survey.suggested_mark,
                )
            )
        if survey.available_marks:
            print(_t(runtime, "auth.mark_pick_title", "Choose another ct mark candidate:"))
            for index, mark in enumerate(survey.available_marks, start=1):
                print(f" {index}. {_format_mark_bit(mark)} ({mark})")
        else:
            print(_t(runtime, "auth.mark_all_conflict", "All MARK candidates are detected as conflicting."))
        if survey.suggested_mark in survey.conflicting_marks:
            print(f" c. {_t(runtime, 'auth.mark_action_continue', 'Continue with the current suggested value anyway')}")
        print(f" l. {_t(runtime, 'auth.mark_action_label', 'Switch to ct label instead')}")
        print(f" r. {_t(runtime, 'auth.mark_action_refresh', 'Run dynamic detection again')}")
        action = input(
            _t(
                runtime,
                "auth.mark_action_prompt",
                "Press Enter to apply current choice, or choose number / c / l / r",
            )
            + ": "
        ).strip().lower()
        if action == "":
            return survey.suggested_mark
        if action == "c":
            print(_t(runtime, "auth.mark_ignore_continue", "MARK conflict ignored as requested. Continue switching."))
            return survey.suggested_mark
        if action == "l":
            print(_t(runtime, "auth.mark_switch_label", "Switched to ct label mode."))
            return "__label__"
        if action == "r":
            continue
        if action.isdigit():
            index = int(action, 10) - 1
            if 0 <= index < len(survey.available_marks):
                return survey.available_marks[index]
        print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _wait_for_enter_to_stop(timeout_seconds: float) -> bool:
    if not sys.stdin or not hasattr(sys.stdin, "fileno"):
        return True
    try:
        ready, _write_ready, _errors = select.select([sys.stdin], [], [], timeout_seconds)
    except (AttributeError, OSError, ValueError):
        return True
    if not ready:
        return False
    try:
        sys.stdin.readline()
    except Exception:
        pass
    return True


def _watch_mark_detection_interactive(
    paths: Paths,
    runtime: RuntimeI18N,
    current,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    wait_for_stop: Optional[Callable[[float], bool]] = None,
):
    adapter = adapter or SubprocessSystemAdapter()
    wait_for_stop = wait_for_stop or _wait_for_enter_to_stop
    survey = survey_auth_mark_candidates(current.as_dict(), paths=paths, adapter=adapter)
    if not survey.runtime_scan_available:
        print(
            _t(
                runtime,
                "auth.mark_runtime_unavailable",
                "Unable to read conntrack marks in current environment. Dynamic detection unavailable.",
            )
        )
        return survey
    print(
        _t(
            runtime,
            "auth.mark_detection_running",
            "Dynamic ct mark conflict detection is running. Press Enter to stop detection and review the current result.",
        )
    )
    last_signature = None
    while True:
        survey = survey_auth_mark_candidates(current.as_dict(), paths=paths, adapter=adapter)
        signature = (
            survey.suggested_mark,
            survey.available_marks,
            survey.conflicting_marks,
            survey.runtime_scan_available,
            getattr(survey, "static_conflicting_marks", ()),
            getattr(survey, "runtime_conflicting_marks", ()),
            getattr(survey, "static_conflict_samples", ()),
            getattr(survey, "runtime_conflict_samples", ()),
        )
        if signature != last_signature:
            print(
                _t(
                    runtime,
                    "auth.mark_detection_current",
                    "Current suggested ct mark value: {mark}",
                    mark=survey.suggested_mark,
                )
            )
            if survey.conflicting_marks:
                _print_mark_conflict_details(runtime, survey)
            else:
                print(
                    _t(
                        runtime,
                        "auth.mark_no_conflict_detected",
                        "No conflicting ct mark bits are currently detected.",
                    )
                )
            last_signature = signature
        if wait_for_stop(1.0):
            print(_t(runtime, "auth.mark_detection_stopped", "Dynamic ct mark conflict detection stopped."))
            return survey


def _interactive_auth_switch(paths: Paths, runtime: RuntimeI18N, adapter: Optional[SubprocessSystemAdapter] = None) -> int:
    adapter = adapter or SubprocessSystemAdapter()
    while True:
        print(_t(runtime, "menu.advanced.auth_mode", "Switch Authorization Marking (mark / label)"))
        current = _load_or_default_config(paths)
        if current["AUTH_MODE"] == "label":
            print(
                _t(
                    runtime,
                    "auth.current.label",
                    "Current authorization mode: ct label (label value {value})",
                    value=current["DNAT_LABEL"],
                )
            )
        else:
            print(
                _t(
                    runtime,
                    "auth.current.mark",
                    "Current authorization mode: ct mark (mark value {value})",
                    value=current["DNAT_MARK"],
                )
            )
        print(_t(runtime, "auth.intro", "Choose how LOHA marks authorized connections. `ct mark` is the best default for most deployments."))
        print(
            f" 1. {_t(runtime, 'auth.option.mark', 'ct mark (recommended): performance-first, with static+dynamic conflict avoidance.')}"
        )
        print(
            f" 2. {_t(runtime, 'auth.option.label', 'ct label: easier isolation from existing mark rules, currently static conflict check only.')}"
        )
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        choice = _prompt_submenu_choice(runtime)
        if choice in {"", "0"}:
            return 0
        if choice not in {"1", "2"}:
            print(_t(runtime, "auth.invalid_selection", "Invalid option. Please enter 1 or 2."))
            continue
        requested_mode = "mark" if choice == "1" else "label"
        break
    if requested_mode == "mark":
        selected_mark = _prompt_mark_choice_interactive(paths, runtime, current, adapter=adapter)
        if selected_mark == "__label__":
            requested_mode = "label"
        else:
            plan = plan_selected_auth_mode_switch(
                current.as_dict(),
                "mark",
                selected_mark=selected_mark,
                paths=paths,
                adapter=adapter,
            )
    if requested_mode == "label":
        selected_label = _prompt_label_value_interactive(paths, runtime, current, adapter=adapter)
        plan = plan_selected_auth_mode_switch(
            current.as_dict(),
            "label",
            selected_label=selected_label,
            paths=paths,
            adapter=adapter,
        )
    for warning in _render_messages(runtime, plan.warnings):
        print(warning)
    if plan.changed:
        _apply_config_update(
            paths,
            {
                "AUTH_MODE": plan.auth_mode,
                "DNAT_MARK": plan.dnat_mark,
                "DNAT_LABEL": plan.dnat_label,
            },
            "config-set-auth_mode",
            adapter=adapter,
        )
    print(_render_message(runtime, plan.message))
    if plan.reload_hint:
        if _prompt_yes_no(
            runtime,
            "auth.reload_prompt",
            "Apply rules now (reload --full)? [Y/n]",
            default=True,
        ):
            print(_service_reload(paths, full=True, adapter=adapter, runtime=runtime))
    return 0


def _remove_if_exists(path: Path) -> None:
    if path.exists():
        path.unlink()


def _sync_sysctl(adapter: SubprocessSystemAdapter) -> None:
    if not adapter.command_exists("sysctl"):
        return "Missing 'sysctl' command"
    result = adapter.run(["sysctl", "--system"], check=False)
    if result.returncode != 0:
        return result.stderr.strip() or result.stdout.strip() or "sysctl --system failed"
    return ""


def _apply_config_side_effects(
    paths: Paths,
    config,
    *,
    changed_keys,
    adapter: SubprocessSystemAdapter,
    desired_revision: int,
    assume_locked: bool = False,
) -> str:
    should_sync_sysctl = False
    if "RP_FILTER_MODE" in changed_keys:
        apply_rp_filter_files(
            paths,
            config,
            write_text=_write_plain_text,
        )
        should_sync_sysctl = True
    if changed_keys & {"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"}:
        apply_conntrack_files(
            paths,
            config,
            write_text=_write_plain_text,
            remove_path=_remove_if_exists,
        )
        should_sync_sysctl = True
    sync_error = ""
    if should_sync_sysctl:
        sync_error = _sync_sysctl(adapter)
        had_sysctl_pending = "sysctl_sync" in read_runtime_state(paths).pending_actions
        update_runtime_state(
            paths,
            lambda current: RuntimeStateSnapshot(
                desired_revision=desired_revision or current.desired_revision,
                applied_revision=current.applied_revision,
                last_apply_mode=current.last_apply_mode,
                last_apply_status=current.last_apply_status,
                last_error=sync_error if sync_error else ("" if had_sysctl_pending else current.last_error),
                pending_actions=tuple(
                    action
                    for action in (
                        [item for item in current.pending_actions if item != "sysctl_sync"]
                        + (["sysctl_sync"] if sync_error else [])
                    )
                    if action
                ),
                updated_at_epoch=int(time.time()),
            ),
            assume_locked=assume_locked,
        )
    return sync_error


def _apply_config_update(
    paths: Paths,
    updates,
    reason: str,
    *,
    adapter: Optional[SubprocessSystemAdapter] = None,
    include_plan: bool = False,
):
    adapter = adapter or SubprocessSystemAdapter()
    with control_file_lock(paths):
        result, changed_keys, _rules, transaction_artifacts, side_effect_artifacts, _actions, _artifacts = _plan_config_update(
            paths,
            updates,
            adapter=adapter,
            assume_locked=True,
        )
        desired_revision = inspect_control_plane_status(paths, assume_locked=True).desired_revision
        if _artifacts_would_change(transaction_artifacts):
            desired_revision = commit_desired_state(
                paths,
                config_text=render_canonical_text(result.config),
                rules_text=render_rules_text(_rules),
                source="cli",
                reason=reason,
                assume_locked=True,
            ).revision
        if _artifacts_would_change(side_effect_artifacts):
            _apply_config_side_effects(
                paths,
                result.config,
                changed_keys=changed_keys,
                adapter=adapter,
                desired_revision=desired_revision,
                assume_locked=True,
            )
    if include_plan:
        return result, changed_keys, transaction_artifacts, side_effect_artifacts, _actions, _artifacts
    return result


def _run_standard_config_update_command(
    paths: Paths,
    runtime: RuntimeI18N,
    *,
    updates,
    reason: str,
    check_category: str,
    update_category: str,
    followup_changed_keys,
    adapter: Optional[SubprocessSystemAdapter] = None,
    json_enabled: bool = False,
    check_only: bool = False,
) -> int:
    adapter = adapter or SubprocessSystemAdapter()
    if check_only:
        result, changed_keys, rules, _transaction_artifacts, _side_effect_artifacts, actions, artifacts = _plan_config_update(
            paths,
            updates,
            adapter=adapter,
        )
        changed = _artifacts_would_change(artifacts)
        if json_enabled:
            _emit_json(
                _json_check_payload(
                    category=check_category,
                    config=result.config,
                    would_change=changed,
                    artifacts=artifacts,
                    actions=actions,
                    notices=result.notices,
                    changed_keys=changed_keys,
                    rules=rules,
                )
            )
            return 0
        for notice in _render_messages(runtime, result.notices):
            print(notice)
        _print_check_result(runtime, would_change=changed)
        return 0

    result, changed_keys, _transaction_artifacts, _side_effect_artifacts, actions, artifacts = _apply_config_update(
        paths,
        updates,
        reason,
        adapter=adapter,
        include_plan=True,
    )
    changed = _artifacts_would_change(artifacts)
    if json_enabled:
        _emit_json(
            _json_config_update_payload(
                paths,
                result,
                category=update_category,
                changed_keys=changed_keys,
                changed=changed,
                artifacts=artifacts,
                actions=actions,
                adapter=adapter,
            )
        )
        return 0
    _print_config_update_followup(paths, result.config, runtime, changed_keys=followup_changed_keys, adapter=adapter)
    return 0


def _history_status_text(paths: Paths, runtime: Optional[RuntimeI18N] = None) -> str:
    status = "enabled" if history_enabled(paths) else "disabled"
    if runtime is None:
        return status
    return _t(runtime, f"history.status.{status}", status)


def _print_history_listing(paths: Paths, runtime: Optional[RuntimeI18N] = None) -> None:
    snapshots = list_snapshots(paths)
    checkpoint = load_rollback_checkpoint(paths)
    if runtime is None:
        runtime = _runtime_i18n(paths)
    print(_t(runtime, "history.list.title", "Configuration History"))
    if not snapshots and checkpoint is None:
        print(f"  {_t(runtime, 'history.list.empty', 'No snapshots.')}")
        return
    for index, entry in enumerate(snapshots, start=1):
        print(f"{index}. {entry.path.name}")
        print(f"  {_t(runtime, 'history.list.source', 'Source')}: {entry.source}")
        print(f"  {_t(runtime, 'history.list.reason', 'Reason')}: {entry.reason}")
        print(f"  {_t(runtime, 'history.list.config_hash', 'Config hash')}: {entry.config_hash}")
        print(f"  {_t(runtime, 'history.list.rules_hash', 'Rules hash')}: {entry.rules_hash}")
    if checkpoint is not None:
        if snapshots:
            print()
        print(_t(runtime, "history.list.checkpoint_title", "Rollback checkpoint"))
        print(f"  {_t(runtime, 'history.list.checkpoint_note', 'Not counted in regular history limit.')}")
        print(f"  {_t(runtime, 'history.list.source', 'Source')}: {checkpoint.source}")
        print(f"  {_t(runtime, 'history.list.reason', 'Reason')}: {checkpoint.reason}")
        print(f"  {_t(runtime, 'history.list.config_hash', 'Config hash')}: {checkpoint.config_hash}")
        print(f"  {_t(runtime, 'history.list.rules_hash', 'Rules hash')}: {checkpoint.rules_hash}")


def _print_rollback_rescue(runtime: Optional[RuntimeI18N], exc: HistoryError) -> None:
    if exc.rescue_dir is None:
        return
    message = (
        _t(runtime, "history.rollback.rescue_files", "Rollback rescue files were kept in: {path}", path=str(exc.rescue_dir))
        if runtime is not None
        else f"Rollback rescue files were kept in: {exc.rescue_dir}"
    )
    print(message)
    if runtime is not None:
        print(
            _t(
                runtime,
                "history.rollback.rescue_hint",
                "Review or copy the full rescue paths from the terminal output above if manual recovery is needed.",
            )
        )


def _run_rollback(
    paths: Paths,
    selector: str,
    *,
    apply_after: bool,
    runtime: Optional[RuntimeI18N] = None,
    json_enabled: bool = False,
) -> int:
    runtime = runtime or _runtime_i18n(paths)
    try:
        outcome = rollback_snapshot(
            paths,
            selector,
            apply_callback=(lambda: _service_reload(paths, full=False, runtime=runtime)) if apply_after else None,
        )
    except HistoryError as exc:
        if json_enabled:
            raise
        print(str(exc))
        _print_rollback_rescue(runtime, exc)
        return _exit_code_for_exception(exc)
    if json_enabled:
        _emit_json(_json_rollback_payload(paths, selector=selector, outcome=outcome, apply_message=outcome.apply_message))
        return 0
    if outcome.restored_from == "rollback_checkpoint":
        print(_t(runtime, "history.rollback.checkpoint_restored", "The rollback checkpoint has been restored."))
    elif selector == "latest":
        print(_t(runtime, "history.rollback.latest_restored", "The latest configuration snapshot has been restored."))
    else:
        print(
            _t(
                runtime,
                "history.rollback.index_restored",
                "Configuration history entry {selector} has been restored.",
                selector=selector,
            )
        )
    if apply_after and outcome.apply_message:
        print(outcome.apply_message)
    else:
        print(
            _t(
                runtime,
                "history.rollback.reload_hint",
                "Run `loha reload` to apply the restored configuration.",
            )
        )
    if outcome.rescue_dir is not None:
        print(
            _t(
                runtime,
                "history.rollback.rescue_files",
                "Rollback rescue files were kept in: {path}",
                path=str(outcome.rescue_dir),
            )
        )
    return 0


def cmd_config_set(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    key = _resolve_config_key(args.key)
    adapter = SubprocessSystemAdapter()
    json_enabled = getattr(args, "json", False)
    try:
        if key == "AUTH_MODE":
            current, _notices = _load_management_config_or_default(paths, adapter=adapter)
            plan = plan_auth_mode_switch(current.as_dict(), args.value, paths=paths, adapter=adapter)
            if getattr(args, "check", False):
                result, changed_keys, rules, transaction_artifacts, side_effect_artifacts, actions, artifacts = _plan_config_update(
                    paths,
                    {
                        "AUTH_MODE": plan.auth_mode,
                        "DNAT_MARK": plan.dnat_mark,
                        "DNAT_LABEL": plan.dnat_label,
                    },
                    adapter=adapter,
                )
                changed = _artifacts_would_change(artifacts)
                if json_enabled:
                    payload = _json_check_payload(
                        category="config_check",
                        config=result.config,
                        would_change=changed,
                        artifacts=artifacts,
                        actions=actions,
                        notices=result.notices,
                        warnings=plan.warnings,
                        changed_keys=changed_keys,
                        rules=rules,
                    )
                    payload["message"] = _json_localized_message(plan.message)
                    if plan.reload_hint is not None:
                        payload["reload_hint"] = _json_localized_message(plan.reload_hint)
                    _emit_json(payload)
                    return 0
                for warning in _render_messages(runtime, plan.warnings):
                    print(warning)
                print(_auth_check_message(runtime, plan))
                _print_check_result(
                    runtime,
                    would_change=changed,
                )
                return 0
            if plan.changed:
                result, changed_keys, transaction_artifacts, side_effect_artifacts, actions, artifacts = _apply_config_update(
                    paths,
                    {
                        "AUTH_MODE": plan.auth_mode,
                        "DNAT_MARK": plan.dnat_mark,
                        "DNAT_LABEL": plan.dnat_label,
                    },
                    "config-set-auth_mode",
                    adapter=adapter,
                    include_plan=True,
                )
                changed = _artifacts_would_change(artifacts)
            else:
                result, changed_keys, rules, transaction_artifacts, side_effect_artifacts, actions, artifacts = _plan_config_update(
                    paths,
                    {
                        "AUTH_MODE": plan.auth_mode,
                        "DNAT_MARK": plan.dnat_mark,
                        "DNAT_LABEL": plan.dnat_label,
                    },
                    adapter=adapter,
                )
                changed = _artifacts_would_change(artifacts)
            if json_enabled:
                payload = _json_config_update_payload(
                    paths,
                    result,
                    category="config_update",
                    changed_keys=changed_keys,
                    changed=changed,
                    artifacts=artifacts,
                    actions=actions,
                    adapter=adapter,
                )
                payload["message"] = _json_localized_message(plan.message)
                payload["warnings"] = [_json_localized_message(message) for message in plan.warnings]
                if not payload["warnings"]:
                    payload.pop("warnings")
                if plan.reload_hint is not None:
                    payload["reload_hint"] = _json_localized_message(plan.reload_hint)
                _emit_json(payload)
                return 0
            for warning in _render_messages(runtime, plan.warnings):
                print(warning)
            print(_render_message(runtime, plan.message))
            if plan.reload_hint:
                print(_render_message(runtime, plan.reload_hint))
            return 0
        if getattr(args, "check", False):
            result, changed_keys, rules, transaction_artifacts, side_effect_artifacts, actions, artifacts = _plan_config_update(
                paths,
                {key: args.value},
                adapter=adapter,
            )
            changed = _artifacts_would_change(artifacts)
            if json_enabled:
                _emit_json(
                    _json_check_payload(
                        category="config_check",
                        config=result.config,
                        would_change=changed,
                        artifacts=artifacts,
                        actions=actions,
                        notices=result.notices,
                        changed_keys=changed_keys,
                        rules=rules,
                    )
                )
                return 0
            for notice in _render_messages(runtime, result.notices):
                print(notice)
            _print_check_result(
                runtime,
                would_change=changed,
            )
            return 0
        result, changed_keys, transaction_artifacts, side_effect_artifacts, actions, artifacts = _apply_config_update(
            paths,
            {key: args.value},
            f"config-set-{key.lower()}",
            adapter=adapter,
            include_plan=True,
        )
        changed = _artifacts_would_change(artifacts)
        if json_enabled:
            _emit_json(
                _json_config_update_payload(
                    paths,
                    result,
                    category="config_update",
                    changed_keys=changed_keys,
                    changed=changed,
                    artifacts=artifacts,
                    actions=actions,
                    adapter=adapter,
                )
            )
            return 0
        for notice in _render_messages(runtime, result.notices):
            print(notice)
        _print_config_update_followup(paths, result.config, runtime, changed_keys={key}, adapter=adapter)
        return 0
    except (ConfigSyntaxError, ConfigValidationError) as exc:
        _print_config_command_invalid(runtime, exc)
        return _exit_code_for_exception(exc)


def cmd_config_normalize(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    adapter = SubprocessSystemAdapter()
    json_enabled = getattr(args, "json", False)
    try:
        result, changed_keys, rules, transaction_artifacts = _plan_config_normalize(paths, adapter=adapter)
    except (ConfigSyntaxError, ConfigValidationError) as exc:
        _print_config_command_invalid(runtime, exc)
        return _exit_code_for_exception(exc)
    changed = _artifacts_would_change(transaction_artifacts)
    if getattr(args, "check", False):
        if json_enabled:
            _emit_json(
                _json_check_payload(
                    category="config_check",
                    config=result.config,
                    would_change=changed,
                    artifacts=transaction_artifacts,
                    notices=result.notices,
                    changed_keys=changed_keys,
                    rules=rules,
                )
            )
            return 0
        for notice in _render_messages(runtime, result.notices):
            print(notice)
        _print_check_result(runtime, would_change=changed)
        return 0
    if changed:
        _write_config_only(paths, result.config, "config-normalize")
    if json_enabled:
        _emit_json(
            _json_config_update_payload(
                paths,
                result,
                category="config_update",
                changed_keys=changed_keys,
                changed=changed,
                artifacts=transaction_artifacts,
                adapter=adapter,
            )
        )
        return 0
    for notice in _render_messages(runtime, result.notices):
        print(notice)
    print(_t(runtime, "config.normalize.completed", "Canonical loha.conf has been rewritten."))
    return 0


def cmd_config_history(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    if args.subcommand == "status":
        if getattr(args, "json", False):
            _emit_json(_json_history_status_payload(paths))
            return 0
        print(_t(runtime, "history.command.status", "Automatic snapshots: {status}", status=_history_status_text(paths, runtime)))
        return 0
    if args.subcommand == "enable":
        _apply_config_update(paths, {"ENABLE_CONFIG_HISTORY": "on"}, "config-history-enable")
        print(_t(runtime, "history.command.enabled", "Automatic configuration snapshots have been enabled."))
        return 0
    if args.subcommand == "disable":
        _apply_config_update(paths, {"ENABLE_CONFIG_HISTORY": "off"}, "config-history-disable")
        print(_t(runtime, "history.command.disabled", "Automatic configuration snapshots have been disabled."))
        return 0
    if getattr(args, "json", False):
        _emit_json(_json_history_show_payload(paths))
        return 0
    _print_history_listing(paths, runtime)
    return 0


def cmd_config_rollback(args) -> int:
    paths = _paths_from_args(args)
    return _run_rollback(
        paths,
        args.selector,
        apply_after=args.apply,
        runtime=_runtime_i18n(paths),
        json_enabled=getattr(args, "json", False),
    )


def cmd_config_wizard(args) -> int:
    paths = _paths_from_args(args)
    adapter = SubprocessSystemAdapter()
    runtime = _runtime_i18n(paths)
    initial = _load_or_default_config(paths, adapter=adapter)
    try:
        outcome = run_config_wizard_flow(
            adapter,
            initial=initial,
            i18n=runtime,
            surface="cli",
            input_func=input,
            paths=paths,
        )
    except KeyboardInterrupt:
        print(_t(runtime, "wizard.command.cancelled", "The configuration wizard was cancelled."))
        return 0
    state = outcome.config.as_dict()
    state["LOCALE"] = runtime.locale
    _write_config_only(paths, normalize_mapping(state), "config-wizard")
    for notice in _render_messages(runtime, outcome.persist_notices):
        print(notice)
    print(_t(runtime, "wizard.command.saved", "Core configuration has been written."))
    print(_t(runtime, "wizard.command.reload_hint", "Run `loha reload` to apply the updated configuration."))
    return 0


def cmd_rules_render(args) -> int:
    paths = _paths_from_args(args)
    rendered = LoaderService(paths=paths).render()
    if getattr(args, "json", False):
        _emit_json(
            _json_result_payload(
                "rules_render",
                ok=True,
                ruleset=rendered.full_ruleset,
            )
        )
        return 0
    sys.stdout.write(rendered.full_ruleset)
    return 0


def cmd_rpfilter(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    json_enabled = getattr(args, "json", False)
    return _run_standard_config_update_command(
        paths,
        runtime,
        updates={"RP_FILTER_MODE": args.mode},
        reason="rpfilter-set",
        check_category="rpfilter_check",
        update_category="rpfilter_update",
        followup_changed_keys={"RP_FILTER_MODE"},
        adapter=SubprocessSystemAdapter(),
        json_enabled=json_enabled,
        check_only=getattr(args, "check", False),
    )


def cmd_rpfilter_status(args) -> int:
    paths = _paths_from_args(args)
    config = _load_or_default_config(paths)
    adapter = SubprocessSystemAdapter()
    report = collect_rp_filter_status(paths, config, adapter)
    if getattr(args, "json", False):
        _emit_json(
            _json_result_payload(
                "rpfilter_status",
                ok=True,
                rp_filter=_json_rpfilter_report_payload(report),
            )
        )
        return 0
    runtime = _runtime_i18n(paths)
    for line in format_rp_filter_status_lines(report, translate=lambda key, default: _template(runtime, key, default)):
        print(line)
    return 0


def cmd_conntrack_status(args) -> int:
    paths = _paths_from_args(args)
    config = _load_or_default_config(paths)
    adapter = SubprocessSystemAdapter()
    report = collect_conntrack_status(paths, config, adapter)
    if getattr(args, "json", False):
        _emit_json(
            _json_result_payload(
                "conntrack_status",
                ok=True,
                conntrack=_json_conntrack_report_payload(report),
            )
        )
        return 0
    runtime = _runtime_i18n(paths)
    for line in format_conntrack_status_lines(report, translate=lambda key, default: _template(runtime, key, default)):
        print(line)
    return 0


def cmd_conntrack_profile(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_config_update_command(
        paths,
        runtime,
        updates={
            "CONNTRACK_MODE": args.profile,
            "CONNTRACK_TARGET_MAX": "",
            "CONNTRACK_PEAK": "",
            "CONNTRACK_MEMORY_PERCENT": "",
        },
        reason="conntrack-set",
        check_category="conntrack_check",
        update_category="conntrack_update",
        followup_changed_keys={"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"},
        adapter=SubprocessSystemAdapter(),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_conntrack_auto(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_config_update_command(
        paths,
        runtime,
        updates={
            "CONNTRACK_MODE": "auto",
            "CONNTRACK_PEAK": str(args.peak),
            "CONNTRACK_MEMORY_PERCENT": str(args.memory_percent),
            "CONNTRACK_TARGET_MAX": "",
        },
        reason="conntrack-set",
        check_category="conntrack_check",
        update_category="conntrack_update",
        followup_changed_keys={"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"},
        adapter=SubprocessSystemAdapter(),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_conntrack_set(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_config_update_command(
        paths,
        runtime,
        updates={
            "CONNTRACK_MODE": "custom",
            "CONNTRACK_TARGET_MAX": str(args.max_value),
            "CONNTRACK_MEMORY_PERCENT": str(args.memory_percent),
            "CONNTRACK_PEAK": "",
        },
        reason="conntrack-set",
        check_category="conntrack_check",
        update_category="conntrack_update",
        followup_changed_keys={"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"},
        adapter=SubprocessSystemAdapter(),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def cmd_conntrack_system(args) -> int:
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    return _run_standard_config_update_command(
        paths,
        runtime,
        updates={
            "CONNTRACK_MODE": "system",
            "CONNTRACK_TARGET_MAX": "",
            "CONNTRACK_PEAK": "",
            "CONNTRACK_MEMORY_PERCENT": "",
        },
        reason="conntrack-set",
        check_category="conntrack_check",
        update_category="conntrack_update",
        followup_changed_keys={"CONNTRACK_MODE", "CONNTRACK_TARGET_MAX", "CONNTRACK_PEAK", "CONNTRACK_MEMORY_PERCENT"},
        adapter=SubprocessSystemAdapter(),
        json_enabled=getattr(args, "json", False),
        check_only=getattr(args, "check", False),
    )


def _menu_alias(paths: Paths, runtime: RuntimeI18N) -> None:
    while True:
        print(_t(runtime, "menu.alias.title", "Manage Aliases"))
        print(f" 1. {_t(runtime, 'menu.alias.add', 'Add alias')}")
        print(f" 2. {_t(runtime, 'menu.alias.remove', 'Remove alias')}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        sub = _prompt_submenu_choice(runtime)
        if sub in {"", "0"}:
            return
        if sub == "1":
            name = _prompt_validated_text(
                runtime,
                "menu.alias.name_prompt",
                "Alias name",
                validator=_validate_alias_name_text,
            )
            ip = _prompt_validated_text(
                runtime,
                "menu.alias.ip_prompt",
                "IPv4 address",
                validator=validate_ipv4,
            )
            _run_menu_action(
                runtime,
                cmd_alias_add,
                _menu_args(paths, name=name, ip=ip),
            )
            continue
        if sub == "2":
            name = _prompt_validated_text(
                runtime,
                "menu.alias.name_prompt",
                "Alias name",
                validator=_validate_alias_name_text,
            )
            _run_menu_action(
                runtime,
                cmd_alias_rm,
                _menu_args(paths, name=name),
            )
            continue
        print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _menu_add_port(paths: Paths, runtime: RuntimeI18N) -> None:
    adapter = SubprocessSystemAdapter()
    while True:
        print(_t(runtime, "menu.port_add.title", "Add Port Forwarding Rule"))
        print(f" 1. {_t(runtime, 'menu.port_add.protocol.tcp', 'TCP')}")
        print(f" 2. {_t(runtime, 'menu.port_add.protocol.udp', 'UDP')}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        sub = _prompt_submenu_choice(runtime)
        if sub in {"", "0"}:
            return
        proto = {"1": "tcp", "2": "udp"}.get(sub)
        if proto is None:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))
            continue
        orig = _prompt_validated_text(
            runtime,
            "menu.port_add.orig_prompt",
            "Original port spec",
            validator=_validate_port_spec_text,
        )
        dest = _prompt_validated_text(
            runtime,
            "menu.port_add.dest_prompt",
            "Destination alias or IPv4",
            validator=_validate_destination_text,
        )
        dest_port = _prompt_validated_text(
            runtime,
            "menu.port_add.dest_port_prompt",
            "Destination port spec [default=orig]",
            default_value=orig,
            validator=_validate_port_spec_text,
        )
        force = False
        conflicts = _detect_listener_conflicts(adapter, proto, orig)
        if conflicts is None:
            if _prompt_yes_no(
                runtime,
                "menu.port_add.listener_scan_unavailable",
                "Local listener scan is unavailable. Continue anyway? [y/N]",
                default=False,
            ):
                force = True
            else:
                continue
        elif conflicts:
            if _prompt_yes_no(
                runtime,
                "menu.port_add.listener_conflict_confirm",
                "Local listener conflict detected on {proto} {ports}. Continue anyway? [y/N]",
                default=False,
                proto=proto,
                ports=",".join(str(port) for port in conflicts),
            ):
                force = True
            else:
                continue
        _run_menu_action(
            runtime,
            cmd_port_add,
            _menu_args(
                paths,
                proto=proto,
                orig_port_spec=orig,
                dest_addr=dest,
                dest_port_spec=dest_port,
                force=force,
            ),
        )


def _menu_del_port(paths: Paths, runtime: RuntimeI18N) -> None:
    while True:
        print(_t(runtime, "menu.port_del.title", "Delete Port Forwarding Rule"))
        print(f" 1. {_t(runtime, 'menu.port_add.protocol.tcp', 'TCP')}")
        print(f" 2. {_t(runtime, 'menu.port_add.protocol.udp', 'UDP')}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        sub = _prompt_submenu_choice(runtime)
        if sub in {"", "0"}:
            return
        proto = {"1": "tcp", "2": "udp"}.get(sub)
        if proto is None:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))
            continue
        orig = _prompt_validated_text(
            runtime,
            "menu.port_del.orig_prompt",
            "Original port spec",
            validator=_validate_port_spec_text,
        )
        _run_menu_action(
            runtime,
            cmd_port_rm,
            _menu_args(paths, proto=proto, orig_port_spec=orig),
        )


def _print_status_option_menu(
    runtime: RuntimeI18N,
    *,
    title_key: str,
    title_default: str,
    description_key: str,
    description_default: str,
    status_lines: Iterable[str],
    options: dict[str, tuple[str, str, str]],
) -> None:
    print(_t(runtime, title_key, title_default))
    print(_t(runtime, description_key, description_default))
    for line in status_lines:
        print(f"  {line}")
    for token, (_value, key, default_text) in options.items():
        print(f" {token}. {_t(runtime, key, default_text)}")
    print(f" 0. {_t(runtime, 'common.back', 'Back')}")


def _menu_rpfilter(paths: Paths, runtime: RuntimeI18N) -> None:
    adapter = SubprocessSystemAdapter()
    options = {
        "1": ("system", "wizard.steps.rp_filter_mode.options.system", "Keep system defaults"),
        "2": ("strict", "wizard.steps.rp_filter_mode.options.strict", "Strict (managed interfaces only)"),
        "3": ("loose_scoped", "wizard.steps.rp_filter_mode.options.loose_scoped", "Loose (managed interfaces only)"),
        "4": ("loose_global", "wizard.steps.rp_filter_mode.options.loose_global", "Loose (all interfaces)"),
    }
    while True:
        config = _load_or_default_config(paths)
        report = _collect_rpfilter_report(paths, adapter)
        _print_status_option_menu(
            runtime,
            title_key="wizard.steps.rp_filter_mode.title",
            title_default="Advanced NAT Support (rp_filter)",
            description_key="wizard.steps.rp_filter_mode.description",
            description_default="Hairpin NAT and WAN-to-WAN forwarding may require a different rp_filter handling mode. Choose how LOHA should manage rp_filter.",
            status_lines=format_rp_filter_status_lines(
                report,
                translate=lambda key, default: _template(runtime, key, default),
            ),
            options=options,
        )
        choice = _prompt_submenu_choice(runtime)
        if choice in {"", "0"}:
            return
        selected = options.get(choice)
        if selected is None:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))
            continue
        mode = selected[0]
        if _rpfilter_selection_is_applied(config, report, mode):
            print(_t(runtime, "common.already_applied", "Already applied."))
            continue
        _run_menu_action(runtime, cmd_rpfilter, _menu_args(paths, mode=mode))


def _menu_conntrack(paths: Paths, runtime: RuntimeI18N) -> None:
    adapter = SubprocessSystemAdapter()
    options = {
        "1": ("system", "wizard.steps.conntrack_mode.options.system", "Keep system defaults"),
        "2": ("conservative", "wizard.steps.conntrack_mode.options.conservative", "[Conservative] 65k concurrent connections (better for low-memory systems)"),
        "3": ("standard", "wizard.steps.conntrack_mode.options.standard", "[Standard] 262k concurrent connections (fits most deployments)"),
        "4": ("high", "wizard.steps.conntrack_mode.options.high", "[High] 1,048k concurrent connections (better for high-memory gateways)"),
        "5": ("auto", "wizard.steps.conntrack_mode.options.auto", "[Auto] Calculate from estimated peak concurrency and memory percentage"),
        "6": ("custom", "wizard.steps.conntrack_mode.options.custom", "[Custom] Enter the maximum concurrent connections manually"),
    }
    while True:
        config = _load_or_default_config(paths)
        report = _collect_conntrack_report(paths, adapter)
        _print_status_option_menu(
            runtime,
            title_key="wizard.steps.conntrack_mode.title",
            title_default="Connection Capacity Tuning (conntrack)",
            description_key="wizard.steps.conntrack_mode.description",
            description_default="Choose how LOHA manages concurrent connection capacity and conntrack tuning.",
            status_lines=format_conntrack_status_lines(
                report,
                translate=lambda key, default: _template(runtime, key, default),
            ),
            options=options,
        )
        choice = _prompt_submenu_choice(runtime)
        if choice in {"", "0"}:
            return
        selected = options.get(choice)
        if selected is None:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))
            continue
        mode = selected[0]
        if mode in {"system", "conservative", "standard", "high"}:
            if _conntrack_selection_is_applied(config, report, mode=mode):
                print(_t(runtime, "common.already_applied", "Already applied."))
                continue
            if mode == "system":
                _run_menu_action(runtime, cmd_conntrack_system, _menu_args(paths))
            else:
                _run_menu_action(
                    runtime,
                    cmd_conntrack_profile,
                    _menu_args(paths, profile=mode),
                )
        elif mode == "auto":
            peak = _prompt_positive_int(
                runtime,
                "menu.conntrack.peak_prompt",
                "Estimated peak concurrent connections",
                validation_key="CONNTRACK_PEAK",
                default_value=config["CONNTRACK_PEAK"] or "12000",
            )
            memory = _prompt_positive_int(
                runtime,
                "menu.conntrack.memory_prompt",
                "Memory share for connection tracking",
                validation_key="CONNTRACK_MEMORY_PERCENT",
                default_value=config["CONNTRACK_MEMORY_PERCENT"] or "35",
                maximum=90,
            )
            if _conntrack_selection_is_applied(
                config,
                report,
                mode="auto",
                peak=str(peak),
                memory_percent=str(memory),
            ):
                print(_t(runtime, "common.already_applied", "Already applied."))
                continue
            _run_menu_action(
                runtime,
                cmd_conntrack_auto,
                _menu_args(paths, peak=peak, memory_percent=memory),
            )
        elif mode == "custom":
            max_value = _prompt_positive_int(
                runtime,
                "menu.conntrack.max_prompt",
                "Maximum concurrent connections",
                validation_key="CONNTRACK_TARGET_MAX",
                default_value=config["CONNTRACK_TARGET_MAX"],
            )
            memory = _prompt_positive_int(
                runtime,
                "menu.conntrack.memory_prompt",
                "Memory share for connection tracking",
                validation_key="CONNTRACK_MEMORY_PERCENT",
                default_value=config["CONNTRACK_MEMORY_PERCENT"] or "35",
                maximum=90,
            )
            if _conntrack_selection_is_applied(
                config,
                report,
                mode="custom",
                target_max=str(max_value),
                memory_percent=str(memory),
            ):
                print(_t(runtime, "common.already_applied", "Already applied."))
                continue
            _run_menu_action(
                runtime,
                cmd_conntrack_set,
                _menu_args(paths, max_value=max_value, memory_percent=memory),
            )
        else:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _run_standard_config_selection_menu(
    paths: Paths,
    runtime: RuntimeI18N,
    *,
    config_key: str,
    title_key: str,
    title_default: str,
    description_key: str,
    description_default: str,
    render_current_line: Callable[[RuntimeI18N, str], str],
    options: dict[str, tuple[str, str, str]],
) -> None:
    while True:
        config = _load_or_default_config(paths)
        print(_t(runtime, title_key, title_default))
        print(_t(runtime, description_key, description_default))
        print(render_current_line(runtime, config[config_key]))
        for token, (_value, key, default_text) in options.items():
            print(f" {token}. {_t(runtime, key, default_text)}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        choice = _prompt_submenu_choice(runtime)
        if choice in {"", "0"}:
            return
        selected = options.get(choice)
        if selected is None:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))
            continue
        value = selected[0]
        _menu_apply_config_value(paths, runtime, config, key=config_key, value=value)


def _menu_apply_config_value(
    paths: Paths,
    runtime: RuntimeI18N,
    config,
    *,
    key: str,
    value: str,
) -> bool:
    if config[key] == value:
        print(_t(runtime, "common.already_applied", "Already applied."))
        return False
    _run_menu_action(
        runtime,
        cmd_config_set,
        _menu_args(paths, key=key, value=value),
    )
    return True


def _menu_wan_to_wan(paths: Paths, runtime: RuntimeI18N) -> None:
    _run_standard_config_selection_menu(
        paths,
        runtime,
        config_key="ENABLE_WAN_TO_WAN",
        title_key="wizard.steps.enable_wan_to_wan.title",
        title_default="Allow WAN-to-WAN Forwarding",
        description_key="wizard.steps.enable_wan_to_wan.description",
        description_default="Enable this only when external clients must use port forwarding on this gateway's exposure address to reach services on other external hosts. Most deployments can leave this disabled.",
        render_current_line=lambda runtime_value, current: _t(
            runtime_value,
            "menu.setting.current_status",
            "Current status: {status}",
            status=_toggle_status_text(runtime_value, current),
        ),
        options={
            "1": ("on", "wizard.steps.enable_wan_to_wan.options.on", "Enable"),
            "2": ("off", "wizard.steps.enable_wan_to_wan.options.off", "Disable"),
        },
    )


def _menu_tcpmss_clamp(paths: Paths, runtime: RuntimeI18N) -> None:
    _run_standard_config_selection_menu(
        paths,
        runtime,
        config_key="ENABLE_TCPMSS_CLAMP",
        title_key="wizard.steps.enable_tcpmss_clamp.title",
        title_default="Automatic TCP MSS Adjustment",
        description_key="wizard.steps.enable_tcpmss_clamp.description",
        description_default="Enable this when PMTU black holes are a risk; LOHA will adjust WAN egress TCP MSS to avoid stalled connections.",
        render_current_line=lambda runtime_value, current: _t(
            runtime_value,
            "menu.setting.current_status",
            "Current status: {status}",
            status=_toggle_status_text(runtime_value, current),
        ),
        options={
            "1": ("on", "wizard.steps.enable_tcpmss_clamp.options.on", "Enable"),
            "2": ("off", "wizard.steps.enable_tcpmss_clamp.options.off", "Disable"),
        },
    )


def _menu_counter_mode(paths: Paths, runtime: RuntimeI18N) -> None:
    _run_standard_config_selection_menu(
        paths,
        runtime,
        config_key="COUNTER_MODE",
        title_key="wizard.steps.counter_mode.title",
        title_default="Rule Counters",
        description_key="wizard.steps.counter_mode.description",
        description_default="Choose how many nft rule counters to keep for troubleshooting and traffic observation.",
        render_current_line=lambda runtime_value, current: _t(
            runtime_value,
            "menu.setting.current_value",
            "Current setting: {value}",
            value=_counter_mode_text(runtime_value, current),
        ),
        options={
            "1": ("off", "wizard.steps.counter_mode.options.off", "Off"),
            "2": ("minimal", "wizard.steps.counter_mode.options.minimal", "Minimal (important rules only)"),
            "3": ("all", "wizard.steps.counter_mode.options.all", "All rules"),
        },
    )


def _menu_strict_validation(paths: Paths, runtime: RuntimeI18N) -> None:
    while True:
        config = _load_or_default_config(paths)
        print(_t(runtime, "wizard.steps.enable_strict_validation.title", "Strict Internal Source Validation"))
        print(
            _t(
                runtime,
                "wizard.steps.enable_strict_validation.description",
                "Drop internal traffic early when its source address does not match the expected trusted networks. Enable this only when you know which interfaces and IPv4 CIDRs should be trusted.",
            )
        )
        print(
            _t(
                runtime,
                "menu.setting.current_status",
                "Current status: {status}",
                status=_toggle_status_text(runtime, config["ENABLE_STRICT_LAN_VALIDATION"]),
            )
        )
        print(
            f"{_t(runtime, 'wizard.summary.fields.internal_ifs', 'Interfaces to validate')}: "
            f"{config['INTERNAL_IFS'] or _t(runtime, 'list.none', '(none)')}"
        )
        print(
            f"{_t(runtime, 'wizard.summary.fields.trusted_internal_nets', 'Trusted source networks')}: "
            f"{config['TRUSTED_INTERNAL_NETS'] or _t(runtime, 'list.none', '(none)')}"
        )
        print(f" 1. {_t(runtime, 'wizard.steps.enable_strict_validation.options.on', 'Enable')}")
        print(f" 2. {_t(runtime, 'wizard.steps.enable_strict_validation.options.off', 'Disable')}")
        print(f" 3. {_t(runtime, 'wizard.steps.internal_ifs.title', 'Interfaces to Validate')}")
        print(f" 4. {_t(runtime, 'wizard.steps.trusted_internal_nets.title', 'Trusted Source Networks')}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        choice = _prompt_submenu_choice(runtime)
        if choice in {"", "0"}:
            return
        if choice in {"1", "2"}:
            selected = "on" if choice == "1" else "off"
            _menu_apply_config_value(
                paths,
                runtime,
                config,
                key="ENABLE_STRICT_LAN_VALIDATION",
                value=selected,
            )
            continue
        if choice == "3":
            value = _prompt_validated_text(
                runtime,
                "wizard.steps.internal_ifs.title",
                "Interfaces to Validate",
                default_value=config["INTERNAL_IFS"] or config["LAN_IFS"],
                validator=_normalize_iface_csv_text,
            )
            _menu_apply_config_value(
                paths,
                runtime,
                config,
                key="INTERNAL_IFS",
                value=value,
            )
            continue
        if choice == "4":
            value = _prompt_validated_text(
                runtime,
                "wizard.steps.trusted_internal_nets.title",
                "Trusted Source Networks",
                default_value=config["TRUSTED_INTERNAL_NETS"] or config["LAN_NETS"],
                validator=_normalize_cidr_csv_text,
            )
            _menu_apply_config_value(
                paths,
                runtime,
                config,
                key="TRUSTED_INTERNAL_NETS",
                value=value,
            )
            continue
        print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _menu_advanced(paths: Paths, runtime: RuntimeI18N) -> None:
    adapter = SubprocessSystemAdapter()
    while True:
        runtime = _runtime_i18n(paths)
        print(_t(runtime, "menu.advanced.title", "Advanced Settings"))
        print(_t(runtime, "menu.advanced.current_status", "Current Status"))
        for line in _build_advanced_status_lines(paths, runtime, adapter=adapter):
            print(f"  {line}")
        print(f" 1. {_t(runtime, 'menu.advanced.config_wizard', 'Configuration Wizard')}")
        print(f" 2. {_t(runtime, 'menu.advanced.config_history', 'Configuration History / Rollback')}")
        print(f" 3. {_t(runtime, 'menu.advanced.rpfilter', 'Advanced NAT Support (rp_filter)')}")
        print(f" 4. {_t(runtime, 'menu.advanced.conntrack', 'Connection Capacity Tuning (conntrack)')}")
        print(f" 5. {_t(runtime, 'menu.advanced.auth_mode', 'Switch Authorization Marking (mark / label)')}")
        print(f" 6. {_t(runtime, 'menu.advanced.wan_to_wan', 'WAN-to-WAN Forwarding')}")
        print(f" 7. {_t(runtime, 'menu.advanced.tcpmss_clamp', 'Automatic TCP MSS Adjustment')}")
        print(f" 8. {_t(runtime, 'menu.advanced.counter_mode', 'nftables Rule Counters')}")
        print(f" 9. {_t(runtime, 'menu.advanced.strict_validation', 'Strict Internal Source Validation')}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        sub = _prompt_submenu_choice(runtime)
        if sub in {"", "0"}:
            return
        if sub == "1":
            _run_menu_action(runtime, cmd_config_wizard, _menu_args(paths))
        elif sub == "2":
            _menu_config_history(paths, runtime)
        elif sub == "3":
            _menu_rpfilter(paths, runtime)
        elif sub == "4":
            _menu_conntrack(paths, runtime)
        elif sub == "5":
            _run_menu_action(runtime, _interactive_auth_switch, paths, runtime)
        elif sub == "6":
            _menu_wan_to_wan(paths, runtime)
        elif sub == "7":
            _menu_tcpmss_clamp(paths, runtime)
        elif sub == "8":
            _menu_counter_mode(paths, runtime)
        elif sub == "9":
            _menu_strict_validation(paths, runtime)
        else:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _prompt_history_apply(runtime: RuntimeI18N) -> bool:
    return _prompt_yes_no(
        runtime,
        "history.rollback.apply_prompt",
        "Apply restored configuration immediately with `loha reload`? [y/N]",
        default=False,
    )


def _menu_config_history(paths: Paths, runtime: RuntimeI18N) -> None:
    while True:
        enabled = history_enabled(paths)
        print(_t(runtime, "history.menu.title", "Configuration History"))
        print(
            _t(
                runtime,
                "history.menu.status",
                "Automatic snapshots: {status}",
                status=_history_status_text(paths, runtime),
            )
        )
        print(
            f" 1. {_t(runtime, 'history.menu.toggle_disable', 'Disable automatic snapshots') if enabled else _t(runtime, 'history.menu.toggle_enable', 'Enable automatic snapshots')}"
        )
        print(f" 2. {_t(runtime, 'history.menu.show', 'Show snapshot list')}")
        print(f" 3. {_t(runtime, 'history.menu.rollback_latest', 'Rollback latest snapshot')}")
        print(f" 4. {_t(runtime, 'history.menu.rollback_index', 'Rollback by index')}")
        print(f" 0. {_t(runtime, 'common.back', 'Back')}")
        choice = _prompt_submenu_choice(runtime)
        if choice in {"", "0"}:
            return
        if choice == "1":
            subcommand = "disable" if enabled else "enable"
            _run_menu_action(runtime, cmd_config_history, _menu_args(paths, subcommand=subcommand))
            continue
        if choice == "2":
            _print_history_listing(paths, runtime)
            continue
        if choice == "3":
            apply_after = _prompt_history_apply(runtime)
            _run_rollback(paths, "latest", apply_after=apply_after, runtime=runtime)
            continue
        if choice == "4":
            _print_history_listing(paths, runtime)
            selector = input(
                _t(runtime, "history.menu.index_prompt", "Enter history index to restore")
                + ": "
            ).strip()
            if not selector:
                continue
            if not selector.isdigit():
                print(_t(runtime, "history.menu.index_invalid", "History index must be a positive integer."))
                continue
            apply_after = _prompt_history_apply(runtime)
            _run_rollback(paths, selector, apply_after=apply_after, runtime=runtime)
            continue
        print(_t(runtime, "common.invalid_choice", "Invalid choice."))


def _interactive_menu(paths: Paths) -> int:
    adapter = SubprocessSystemAdapter()
    while True:
        runtime = _runtime_i18n(paths)
        print(f"LOHA Port Forwarder v{__version__}")
        print(f" 1. {_t(runtime, 'menu.main.status', 'List current status and rules')}")
        print(f" 2. {_t(runtime, 'menu.main.alias', 'Manage aliases')}")
        print(f" 3. {_t(runtime, 'menu.main.add_port', 'Add port forwarding rule')}")
        print(f" 4. {_t(runtime, 'menu.main.del_port', 'Delete port forwarding rule')}")
        print(f" 5. {_t(runtime, 'menu.main.reload', 'Apply rules (reload)')}")
        print(f" 6. {_t(runtime, 'menu.main.edit', 'Edit rules.conf')}")
        print(f" 7. {_t(runtime, 'menu.main.rendered_rules', 'Show rendered nft rules')}")
        print(f" 8. {_t(runtime, 'menu.main.advanced', 'Advanced settings')}")
        print(f" 9. {_change_language_menu_label(runtime)}")
        print(f" 0. {_t(runtime, 'common.exit', 'Exit')}")
        choice = input(_t(runtime, "menu.choice", "Choice") + ": ").strip()
        if choice == "0":
            return 0
        if choice == "1":
            _run_menu_action(
                runtime,
                cmd_list,
                _menu_args(paths),
            )
        elif choice == "2":
            _menu_alias(paths, runtime)
        elif choice == "3":
            _menu_add_port(paths, runtime)
        elif choice == "4":
            _menu_del_port(paths, runtime)
        elif choice == "5":
            result = _run_menu_action(
                runtime,
                lambda: _service_reload(paths, full=False, adapter=adapter, runtime=runtime),
            )
            if result:
                print(result)
        elif choice == "6":
            if _confirm_rules_conf_edit(runtime):
                _run_menu_action(runtime, _edit_rules_conf, paths, runtime, adapter=adapter)
        elif choice == "7":
            result = _run_menu_action(runtime, LoaderService(paths=paths, adapter=adapter).render)
            if result is not None:
                print(result.full_ruleset)
        elif choice == "8":
            _menu_advanced(paths, runtime)
        elif choice == "9":
            _menu_change_language(paths, runtime)
        else:
            print(_t(runtime, "common.invalid_choice", "Invalid choice."))
        print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loha")
    parser.add_argument("--etc-dir")
    parser.add_argument("--prefix")
    parser.add_argument("--run-dir")
    parser.add_argument("--systemd-dir")
    subparsers = parser.add_subparsers(dest="command")

    def add_check_flag(command):
        command.add_argument("--check", "--dry-run", dest="check", action="store_true")

    subparsers.add_parser("version").set_defaults(func=cmd_version)
    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=cmd_list)

    alias = subparsers.add_parser("alias")
    alias_sub = alias.add_subparsers(dest="subcommand", required=True)
    alias_add = alias_sub.add_parser("add")
    add_check_flag(alias_add)
    alias_add.add_argument("--json", action="store_true")
    alias_add.add_argument("name")
    alias_add.add_argument("ip")
    alias_add.set_defaults(func=cmd_alias_add)
    alias_rm = alias_sub.add_parser("rm")
    add_check_flag(alias_rm)
    alias_rm.add_argument("--json", action="store_true")
    alias_rm.add_argument("name")
    alias_rm.set_defaults(func=cmd_alias_rm)

    port = subparsers.add_parser("port")
    port_sub = port.add_subparsers(dest="subcommand", required=True)
    port_add = port_sub.add_parser("add")
    add_check_flag(port_add)
    port_add.add_argument("--json", action="store_true")
    port_add.add_argument("--force", action="store_true")
    port_add.add_argument("proto")
    port_add.add_argument("orig_port_spec")
    port_add.add_argument("dest_addr")
    port_add.add_argument("dest_port_spec", nargs="?")
    port_add.set_defaults(func=cmd_port_add)
    port_rm = port_sub.add_parser("rm")
    add_check_flag(port_rm)
    port_rm.add_argument("--json", action="store_true")
    port_rm.add_argument("proto")
    port_rm.add_argument("orig_port_spec")
    port_rm.set_defaults(func=cmd_port_rm)
    port_prune = port_sub.add_parser("prune")
    add_check_flag(port_prune)
    port_prune.add_argument("--json", action="store_true")
    port_prune.add_argument("--dest")
    port_prune.add_argument("--proto")
    port_prune.add_argument("--range")
    port_prune.set_defaults(func=cmd_port_prune)

    reload_command = subparsers.add_parser("reload")
    reload_command.add_argument("--full", action="store_true")
    reload_command.add_argument("--json", action="store_true")
    reload_command.set_defaults(func=cmd_reload)

    rules = subparsers.add_parser("rules")
    rules_sub = rules.add_subparsers(dest="subcommand", required=True)
    rules_render = rules_sub.add_parser("render")
    rules_render.add_argument("--json", action="store_true")
    rules_render.set_defaults(func=cmd_rules_render)

    doctor = subparsers.add_parser("doctor")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    config = subparsers.add_parser("config")
    config_sub = config.add_subparsers(dest="subcommand", required=True)
    config_show = config_sub.add_parser("show")
    config_show.add_argument("--json", action="store_true")
    config_show.set_defaults(func=cmd_config_show)
    config_get = config_sub.add_parser("get")
    config_get.add_argument("key")
    config_get.set_defaults(func=cmd_config_get)
    config_set = config_sub.add_parser("set")
    add_check_flag(config_set)
    config_set.add_argument("--json", action="store_true")
    config_set.add_argument("key")
    config_set.add_argument("value")
    config_set.set_defaults(func=cmd_config_set)
    config_normalize = config_sub.add_parser("normalize")
    add_check_flag(config_normalize)
    config_normalize.add_argument("--json", action="store_true")
    config_normalize.set_defaults(func=cmd_config_normalize)
    config_history = config_sub.add_parser("history")
    config_history.add_argument("--json", action="store_true")
    config_history.add_argument("subcommand", nargs="?", default="show", choices=["show", "enable", "disable", "status"])
    config_history.set_defaults(func=cmd_config_history)
    config_rollback = config_sub.add_parser("rollback")
    config_rollback.add_argument("--json", action="store_true")
    config_rollback.add_argument("selector", nargs="?", default="latest")
    config_rollback.add_argument("--apply", action="store_true")
    config_rollback.set_defaults(func=cmd_config_rollback)
    config_sub.add_parser("wizard").set_defaults(func=cmd_config_wizard)

    rpfilter = subparsers.add_parser("rpfilter")
    rpfilter_sub = rpfilter.add_subparsers(dest="subcommand", required=True)
    rpfilter_status = rpfilter_sub.add_parser("status")
    rpfilter_status.add_argument("--json", action="store_true")
    rpfilter_status.set_defaults(func=cmd_rpfilter_status)
    rpfilter_set = rpfilter_sub.add_parser("set")
    rpfilter_set.add_argument("--json", action="store_true")
    add_check_flag(rpfilter_set)
    rpfilter_set.add_argument("mode")
    rpfilter_set.set_defaults(func=cmd_rpfilter)

    conntrack = subparsers.add_parser("conntrack")
    conntrack_sub = conntrack.add_subparsers(dest="subcommand", required=True)
    conntrack_status = conntrack_sub.add_parser("status")
    conntrack_status.add_argument("--json", action="store_true")
    conntrack_status.set_defaults(func=cmd_conntrack_status)
    profile = conntrack_sub.add_parser("profile")
    add_check_flag(profile)
    profile.add_argument("--json", action="store_true")
    profile.add_argument("profile")
    profile.set_defaults(func=cmd_conntrack_profile)
    auto = conntrack_sub.add_parser("auto")
    add_check_flag(auto)
    auto.add_argument("--json", action="store_true")
    auto.add_argument("peak", type=int)
    auto.add_argument("memory_percent", nargs="?", type=int, default=35)
    auto.set_defaults(func=cmd_conntrack_auto)
    custom = conntrack_sub.add_parser("set")
    add_check_flag(custom)
    custom.add_argument("--json", action="store_true")
    custom.add_argument("max_value", type=int)
    custom.add_argument("memory_percent", nargs="?", type=int, default=35)
    custom.set_defaults(func=cmd_conntrack_set)
    conntrack_system = conntrack_sub.add_parser("system")
    add_check_flag(conntrack_system)
    conntrack_system.add_argument("--json", action="store_true")
    conntrack_system.set_defaults(func=cmd_conntrack_system)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = _paths_from_args(args)
    runtime = _runtime_i18n(paths)
    try:
        if args.command is None:
            return _interactive_menu(paths)
        return args.func(args)
    except KeyboardInterrupt:
        if getattr(args, "json", False):
            _emit_json(
                _json_error_payload(
                    "Cancelled.",
                    error_type="KeyboardInterrupt",
                    exit_code=EXIT_CODE_CANCELLED,
                )
            )
        else:
            print(_t(runtime, "common.cancelled", "Cancelled."))
        return EXIT_CODE_CANCELLED
    except Exception as exc:
        exit_code = _exit_code_for_exception(exc)
        if getattr(args, "json", False):
            _emit_json(_json_error_payload(str(exc), error_type=exc.__class__.__name__, exit_code=exit_code))
        else:
            print(_format_plain_error(runtime, exc))
        return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
