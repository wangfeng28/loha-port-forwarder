import hashlib
import json
import os
import shutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional, Sequence, Tuple

from .config import normalize_mapping, parse_canonical_text
from .exceptions import ControlLockError, ControlStateError
from .history import capture_snapshot_if_enabled, clear_rollback_checkpoint, write_state_files
from .models import (
    CanonicalConfig,
    ControlPlaneStatus,
    ControlStateManifest,
    DesiredStateSnapshot,
    Paths,
    RulesFile,
    RuntimeStateSnapshot,
)
from .rules import parse_rules_text


ALLOWED_PENDING_ACTIONS = ("reload", "sysctl_sync", "install_sync")


def _etc_dir(paths) -> Path:
    return Path(getattr(paths, "etc_dir"))


def _run_dir(paths) -> Path:
    return Path(getattr(paths, "run_dir"))


def _loha_conf(paths) -> Path:
    return Path(getattr(paths, "loha_conf", _etc_dir(paths) / "loha.conf"))


def _rules_conf(paths) -> Path:
    return Path(getattr(paths, "rules_conf", _etc_dir(paths) / "rules.conf"))


def _state_file(paths) -> Path:
    return Path(getattr(paths, "state_file", _etc_dir(paths) / "state.json"))


def _txn_dir(paths) -> Path:
    return Path(getattr(paths, "txn_dir", _etc_dir(paths) / "txn"))


def _pending_txn_file(paths) -> Path:
    return Path(getattr(paths, "pending_txn_file", _txn_dir(paths) / "pending.json"))


def _control_lock_dir(paths) -> Path:
    return Path(getattr(paths, "control_lock_dir", _run_dir(paths) / "control.lock.d"))


def _runtime_state_file(paths) -> Path:
    return Path(getattr(paths, "runtime_state_file", _run_dir(paths) / "runtime_state.json"))


def _pid_file(lock_dir: Path) -> Path:
    return lock_dir / "pid"


def _pid_is_alive(pid_text: str) -> bool:
    if not pid_text.strip().isdigit():
        return False
    pid = int(pid_text.strip(), 10)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


@contextmanager
def control_file_lock(
    paths: Paths,
    *,
    timeout_seconds: float = 10.0,
    poll_interval_seconds: float = 0.1,
) -> Iterator[None]:
    lock_dir = _control_lock_dir(paths)
    pid_file = _pid_file(lock_dir)
    deadline = time.monotonic() + max(0.0, timeout_seconds)

    while True:
        try:
            lock_dir.parent.mkdir(parents=True, exist_ok=True)
            lock_dir.mkdir()
            break
        except FileExistsError:
            if pid_file.exists():
                pid_text = pid_file.read_text(encoding="utf-8").strip()
                if pid_text and not _pid_is_alive(pid_text):
                    try:
                        pid_file.unlink()
                    except FileNotFoundError:
                        pass
                    try:
                        lock_dir.rmdir()
                    except OSError:
                        pass
                    continue
            if time.monotonic() >= deadline:
                raise ControlLockError(
                    f"Timed out waiting for exclusive access to {_etc_dir(paths)}. "
                    "Another LOHA control-plane update may still be running."
                )
            time.sleep(poll_interval_seconds)

    try:
        pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
        yield
    finally:
        try:
            pid_file.unlink()
        except FileNotFoundError:
            pass
        try:
            lock_dir.rmdir()
        except OSError:
            pass


def _with_lock(
    paths: Paths,
    *,
    assume_locked: bool,
    timeout_seconds: float,
    callback: Callable[[], object],
):
    if assume_locked:
        return callback()
    with control_file_lock(paths, timeout_seconds=timeout_seconds):
        return callback()


def _hash_text(text: str) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def _read_path_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + ".tmp")
    temp_path.write_text(text, encoding="utf-8")
    temp_path.replace(path)


def _write_json_atomic(path: Path, payload) -> None:
    _write_text_atomic(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _normalize_pending_actions(actions: Sequence[str]) -> Tuple[str, ...]:
    normalized = []
    seen = set()
    for action in actions:
        if not action:
            continue
        if action not in ALLOWED_PENDING_ACTIONS:
            raise ControlStateError(f"unsupported pending action: {action}")
        if action not in seen:
            seen.add(action)
            normalized.append(action)
    return tuple(normalized)


def _manifest_payload(
    *,
    revision: int,
    config_hash: str,
    rules_hash: str,
    updated_at_epoch: int,
    source: str,
    reason: str,
):
    return {
        "revision": revision,
        "config_hash": config_hash,
        "rules_hash": rules_hash,
        "updated_at_epoch": updated_at_epoch,
        "source": source,
        "reason": reason,
    }


def _manifest_from_payload(payload) -> ControlStateManifest:
    return ControlStateManifest(
        revision=int(payload.get("revision", 0)),
        config_hash=str(payload.get("config_hash", "")),
        rules_hash=str(payload.get("rules_hash", "")),
        updated_at_epoch=int(payload.get("updated_at_epoch", 0)),
        source=str(payload.get("source", "")),
        reason=str(payload.get("reason", "")),
    )


def read_control_manifest(paths: Paths) -> Optional[ControlStateManifest]:
    state_file = _state_file(paths)
    if not state_file.exists():
        return None
    return _manifest_from_payload(json.loads(state_file.read_text(encoding="utf-8")))


def build_desired_snapshot_from_texts(
    config_text: str,
    rules_text: str,
    *,
    revision: int = 0,
    source: str = "",
    reason: str = "",
    manifest_present: bool = False,
    state_mismatch: bool = False,
    pending_txn_present: bool = False,
) -> DesiredStateSnapshot:
    config: CanonicalConfig
    if config_text:
        config = normalize_mapping(parse_canonical_text(config_text), materialize_defaults=False)
    else:
        raise FileNotFoundError("loha.conf is missing")
    rules = parse_rules_text(rules_text) if rules_text else RulesFile()
    return DesiredStateSnapshot(
        config=config,
        rules=rules,
        config_text=config_text,
        rules_text=rules_text,
        revision=revision,
        source=source,
        reason=reason,
        manifest_present=manifest_present,
        state_mismatch=state_mismatch,
        pending_txn_present=pending_txn_present,
    )


def _cleanup_pending(paths: Paths, pending_payload=None) -> None:
    stage_dir = None
    if pending_payload is not None and pending_payload.get("stage_dir"):
        stage_dir = Path(pending_payload["stage_dir"])
    try:
        pending_file = _pending_txn_file(paths)
        if pending_file.exists():
            pending_file.unlink()
    except FileNotFoundError:
        pass
    if stage_dir is not None:
        shutil.rmtree(stage_dir, ignore_errors=True)


def reconcile_pending_transaction(paths: Paths) -> bool:
    pending_file = _pending_txn_file(paths)
    if not pending_file.exists():
        return False
    payload = json.loads(pending_file.read_text(encoding="utf-8"))
    pending_manifest = _manifest_from_payload(payload)
    stage_dir = Path(payload["stage_dir"]) if payload.get("stage_dir") else None
    stage_config = stage_dir / "loha.conf" if stage_dir is not None else None
    stage_rules = stage_dir / "rules.conf" if stage_dir is not None else None
    if stage_config is not None and stage_config.exists() and stage_rules is not None and stage_rules.exists():
        config_text = stage_config.read_text(encoding="utf-8")
        rules_text = stage_rules.read_text(encoding="utf-8")
        if _hash_text(config_text) != pending_manifest.config_hash or _hash_text(rules_text) != pending_manifest.rules_hash:
            raise ControlStateError("pending transaction staged files do not match recorded hashes")
        write_state_files(paths, config_text=config_text, rules_text=rules_text)
        _write_json_atomic(
            _state_file(paths),
            _manifest_payload(
                revision=pending_manifest.revision,
                config_hash=pending_manifest.config_hash,
                rules_hash=pending_manifest.rules_hash,
                updated_at_epoch=pending_manifest.updated_at_epoch,
                source=pending_manifest.source,
                reason=pending_manifest.reason,
            ),
        )
        _cleanup_pending(paths, payload)
        return True

    live_config_text = _read_path_text(_loha_conf(paths))
    live_rules_text = _read_path_text(_rules_conf(paths))
    live_config_hash = _hash_text(live_config_text)
    live_rules_hash = _hash_text(live_rules_text)
    if live_config_hash == pending_manifest.config_hash and live_rules_hash == pending_manifest.rules_hash:
        _write_json_atomic(
            _state_file(paths),
            _manifest_payload(
                revision=pending_manifest.revision,
                config_hash=pending_manifest.config_hash,
                rules_hash=pending_manifest.rules_hash,
                updated_at_epoch=pending_manifest.updated_at_epoch,
                source=pending_manifest.source,
                reason=pending_manifest.reason,
            ),
        )
        _cleanup_pending(paths, payload)
        return True

    manifest = read_control_manifest(paths)
    if manifest is not None and manifest.config_hash == live_config_hash and manifest.rules_hash == live_rules_hash:
        _cleanup_pending(paths, payload)
        return True
    raise ControlStateError("pending transaction could not be reconciled safely")


def read_desired_state(
    paths: Paths,
    *,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
) -> DesiredStateSnapshot:
    def _read():
        reconcile_pending_transaction(paths)
        pending_present = _pending_txn_file(paths).exists()
        manifest = read_control_manifest(paths)
        config_text = _read_path_text(_loha_conf(paths))
        if not config_text:
            raise FileNotFoundError("loha.conf is missing")
        rules_text = _read_path_text(_rules_conf(paths))
        config_hash = _hash_text(config_text)
        rules_hash = _hash_text(rules_text)
        state_mismatch = bool(
            manifest is not None and (manifest.config_hash != config_hash or manifest.rules_hash != rules_hash)
        )
        return build_desired_snapshot_from_texts(
            config_text,
            rules_text,
            revision=manifest.revision if manifest is not None else 0,
            source=manifest.source if manifest is not None else "",
            reason=manifest.reason if manifest is not None else "",
            manifest_present=manifest is not None,
            state_mismatch=state_mismatch,
            pending_txn_present=pending_present,
        )

    return _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_read,
    )


def read_desired_texts(
    paths: Paths,
    *,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
) -> Tuple[str, str]:
    def _read():
        reconcile_pending_transaction(paths)
        config_text = _read_path_text(_loha_conf(paths))
        if not config_text:
            raise FileNotFoundError("loha.conf is missing")
        return config_text, _read_path_text(_rules_conf(paths))

    return _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_read,
    )


def read_runtime_state(paths: Paths) -> RuntimeStateSnapshot:
    runtime_state_file = _runtime_state_file(paths)
    if not runtime_state_file.exists():
        return RuntimeStateSnapshot()
    payload = json.loads(runtime_state_file.read_text(encoding="utf-8"))
    return RuntimeStateSnapshot(
        desired_revision=int(payload.get("desired_revision", 0)),
        applied_revision=int(payload.get("applied_revision", 0)),
        last_apply_mode=str(payload.get("last_apply_mode", "")),
        last_apply_status=str(payload.get("last_apply_status", "unknown")),
        last_error=str(payload.get("last_error", "")),
        pending_actions=_normalize_pending_actions(payload.get("pending_actions", ()) or ()),
        updated_at_epoch=int(payload.get("updated_at_epoch", 0)),
    )


def write_runtime_state(
    paths: Paths,
    runtime_state: RuntimeStateSnapshot,
    *,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
) -> RuntimeStateSnapshot:
    payload = {
        "desired_revision": runtime_state.desired_revision,
        "applied_revision": runtime_state.applied_revision,
        "last_apply_mode": runtime_state.last_apply_mode,
        "last_apply_status": runtime_state.last_apply_status,
        "last_error": runtime_state.last_error,
        "pending_actions": list(_normalize_pending_actions(runtime_state.pending_actions)),
        "updated_at_epoch": runtime_state.updated_at_epoch or int(time.time()),
    }

    def _write():
        _write_json_atomic(_runtime_state_file(paths), payload)
        return RuntimeStateSnapshot(
            desired_revision=int(payload["desired_revision"]),
            applied_revision=int(payload["applied_revision"]),
            last_apply_mode=str(payload["last_apply_mode"]),
            last_apply_status=str(payload["last_apply_status"]),
            last_error=str(payload["last_error"]),
            pending_actions=tuple(payload["pending_actions"]),
            updated_at_epoch=int(payload["updated_at_epoch"]),
        )

    return _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_write,
    )


def update_runtime_state(
    paths: Paths,
    transform: Callable[[RuntimeStateSnapshot], RuntimeStateSnapshot],
    *,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
) -> RuntimeStateSnapshot:
    def _update():
        current = read_runtime_state(paths)
        updated = transform(current)
        return write_runtime_state(paths, updated, assume_locked=True)

    return _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_update,
    )


def commit_desired_state(
    paths: Paths,
    *,
    config_text: str,
    rules_text: str,
    source: str,
    reason: str,
    clear_rollback_checkpoint_after_write: bool = True,
    capture_history: bool = True,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
    extra_pending_actions: Sequence[str] = (),
) -> DesiredStateSnapshot:
    def _commit():
        reconcile_pending_transaction(paths)
        manifest = read_control_manifest(paths)
        if capture_history:
            capture_snapshot_if_enabled(paths, source=source, reason=reason)
        revision = (manifest.revision if manifest is not None else 0) + 1
        now = int(time.time())
        config_hash = _hash_text(config_text)
        rules_hash = _hash_text(rules_text)
        stage_dir = _txn_dir(paths) / f"rev-{revision}-{time.time_ns()}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        (stage_dir / "loha.conf").write_text(config_text, encoding="utf-8")
        (stage_dir / "rules.conf").write_text(rules_text, encoding="utf-8")
        _write_json_atomic(
            _pending_txn_file(paths),
            {
                **_manifest_payload(
                    revision=revision,
                    config_hash=config_hash,
                    rules_hash=rules_hash,
                    updated_at_epoch=now,
                    source=source,
                    reason=reason,
                ),
                "stage_dir": str(stage_dir),
            },
        )
        write_state_files(paths, config_text=config_text, rules_text=rules_text)
        _write_json_atomic(
            _state_file(paths),
            _manifest_payload(
                revision=revision,
                config_hash=config_hash,
                rules_hash=rules_hash,
                updated_at_epoch=now,
                source=source,
                reason=reason,
            ),
        )
        _cleanup_pending(paths, {"stage_dir": str(stage_dir)})
        if clear_rollback_checkpoint_after_write:
            clear_rollback_checkpoint(paths)

        current_runtime = read_runtime_state(paths)
        pending_actions = list(current_runtime.pending_actions)
        if "reload" not in pending_actions:
            pending_actions.append("reload")
        for action in _normalize_pending_actions(extra_pending_actions):
            if action not in pending_actions:
                pending_actions.append(action)
        write_runtime_state(
            paths,
            RuntimeStateSnapshot(
                desired_revision=revision,
                applied_revision=current_runtime.applied_revision,
                last_apply_mode=current_runtime.last_apply_mode,
                last_apply_status=current_runtime.last_apply_status,
                last_error=current_runtime.last_error,
                pending_actions=tuple(pending_actions),
                updated_at_epoch=now,
            ),
            assume_locked=True,
        )
        return build_desired_snapshot_from_texts(
            config_text,
            rules_text,
            revision=revision,
            source=source,
            reason=reason,
            manifest_present=True,
            state_mismatch=False,
            pending_txn_present=False,
        )

    return _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_commit,
    )


def remove_runtime_state(
    paths: Paths,
    *,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
) -> None:
    def _remove():
        try:
            _runtime_state_file(paths).unlink()
        except FileNotFoundError:
            pass

    _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_remove,
    )


def inspect_control_plane_status(
    paths: Paths,
    *,
    assume_locked: bool = False,
    timeout_seconds: float = 10.0,
) -> ControlPlaneStatus:
    def _inspect():
        pending_present = _pending_txn_file(paths).exists()
        manifest = read_control_manifest(paths)
        state_mismatch = False
        desired_revision = manifest.revision if manifest is not None else 0
        if _loha_conf(paths).exists():
            config_text = _read_path_text(_loha_conf(paths))
            rules_text = _read_path_text(_rules_conf(paths))
            if manifest is not None:
                state_mismatch = (
                    manifest.config_hash != _hash_text(config_text) or manifest.rules_hash != _hash_text(rules_text)
                )
        runtime_state = read_runtime_state(paths)
        return ControlPlaneStatus(
            desired_revision=desired_revision or runtime_state.desired_revision,
            applied_revision=runtime_state.applied_revision,
            runtime_synced=not runtime_state.pending_actions,
            pending_actions=runtime_state.pending_actions,
            last_apply_mode=runtime_state.last_apply_mode,
            last_apply_status=runtime_state.last_apply_status,
            last_error=runtime_state.last_error,
            manifest_present=manifest is not None,
            pending_txn_present=pending_present,
            state_mismatch=state_mismatch,
        )

    return _with_lock(
        paths,
        assume_locked=assume_locked,
        timeout_seconds=timeout_seconds,
        callback=_inspect,
    )
