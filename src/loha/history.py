import hashlib
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from .config import load_config
from .exceptions import ApplyError, HistoryError
from .models import HistoryEntry, Paths, RollbackOutcome

ROLLBACK_CHECKPOINT_DIRNAME = "_rollback_checkpoint"


def _state_exists(paths: Paths) -> bool:
    return paths.loha_conf.exists() or paths.rules_conf.exists()


def _rollback_checkpoint_dir(paths) -> Path:
    explicit = getattr(paths, "rollback_checkpoint_dir", None)
    if explicit is not None:
        return explicit
    return Path(paths.history_dir) / ROLLBACK_CHECKPOINT_DIRNAME


def _hash_path(path: Path) -> str:
    if not path.exists():
        return "missing"
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _meta_path(snapshot_dir: Path) -> Path:
    return snapshot_dir / "meta.json"


def _snapshot_dir_name(created_at_epoch: int, created_at_ns: int, source: str, reason: str) -> str:
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(created_at_epoch))
    return f"{timestamp}-{created_at_ns % 1_000_000_000:09d}_{source}-{reason}"


def _entry_from_snapshot_dir(directory: Path) -> Optional[HistoryEntry]:
    meta_file = _meta_path(directory)
    if not meta_file.exists():
        return None
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    return HistoryEntry(
        path=directory,
        created_at_epoch=int(data["created_at_epoch"]),
        updated_at_epoch=int(data["updated_at_epoch"]),
        source=data["source"],
        reason=data["reason"],
        config_hash=data["config_hash"],
        rules_hash=data["rules_hash"],
    )


def list_snapshots(paths: Paths) -> List[HistoryEntry]:
    entries: List[HistoryEntry] = []
    if not paths.history_dir.exists():
        return entries
    for directory in sorted((path for path in paths.history_dir.iterdir() if path.is_dir()), reverse=True):
        if directory.name == ROLLBACK_CHECKPOINT_DIRNAME:
            continue
        entry = _entry_from_snapshot_dir(directory)
        if entry is not None:
            entries.append(entry)
    return entries


def load_rollback_checkpoint(paths: Paths) -> Optional[HistoryEntry]:
    checkpoint_dir = _rollback_checkpoint_dir(paths)
    if not checkpoint_dir.exists():
        return None
    return _entry_from_snapshot_dir(checkpoint_dir)


def _write_snapshot(
    snapshot_dir: Path,
    *,
    source: str,
    reason: str,
    conf_path: Path,
    rules_path: Path,
    config_hash: str,
    rules_hash: str,
    created_at_epoch: int,
) -> None:
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    if conf_path.exists():
        shutil.copy2(conf_path, snapshot_dir / "loha.conf")
    if rules_path.exists():
        shutil.copy2(rules_path, snapshot_dir / "rules.conf")
    payload = {
        "created_at_epoch": created_at_epoch,
        "updated_at_epoch": created_at_epoch,
        "source": source,
        "reason": reason,
        "config_hash": config_hash,
        "rules_hash": rules_hash,
    }
    _meta_path(snapshot_dir).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_rollback_checkpoint(
    paths: Paths,
    *,
    conf_path: Path,
    rules_path: Path,
) -> Optional[Path]:
    if not conf_path.exists() and not rules_path.exists():
        clear_rollback_checkpoint(paths)
        return None
    config_hash = _hash_path(conf_path)
    rules_hash = _hash_path(rules_path)
    _write_snapshot(
        _rollback_checkpoint_dir(paths),
        source="rollback",
        reason="checkpoint",
        conf_path=conf_path,
        rules_path=rules_path,
        config_hash=config_hash,
        rules_hash=rules_hash,
        created_at_epoch=int(time.time()),
    )
    return _rollback_checkpoint_dir(paths)


def clear_rollback_checkpoint(paths: Paths) -> None:
    shutil.rmtree(_rollback_checkpoint_dir(paths), ignore_errors=True)


def capture_snapshot(
    paths: Paths,
    *,
    source: str,
    reason: str,
    limit: int = 5,
    window_seconds: int = 600,
) -> Optional[Path]:
    if not _state_exists(paths):
        return None
    config_hash = _hash_path(paths.loha_conf)
    rules_hash = _hash_path(paths.rules_conf)
    paths.history_dir.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    now_ns = time.time_ns()
    current = list_snapshots(paths)
    if current:
        latest = current[0]
        if latest.config_hash == config_hash and latest.rules_hash == rules_hash:
            return latest.path
        if window_seconds > 0 and now - latest.updated_at_epoch <= window_seconds:
            shutil.rmtree(latest.path, ignore_errors=True)
            target = latest.path
        else:
            target = paths.history_dir / _snapshot_dir_name(now, now_ns, source, reason)
    else:
        target = paths.history_dir / _snapshot_dir_name(now, now_ns, source, reason)
    _write_snapshot(
        target,
        source=source,
        reason=reason,
        conf_path=paths.loha_conf,
        rules_path=paths.rules_conf,
        config_hash=config_hash,
        rules_hash=rules_hash,
        created_at_epoch=now,
    )
    snapshots = list_snapshots(paths)
    for entry in snapshots[limit:]:
        shutil.rmtree(entry.path, ignore_errors=True)
    return target


def capture_snapshot_if_enabled(
    paths: Paths,
    *,
    source: str,
    reason: str,
    limit: int = 5,
    window_seconds: int = 600,
) -> Optional[Path]:
    if not _state_exists(paths):
        return None
    if not history_enabled(paths):
        return None
    return capture_snapshot(
        paths,
        source=source,
        reason=reason,
        limit=limit,
        window_seconds=window_seconds,
    )


def history_enabled(paths: Paths) -> bool:
    if not paths.loha_conf.exists():
        return True
    try:
        config = load_config(paths.loha_conf)
    except Exception:
        return True
    return config["ENABLE_CONFIG_HISTORY"] == "on"


def write_state_files(
    paths: Paths,
    *,
    config_text: str,
    rules_text: str,
) -> None:
    paths.etc_dir.mkdir(parents=True, exist_ok=True)
    temp_config = paths.loha_conf.with_name(paths.loha_conf.name + ".tmp")
    temp_rules = paths.rules_conf.with_name(paths.rules_conf.name + ".tmp")
    temp_config.write_text(config_text, encoding="utf-8")
    temp_rules.write_text(rules_text, encoding="utf-8")
    temp_config.replace(paths.loha_conf)
    temp_rules.replace(paths.rules_conf)


def write_transaction(
    paths: Paths,
    *,
    config_text: str,
    rules_text: str,
    source: str,
    reason: str,
) -> None:
    from .control_tx import commit_desired_state

    commit_desired_state(
        paths,
        config_text=config_text,
        rules_text=rules_text,
        source=source,
        reason=reason,
    )


def _snapshot_file(entry: HistoryEntry, name: str) -> Path:
    return entry.path / name


def rollback_snapshot(
    paths: Paths,
    selector: str,
    *,
    apply_callback: Optional[Callable[[], str]] = None,
) -> RollbackOutcome:
    from .control_tx import commit_desired_state, control_file_lock

    snapshots = list_snapshots(paths)
    checkpoint = load_rollback_checkpoint(paths)
    if selector == "latest":
        if checkpoint is not None:
            target = checkpoint
            restored_from = "rollback_checkpoint"
        elif snapshots:
            target = snapshots[0]
            restored_from = "snapshot"
        else:
            raise HistoryError("no configuration snapshots are available")
    else:
        restored_from = "snapshot"
        if not selector.isdigit():
            raise HistoryError("rollback selector must be latest or a 1-based index")
        index = int(selector, 10) - 1
        if index < 0 or index >= len(snapshots):
            raise HistoryError("rollback index is out of range")
        target = snapshots[index]

    backup_dir = Path(tempfile.mkdtemp(prefix="loha-rollback-", dir=str(paths.history_dir.parent)))
    preserve_backup = False
    apply_message = ""
    try:
        with control_file_lock(paths):
            if paths.loha_conf.exists():
                shutil.copy2(paths.loha_conf, backup_dir / "loha.conf")
            if paths.rules_conf.exists():
                shutil.copy2(paths.rules_conf, backup_dir / "rules.conf")

            snapshot_conf = _snapshot_file(target, "loha.conf")
            snapshot_rules = _snapshot_file(target, "rules.conf")
            if not snapshot_conf.exists():
                raise HistoryError("rollback snapshot is missing loha.conf")
            rollback_config_text = snapshot_conf.read_text(encoding="utf-8")
            rollback_rules_text = snapshot_rules.read_text(encoding="utf-8") if snapshot_rules.exists() else ""
            commit_desired_state(
                paths,
                config_text=rollback_config_text,
                rules_text=rollback_rules_text,
                source="rollback",
                reason=f"rollback-{selector}",
                clear_rollback_checkpoint_after_write=False,
                assume_locked=True,
            )
            _write_rollback_checkpoint(
                paths,
                conf_path=backup_dir / "loha.conf",
                rules_path=backup_dir / "rules.conf",
            )

        if apply_callback is not None:
            try:
                apply_message = apply_callback() or ""
            except Exception as exc:
                with control_file_lock(paths):
                    if not (backup_dir / "loha.conf").exists():
                        raise HistoryError("rollback recovery failed; previous loha.conf is unavailable") from exc
                    commit_desired_state(
                        paths,
                        config_text=(backup_dir / "loha.conf").read_text(encoding="utf-8"),
                        rules_text=(backup_dir / "rules.conf").read_text(encoding="utf-8")
                        if (backup_dir / "rules.conf").exists()
                        else "",
                        source="rollback",
                        reason="rollback-recovery",
                        clear_rollback_checkpoint_after_write=False,
                        assume_locked=True,
                    )
                    clear_rollback_checkpoint(paths)
                try:
                    apply_callback()
                except Exception:
                    preserve_backup = True
                    raise HistoryError(
                        f"rollback apply failed and automatic recovery also failed; rescue files kept in {backup_dir}",
                        rescue_dir=backup_dir,
                    ) from exc
                raise HistoryError("rollback apply failed; previous files were restored", recovered=True) from exc
    finally:
        if backup_dir.exists() and not preserve_backup:
            shutil.rmtree(backup_dir, ignore_errors=True)
    return RollbackOutcome(entry=target, apply_message=apply_message, restored_from=restored_from)
