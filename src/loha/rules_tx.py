import os
import time
from typing import Callable

from .config import recommended_config, render_canonical_text
from .control_tx import commit_desired_state, control_file_lock, read_desired_state
from .exceptions import ControlLockError, RulesLockError
from .rules import RulesFile, render_rules_text


def rules_file_lock(
    path,
    *,
    timeout_seconds: float = 10.0,
    poll_interval_seconds: float = 0.1,
):
    sibling_run_dir = path.parent.parent / "run"
    lock_root = sibling_run_dir if path.parent.name == "etc" else path.parent
    lock_dir = lock_root / "control.lock.d"
    pid_file = lock_dir / "pid"

    class _LockContext:
        def __enter__(self):
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
                        raise RulesLockError(
                            f"Timed out waiting for exclusive access to {path}. "
                            "Another LOHA control-plane update may still be running."
                        )
                    time.sleep(poll_interval_seconds)
            pid_file.write_text(f"{os.getpid()}\n", encoding="utf-8")
            return None

        def __exit__(self, exc_type, exc, tb):
            try:
                pid_file.unlink()
            except FileNotFoundError:
                pass
            try:
                lock_dir.rmdir()
            except OSError:
                pass
            return False

    return _LockContext()


def _pid_is_alive(pid_text: str) -> bool:
    if not pid_text.strip().isdigit():
        return False
    pid = int(pid_text.strip(), 10)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def mutate_rules_transaction(
    paths,
    *,
    config,
    source: str,
    reason: str,
    mutate: Callable[[RulesFile], RulesFile],
    timeout_seconds: float = 10.0,
) -> RulesFile:
    try:
        with control_file_lock(paths, timeout_seconds=timeout_seconds):
            if paths.loha_conf.exists():
                snapshot = read_desired_state(paths, assume_locked=True)
                current = snapshot.rules
                config = snapshot.config
            else:
                config = recommended_config()
                current = RulesFile()
            updated = mutate(current)
            commit_desired_state(
                paths,
                config_text=render_canonical_text(config),
                rules_text=render_rules_text(updated),
                source=source,
                reason=reason,
                assume_locked=True,
            )
            return updated
    except ControlLockError as exc:
        raise RulesLockError(str(exc)) from exc
