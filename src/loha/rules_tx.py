import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from .config import render_canonical_text
from .exceptions import RulesLockError
from .history import write_transaction
from .rules import RulesFile, load_rules, render_rules_text


def _lock_dir(path: Path) -> Path:
    return path.with_name(path.name + ".lock.d")


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
def rules_file_lock(
    path: Path,
    *,
    timeout_seconds: float = 10.0,
    poll_interval_seconds: float = 0.1,
) -> Iterator[None]:
    lock_dir = _lock_dir(path)
    pid_file = _pid_file(lock_dir)
    deadline = time.monotonic() + max(0.0, timeout_seconds)

    while True:
        try:
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
                    "Another LOHA rules update may still be running."
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


def mutate_rules_transaction(
    paths,
    *,
    config,
    source: str,
    reason: str,
    mutate: Callable[[RulesFile], RulesFile],
    timeout_seconds: float = 10.0,
) -> RulesFile:
    with rules_file_lock(paths.rules_conf, timeout_seconds=timeout_seconds):
        current = load_rules(paths.rules_conf)
        updated = mutate(current)
        write_transaction(
            paths,
            config_text=render_canonical_text(config),
            rules_text=render_rules_text(updated),
            source=source,
            reason=reason,
        )
        return updated
