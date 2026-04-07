import argparse
import time
from pathlib import Path
from typing import Optional

from .control_tx import control_file_lock, read_desired_state, read_runtime_state, write_runtime_state
from .exceptions import ApplyError, ConfigValidationError
from .i18n import RuntimeI18N, build_runtime_i18n_for_paths, render_localized_message
from .models import DesiredStateSnapshot, LocalizedMessage, Paths, RenderContext, RuntimeStateSnapshot
from .render import render_ruleset
from .runtime_binding import resolve_runtime_binding
from .system import SubprocessSystemAdapter, SystemAdapter


class LoaderService:
    def __init__(self, paths: Optional[Paths] = None, adapter: Optional[SystemAdapter] = None) -> None:
        self.paths = paths or Paths()
        self.adapter = adapter or SubprocessSystemAdapter()

    def load_context(self, *, snapshot: Optional[DesiredStateSnapshot] = None) -> RenderContext:
        snapshot = snapshot or read_desired_state(self.paths)
        return RenderContext(config=snapshot.config, rules=snapshot.rules)

    def _validate_runtime_binding(self, context: RenderContext) -> None:
        resolve_runtime_binding(context.config.as_dict(), self.adapter)

    def render(self, *, snapshot: Optional[DesiredStateSnapshot] = None):
        context = self.load_context(snapshot=snapshot)
        self._validate_runtime_binding(context)
        return render_ruleset(context)

    def _control_state_matches(self, rendered) -> bool:
        if not self.paths.control_state_file.exists():
            return False
        return self.paths.control_state_file.read_text(encoding="utf-8").strip() == rendered.control_state.strip()

    def apply_result(
        self,
        *,
        mode: str,
        check_only: bool = False,
        snapshot: Optional[DesiredStateSnapshot] = None,
    ) -> LocalizedMessage:
        with control_file_lock(self.paths):
            desired = snapshot or read_desired_state(self.paths, assume_locked=True)
            rendered = self.render(snapshot=desired)
            effective_mode = mode
            if effective_mode == "reload" and not self._control_state_matches(rendered):
                effective_mode = "full"
            runtime_state = read_runtime_state(self.paths)
            now = int(time.time())
            try:
                if effective_mode == "reload":
                    self.adapter.nft_apply(rendered.map_update, check_only=check_only)
                    if not check_only:
                        self.paths.run_dir.mkdir(parents=True, exist_ok=True)
                        self.paths.debug_ruleset_file.write_text(rendered.full_ruleset, encoding="utf-8")
                else:
                    self.paths.run_dir.mkdir(parents=True, exist_ok=True)
                    self.adapter.nft_apply(rendered.full_ruleset, check_only=check_only)
                    if not check_only:
                        self.paths.debug_ruleset_file.write_text(rendered.full_ruleset, encoding="utf-8")
                        self.paths.control_state_file.write_text(rendered.control_state + "\n", encoding="utf-8")
            except Exception as exc:
                if not check_only:
                    pending_actions = list(runtime_state.pending_actions)
                    if "reload" not in pending_actions:
                        pending_actions.append("reload")
                    write_runtime_state(
                        self.paths,
                        RuntimeStateSnapshot(
                            desired_revision=desired.revision,
                            applied_revision=runtime_state.applied_revision,
                            last_apply_mode=effective_mode,
                            last_apply_status="failed",
                            last_error=str(exc),
                            pending_actions=tuple(pending_actions),
                            updated_at_epoch=now,
                        ),
                        assume_locked=True,
                    )
                raise
            if not check_only:
                pending_actions = tuple(action for action in runtime_state.pending_actions if action != "reload")
                write_runtime_state(
                    self.paths,
                    RuntimeStateSnapshot(
                        desired_revision=desired.revision,
                        applied_revision=desired.revision,
                        last_apply_mode=effective_mode,
                        last_apply_status="applied",
                        last_error="",
                        pending_actions=pending_actions,
                        updated_at_epoch=now,
                    ),
                    assume_locked=True,
                )
            if effective_mode == "reload":
                return LocalizedMessage(
                    "loader.apply.reload",
                    "Mappings hot-swapped successfully.",
                )
            return LocalizedMessage(
                "loader.apply.full",
                "Full ruleset initialized successfully.",
            )

    def apply(
        self,
        *,
        mode: str,
        check_only: bool = False,
        runtime: Optional[RuntimeI18N] = None,
        snapshot: Optional[DesiredStateSnapshot] = None,
    ) -> str:
        return render_localized_message(self.apply_result(mode=mode, check_only=check_only, snapshot=snapshot), runtime)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loha-loader")
    parser.add_argument("mode", nargs="?", default="full", choices=["full", "reload", "check"])
    parser.add_argument("--etc-dir")
    parser.add_argument("--run-dir")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    paths = Paths(
        etc_dir=Path(args.etc_dir) if args.etc_dir else Paths().etc_dir,
        run_dir=Path(args.run_dir) if args.run_dir else Paths().run_dir,
    )
    runtime = build_runtime_i18n_for_paths(paths)
    service = LoaderService(paths=paths)
    check_only = args.mode == "check"
    mode = "full" if check_only else args.mode
    message = service.apply(mode=mode, check_only=check_only, runtime=runtime)
    print(message)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
