import argparse
from pathlib import Path
from typing import Optional

from .config import load_config
from .exceptions import ApplyError, ConfigValidationError
from .i18n import RuntimeI18N, build_runtime_i18n_for_paths, render_localized_message
from .models import LocalizedMessage, Paths, RenderContext
from .render import render_ruleset
from .runtime_binding import resolve_runtime_binding
from .rules import load_rules
from .system import SubprocessSystemAdapter, SystemAdapter


class LoaderService:
    def __init__(self, paths: Optional[Paths] = None, adapter: Optional[SystemAdapter] = None) -> None:
        self.paths = paths or Paths()
        self.adapter = adapter or SubprocessSystemAdapter()

    def load_context(self) -> RenderContext:
        config = load_config(self.paths.loha_conf)
        rules = load_rules(self.paths.rules_conf)
        return RenderContext(config=config, rules=rules)

    def _validate_runtime_binding(self, context: RenderContext) -> None:
        resolve_runtime_binding(context.config.as_dict(), self.adapter)

    def render(self):
        context = self.load_context()
        self._validate_runtime_binding(context)
        return render_ruleset(context)

    def _control_state_matches(self, rendered) -> bool:
        if not self.paths.control_state_file.exists():
            return False
        return self.paths.control_state_file.read_text(encoding="utf-8").strip() == rendered.control_state.strip()

    def apply_result(self, *, mode: str, check_only: bool = False) -> LocalizedMessage:
        rendered = self.render()
        effective_mode = mode
        if effective_mode == "reload" and not self._control_state_matches(rendered):
            effective_mode = "full"
        if effective_mode == "reload":
            self.adapter.nft_apply(rendered.map_update, check_only=check_only)
            if not check_only:
                self.paths.run_dir.mkdir(parents=True, exist_ok=True)
                self.paths.debug_ruleset_file.write_text(rendered.full_ruleset, encoding="utf-8")
            return LocalizedMessage(
                "loader.apply.reload",
                "Mappings hot-swapped successfully.",
            )
        self.paths.run_dir.mkdir(parents=True, exist_ok=True)
        self.adapter.nft_apply(rendered.full_ruleset, check_only=check_only)
        if not check_only:
            self.paths.debug_ruleset_file.write_text(rendered.full_ruleset, encoding="utf-8")
            self.paths.control_state_file.write_text(rendered.control_state + "\n", encoding="utf-8")
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
    ) -> str:
        return render_localized_message(self.apply_result(mode=mode, check_only=check_only), runtime)


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
