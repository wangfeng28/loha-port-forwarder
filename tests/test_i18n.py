import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from loha.i18n import (
    CatalogManager,
    build_runtime_i18n,
    lint_catalogs,
    load_catalog,
    load_catalogs,
    pick_locale,
    render_localized_message,
    resolve_locale_directory,
    runtime_template,
    select_locale_interactive,
    translate_text,
)
from loha.models import LocalizedMessage


class I18NTests(unittest.TestCase):
    def test_catalogs_load_and_lint(self):
        catalogs = load_catalogs(Path(__file__).resolve().parents[1] / "locales")
        lint_catalogs(catalogs)
        manager = CatalogManager(catalogs)
        self.assertEqual("外部接口", manager.translate("wizard.steps.external_ifs.title", locale="zh_CN"))

    def test_locale_picker_accepts_language_only(self):
        catalogs = load_catalogs(Path(__file__).resolve().parents[1] / "locales")
        self.assertEqual("zh_CN", pick_locale(catalogs, "zh"))

    def test_interactive_locale_selection_accepts_enter_for_recommended(self):
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="en_US")
        selected = select_locale_interactive(runtime, recommended_locale="zh_CN", input_func=lambda _prompt: "")
        self.assertEqual("zh_CN", selected)

    def test_interactive_locale_selection_lists_display_names(self):
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="en_US")
        output = []
        selected = select_locale_interactive(
            runtime,
            recommended_locale="zh_CN",
            input_func=lambda _prompt: "2",
            output_func=output.append,
        )
        self.assertEqual("zh_CN", selected)
        self.assertTrue(any("zh_CN - 简体中文" in line for line in output))

    def test_interactive_locale_selection_retries_invalid_numeric_choice(self):
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="en_US")
        output = []
        answers = iter(["9", "2"])
        selected = select_locale_interactive(
            runtime,
            recommended_locale="zh_CN",
            input_func=lambda _prompt: next(answers),
            output_func=output.append,
        )
        self.assertEqual("zh_CN", selected)
        self.assertTrue(any("Invalid choice." in line for line in output))

    def test_catalog_display_name_uses_known_locale_fallback_when_name_is_missing(self):
        temp_dir = Path(tempfile.mkdtemp())
        locale_path = temp_dir / "zh_CN.toml"
        locale_path.write_text(
            '[meta]\n'
            'locale = "zh_CN"\n'
            'fallback = "en_US"\n'
            '\n'
            '[messages.common]\n'
            'invalid_choice = "无效选项。"\n',
            encoding="utf-8",
        )
        catalog = load_catalog(locale_path)
        self.assertEqual("简体中文", catalog.display_name)

    def test_resolve_locale_directory_prefers_repo_locales_over_installed_locales(self):
        temp_dir = Path(tempfile.mkdtemp())
        repo_root = temp_dir / "repo"
        repo_locales = repo_root / "locales"
        repo_locales.mkdir(parents=True)
        installed_locales = temp_dir / "installed" / "locales"
        installed_locales.mkdir(parents=True)
        paths = SimpleNamespace(locale_dir=installed_locales)
        with patch("loha.i18n.REPO_ROOT", repo_root):
            self.assertEqual(repo_locales, resolve_locale_directory(paths))

    def test_shared_render_helpers_use_runtime_templates(self):
        runtime = build_runtime_i18n(Path(__file__).resolve().parents[1] / "locales", requested_locale="zh_CN")
        message = LocalizedMessage(
            "runtime_binding.notice.external_auto_materialized",
            "EXTERNAL_IFS=auto was resolved to {value} before saving; loha.conf will store that resolved value.",
            values={"value": "eth0"},
        )
        self.assertIn("已在保存前解析为 eth0", render_localized_message(message, runtime))
        self.assertEqual("外部接口", runtime_template(runtime, "wizard.steps.external_ifs.title", "fallback"))
        self.assertEqual("Canonical Values", translate_text(None, "unused", "Canonical Values"))


if __name__ == "__main__":
    unittest.main()
