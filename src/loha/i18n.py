import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .constants import DEFAULT_LOCALE, LITERAL_TOKENS, REPO_ROOT
from .exceptions import LocaleLintError
from .input_parsing import InputValidationError, parse_menu_indices
from .models import LocaleCatalog, LocalizedMessage, Paths
from .toml_compat import load_toml_bytes


PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")
CONF_VALUE_RE = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*)$")
LOCALE_DISPLAY_NAME_FALLBACKS = {
    "en_US": "English",
    "zh_CN": "简体中文",
}


def _flatten(prefix: str, value, output: Dict[str, str]) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else key
            _flatten(next_prefix, nested, output)
        return
    output[prefix] = str(value)


def load_catalog(path: Path) -> LocaleCatalog:
    data = load_toml_bytes(path.read_bytes())
    meta = data.get("meta", {})
    messages = {}
    _flatten("", data.get("messages", {}), messages)
    locale = str(meta.get("locale", path.stem))
    display_name = str(meta.get("name", "")).strip() or LOCALE_DISPLAY_NAME_FALLBACKS.get(locale, path.stem)
    return LocaleCatalog(
        locale=locale,
        fallback=str(meta.get("fallback", "en_US")),
        messages=messages,
        display_name=display_name,
        glossary={str(k): str(v) for k, v in data.get("glossary", {}).items()},
        literal_tokens=tuple(data.get("lint", {}).get("literal_tokens", LITERAL_TOKENS)),
        required_terms={str(k): str(v) for k, v in data.get("lint", {}).get("required_terms", {}).items()},
        forbidden_substrings=tuple(data.get("lint", {}).get("forbidden_substrings", [])),
    )


def load_catalogs(directory: Path) -> Dict[str, LocaleCatalog]:
    catalogs = {}
    for path in sorted(directory.glob("*.toml")):
        catalog = load_catalog(path)
        catalogs[catalog.locale] = catalog
    return catalogs


def _placeholder_sequence(text: str) -> Tuple[str, ...]:
    return tuple(match.group(1) for match in PLACEHOLDER_RE.finditer(text))


def lint_catalogs(catalogs: Mapping[str, LocaleCatalog], source_locale: str = "en_US") -> None:
    if source_locale not in catalogs:
        raise LocaleLintError(f"source locale is missing: {source_locale}")
    source = catalogs[source_locale]
    source_keys = set(source.messages)
    for locale, catalog in catalogs.items():
        missing = sorted(source_keys - set(catalog.messages))
        extra = sorted(set(catalog.messages) - source_keys)
        if missing or extra:
            raise LocaleLintError(
                f"{locale}: locale key mismatch; missing={missing or '[]'} extra={extra or '[]'}"
            )
        for key in source.messages:
            source_text = source.messages[key]
            translated = catalog.messages[key]
            if _placeholder_sequence(source_text) != _placeholder_sequence(translated):
                raise LocaleLintError(f"{locale}: placeholder mismatch for key {key}")
            for token in catalog.literal_tokens:
                if token in source_text and token not in translated:
                    raise LocaleLintError(f"{locale}: literal token {token!r} must stay unchanged in {key}")
            for source_term, target_term in catalog.required_terms.items():
                if source_term in source_text and target_term not in translated:
                    raise LocaleLintError(
                        f"{locale}: glossary term {source_term!r} must map to {target_term!r} in {key}"
                    )
            for forbidden in catalog.forbidden_substrings:
                if forbidden in translated:
                    raise LocaleLintError(f"{locale}: forbidden substring {forbidden!r} found in {key}")


class CatalogManager:
    def __init__(self, catalogs: Mapping[str, LocaleCatalog], default_locale: str = "en_US") -> None:
        self.catalogs = dict(catalogs)
        self.default_locale = default_locale

    def translate(self, key: str, *, locale: str, **values) -> str:
        catalog = self.catalogs.get(locale) or self.catalogs[self.default_locale]
        template = catalog.messages.get(key)
        if template is None and catalog.fallback in self.catalogs:
            template = self.catalogs[catalog.fallback].messages.get(key)
        if template is None:
            template = self.catalogs[self.default_locale].messages.get(key, key)
        return template.format(**values)


@dataclass(frozen=True)
class RuntimeI18N:
    manager: CatalogManager
    catalogs: Mapping[str, LocaleCatalog]
    locale: str
    default_locale: str = DEFAULT_LOCALE

    def t(self, key: str, default: Optional[str] = None, **values) -> str:
        translated = self.manager.translate(key, locale=self.locale, **values)
        if translated == key and default is not None:
            return default.format(**values)
        return translated

    def locale_name(self, locale: Optional[str] = None) -> str:
        catalog = self.catalogs.get(locale or self.locale)
        if catalog is None:
            return locale or self.locale
        return catalog.display_name or catalog.locale

    @property
    def available_locales(self) -> Tuple[str, ...]:
        return tuple(sorted(self.catalogs))


def translate_text(
    translate: Optional[Callable[[str, str], str]],
    key: str,
    default: str,
    **values,
) -> str:
    if translate is None:
        template = default
    else:
        try:
            template = translate(key, default, **values)
        except TypeError:
            template = translate(key, default)
    return template.format(**values)


def runtime_template(runtime: Optional[RuntimeI18N], key: str, default: str) -> str:
    if runtime is None:
        return default
    catalog = runtime.catalogs.get(runtime.locale) or runtime.catalogs.get(runtime.default_locale)
    template = catalog.messages.get(key) if catalog is not None else None
    if template is None and catalog is not None and catalog.fallback in runtime.catalogs:
        template = runtime.catalogs[catalog.fallback].messages.get(key)
    if template is None and runtime.default_locale in runtime.catalogs:
        template = runtime.catalogs[runtime.default_locale].messages.get(key)
    return template or default


def runtime_translate(runtime: Optional[RuntimeI18N], key: str, default: str, **values) -> str:
    if runtime is None:
        return default.format(**values)
    return runtime.t(key, default, **values)


def render_localized_message(message: LocalizedMessage, runtime: Optional[RuntimeI18N] = None) -> str:
    translate = None if runtime is None else lambda key, default: runtime_template(runtime, key, default)
    return message.render(translate)


def render_localized_messages(
    messages: Iterable[LocalizedMessage],
    runtime: Optional[RuntimeI18N] = None,
) -> Tuple[str, ...]:
    return tuple(render_localized_message(message, runtime) for message in messages)


def normalize_locale(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    raw = raw.replace("-", "_")
    if "_" not in raw:
        return raw.lower()
    language, territory = raw.split("_", 1)
    return f"{language.lower()}_{territory.upper()}"


def detect_env_locale(environ: Optional[Mapping[str, str]] = None) -> str:
    environ = environ or os.environ
    for key in ("LOHA_LANG", "LC_ALL", "LC_MESSAGES", "LANG"):
        value = normalize_locale(environ.get(key, ""))
        if value:
            return value.split(".", 1)[0]
    return ""


def pick_locale(
    catalogs: Mapping[str, LocaleCatalog],
    requested_locale: str,
    default_locale: str = DEFAULT_LOCALE,
) -> str:
    requested = normalize_locale(requested_locale)
    if requested in catalogs:
        return requested
    if requested:
        language = requested.split("_", 1)[0]
        for code in sorted(catalogs):
            if code.startswith(f"{language}_"):
                return code
        common_map = {"en": "en_US", "zh": "zh_CN", "ja": "ja_JP"}
        mapped = common_map.get(language, "")
        if mapped in catalogs:
            return mapped
    if default_locale in catalogs:
        return default_locale
    if catalogs:
        return sorted(catalogs)[0]
    return default_locale


def decode_config_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    if "\\\\" in value or '\\"' in value:
        value = value.replace("\\\\", "\\").replace('\\"', '"')
    return value.strip()


def read_first_config_value(key: str, candidates: Sequence[Path]) -> str:
    for path in candidates:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = CONF_VALUE_RE.match(line)
            if not match:
                continue
            current_key, raw_value = match.groups()
            if current_key == key:
                return decode_config_value(raw_value)
    return ""


def resolve_locale_directory(paths: Optional[Paths] = None) -> Path:
    candidate = getattr(paths, "locale_dir", None) if paths is not None else None
    repo_dir = REPO_ROOT / "locales"
    if repo_dir.is_dir():
        return repo_dir
    if isinstance(candidate, Path) and candidate.is_dir():
        return candidate
    if isinstance(candidate, Path):
        return candidate
    return repo_dir


def build_runtime_i18n(
    locale_dir: Path,
    *,
    requested_locale: str = "",
    default_locale: str = DEFAULT_LOCALE,
) -> RuntimeI18N:
    catalogs = load_catalogs(locale_dir)
    lint_catalogs(catalogs, source_locale=default_locale)
    selected = pick_locale(catalogs, requested_locale or detect_env_locale(), default_locale)
    return RuntimeI18N(
        manager=CatalogManager(catalogs, default_locale=default_locale),
        catalogs=catalogs,
        locale=selected,
        default_locale=default_locale,
    )


def build_runtime_i18n_for_paths(
    paths: Optional[Paths] = None,
    *,
    requested_locale: str = "",
    extra_config_candidates: Sequence[Path] = (),
) -> RuntimeI18N:
    locale_dir = resolve_locale_directory(paths)
    config_candidates: List[Path] = list(extra_config_candidates)
    if paths is not None:
        config_candidates.append(paths.loha_conf)
    locale_from_conf = read_first_config_value("LOCALE", config_candidates)
    requested = requested_locale or locale_from_conf or detect_env_locale()
    return build_runtime_i18n(locale_dir, requested_locale=requested)


def select_locale_interactive(
    runtime: RuntimeI18N,
    *,
    recommended_locale: str,
    input_func=None,
    output_func=print,
    title_key: str = "install.language.title",
    title_default: str = "LOHA Language Selection",
    description_key: str = "install.language.description",
    description_default: str = "Choose installer language.",
    prompt_key: str = "install.language.prompt",
    prompt_default: str = "Enter number or locale code (press Enter for {recommended})",
    recommended_suffix_key: str = "install.language.recommended_suffix",
    recommended_suffix_default: str = "(recommended)",
) -> str:
    input_func = input_func or input
    output_func(runtime.t(title_key, title_default))
    output_func(runtime.t(description_key, description_default))
    locales = runtime.available_locales
    for index, locale in enumerate(locales, start=1):
        suffix = ""
        if locale == recommended_locale:
            suffix = f" {runtime.t(recommended_suffix_key, recommended_suffix_default)}"
        output_func(f" {index}. {locale} - {runtime.locale_name(locale)}{suffix}")
    while True:
        raw = input_func(
            runtime.t(
                prompt_key,
                prompt_default,
                recommended=recommended_locale,
            )
            + ": "
        ).strip()
        if not raw:
            return recommended_locale
        try:
            index = parse_menu_indices(raw, size=len(locales), allow_multiple=False)[0]
            return locales[index]
        except InputValidationError:
            pass
        normalized = normalize_locale(raw)
        if normalized in runtime.catalogs:
            return normalized
        if normalized:
            language = normalized.split("_", 1)[0]
            matches = [code for code in locales if code.startswith(f"{language}_")]
            if matches:
                return matches[0]
        output_func(runtime.t("common.invalid_choice", "Invalid choice."))
