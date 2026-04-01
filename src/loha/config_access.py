from pathlib import Path
from typing import Mapping, Tuple

from .config import normalize_mapping, parse_canonical_text
from .models import CanonicalConfig, LocalizedMessage
from .runtime_binding import (
    sync_toggle_shortcut_state,
    sync_runtime_binding_state,
)
from .system import SystemAdapter


def parse_management_config_text(text: str):
    return parse_canonical_text(text)


def normalize_management_state(
    state: Mapping[str, str],
    adapter: SystemAdapter,
) -> Tuple[CanonicalConfig, Tuple[LocalizedMessage, ...]]:
    notices = []
    updated = sync_toggle_shortcut_state(state)
    updated, materialize_notices = sync_runtime_binding_state(updated, adapter, only_if_shortcuts=True)
    notices.extend(materialize_notices)
    return normalize_mapping(updated, materialize_defaults=True), tuple(notices)


def load_management_config(
    path: Path,
    adapter: SystemAdapter,
) -> Tuple[CanonicalConfig, Tuple[LocalizedMessage, ...]]:
    raw_state = parse_management_config_text(path.read_text(encoding="utf-8"))
    return normalize_management_state(raw_state, adapter)
