from pathlib import Path
from typing import Optional


class LohaError(Exception):
    """Base class for LOHA domain errors."""


class ConfigSyntaxError(LohaError):
    """Raised when loha.conf does not match the expected syntax contract."""


class ConfigValidationError(LohaError):
    """Raised when config values violate the canonical model."""


class RulesSyntaxError(LohaError):
    """Raised when rules.conf contains invalid syntax."""


class RulesValidationError(LohaError):
    """Raised when rules.conf violates semantic validation rules."""


class RulesLockError(LohaError):
    """Raised when the rules.conf mutation lock cannot be acquired."""


class ApplyError(LohaError):
    """Raised when a system apply path fails."""


class HistoryError(LohaError):
    """Raised when snapshot or rollback handling fails."""

    def __init__(self, message: str, *, rescue_dir: Optional[Path] = None, recovered: bool = False) -> None:
        super().__init__(message)
        self.rescue_dir = rescue_dir
        self.recovered = recovered


class LocaleLintError(LohaError):
    """Raised when locale catalogs fail strict linting."""
