from typing import Optional, Tuple


class InputValidationError(ValueError):
    """Raised when interactive user input cannot be parsed safely."""


def parse_yes_no(raw: str, *, default: Optional[bool] = None) -> bool:
    normalized = raw.strip().lower()
    if not normalized:
        if default is None:
            raise InputValidationError("a yes/no answer is required")
        return default
    if normalized in {"y", "yes"}:
        return True
    if normalized in {"n", "no"}:
        return False
    raise InputValidationError("invalid yes/no answer")


def parse_menu_indices(raw: str, *, size: int, allow_multiple: bool) -> Tuple[int, ...]:
    tokens = [token.strip() for token in raw.split(",")]
    if any(not token for token in tokens):
        raise InputValidationError("selection contains an empty item")
    parsed = []
    seen = set()
    for token in tokens:
        if not token.isdigit():
            raise InputValidationError("selection must use numeric menu tokens")
        index = int(token, 10) - 1
        if index < 0 or index >= size:
            raise InputValidationError("selection is out of range")
        if index in seen:
            raise InputValidationError("selection contains duplicate items")
        seen.add(index)
        parsed.append(index)
    if not allow_multiple and len(parsed) != 1:
        raise InputValidationError("exactly one menu item is required")
    return tuple(parsed)
