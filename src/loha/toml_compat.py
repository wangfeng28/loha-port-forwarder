try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


def load_toml_bytes(data: bytes):
    return tomllib.loads(data.decode("utf-8"))
