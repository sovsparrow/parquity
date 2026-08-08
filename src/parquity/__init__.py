"""Package metadata for Parquity."""

from importlib import metadata

__version__: str
__all__ = ["__version__"]


def __getattr__(name: str) -> str:
    if name == "__version__":
        return metadata.version("parquity")
    raise AttributeError(name)
