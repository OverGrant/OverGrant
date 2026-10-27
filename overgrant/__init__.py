"""overgrant: local security scan of AI coding-agent setups."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("overgrant")
except PackageNotFoundError:  # running from a source checkout
    __version__ = "0.1.0"
