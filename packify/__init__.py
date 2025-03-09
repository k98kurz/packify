from .errors import UsageError
from .interface import Packable
from .serialization import pack, unpack, SerializableType


__version__ = '0.3.1'


def version() -> str:
    """Returns the current version of the packify package."""
    return __version__


__all__ = [
    'UsageError',
    'Packable',
    'pack',
    'unpack',
    'SerializableType',
    'version',
]