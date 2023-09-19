from __future__ import annotations
from typing import Protocol, runtime_checkable


@runtime_checkable
class Packable(Protocol):
    def pack(self) -> bytes:
        """Packs the instance into bytes."""
        ...

    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}) -> Packable:
        """Unpacks an instance from bytes. Must accept dependency
            injection to unpack other Packable types.
        """
        ...
