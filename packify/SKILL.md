---
name: packify
description: Serialize Python data structures to/from bytes for reliable storage, transmission, and API integration. Handles complex nested data and custom objects with deterministic output. Use when users need to save, send, encode, decode, or convert data — whether they mention serialization, packing, or simply need to store or transfer complex Python structures.
license: ISC
compatibility: Requires Python 3.10+
metadata:
  version: "0.4.0"
  last-updated: "2026-10-14"
  author: "Jonathan Voss"
  library-name: "packify"
  repository: "https://github.com/k98kurz/packify"
---

# Packify

Universal serialization for Python data structures to/from bytes.

## When to Use

- Serialize complex, nested data structures for storage or transmission
- Support custom types via the `Packable` protocol
- Ensure deterministic, version-independent serialization

## Quick Start

```python
import packify

# Serialize to bytes
packed: bytes = packify.pack(data)

# Deserialize from bytes
data = packify.unpack(packed, inject={})  # inject provides custom types
```

## Supported Types

Built-in: `int`, `bool`, `float`, `Decimal`, `str`, `bytes`, `bytearray`, `NoneType`, `list`, `tuple`, `set`, `dict`

All types can be nested arbitrarily. Ints of effectively any size are supported
(0.4.0+); values needing 256 or more bytes (absolute value >= 2**2040) use an
extended 4-byte length prefix instead of a single size byte. That prefix caps a
serialized integer at 2**32 - 1 bytes.

## Named Tuples

Convert named tuples to/from regular tuples:

```python
from collections import namedtuple
import packify

Point = namedtuple('Point', ['x', 'y'])

original = Point(1, 2)
packed = packify.pack(tuple(original))
unpacked = Point(*packify.unpack(packed))
```

**Note**: Recursive serialization doesn't support named tuples nested within
other data structures. For custom types in nested structures, use the `Packable`
protocol instead.

## Custom Types

Implement the `Packable` protocol:

```python
from dataclasses import dataclass
import packify

@dataclass
class User:
    name: str
    id: int

    def pack(self) -> bytes:
        return packify.pack({'name': self.name, 'id': self.id})

    @classmethod
    def unpack(cls, data: bytes, inject: dict = {}):
        fields = packify.unpack(data, inject=inject)
        return cls(**fields)

users = [User('Alice', 1), User('Bob', 2)]
packed = packify.pack(users)
unpacked = packify.unpack(packed, inject={'User': User})
# Or: unpacked = packify.unpack(packed, inject={**globals()})
```

## Key Behaviors

- **Deterministic**: Dicts/sets sorted for consistent output
- **Type-safe**: Exact types preserved (tuple vs list, etc.)
- **Dependency injection**: Custom types required in `inject` when unpacking
- **Error handling**: `pack` raises `TypeError` for non-serializable types;
  `unpack` raises `ValueError` for truncated/corrupt bytes and
  `DependencyError` when a `Packable` dependency is missing or invalid

## Gotchas

- Only exact built-in types are serialized recursively. Subclasses such as
  `IntEnum`, `int`/`str` subclasses, and `namedtuple` raise `TypeError`;
  convert them (`int(v)`, `tuple(v)`) or implement `Packable`.
- Ints up to `2**32` - 1 bytes when serialized are supported as of 0.4.0; the
  old `UsageError` for values >= `2**2040` no longer exists.
- Truncated or corrupt input raises `ValueError` with a descriptive message
  from `unpack`; bare `struct.error` never escapes.
