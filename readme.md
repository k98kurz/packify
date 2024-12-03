# Packify

This is a simple package that allows one to serialize and deserialize
practically any data structure to and from bytes.

## Installation

```bash
pip install packify
```

## Usage

Usage is simple: import the package and call the pack/unpack functions.

```python
from packify import pack, unpack
from decimal import Decimal

data = {
    123: 432.1,
    "abc": "cba",
    b"abc": b"cba",
    "None": None,
    "true": True,
    "false": False,
    'list': [
        '123',
        123,
        b'123',
        True,
    ],
    'tuple': (
        '123',
        123,
        b'123',
        False,
    ),
    'set': {
        '123',
        123,
        b'123',
    },
    'Decimal': Decimal('123.321'),
}

packed = pack(data)
unpacked = unpack(packed)
assert type(packed) is bytes
assert unpacked == data
```

The following types are supported:

- int
- bool
- float
- Decimal
- str
- bytes
- bytearray
- NoneType
- list
- tuple
- set
- dict

Additionally, a simple duck-type interface/protocol, `Packable`, is included.
Any more complex data structure can be handled if it implements the `Packable`
interface. `Packable` is defined as follows:

```python
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
```

If a class that implements `Packable` is used, then it needs to be included in
the `inject` parameter for calls to `unpack`. For example:

```python
from dataclasses import dataclass, field
from packify import pack, unpack

@dataclass
class Thing:
    data: str = field()
    amount: int = field()
    fraction: float = field()
    parts: list = field()
    def __eq__(self, other) -> bool:
        return type(self) is type(other) and self.pack() == other.pack()
    def pack(self) -> bytes:
        return pack((self.data, self.amount, self.fraction, self.parts))
    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}):
        return cls(*unpack(data, inject={**globals(), **inject}))

thing = Thing("hello world", 123, 420.69, ['a', b'b', 3])
packed = pack(thing)
unpacked = unpack(packed, inject={'Thing': Thing})
assert unpacked == thing
# alternately, the easier but less specific method is to copy globals
unpacked = unpack(packed, inject={**globals()})
assert unpacked == thing
```

As long as the class implements the `Packable` protocol, it can be included in
lists, sets, tuples, and dicts (assuming it is hashable for set or to be used as
a dict key), and it will just work.

Technically, monkey-patching is also possible:

```python
import packify
packify.SomeClass = SomeClass

packed = packify.pack(SomeClass())
unpacked = packify.unpack(packed)
```

This is not encouraged, but it is possible if you do not want to pass `inject`
parameters. (Code should be easier to test when using the `inject` parameter
instead of monkey-patching.)

The `pack` function will raise a `UsageError` if the data is not serializable,
and the `unpack` function will raise a `UsageError` if it is unable to find a
`Packable` class to unpack the relevant item.

For convenience/use in annotations, a `SerializableType` is exported which
includes the above type information.

Full documentation can be found in
[dox.md](https://github.com/k98kurz/packify/blob/master/dox.md), which was
generated automagically by [autodox](https://pypi.org/project/autodox).

## Tests

Since it is a simple package, there are only 9 tests, and they are mostly e2e
tests of both the `pack` and `unpack` functions. After using this for a year, I
found an edge case, and there is a test to prove it has been fixed. To run the
tests, clone the repository and use the following:

```bash
python tests/test_serialization.py
```

## License

Copyleft (c) 2023, 2024 k98kurz

Permission to use, copy, modify, and/or distribute this software
for any purpose with or without fee is hereby granted, provided
that the above copyleft notice and this permission notice appear in
all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
