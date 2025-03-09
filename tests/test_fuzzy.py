from __future__ import annotations
from context import pack, unpack, Packable, SerializableType
from dataclasses import dataclass, field
from decimal import Decimal
import random
import struct
import unittest


@dataclass
class StrWrapper:
    data: str = field()

    def __eq__(self, other) -> bool:
        return type(self) is type(other) and self.data == other.data

    def __hash__(self) -> int:
        return hash(("StrWrapper", self.data))

    def pack(self) -> bytes:
        return bytes(self.data, 'utf-8')

    @classmethod
    def unpack(cls, data: bytes, /, *, inject: dict = {}) -> StrWrapper:
        return cls(str(data, 'utf-8'))


class PackableMapEntry:
    key: Packable
    value: Packable

    def __init__(self, key: Packable,
                 value: Packable) -> None:
        self.key = key
        self.value = value

    def __hash__(self) -> int:
        return hash((self.key, self.value))

    def __str__(self) -> str:
        return f"PackableMapEntry(key={self.key}, value={self.value})"

    def __eq__(self, other: PackableMapEntry) -> bool:
        return type(other) is type(self) and other.key == self.key and \
            other.value == self.value

    def pack(self) -> bytes:
        key = bytes(self.key.__class__.__name__, 'utf-8').hex()
        key = bytes(key, 'utf-8') + b'_' + self.key.pack()
        value = bytes(self.value.__class__.__name__, 'utf-8').hex()
        value = bytes(value, 'utf-8') + b'_' + self.value.pack()
        return struct.pack(
            f'!HH{len(key)}s{len(value)}s',
            len(key),
            len(value),
            key,
            value
        )

    @classmethod
    def unpack(cls, data: bytes, inject: dict = {}) -> PackableMapEntry:
        key_len, value_len, data = struct.unpack(f'!HH{len(data)-4}s', data)
        key_data, value_data = struct.unpack(f'{key_len}s{value_len}s', data)
        dependencies = {**globals(), **inject}

        assert type(key_data) is bytes
        key_class, key_data = key_data.split(b'_', 1)
        key_class = str(bytes.fromhex(str(key_class, 'utf-8')), 'utf-8')
        key = dependencies[key_class].unpack(key_data, inject=inject)

        assert type(value_data) is bytes
        value_class, value_data = value_data.split(b'_', 1)
        value_class = str(bytes.fromhex(str(value_class, 'utf-8')), 'utf-8')
        value = dependencies[value_class].unpack(value_data, inject=inject)

        return cls(key, value)


class FuzzTest(unittest.TestCase):
    inject = {
        "StrWrapper": StrWrapper,
        "PackableMapEntry": PackableMapEntry,
    }

    def generate_basic_type(self) -> SerializableType:
        t = random.choice([int, float, str, bytes])
        if t is int:
            return random.randint(-1000000, 1000000)
        elif t is float:
            return random.uniform(-1000000, 1000000)
        elif t is str:
            return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, 100)))
        elif t is bytes:
            return bytes(random.randint(0, 255) for _ in range(random.randint(1, 100)))
        elif t is bool:
            return random.choice([True, False])
        elif t is Decimal:
            return Decimal(random.uniform(-1000000, 1000000))

    def generate_non_container(self) -> SerializableType:
        t = random.choice([PackableMapEntry, StrWrapper, 'other'])
        if t is PackableMapEntry:
            return PackableMapEntry(
                StrWrapper(''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, 100)))),
                StrWrapper(''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, 100)))),
            )
        elif t is StrWrapper:
            return StrWrapper(''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, 100))))
        else:
            return self.generate_basic_type()

    def generate_vector(self, recursive_limit: int = 3) -> SerializableType:
        if recursive_limit <= 0:
            return self.generate_non_container()
        size_limit = 66 // recursive_limit
        t = random.choice([int, float, str, bytes, bool, Decimal, dict, list, set, tuple, PackableMapEntry, StrWrapper])
        if t is int:
            return random.randint(-1000000, 1000000)
        elif t is float:
            return random.uniform(-1000000, 1000000)
        elif t is str:
            return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, size_limit)))
        elif t is bytes:
            return bytes(random.randint(0, 255) for _ in range(random.randint(1, size_limit)))
        elif t is bool:
            return random.choice([True, False])
        elif t is Decimal:
            return Decimal(random.uniform(-1000000, 1000000))
        elif t is dict:
            return {self.generate_non_container(): self.generate_vector(recursive_limit - 1) for _ in range(random.randint(1, size_limit))}
        elif t is list:
            return [self.generate_vector(recursive_limit - 1) for _ in range(random.randint(1, size_limit))]
        elif t is set:
            return set(self.generate_non_container() for _ in range(random.randint(1, size_limit)))
        elif t is tuple:
            return tuple(self.generate_vector(recursive_limit - 1) for _ in range(random.randint(1, size_limit)))
        elif t is PackableMapEntry:
            return PackableMapEntry(
                StrWrapper(''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, size_limit)))),
                StrWrapper(''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, size_limit)))),
            )
        elif t is StrWrapper:
            return StrWrapper(''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(1, size_limit))))

    def test_fuzz(self):
        for _ in range(1000):
            vector = self.generate_vector()
            packed = pack(vector)
            unpacked = unpack(packed, inject=self.inject)
            assert vector == unpacked, (vector, unpacked)


if __name__ == '__main__':
    unittest.main()
