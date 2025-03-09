from __future__ import annotations
from context import pack, unpack, Packable, UsageError
from dataclasses import dataclass, field
from decimal import Decimal
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


class TestSerialization(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        self.inject = {
            "StrWrapper": StrWrapper,
        }
        super().__init__(methodName)

    def test_pack_and_unpack_basic_types_e2e(self):
        vectors = [
            123,
            123.456,
            "hello world",
            b"yellow submarine",
            bytearray(b"just more bytes really"),
            Decimal('123.456'),
        ]
        for vector in vectors:
            packed = pack(vector)
            assert type(packed) is bytes
            unpacked = unpack(packed)
            assert type(unpacked) is type(vector)
            assert unpacked == vector

    def test_pack_and_unpack_list_e2e(self):
        data = [
            "hello world",
            b'hello world',
            bytearray(b'hello world'),
            1234,
            123.456,
            PackableMapEntry(
                StrWrapper("some key"),
                StrWrapper("some value"),
            ),
            None,
            Decimal('123.456'),
        ]
        packed = pack(data)
        unpacked = unpack(
            packed,
            inject={**self.inject, "PackableMapEntry": PackableMapEntry}
        )

        # compare all parts
        assert len(data) == len(unpacked)
        assert type(data) == type(unpacked)
        for i in range(len(data)):
            assert type(data[i]) == type(unpacked[i])
            if type(data[i]) is float:
                p1 = pack(data[i])
                p2 = pack(unpacked[i])
                assert p1 == p2
            else:
                assert data[i] == unpacked[i], f"expected {data[i]}, encountered {unpacked[i]}"

    def test_pack_and_unpack_set_e2e(self):
        data = set([
            123, 4321, "abc", "cba", b"abc", b"cba",
            PackableMapEntry(StrWrapper("123"), StrWrapper("321")),
            None,
            Decimal('123.456'),
        ])
        packed = pack(data)
        unpacked = unpack(
            packed,
            inject={"PackableMapEntry": PackableMapEntry}
        )

        # compare all parts
        assert len(data) == len(unpacked)
        assert type(data) == type(unpacked)
        for item in data:
            assert item in unpacked

    def test_pack_and_unpack_tuple_e2e(self):
        data = tuple([
            123, 4321, "abc", "cba", b"abc", b"cba",
            PackableMapEntry(StrWrapper("123"), StrWrapper("321")),
            None,
            Decimal('123.456'),
        ])
        packed = pack(data)
        unpacked = unpack(
            packed,
            inject={"PackableMapEntry": PackableMapEntry}
        )

        # compare all parts
        assert len(data) == len(unpacked)
        assert type(data) == type(unpacked)
        for item in data:
            assert item in unpacked

    def test_pack_and_unpack_dict_e2e(self):
        data = {
            123: 4321,
            "abc": "cba",
            b"abc": b"cba",
            StrWrapper("key"): PackableMapEntry(StrWrapper("123"), StrWrapper("321")),
            "None": None,
            "Decimal": Decimal('123.456'),
        }
        packed = pack(data)
        unpacked = unpack(
            packed,
            inject={**self.inject, "PackableMapEntry": PackableMapEntry}
        )

        # compare all parts
        assert len(data) == len(unpacked)
        assert type(data) == type(unpacked)
        for item in data:
            assert item in unpacked

    def test_pack_dict_is_deterministic(self):
        vector = {
            'str': 'abc',
            123: 321,
            'Decimal': Decimal('123.321'),
            'list': [
                'abc',
                123
            ]
        }
        packed = pack(vector)
        for _ in range(100):
            assert pack(vector) == packed

    def test_pack_set_is_deterministic(self):
        vector = {
            123,
            'abc',
            'str',
            Decimal('123.321'),
            (123, '321'),
        }
        packed = pack(vector)
        for _ in range(100):
            assert pack(vector) == packed

    def test_unserializable_type_raises_error(self):
        with self.assertRaises(UsageError) as e:
            pack(lambda: None)
        assert "<class 'function'> is not serializable" in str(e.exception)


class TestReportedBugs(unittest.TestCase):
    def test_pack_and_unpack_specific_dict(self):
        test_vector = {
            'field1': 'value1',
            'field2': 2,
            'field3': True,
            'field4': b'123',
            'field5': 1.23,
            'field1nd': None,
            'field1n': None,
            'field2n': None,
            'field3n': None,
            'field4n': None,
            'field5n': None,
            'field1d': 'foobar',
            'field2d': 123,
            'field3d': True,
            'field4d': b'123',
            'field5d': 1.23,
            'field2nd': 123,
            'field3nd': True,
            'field4nd': b'123',
            'field5nd': 1.23,
        }
        packed = pack(test_vector)
        unpacked = unpack(packed)
        assert test_vector == unpacked

    def test_pack_and_unpack_empty_list(self):
        test_vector = []
        packed = pack(test_vector)
        unpacked = unpack(packed)
        assert test_vector == unpacked

    def test_pack_and_unpack_empty_dict(self):
        test_vector = {}
        packed = pack(test_vector)
        unpacked = unpack(packed)
        assert test_vector == unpacked

    def test_pack_and_unpack_empty_tuple(self):
        test_vector = ()
        packed = pack(test_vector)
        unpacked = unpack(packed)
        assert test_vector == unpacked

    def test_pack_and_unpack_empty_set(self):
        test_vector = set()
        packed = pack(test_vector)
        unpacked = unpack(packed)
        assert test_vector == unpacked


if __name__ == '__main__':
    unittest.main()
