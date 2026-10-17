from __future__ import annotations
from packify import (
    pack,
    unpack,
    Packable,
    MissingDependencyError,
    InvalidDependencyError
)
from packify.serialization import (
    EncodedType,
    LengthCategory,
    _pack_packed_items
)
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
        with self.assertRaises(TypeError) as e:
            pack(lambda: None)
        e = str(e.exception)
        assert "<class 'function'> is not serializable" in e, e

    def test_pack_big_ints_supported(self):
        cases = [2**2040-1, 2**2040, 2**2040+1, 2**2050, 2**4096]
        cases = [v for value in cases for v in (-value, value)]
        for value in cases:
            packed = pack(value)
            unpacked = unpack(packed)
            assert unpacked == value, (value, unpacked)

        nested = [2**2050, -2**2050, (2**4096,), {'k': -2**2041}]
        assert unpack(pack(nested)) == nested, nested

    def test_big_int_wire_format(self):
        """Ints fitting in one size byte keep the 0.3.4 wire format;
            larger ints use `BIG_INT`/`BIG_NEG` with a 4-byte size.
        """
        small = 2**2040 - 1
        packed = pack(small)
        assert packed == b'\x04\xff' + small.to_bytes(255, 'big'), packed.hex()
        assert pack(-small) == (
            b'\x05\xff' + small.to_bytes(255, 'big')
        ), pack(-small).hex()
        big = 2**2040
        packed = pack(big)
        assert packed == (
            b'\x0e' + (256).to_bytes(4, 'big') + big.to_bytes(256, 'big')
        ), packed.hex()
        assert pack(-big) == (
            b'\x0f' + (256).to_bytes(4, 'big') + big.to_bytes(256, 'big')
        ), pack(-big).hex()

    def test_big_ints_in_sets_and_dicts(self):
        big_set = {2**2050, -2**2050, 2**2040, -(2**2040 - 1)}
        big_dict = {
            2**2050: -2**2050,
            -2**2041: 2**4096,
            2**2040: 2**2040,
        }
        packed_set = pack(big_set)
        packed_dict = pack(big_dict)
        assert unpack(packed_set) == big_set
        assert unpack(packed_dict) == big_dict
        for _ in range(100):
            assert pack(set(big_set)) == packed_set
            assert pack(dict(big_dict)) == packed_dict

    def test_unpack_truncated_ints_raise_ValueError(self):
        big = pack(2**2050)
        with self.assertRaises(ValueError) as e:
            unpack(big[:3])
        assert 'missing size prefix and value' in str(e.exception)
        assert '(got 2 bytes)' in str(e.exception)
        with self.assertRaises(ValueError) as e:
            unpack(big[:-10])
        assert 'value shorter than declared size' in str(e.exception)
        assert '(got 247 of 257 bytes)' in str(e.exception)

        cat0 = pack(2**40)
        with self.assertRaises(ValueError) as e:
            unpack(cat0[:1])
        assert 'missing size prefix and value' in str(e.exception)
        assert '(got 0 bytes)' in str(e.exception)
        with self.assertRaises(ValueError) as e:
            unpack(cat0[:3])
        assert 'value shorter than declared size' in str(e.exception)
        assert '(got 1 of 6 bytes)' in str(e.exception)


class TestUnpackCorruptInputs(unittest.TestCase):
    """Truncated or corrupt input must raise `ValueError` with a
        descriptive message.
    """
    def test_truncated_inputs_raise_ValueError(self):
        cases = [
            ('none', None, {}),
            ('bool', True, {}),
            ('float', 1.5, {}),
            ('int cat1', 200, {}),
            ('int cat2', 300, {}),
            ('int cat3', 70_000, {}),
            ('int cat0', 2**40, {}),
            ('big int', 2**2050, {}),
            ('neg int cat1', -200, {}),
            ('neg int cat2', -300, {}),
            ('big neg', -(2**2050), {}),
            ('str', 'hello world', {}),
            ('long str cat2', 'x'*300, {}),
            ('bytes', b'byte data', {}),
            ('bytearray', bytearray(b'byte data'), {}),
            ('decimal', Decimal('123.321'), {}),
            ('empty list', [], {}),
            ('list', [1, 'two', 3.0], {}),
            ('large list cat2', list(range(300)), {}),
            ('tuple', (1, 'two', 3.0), {}),
            ('set', {1, 'two', 3.0}, {}),
            ('empty dict', {}, {}),
            ('dict', {'one': 1, 'two': '2'}, {}),
            ('packable', StrWrapper('wrapped'), {'StrWrapper': StrWrapper}),
        ]
        for label, value, inject in cases:
            packed = pack(value)
            assert len(packed) > 0, label
            for n in range(len(packed)):
                with self.subTest(label=label, cut=n):
                    with self.assertRaises(ValueError):
                        unpack(packed[:n], inject=inject)

    def test_corrupt_codes_raise_ValueError(self):
        cases = [
            (b'', 'empty input', 'data is truncated'),
            (b'\x09\x00', 'unknown encoded type 9', 'unknown encoded type 9'),
            (b'\x21\x00', 'unknown encoded type 33', 'unknown encoded type 33'),
            (b'\x01\x03abc', 'cat0 bytes', 'for BYTES'),
            (b'\x02\x03abc', 'cat0 bytearray', 'for BYTEARRAY'),
            (b'\x03\x05hello', 'cat0 str', 'for STR'),
            (b'\x08\x031.5', 'cat0 decimal', 'for DECIMAL'),
            (b'\x0a\x41\x02\x01\x02\x01\x02\x01\x02\x00\x00', 'cat0 list',
             'for LIST'),
            (b'\x14\x02\x02User\x00', 'cat0 packable', 'for PACKABLE'),
        ]
        for data, label, expected in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError) as e:
                    unpack(data)
                assert expected in str(e.exception), \
                    (expected, str(e.exception))

    def test_corrupt_content_raises_ValueError(self):
        cases = [
            (b'\x43\x01\xff', 'str invalid utf-8'),
            (b'\x48\x03abc', 'decimal not numeric'),
            (b'\x54\x01\x01\xff\x00', 'packable invalid utf-8 name'),
        ]
        for data, label in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    unpack(data)

    def test_corrupt_containers_raise_ValueError(self):
        cases = [
            (b'\x4a', 'list missing item category and count'),
            (b'\x4a\x40', 'list missing count'),
            (b'\x4a\x40\x02', 'list missing item lengths'),
            (b'\x4a\x00\x02\x01\x02\x01\x02\x01\x02\x00\x00',
             'list cat0 item category'),
            (b'\x4a\x04\x02\x01\x02\x01\x02\x01\x02\x00\x00',
             'list invalid item category'),
            (b'\x4a\xff\x02\x01\x02\x01\x02\x01\x02\x00\x00',
             'list invalid item category 255'),
            (b'\xca\x40' + b'\xff\xff\xff\xff', 'list huge count'),
            (b'\x4a\x40\x02\xff\xff' + pack(1) + pack(2),
             'list item lengths exceed data'),
            (b'\x4d\x00\x01\x02x', 'dict cat0 item category'),
            (b'\x8c\x40\x01', 'tuple cat2 count truncated'),
        ]
        for data, label in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    unpack(data)

    def test_corrupt_set_with_list_item_raises_ValueError(self):
        """A set whose item is unhashable must raise `ValueError`, not
            leak `TypeError`.
        """
        data = _pack_packed_items(EncodedType.SET.value, [pack([1, 2])])
        with self.assertRaises(ValueError) as e:
            unpack(data)
        assert 'set item is not hashable' in str(e.exception)

    def test_corrupt_set_with_dict_item_raises_ValueError(self):
        """A set whose item is a dict must raise `ValueError`, not leak
            `TypeError`.
        """
        data = _pack_packed_items(EncodedType.SET.value, [pack({'a': 1})])
        with self.assertRaises(ValueError) as e:
            unpack(data)
        assert 'set item is not hashable' in str(e.exception)

    def test_corrupt_dict_with_int_item_raises_ValueError(self):
        """A dict whose item is not a key/value pair must raise
            `ValueError`, not leak `TypeError`.
        """
        data = _pack_packed_items(EncodedType.DICT.value, [pack(42)])
        with self.assertRaises(ValueError) as e:
            unpack(data)
        assert 'item is not a key/value pair' in str(e.exception)

    def test_corrupt_dict_with_short_tuple_item_raises_ValueError(self):
        """A dict whose item is a 1-tuple must raise `ValueError`, not
            leak `IndexError`.
        """
        data = _pack_packed_items(EncodedType.DICT.value, [pack((1,))])
        with self.assertRaises(ValueError) as e:
            unpack(data)
        assert 'item is not a key/value pair' in str(e.exception)

    def test_corrupt_dict_with_str_item_raises_ValueError(self):
        """A dict whose item is a str (subscriptable but not a pair)
            must raise `ValueError` instead of silently mis-decoding.
        """
        data = _pack_packed_items(EncodedType.DICT.value, [pack('abcd')])
        with self.assertRaises(ValueError) as e:
            unpack(data)
        assert 'item is not a key/value pair' in str(e.exception)


class TestUnpackTrailingData(unittest.TestCase):
    """Pins the behavior that `unpack` decodes a single value and
        discards any trailing bytes.
    """
    def test_trailing_bytes_are_ignored(self):
        for value in (1, 'hello', [1, 2], {'a': 1}, None):
            assert unpack(pack(value) + b'trailing') == value, value


class TestUnpackPackableDependencyErrors(unittest.TestCase):
    """Unpacking a Packable whose class is missing or invalid raises the
        appropriate `DependencyError` subclass.
    """
    def test_missing_dependency_raises_MissingDependencyError(self):
        packed = pack(StrWrapper('wrapped'))
        with self.assertRaises(MissingDependencyError) as e:
            unpack(packed, inject={})
        assert 'not found in inject' in str(e.exception)

    def test_dependency_without_unpack_raises_InvalidDependencyError(self):
        packed = pack(StrWrapper('wrapped'))
        with self.assertRaises(InvalidDependencyError) as e:
            unpack(packed, inject={'StrWrapper': object})
        assert 'StrWrapper must have unpack method' in str(e.exception)

    def test_non_class_dependency_raises_InvalidDependencyError(self):
        packed = pack(StrWrapper('wrapped'))
        with self.assertRaises(InvalidDependencyError) as e:
            unpack(packed, inject={'StrWrapper': object()})
        assert 'StrWrapper must have unpack method' in str(e.exception)


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

    def test_pack_exact_powers_of_256_round_trip(self):
        """`pack` must round-trip ints with absolute value a power of
            256 with exponent of at least 4. The CAT0 branch in `pack`
            computed `size = ceil(log(data, 2)/8)`, which
            under-allocated by one byte for these values, so
            `int.to_bytes(size, 'big')` raised `OverflowError`.
        """
        failures = []
        for exp in range(10):
            for sign in (1, -1):
                value = sign * (256 ** exp)
                try:
                    packed = pack(value)
                    unpacked = unpack(packed)
                    if unpacked != value:
                        failures.append(
                            f'round-trip mismatch for sign={sign} '
                            f'256**{exp}: got {unpacked}, want {value} '
                            f'(packed hex: {packed.hex()})'
                        )
                except Exception as e:
                    failures.append(
                        f'{type(e).__name__} for sign={sign} 256**{exp}: '
                        f'{e} '
                    )
        assert len(failures) == 0, failures

    def test_pack_one_less_than_power_of_256_does_not_overallocate(self):
        failures = []
        for exp in range(4, 10):
            value = (256 ** exp)
            under = value - 1
            value_packed = pack(value)
            under_packed = pack(under)
            under_unpacked = unpack(under_packed)
            if under_unpacked != under:
                failures.append(
                    f"failure for 256**{exp}-1: "
                    f"{under_unpacked} != {under}"
                )

            if len(under_packed) >= len(value_packed):
                failures.append(
                    f"failure for 256**{exp}-1: "
                    f"{len(under_packed)=} >= {len(value_packed)}"
                )

        assert len(failures) == 0, failures


class TestPackWireFormat(unittest.TestCase):
    """Pins the exact packed bytes for representative values so that
        refactors of `pack` cannot silently change the wire format.
    """
    def test_packed_bytes_are_stable(self):
        cases = [
            (None, '00'),
            (True, '0601'),
            (False, '0600'),
            (42, '442a'),
            (-42, '452a'),
            (255, '44ff'),
            (256, '840100'),
            (65535, '84ffff'),
            (65536, 'c400010000'),
            (2**32, '04050100000000'),
            (3.14, '0740091eb851eb851f'),
            (Decimal('1.5'), '4803312e35'),
            ('hello', '430568656c6c6f'),
            (b'abc', '4103616263'),
            (bytearray(b'abc'), '4203616263'),
            ([], '4a4000'),
            ([1, 2], '4a4002020244014402'),
            ((), '4c4000'),
            ((1, 2), '4c4002020244014402'),
            (set(), '4b4000'),
            ({2, 1}, '4b4002020244014402'),
            ({}, '4d4000'),
            ({'a': 1}, '4d40010a4c400203024301614401'),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                packed = pack(value)
                assert packed.hex() == expected, (
                    value, packed.hex(), expected
                )

    def test_long_str_uses_cat2_length_prefix(self):
        assert pack('x' * 300) == b'\x83\x01\x2c' + b'x' * 300

    def test_nested_container_wire_format(self):
        assert pack({'k': (1, 'a')}) == bytes.fromhex(
            '4d4001124c4002030a43016b4c400202034401430161'
        )


class TestPackOversizedLengths(unittest.TestCase):
    """Serialized lengths >= 2**32 cannot fit the 32-bit length
        prefixes; `pack` raises `OverflowError` instead of leaking a
        confusing `struct.error`. `LengthCategory.for_len` is tested
        directly since constructing a 4GiB value in a test is not
        feasible.
    """
    def test_for_len_boundaries(self):
        assert LengthCategory.for_len(0) is LengthCategory.CAT1
        assert LengthCategory.for_len(2**8 - 1) is LengthCategory.CAT1
        assert LengthCategory.for_len(2**8) is LengthCategory.CAT2
        assert LengthCategory.for_len(2**16 - 1) is LengthCategory.CAT2
        assert LengthCategory.for_len(2**16) is LengthCategory.CAT3
        assert LengthCategory.for_len(2**32 - 1) is LengthCategory.CAT3
        assert (LengthCategory.for_len(2**32 - 1, allow_cat0=True)
            is LengthCategory.CAT3)
        assert (LengthCategory.for_len(2**32, allow_cat0=True)
            is LengthCategory.CAT0)

    def test_for_len_raises_OverflowError_beyond_32_bits(self):
        with self.assertRaises(OverflowError) as e:
            LengthCategory.for_len(2**32)
        assert 'exceeds the 32-bit limit' in str(e.exception)
        assert str(2**32) in str(e.exception)


if __name__ == '__main__':
    unittest.main()
