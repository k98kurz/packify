from __future__ import annotations
from .errors import mdsert, idsert, tert, vert
from .interface import Packable
from decimal import Decimal
from enum import IntEnum
from types import NoneType
import struct


SerializableType = Packable|dict|list|set|tuple|int|bool|float|Decimal|str|bytes|\
    bytearray|NoneType


class LengthCategory(IntEnum):
    """Represents the 2 highest bits of a code, controlling how the
        length of a value is encoded.
    """
    CAT0 = 0 << 6       # 00xxxxxx
    CAT1 = 1 << 6       # 01xxxxxx
    CAT2 = 2 << 6       # 10xxxxxx
    CAT3 = 3 << 6       # 11xxxxxx

    def fmt(self) -> str:
        """Returns the format string character to use for encoding a
            length of this category. CAT0 is a special category used for
            ints too large to fit into a uint32.
        """
        return {
            LengthCategory.CAT0: 'x',
            LengthCategory.CAT1: 'B',
            LengthCategory.CAT2: 'H',
            LengthCategory.CAT3: 'I'
        }[self]

    def fmt_count(self) -> int:
        """Returns the number of bytes required to encode a length of this
            category.
        """
        return {
            LengthCategory.CAT0: 0,
            LengthCategory.CAT1: 1,
            LengthCategory.CAT2: 2,
            LengthCategory.CAT3: 4
        }[self]

    @staticmethod
    def for_len(n: int) -> LengthCategory:
        """Returns the appropriate length category for a given length.
            For ints, `n` is the integer value itself; when it does not
            fit in a uint32 (`CAT0`), the caller encodes the byte length
            explicitly using a single byte, or a 4-byte prefix via
            `EncodedType.BIG_INT`/`EncodedType.BIG_NEG` for values whose
            byte length exceeds 255.
        """
        if n < 2**8:
            return LengthCategory.CAT1
        elif n < 2**16:
            return LengthCategory.CAT2
        elif n < 2**32:
            return LengthCategory.CAT3
        else:
            return LengthCategory.CAT0


class EncodedType(IntEnum):
    """Represents the 6 lowest bits of a code, encoding the type of a value."""
    NONE      = 0
    BYTES     = 1
    BYTEARRAY = 2
    STR       = 3
    INT       = 4
    NEG_INT   = 5
    BOOL      = 6
    FLOAT     = 7
    DECIMAL   = 8
    LIST      = 10
    SET       = 11
    TUPLE     = 12
    DICT      = 13
    BIG_INT   = 14
    BIG_NEG   = 15
    PACKABLE  = 20


LENGTH_MASK = 0b11000000  # The two high bits
TYPE_MASK   = 0b00111111  # The six low bits
ENCODED_TYPE_VALUES = frozenset(t.value for t in EncodedType)
CAT0_ENCODED_TYPES = (
    EncodedType.INT, EncodedType.NEG_INT, EncodedType.BIG_INT,
    EncodedType.BIG_NEG, EncodedType.BOOL, EncodedType.FLOAT,
    EncodedType.NONE
)

def decode(code: int) -> tuple[LengthCategory, EncodedType]:
    """Decodes a code into a length category and encoded type."""
    return LengthCategory(code & LENGTH_MASK), EncodedType(code & TYPE_MASK)


def pack(data: SerializableType) -> bytes:
    """Serializes an instance of a Packable implementation or built-in
        type, recursively calling itself as necessary. Raises TypeError
        if the type is not serializable. Dicts and sets are sorted for
        deterministic serialized format that is consistent between
        environments (e.g. Python versions).
    """
    tert(isinstance(data, Packable) or
        type(data) in (
            dict, list, set, tuple, str, bytes, bytearray, int,
            bool, float, Decimal
        ) or data is None,
        'data type must be one of (Packable, list, set, tuple, ' + \
        'str, bytes, bytearray, int, bool, float, Decimal, NoneType); ' + \
        f'{type(data)} is not serializable')

    if isinstance(data, Packable):
        name = bytes(data.__class__.__name__, 'utf-8')
        packed = data.pack()
        category = LengthCategory.for_len(max(len(name), len(packed)))
        code = category.value | EncodedType.PACKABLE.value

        fmt = f'!B{category.fmt()}{category.fmt()}{len(name)}s{len(packed)}s'

        return struct.pack(
            fmt,
            code,
            len(name),
            len(packed),
            name,
            packed
        )

    if type(data) in (list, set, tuple):
        items = [pack(item) for item in data]
        items = sorted(items) if type(data) is set else items
        count = len(items)
        item_lens = [len(item) for item in items]
        category = LengthCategory.for_len(count)
        item_category = LengthCategory.for_len(max(item_lens) if len(item_lens) > 0 else 0)
        code = category.value | ({
            list: EncodedType.LIST,
            set: EncodedType.SET,
            tuple: EncodedType.TUPLE
        })[type(data)]

        fmt = f'!BB{category.fmt()}{count}{item_category.fmt()}'
        for il in item_lens:
            fmt += f'{il}s'

        return struct.pack(
            fmt,
            code,
            item_category.value,
            count,
            *item_lens,
            *items
        )

    if type(data) in (bytes, bytearray):
        length = len(data)
        category = LengthCategory.for_len(length)
        code = category.value | ({
            bytes: EncodedType.BYTES,
            bytearray: EncodedType.BYTEARRAY
        })[type(data)]

        return struct.pack(
            f'!B{category.fmt()}{length}s',
            code,
            length,
            data
        )

    if type(data) is str:
        data = bytes(data, 'utf-8')
        length = len(data)
        category = LengthCategory.for_len(length)
        code = category.value | EncodedType.STR
        fmt = f'!B{category.fmt()}{length}s'

        return struct.pack(
            fmt,
            code,
            length,
            data
        )

    if type(data) is int:
        negative = data < 0
        if negative:
            category = LengthCategory.for_len(-data)
            code = category.value | EncodedType.NEG_INT
        else:
            category = LengthCategory.for_len(data)
            code = category.value | EncodedType.INT

        data = data if data >= 0 else -data

        if category == LengthCategory.CAT0:
            size = (data.bit_length() + 7) // 8
            data = data.to_bytes(size, 'big')
            if size > 255:
                if negative:
                    code = category.value | EncodedType.BIG_NEG
                else:
                    code = category.value | EncodedType.BIG_INT
                return struct.pack(
                    f'!BI{size}s',
                    code,
                    size,
                    data
                )
            return struct.pack(
                f'!BB{size}s',
                code,
                size,
                data
            )

        return struct.pack(
            f'!B{category.fmt()}',
            code,
            data
        )

    if type(data) is bool:
        return struct.pack(
            f'!B?',
            EncodedType.BOOL.value,
            data
        )

    if type(data) is float:
        return struct.pack(
            f'!Bd',
            EncodedType.FLOAT.value,
            data
        )

    if type(data) is Decimal:
        data = bytes(str(data), 'utf-8')
        length = len(data)
        category = LengthCategory.for_len(length)
        code = category.value | EncodedType.DECIMAL

        return struct.pack(
            f'!B{category.fmt()}{length}s',
            code,
            length,
            data
        )

    if type(data) is dict:
        items = sorted([
            pack((key, value))
            for key, value in data.items()
        ])
        count = len(items)
        item_lens = [len(item) for item in items]
        category = LengthCategory.for_len(count)
        item_category = LengthCategory.for_len(max(item_lens) if len(item_lens) > 0 else 0)
        code = category.value | EncodedType.DICT

        fmt = f'!BB{category.fmt()}{count}{item_category.fmt()}'
        for il in item_lens:
            fmt += f'{il}s'

        return struct.pack(
            fmt,
            code,
            item_category.value,
            count,
            *item_lens,
            *items
        )

    if data is None:
        return struct.pack(f'!B', EncodedType.NONE.value)


_unpack_container_types_dict = {
    EncodedType.LIST: 'list',
    EncodedType.SET: 'set',
    EncodedType.TUPLE: 'tuple',
    EncodedType.DICT: 'dict',
}

def unpack(data: bytes, inject: dict = {}) -> SerializableType:
    """Deserializes an instance of a Packable implementation
        or built-in type, recursively calling itself as necessary.
        Raises ValueError if the input is truncated or corrupt, or
        DependencyError if a dependency class required to unpack a
        Packable implementation is missing or invalid.
    """
    vert(len(data) >= 1,
        'data is truncated; missing type code (got 0 bytes)')
    code, data = struct.unpack(f'!B{len(data)-1}s', data)
    dependencies = dict(globals())
    dependencies.update(inject)

    vert(code & TYPE_MASK in ENCODED_TYPE_VALUES,
        'corrupt data: unknown encoded type ' + \
        f'{code & TYPE_MASK} (got code 0x{code:02x})')
    vert(code & LENGTH_MASK != LengthCategory.CAT0.value or
        code & TYPE_MASK in CAT0_ENCODED_TYPES,
        'corrupt data: CAT0 length category is not a valid encoding ' + \
        f'for {EncodedType(code & TYPE_MASK).name} (got code 0x{code:02x})')
    category, encoded_type = decode(code)

    if encoded_type == EncodedType.PACKABLE:
        vert(len(data) >= category.fmt_count() * 2,
            'packable is truncated; missing name and data length ' + \
            f'prefixes (got {len(data)} bytes)')
        name_len, packed_len, data = struct.unpack(
            f'!{category.fmt()}{category.fmt()}{len(data)-category.fmt_count()*2}s',
            data
        )
        vert(name_len + packed_len <= len(data),
            'packable is truncated; value shorter than declared sizes ' + \
            f'(got {len(data)} of {name_len + packed_len} bytes)')
        packed_class, packed_data, _ = struct.unpack(
            f'!{name_len}s{packed_len}s{len(data)-name_len-packed_len}s',
            data
        )
        packed_class = str(packed_class, 'utf-8')
        mdsert(packed_class, dependencies)
        idsert(packed_class, dependencies[packed_class])
        return dependencies[packed_class].unpack(packed_data, inject=inject)

    if encoded_type in (
            EncodedType.LIST, EncodedType.SET, EncodedType.TUPLE, EncodedType.DICT
        ):
        type_name = _unpack_container_types_dict[encoded_type]
        vert(len(data) >= category.fmt_count() + 1,
            f'{type_name} is truncated; missing item length category ' + \
            f'and count (got {len(data)} bytes)')
        item_category, count, data = struct.unpack(
            f'!B{category.fmt()}{len(data)-category.fmt_count()-1}s',
            data
        )
        vert(item_category in (LengthCategory.CAT1, LengthCategory.CAT2,
                LengthCategory.CAT3),
            f'corrupt {type_name}: invalid item length category ' + \
            f'0x{item_category:02x}')
        item_category = LengthCategory(item_category)
        vert(len(data) >= item_category.fmt_count() * count,
            f'{type_name} is truncated; item length table needs ' + \
            f'{item_category.fmt_count() * count} bytes ' + \
            f'(got {len(data)} bytes)')
        item_lens = struct.unpack(
            f'!{count}{item_category.fmt()}{len(data)-item_category.fmt_count()*count}s',
            data
        )
        data = item_lens[-1]
        item_lens = item_lens[:-1]
        vert(len(data) >= sum(item_lens),
            f'{type_name} is truncated; items need {sum(item_lens)} ' + \
            f'bytes (got {len(data)} bytes)')
        items = struct.unpack(
            '!' + ''.join([f'{il}s' for il in item_lens]) + f'{len(data)-sum(item_lens)}s',
            data
        )
        items = items[:-1]
        items = [unpack(item, inject=inject) for item in items]

        if encoded_type == EncodedType.LIST:
            return items
        if encoded_type == EncodedType.SET:
            return set(items)
        if encoded_type == EncodedType.TUPLE:
            return tuple(items)
        if encoded_type == EncodedType.DICT:
            return {pair[0]: pair[1] for pair in items}

    if encoded_type in (EncodedType.BYTES, EncodedType.BYTEARRAY):
        vert(len(data) >= category.fmt_count(),
            'bytes is truncated; missing length prefix ' + \
            f'(got {len(data)} bytes)')
        bt_len, data = struct.unpack(
            f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
        )
        vert(bt_len <= len(data),
            'bytes is truncated; value shorter than declared size ' + \
            f'(got {len(data)} of {bt_len} bytes)')
        bt_data, _ = struct.unpack(f'!{bt_len}s{len(data)-bt_len}s', data)
        return bt_data if encoded_type == EncodedType.BYTES else bytearray(bt_data)

    if encoded_type == EncodedType.STR:
        vert(len(data) >= category.fmt_count(),
            'str is truncated; missing length prefix ' + \
            f'(got {len(data)} bytes)')
        s_len, data = struct.unpack(
            f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
        )
        vert(s_len <= len(data),
            'str is truncated; value shorter than declared size ' + \
            f'(got {len(data)} of {s_len} bytes)')
        s, _ = struct.unpack(f'!{s_len}s{len(data)-s_len}s', data)
        return str(s, 'utf-8')

    if encoded_type in (EncodedType.INT, EncodedType.NEG_INT):
        if category == LengthCategory.CAT0:
            vert(len(data) >= 1,
                'int is truncated; missing size prefix and value ' + \
                f'(got {len(data)} bytes)')
            size, data = struct.unpack(f'!B{len(data)-1}s', data)
            vert(size <= len(data),
                'int is truncated; value shorter than declared size ' + \
                f'(got {len(data)} of {size} bytes)')
            data, _ = struct.unpack(f'!{size}s{len(data)-size}s', data)
            result = int.from_bytes(data, 'big')
        else:
            vert(len(data) >= category.fmt_count(),
                'int is truncated; missing value ' + \
                f'(got {len(data)} bytes)')
            result = struct.unpack(
                f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
            )[0]
        if encoded_type == EncodedType.NEG_INT:
            result = -result
        return result

    if encoded_type in (EncodedType.BIG_INT, EncodedType.BIG_NEG):
        vert(len(data) >= 4,
            'big int is truncated; missing size prefix and value ' + \
            f'(got {len(data)} bytes)')
        size, data = struct.unpack(f'!I{len(data)-4}s', data)
        vert(size <= len(data),
            'big int is truncated; value shorter than declared size ' + \
            f'(got {len(data)} of {size} bytes)')
        data, _ = struct.unpack(f'!{size}s{len(data)-size}s', data)
        result = int.from_bytes(data, 'big')
        if encoded_type == EncodedType.BIG_NEG:
            result = -result
        return result

    if encoded_type == EncodedType.BOOL:
        vert(len(data) >= 1,
            'bool is truncated; missing value byte ' + \
            f'(got {len(data)} bytes)')
        return struct.unpack(f'!?{len(data)-1}s', data)[0]

    if encoded_type == EncodedType.FLOAT:
        vert(len(data) >= 8,
            'float is truncated; missing 8-byte value ' + \
            f'(got {len(data)} bytes)')
        return struct.unpack(f'!d{len(data)-8}s', data)[0]

    if encoded_type == EncodedType.DECIMAL:
        vert(len(data) >= category.fmt_count(),
            'decimal is truncated; missing length prefix ' + \
            f'(got {len(data)} bytes)')
        s_len, data = struct.unpack(
            f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
        )
        vert(s_len <= len(data),
            'decimal is truncated; value shorter than declared size ' + \
            f'(got {len(data)} of {s_len} bytes)')
        s, _ = struct.unpack(f'!{s_len}s{len(data)-s_len}s', data)
        return Decimal(str(s, 'utf-8'))

    if encoded_type == EncodedType.NONE:
        return None
