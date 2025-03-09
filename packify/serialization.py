from __future__ import annotations
from .errors import tressa
from .interface import Packable
from decimal import Decimal
from enum import IntEnum
from types import NoneType
from math import ceil, log
import struct


SerializableType = Packable|dict|list|set|tuple|int|bool|float|Decimal|str|bytes|bytearray|NoneType


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
            For ints, the length is the number of bytes required to
            encode the int; if the int is larger than 2^32-1, the number
            of bytes required to encode the int will be explicitly
            encoded in its own byte.
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
    PACKABLE  = 20


LENGTH_MASK = 0b11000000  # The two high bits
TYPE_MASK   = 0b00111111  # The six low bits

def decode(code: int) -> tuple[LengthCategory, EncodedType]:
    """Decodes a code into a length category and encoded type."""
    return LengthCategory(code & LENGTH_MASK), EncodedType(code & TYPE_MASK)


def pack(data: SerializableType) -> bytes:
    """Serializes an instance of a Packable implementation or built-in
        type, recursively calling itself as necessary. Raises UsageError
        if the type is not serializable.
    """
    tressa(isinstance(data, Packable) or \
        type(data) in (dict, list, set, tuple, str, bytes, bytearray, int,
                       bool, float, Decimal) or data is None,
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
        if data < 0:
            category = LengthCategory.for_len(-data)
            code = category.value | EncodedType.NEG_INT
        else:
            category = LengthCategory.for_len(data)
            code = category.value | EncodedType.INT

        data = data if data >= 0 else -data

        if category == LengthCategory.CAT0:
            size = ceil(log(data, 2)/8)
            data = data.to_bytes(size, 'big')
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


def unpack(data: bytes, inject: dict = {}) -> SerializableType:
    """Deserializes an instance of a Packable implementation
        or built-in type, recursively calling itself as necessary.
        Raises UsageError if a required dependency class is not found in
        globals or inject (i.e. when unpacking a Packable implementation).
    """
    code, data = struct.unpack(f'!B{len(data)-1}s', data)
    dependencies = {**globals(), **inject}

    category, encoded_type = decode(code)

    if encoded_type == EncodedType.PACKABLE:
        name_len, packed_len, data = struct.unpack(
            f'!{category.fmt()}{category.fmt()}{len(data)-category.fmt_count()*2}s',
            data
        )
        packed_class, packed_data, _ = struct.unpack(
            f'!{name_len}s{packed_len}s{len(data)-name_len-packed_len}s',
            data
        )
        packed_class = str(packed_class, 'utf-8')
        tressa(packed_class in dependencies,
            f'{packed_class} not found in globals or inject; cannot unpack')
        tressa(hasattr(dependencies[packed_class], 'unpack'),
            f'{packed_class} must have unpack method')
        return dependencies[packed_class].unpack(packed_data, inject=inject)

    if encoded_type in (EncodedType.LIST, EncodedType.SET, EncodedType.TUPLE, EncodedType.DICT):
        item_category, count, data = struct.unpack(
            f'!B{category.fmt()}{len(data)-category.fmt_count()-1}s',
            data
        )
        item_category = LengthCategory(item_category)
        item_lens = struct.unpack(
            f'!{count}{item_category.fmt()}{len(data)-item_category.fmt_count()*count}s',
            data
        )
        data = item_lens[-1]
        item_lens = item_lens[:-1]
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
        bt_len, data = struct.unpack(
            f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
        )
        bt_data, _ = struct.unpack(f'!{bt_len}s{len(data)-bt_len}s', data)
        return bt_data if encoded_type == EncodedType.BYTES else bytearray(bt_data)

    if encoded_type == EncodedType.STR:
        s_len, data = struct.unpack(
            f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
        )
        s, _ = struct.unpack(f'!{s_len}s{len(data)-s_len}s', data)
        return str(s, 'utf-8')

    if encoded_type in (EncodedType.INT, EncodedType.NEG_INT):
        if category == LengthCategory.CAT0:
            size, data = struct.unpack(f'!B{len(data)-1}s', data)
            data, _ = struct.unpack(f'!{size}s{len(data)-size}s', data)
            result = int.from_bytes(data, 'big')
        else:
            result = struct.unpack(
                f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
            )[0]
        if encoded_type == EncodedType.NEG_INT:
            result = -result
        return result

    if encoded_type == EncodedType.BOOL:
        return struct.unpack(f'!?', data)[0]

    if encoded_type == EncodedType.FLOAT:
        return struct.unpack(f'!d{len(data)-8}s', data)[0]

    if encoded_type == EncodedType.DECIMAL:
        s_len, data = struct.unpack(
            f'!{category.fmt()}{len(data)-category.fmt_count()}s', data
        )
        s, _ = struct.unpack(f'!{s_len}s{len(data)-s_len}s', data)
        return Decimal(str(s, 'utf-8'))

    if encoded_type == EncodedType.NONE:
        return None
