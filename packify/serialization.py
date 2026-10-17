from __future__ import annotations
from .errors import mdsert, idsert, vert
from .interface import Packable
from decimal import Decimal, InvalidOperation
from enum import IntEnum
from types import NoneType, MappingProxyType
import struct


SerializableType = Packable|dict|list|set|tuple|int|bool|float|Decimal|str|bytes|\
    bytearray|NoneType


_FMT = ('x', 'B', 'H', 'I')
_FMT_COUNT = (0, 1, 2, 4)


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
        return _FMT[self >> 6]

    def fmt_count(self) -> int:
        """Returns the number of bytes required to encode a length of this
            category.
        """
        return _FMT_COUNT[self >> 6]

    @staticmethod
    def for_len(n: int, allow_cat0: bool = False) -> LengthCategory:
        """Returns the appropriate length category for a given length,
            raising `OverflowError` if `n` exceeds the 32-bit limit and
            is not an int value. For ints (`allow_cat0=True`), `n` is
            the integer value itself; when it does not fit in a uint32
            (`CAT0`), the caller encodes the byte length explicitly
            using a single byte, or a 4-byte prefix via
            `EncodedType.BIG_INT`/`EncodedType.BIG_NEG` for values whose
            byte length exceeds 255.
        """
        if n < 2**8:
            return LengthCategory.CAT1
        elif n < 2**16:
            return LengthCategory.CAT2
        elif n < 2**32:
            return LengthCategory.CAT3

        if allow_cat0:
            return LengthCategory.CAT0

        raise OverflowError(
            f'value too large to pack: length {n} exceeds the 32-bit '
            f'limit of {2**32 - 1} bytes'
        )


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


def _mk_code_table() -> tuple[tuple[LengthCategory, EncodedType]|None, ...]:
    """Precomputes the decode result for every possible byte code.
        Entries are `(category, encoded_type)` for valid codes and
        `None` for corrupt codes.
    """
    cat0_types = {t.value for t in CAT0_ENCODED_TYPES}
    table = []
    for code in range(2**8):
        encoded_type = code & TYPE_MASK
        if encoded_type not in ENCODED_TYPE_VALUES:
            table.append(None)
        elif code & LENGTH_MASK == 0 and encoded_type not in cat0_types:
            table.append(None)
        else:
            table.append((
                LengthCategory(code & LENGTH_MASK), EncodedType(encoded_type)
            ))
    return tuple(table)


_CODE_TABLE = _mk_code_table()


def _code_error(code: int) -> str:
    """Returns a descriptive message describing why `code` is corrupt."""
    encoded_type = code & TYPE_MASK
    if encoded_type not in ENCODED_TYPE_VALUES:
        return (
            f'corrupt data: unknown encoded type {encoded_type} '
            f'(got code 0x{code:02x})'
        )
    return (
        f'corrupt data: CAT0 length category is not a valid encoding '
        f'for {EncodedType(encoded_type).name} (got code 0x{code:02x})'
    )


def decode(code: int) -> tuple[LengthCategory, EncodedType]:
    """Decodes a code into a length category and encoded type. Raises
        `ValueError` if the code is corrupt.
    """
    info = _CODE_TABLE[code]
    if info is None:
        raise ValueError(_code_error(code))
    return info


def _pack_len_prefixed(code: int, payload: bytes|bytearray) -> bytes:
    """Packs `payload` behind a length prefix, OR-ing the length
        category into the base type `code`. Raises `OverflowError` if
        the length exceeds the 32-bit limit.
    """
    category = LengthCategory.for_len(len(payload))
    fmt = f'!B{category.fmt()}'
    return struct.pack(fmt, category.value | code, len(payload)) + payload


def _pack_none(data: NoneType) -> bytes:
    """Packs `None` into a single type-code byte."""
    return struct.pack('!B', EncodedType.NONE.value)


def _pack_bool(data: bool) -> bytes:
    """Packs a bool into a type code and a value byte."""
    return struct.pack('!B?', EncodedType.BOOL.value, data)


def _pack_float(data: float) -> bytes:
    """Packs a float into a type code and an 8-byte value."""
    return struct.pack('!Bd', EncodedType.FLOAT.value, data)


def _pack_str(data: str) -> bytes:
    """Packs a `str` into a type code, a length prefix, and its utf-8
        encoded bytes.
    """
    return _pack_len_prefixed(EncodedType.STR.value, data.encode())


def _pack_bytes(data: bytes) -> bytes:
    """Packs `bytes` into a type code, a length prefix, and the value."""
    return _pack_len_prefixed(EncodedType.BYTES.value, data)


def _pack_bytearray(data: bytearray) -> bytes:
    """Packs a `bytearray` into a type code, a length prefix, and the
        value.
    """
    return _pack_len_prefixed(EncodedType.BYTEARRAY.value, data)


def _pack_decimal(data: Decimal) -> bytes:
    """Packs a `Decimal` into a type code, a length prefix, and its
        utf-8 encoded string representation.
    """
    return _pack_len_prefixed(EncodedType.DECIMAL.value, str(data).encode())


def _pack_int(data: int) -> bytes:
    """Packs an `int` into a type code and a fixed-width value, using
        `EncodedType.NEG_INT` for negatives and `EncodedType.BIG_INT`
        or `EncodedType.BIG_NEG` when the value needs more than 255
        bytes.
    """
    negative = data < 0
    magnitude = abs(data)
    category = LengthCategory.for_len(magnitude, allow_cat0=True)

    if category == LengthCategory.CAT0:
        size = (magnitude.bit_length() + 7) // 8
        payload = magnitude.to_bytes(size, 'big')

        if size > 255:
            encoded = EncodedType.BIG_NEG if negative else EncodedType.BIG_INT
            return struct.pack('!BI', encoded.value, size) + payload

        encoded = EncodedType.NEG_INT if negative else EncodedType.INT
        return struct.pack('!BB', encoded.value, size) + payload

    encoded = EncodedType.NEG_INT if negative else EncodedType.INT
    return struct.pack(
        '!B' + category.fmt(),
        category.value | encoded.value,
        magnitude
    )


def _pack_packed_items(code: int, items: list[bytes]) -> bytes:
    """Packs pre-serialized items behind a header of the container
        type `code` OR'd with the count's length category, the item
        length category, the item count, and a table of item lengths,
        followed by the concatenated items.
    """
    count = len(items)
    category = LengthCategory.for_len(count)
    item_lens = [len(item) for item in items]
    item_category = LengthCategory.for_len(max(item_lens, default=0))
    header = struct.pack(
        f'!BB{category.fmt()}{count}{item_category.fmt()}',
        category.value | code,
        item_category.value,
        count,
        *item_lens
    )
    return header + b''.join(items)


def _pack_list(data: list) -> bytes:
    """Packs a `list` by serializing each item and concatenating the
        results behind a shared header.
    """
    return _pack_packed_items(
        EncodedType.LIST.value,
        [pack(item) for item in data]
    )


def _pack_tuple(data: tuple) -> bytes:
    """Packs a `tuple` by serializing each item and concatenating the
        results behind a shared header.
    """
    return _pack_packed_items(
        EncodedType.TUPLE.value,
        [pack(item) for item in data]
    )


def _pack_set(data: set) -> bytes:
    """Packs a `set` by serializing each item, sorting the packed items
        for a deterministic serialized format, and concatenating the
        results behind a shared header.
    """
    items = [pack(item) for item in data]
    items.sort()
    return _pack_packed_items(EncodedType.SET.value, items)


def _pack_dict(data: dict) -> bytes:
    """Packs a `dict` by packing each key/value pair as a tuple, sorting
        the packed pairs for a deterministic serialized format, and
        concatenating the results behind a shared header.
    """
    items = sorted([pack((key, value)) for key, value in data.items()])
    return _pack_packed_items(EncodedType.DICT.value, items)


def _pack_packable(data: Packable) -> bytes:
    """Packs a `Packable` instance into a type code, a length category
        shared by the name and data prefixes, the utf-8 encoded class
        name, and the packed data.
    """
    name = bytes(data.__class__.__name__, 'utf-8')
    packed = data.pack()
    category = LengthCategory.for_len(max(len(name), len(packed)))
    fmt = f'!B{category.fmt()}{category.fmt()}'
    code = category.value | EncodedType.PACKABLE.value
    return struct.pack(fmt, code, len(name), len(packed)) + name + packed


_PACK_HANDLERS = MappingProxyType({
    Packable: _pack_packable,
    dict: _pack_dict,
    list: _pack_list,
    set: _pack_set,
    tuple: _pack_tuple,
    str: _pack_str,
    bytes: _pack_bytes,
    bytearray: _pack_bytearray,
    int: _pack_int,
    bool: _pack_bool,
    float: _pack_float,
    Decimal: _pack_decimal,
    NoneType: _pack_none,
})


def pack(data: SerializableType) -> bytes:
    """Serializes an instance of a `Packable` implementation or built-in
        type, recursively calling itself as necessary. Raises TypeError
        if the type is not serializable and `OverflowError` if a
        serialized value would need a length prefix beyond the 32-bit
        limit. Dicts and sets are sorted for deterministic serialized
        format that is consistent between environments (e.g. Python
        versions).
    """
    handler = _PACK_HANDLERS.get(type(data))
    if handler is not None:
        return handler(data)
    if isinstance(data, Packable):
        return _PACK_HANDLERS[Packable](data)
    raise TypeError(
        'data type must be one of (' +
        ", ".join([k.__name__ for k in _PACK_HANDLERS.keys()]) +
        f'); {type(data)} is not serializable'
    )


_unpack_container_types_dict = {
    EncodedType.LIST: 'list',
    EncodedType.SET: 'set',
    EncodedType.TUPLE: 'tuple',
    EncodedType.DICT: 'dict',
}

def unpack(data: bytes, inject: dict = {}) -> SerializableType:
    """Deserializes an instance of a `Packable` implementation
        or built-in type, recursively calling itself as necessary.
        Raises `ValueError` if the input is truncated or corrupt, or
        `DependencyError` if a dependency class required to unpack a
        `Packable` implementation is missing or invalid.
    """
    vert(len(data) >= 1,
        'data is truncated; missing type code (got 0 bytes)')
    code, data = struct.unpack(f'!B{len(data)-1}s', data)
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
        mdsert(packed_class, inject)
        idsert(packed_class, inject[packed_class])
        return inject[packed_class].unpack(packed_data, inject=inject)

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
        total = sum(item_lens)
        vert(len(data) >= total,
            lambda: f'{type_name} is truncated; items need {total} ' + \
            f'bytes (got {len(data)} bytes)')
        items = struct.unpack(
            '!' + ''.join([f'{il}s' for il in item_lens]) + f'{len(data)-total}s',
            data
        )
        items = items[:-1]
        items = [unpack(item, inject=inject) for item in items]

        if encoded_type == EncodedType.LIST:
            return items
        if encoded_type == EncodedType.SET:
            try:
                return set(items)
            except TypeError as e:
                raise ValueError(
                    f'corrupt {type_name}: set item is not hashable: {e}'
                ) from e
        if encoded_type == EncodedType.TUPLE:
            return tuple(items)
        if encoded_type == EncodedType.DICT:
            for item in items:
                vert(type(item) is tuple and len(item) == 2,
                    f'corrupt {type_name}: item is not a key/value pair')
            try:
                return {pair[0]: pair[1] for pair in items}
            except TypeError as e:
                raise ValueError(
                    f'corrupt {type_name}: dict key is not hashable: {e}'
                ) from e

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
        try:
            return Decimal(str(s, 'utf-8'))
        except (InvalidOperation, UnicodeDecodeError) as e:
            raise ValueError(f'corrupt decimal: {e}') from e

    if encoded_type == EncodedType.NONE:
        return None
