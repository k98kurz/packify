from __future__ import annotations
from .errors import tressa
from .interface import Packable
from decimal import Decimal
from types import NoneType
import struct


SerializableType = Packable|dict|list|set|tuple|int|bool|float|Decimal|str|bytes|bytearray|NoneType


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
        packed = bytes(data.__class__.__name__, 'utf-8').hex()
        packed = bytes(packed, 'utf-8') + b'_' + data.pack()
        return struct.pack(
            f'!1sI{len(packed)}s',
            b'p',
            len(packed),
            packed
        )

    if type(data) in (list, set, tuple):
        items = b''.join([pack(item) for item in data])
        code = ({
            list: b'l',
            set: b'e',
            tuple: b't'
        })[type(data)]

        return struct.pack(
            f'!1sI{len(items)}s',
            code,
            len(items),
            items
        )

    if type(data) in (bytes, bytearray):
        return struct.pack(
            f'!1sI{len(data)}s',
            b'b' if type(data) is bytes else b'a',
            len(data),
            data
        )

    if type(data) is str:
        data = bytes(data, 'utf-8')
        return struct.pack(
            f'!1sI{len(data)}s',
            b's',
            len(data),
            data
        )

    if type(data) is int:
        return struct.pack(
            f'!1sII',
            b'i',
            4,
            data
        )

    if type(data) is bool:
        return struct.pack(
            f'!1sI?',
            b'B',
            1,
            data
        )

    if type(data) is float:
        return struct.pack(
            f'!1sId',
            b'f',
            8,
            data
        )

    if type(data) is Decimal:
        data = bytes(str(data), 'utf-8')
        return struct.pack(
            f'!1sI{len(data)}s',
            b'D',
            len(data),
            data
        )

    if type(data) is dict:
        items = b''.join(sorted([
            pack((key, value))
            for key, value in data.items()
        ]))
        return struct.pack(
            f'!1sI{len(items)}s',
            b'd',
            len(items),
            items
        )

    if data is None:
        return struct.pack(
            f'!1sI',
            b'n',
            0
        )


def unpack(data: bytes, inject: dict = {}) -> SerializableType:
    """Deserializes an instance of a Packable implementation
        or built-in type, recursively calling itself as necessary.
    """
    code, data = struct.unpack(f'!1s{len(data)-1}s', data)
    dependencies = {**globals(), **inject}

    if code == b'p':
        packed_len, data = struct.unpack(f'!I{len(data)-4}s', data)
        packed, _ = struct.unpack(f'!{packed_len}s{len(data)-packed_len}s', data)
        packed_class, _, packed_data = packed.partition(b'_')
        packed_class = str(bytes.fromhex(str(packed_class, 'utf-8')), 'utf-8')
        tressa(packed_class in dependencies,
            f'{packed_class} not found in globals or inject; cannot unpack')
        tressa(hasattr(dependencies[packed_class], 'unpack'),
            f'{packed_class} must have unpack method')
        return dependencies[packed_class].unpack(packed_data, inject=inject)

    if code in (b'l', b'e', b't', b'd'):
        let_len, data = struct.unpack(f'!I{len(data)-4}s', data)
        let_data, _ = struct.unpack(f'!{let_len}s{len(data)-let_len}s', data)
        items = []
        while len(let_data) > 0:
            _, item_len, _ = struct.unpack(f'!1sI{len(let_data)-5}s', let_data)
            item, let_data = struct.unpack(
                f'!{5+item_len}s{len(let_data)-5-item_len}s',
                let_data
            )
            items.append(unpack(item, inject=inject))

        if code == b'l':
            return items
        if code == b'e':
            return set(items)
        if code == b't':
            return tuple(items)
        if code == b'd':
            return {pair[0]: pair[1] for pair in items}

    if code in (b'b', b'a'):
        bt_len, data = struct.unpack(f'!I{len(data)-4}s', data)
        bt_data, _ = struct.unpack(f'!{bt_len}s{len(data)-bt_len}s', data)
        return bt_data if code == b'b' else bytearray(bt_data)

    if code == b's':
        s_len, data = struct.unpack(f'!I{len(data)-4}s', data)
        s, _ = struct.unpack(f'!{s_len}s{len(data)-s_len}s', data)
        return str(s, 'utf-8')

    if code == b'i':
        return struct.unpack(f'!II{len(data)-8}s', data)[1]

    if code == b'B':
        return struct.unpack(f'!I?', data)[1]

    if code == b'f':
        return struct.unpack(f'!Id{len(data)-12}s', data)[1]

    if code == b'D':
        s_len, data = struct.unpack(f'!I{len(data)-4}s', data)
        s, _ = struct.unpack(f'!{s_len}s{len(data)-s_len}s', data)
        return Decimal(str(s, 'utf-8'))

    if code == b'n':
        return None
