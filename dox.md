# packify

## Classes

### `UsageError(BaseException)`

Used with tressa as a replacement for assert and AssertionError.

### `Packable(Protocol)`

#### Methods

##### `pack() -> bytes:`

Packs the instance into bytes.

##### `@classmethod unpack(data: bytes, /, *, inject: dict = {}) -> Packable:`

Unpacks an instance from bytes. Must accept dependency injection to unpack other
Packable types.

## Functions

### `pack(data: SerializableType) -> bytes:`

Serializes an instance of a Packable implementation or built-in type,
recursively calling itself as necessary. Raises UsageError if the type is not
serializable.

### `unpack(data: bytes, inject: dict = {}) -> SerializableType:`

Deserializes an instance of a Packable implementation or built-in type,
recursively calling itself as necessary.


