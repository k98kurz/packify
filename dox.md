# packify

## Classes

### `DependencyError(Exception)`

Base class for errors raised when a `Packable` dependency cannot be resolved.
Alias: `UsageError`.

### `InvalidDependencyError(DependencyError)`

Raised when a resolved dependency lacks the required `unpack` method.

### `MissingDependencyError(DependencyError)`

Raised when a required `Packable` dependency is missing.

### `DependencyError(Exception)`

Base class for errors raised when a `Packable` dependency cannot be resolved.
Alias: `UsageError`.

### `Packable(Protocol)`

Interface for custom packify-able classes.

#### Methods

##### `pack() -> bytes:`

Packs the instance into bytes.

##### `@classmethod unpack(data: bytes, inject: dict = {}) -> Packable:`

Unpacks an instance from bytes. Must accept dependency injection to unpack other
Packable types.

## Functions

### `pack(data: SerializableType) -> bytes:`

Serializes an instance of a `Packable` implementation or built-in type,
recursively calling itself as necessary. Raises TypeError if the type is not
serializable and `OverflowError` if a serialized value would need a length
prefix beyond the 32-bit limit. Dicts and sets are sorted for deterministic
serialized format that is consistent between environments (e.g. Python
versions).

### `unpack(data: bytes, inject: dict = {}) -> SerializableType:`

Deserializes an instance of a `Packable` implementation or built-in type,
recursively calling itself as necessary. Raises `ValueError` if the input is
truncated or corrupt, or `DependencyError` if a dependency class required to
unpack a `Packable` implementation is missing or invalid.

### `version() -> str:`

Returns the current version of the packify package.

## Values

- `SerializableType`: UnionType

