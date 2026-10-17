## 0.4.0

- Added new `EncodedType.BIG_INT` and `EncodedType.BIG_NEG` for integers with
  absolute value >= 2^2040, using a 4-byte length prefix that caps serialized
  ints at 2^32 - 1 bytes; removed the associated `UsageError`
- Corrected typo in command help text
- Corrected Python requirement to 3.10+
- Expanded agent skill docs: documented the new big-int wire format and added
  a gotchas section
- Hardened `unpack` against truncated and structurally corrupt input: it now
  raises `ValueError` with descriptive messages instead of leaking bare
  `struct.error`
- `pack` now raises `TypeError` for non-serializable values
- Replaced `UsageError` with a `DependencyError` hierarchy deriving from
  `Exception`: `MissingDependencyError` and `InvalidDependencyError`
  distinguish a missing dependency from an invalid one, and `UsageError`
  remains as an alias of `DependencyError`
- `unpack` resolves `Packable` dependencies only from `inject`; module
  globals are no longer searched
- `pack` dispatches on the exact value type via a precomputed handler
  table and concatenates pre-serialized container items instead of
  routing them through `struct.pack`, substantially improving
  serialization performance (9x-50x faster in benchmarks)
- `pack` now raises `OverflowError` when a serialized length exceeds
  the 32-bit limit instead of leaking a bare `struct.error`
- `unpack` raises `ValueError` for corrupt `Decimal` content and no longer
  builds dependency/error state on the success path, substantially improving
  deserialization performance (1.7x-2.7x faster in benchmarks)

## 0.3.4

- Improved agent skill to include namedtuple example
- Bug fix: `pack`ing ints with absolute value a power of 256 and exponent of >3
  caused an `OverflowError`
- `pack` now raises `UsageError` for big ints that are too large to be serialized

## 0.3.3

- Added proper Agent Skills frontmatter to SKILL.md with optimized description
  for better trigger reliability

## 0.3.2

- Bug fix: set serialization is now consistent and deterministic between
  installations
- Small syntax update for micropython compatibility
- Added CLI for exporting agent skill to AI coding environments (generic,
  OpenCode, Claude Code, Cursor, Codex): `packify [skill|opencode|claude|cursor|codex]`

## 0.3.1

- Bug fix: empty lists, tuples, sets, and dicts are now packed and unpacked
  correctly

## 0.3.0

- Replaced the type and length encoding system for space efficiency
- Replaced the handling of `Packable` types for space efficiency
- Added fuzz testing to the test suite

## 0.2.3

- Bug fix: added missing bool support

## 0.2.2

- Documentation corrections
- Exported missing type

## 0.2.1

- Made dict serialization deterministic

## 0.2.0

- Added support for Decimal
- Improved error type and messages
