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
