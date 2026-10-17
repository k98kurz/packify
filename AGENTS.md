# Instructions for Agents

## Environment

The environment has been set up in venv/.
Use `source venv/bin/activate` before running any python commands that require the
local environment.

When you run a command, if you forget to do this, it will error with a missing
dependency. DO NOT simply write this off as "oh, it's just a missing dependency from
the project". Re-run the command with the correct environment. There are no missing
dependencies.

## Git

Do NOT stage changes unless explicitly instructed to.

## Code Style

### Line length

- Soft max of 80 for normal lines
- Hard max of 85 for code and 72 for docstrings

### Annotations

- This project uses Python 3.10+ style annotations.
- Do NOT use `Union`: use `type1 | type2`
- Do NOT use `Optional`: use `sometype | None`
- Use built-in generic types: `list[type]`, `dict[key, value]`, `set[type]`,
`tuple[type, ...]` instead of `List[type]`, `Dict[key, value]`, etc. (no import
needed)

### Multi-line function/method signatures

- If a function/method signature is long enough to be more than 80 chars, break it
into a multi-line signature
- Parameters should be on their own line, two indentations in
- More than one parameter can be specified per line
- Parameters following a `*` (keyword only) must start on new line
- Final closing parenthesis and return annotation should be on own line one
indentation in (level with function/method body)

Example:
```python
def some_function_with_lots_of_params(
        param1: bytes, param2: str, ..., *,
        kwarg_only_1: bool = False, ...
    ) -> dict[str, int]:
    ...
```

### Multi-line compound conditionals

- Surround with parentheses, with opening parenthesis one indentation layer in
- First conditional should be on same line as opening parenthesis, indented in once
from the opening parenthesis
- Each additional condition should be on its own line, indented in twice, with the
combining word ("and"/"or") at the beginning of the condition
- Closing "):" should be indented once, level with the body of the block

Example:
```python
if  (   some_long_condition_goes >= here_first
        and some_other_condition <= goes_here
    ):
    ...
```

### Docstrings

- Start docstring on same line as openinig quotation marks
- Do not add an empty line before the first and subsequent lines
- Use additional lines in docstring for word wrapping
- Indent additional lines in one level
- Quote code (variable names, types, etc) within the docstring using backticks
- Closing quotation marks on own line except for short, one-line docstrings
- File-level multiline docstrings should be unindented and should start on own line
- Do NOT write docstrings that are improperly indented
- Do NOT add empty lines in docstrings
- Do NOT add "Arg: " and "Returns: " lists
- ONLY include information that is not obvious from the annotations, and write in
full sentences
- Docstring lines should be a max of 72 chars, excluding closing triple quotes

Examples:
```python
"""
This file does things. It has several functions that do things. Blah
blah blah this is a docstring.
"""

def some_function(x: int, y: int) -> float:
    """This does something. Returns `x / y`."""
    ...

def some_other_function(x: int, y: int, z: int) -> list[float]:
    """This does something else. Returns a list of floats, e.g.
        `x / y`, `z / y`, etc.
    """
    ...
```

### Imports

- Imports must always be at the top of the file, never in function/method bodies
- Group all `from package import whatever` before all `import package` statements
- Order imports alphabetically within each group
- No blank lines between import statements
- Imports come after file-level docstrings

Example:
```python
"""
This is a file-level docstring example. Below, the inline comments are
to explain the import pattern to agents; agents should not replicate
the inline comments in actual code.
"""

from hashlib import sha256
from sys import argv
import json
import os
```

## Testing Style

- This project uses unittest from the stdlib, NOT pytest
- Use `assert` with descriptive error messages instead of `self.assertEqual` etc.
- The only exception is when testing failure cases, in which case use
`with self.assertRaises(...) as e:`
- Tests import directly from `packify` (the venv installs it via
`pip install -e .`); run test files with `python tests/test_*.py`

## changelog.md

Do NOT record changes to intermediate states in the change log. ONLY record things
that ACTUALLY CHANGE BETWEEN RELEASES in the changelog.

## dox.md

The dox.md file is regenerated programmatically before release. Do NOT edit it.

## Running tests

- Run tests with `python tests/test_{name}.py`
- Just run the test ONCE without `tail` or `grep`
