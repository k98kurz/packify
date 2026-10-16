from typing import Callable


class UsageError(Exception):
    """Raised when a condition for proper usage of packify is not met.
        Used with tressa as a replacement for assert and AssertionError.
    """
    ...


def tressa(condition: bool, msg: str|Callable[[], str]) -> None:
    """Raises a UsageError with the given error_message if the condition
        is False. Replacement for assert statements and AssertionError.
    """
    if not condition:
        raise UsageError(msg() if callable(msg) else msg)


def tert(condition: bool, msg: str|Callable[[], str] = 'invalid type') -> None:
    """Raises a TypeError with the given error_message if the condition
        is False.
    """
    if not condition:
        raise TypeError(msg() if callable(msg) else msg)


def vert(condition: bool, msg: str|Callable[[], str] = 'invalid value') -> None:
    """Raises a ValueError with the given error_message if the condition
        is False.
    """
    if not condition:
        raise ValueError(msg() if callable(msg) else msg)
