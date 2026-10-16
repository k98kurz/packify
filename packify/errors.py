from typing import Callable


class DependencyError(Exception):
    """Raised when a `Packable` dependency cannot be resolved."""
    ...


class MissingDependencyError(DependencyError):
    """Raised when a required `Packable` dependency is missing."""
    ...


class InvalidDependencyError(DependencyError):
    """Raised when a resolved dependency lacks the required `unpack`
        method.
    """
    ...


UsageError = DependencyError


def mdsert(packed_class: str, dependencies: dict) -> None:
    """Raises a `MissingDependencyError` if the `packed_class` is not
        within the `dependencies`.
    """
    if packed_class in dependencies:
        return
    raise MissingDependencyError(
        f'{packed_class} not found in globals or inject; cannot unpack'
    )


def idsert(packed_class: str, resolved_class: type) -> None:
    """Raises a `InvalidDependencyError` if the `packed_class` does not
        have the required `unpack` method.
    """
    if hasattr(resolved_class, 'unpack'):
        return
    raise InvalidDependencyError(f'{packed_class} must have unpack method')


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
