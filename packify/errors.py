class UsageError(BaseException):
    """Raised when a condition for proper usage of packify is not met.
        Used with tressa as a replacement for assert and AssertionError.
    """
    ...


def tressa(condition: bool, error_message: str) -> None:
    """Raises a UsageError with the given error_message if the condition
        is False. Replacement for assert statements and AssertionError.
    """
    if not condition:
        raise UsageError(error_message)
