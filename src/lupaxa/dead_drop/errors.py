"""Typed failures and stable process exit codes."""

from __future__ import annotations


class DeadDropError(Exception):
    """Base error carrying a stable code and process exit status."""

    code = "internal_error"
    exit_code = 1

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class ArgumentError(DeadDropError):
    """Invalid arguments or configuration."""

    code = "invalid_arguments"
    exit_code = 2


class UnsupportedError(DeadDropError):
    """Unsupported carrier, algorithm, or encoding."""

    code = "unsupported"
    exit_code = 3


class CapacityError(DeadDropError):
    """The carrier or collection cannot hold the payload."""

    code = "insufficient_capacity"
    exit_code = 4


class AuthenticationError(DeadDropError):
    """Password, key, or authentication tag failure."""

    code = "authentication_failed"
    exit_code = 5


class IntegrityError(DeadDropError):
    """Corrupted, truncated, or inconsistent data."""

    code = "integrity_failure"
    exit_code = 6


class FragmentError(DeadDropError):
    """Too few fragments, or fragments that do not belong together."""

    code = "insufficient_fragments"
    exit_code = 7


class FilesystemError(DeadDropError):
    """Permission, path, or output-collision failure."""

    code = "filesystem_error"
    exit_code = 8


class VaultConflictError(DeadDropError):
    """Concurrent writer, stale generation, or failed vault transaction."""

    code = "vault_conflict"
    exit_code = 9


class LimitError(DeadDropError):
    """A configured safety limit was exceeded."""

    code = "limit_exceeded"
    exit_code = 10


class CancelledError(DeadDropError):
    """The operator cancelled the operation."""

    code = "cancelled"
    exit_code = 11


class PartialBatchError(DeadDropError):
    """A batch finished with both successes and failures."""

    code = "partial_batch"
    exit_code = 12

    def __init__(self, message: str, *, successes: list[str], failures: list[dict[str, str]]) -> None:
        super().__init__(message)
        self.successes = successes
        self.failures = failures
