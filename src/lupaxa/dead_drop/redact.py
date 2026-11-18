"""Best-effort redaction of secrets from log records.

Python cannot guarantee that bytes are erased from memory. ``wipe`` overwrites a
``bytearray`` the process still holds. Copies made by libraries, the allocator,
swap, or crash dumps are outside this application's control.
"""

from __future__ import annotations

import contextvars
import logging

_secrets: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar("dead_drop_secrets", default=())


def register_secret(value: str | bytes | None) -> None:
    """Remember a secret so later log lines can be scrubbed."""
    if value is None:
        return
    text = value.decode("utf-8", "ignore") if isinstance(value, bytes) else value
    if len(text) < 4:
        return
    current = _secrets.get()
    if text not in current:
        _secrets.set((*current, text))


def wipe(buffer: bytearray | None) -> None:
    """Overwrite a mutable buffer. This is not a guarantee of erasure."""
    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


class RedactFilter(logging.Filter):
    """Replace registered secrets in log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Scrub the formatted message and drop the original arguments."""
        message = record.getMessage()
        for secret in _secrets.get():
            if secret and secret in message:
                message = message.replace(secret, "[REDACTED]")
        record.msg = message
        record.args = ()
        return True


def configure_logging(level: int) -> None:
    """Install a stderr logger that redacts registered secrets."""
    root = logging.getLogger("dead_drop")
    root.handlers.clear()
    root.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.addFilter(RedactFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.propagate = False
