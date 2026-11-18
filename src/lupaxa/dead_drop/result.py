"""Machine-readable result envelope."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "1.0"


@dataclass
class Result:
    """One command result."""

    command: str
    success: bool = True
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON object."""
        return {
            "schema_version": SCHEMA_VERSION,
            "command": self.command,
            "success": self.success,
            "data": self.data,
            "warnings": self.warnings,
            "errors": self.errors,
        }

    def to_json(self) -> str:
        """Serialise the envelope without colour or progress text."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)

    def add_error(self, code: str, message: str, *, exit_code: int) -> None:
        """Record a structured error."""
        self.success = False
        self.errors.append({"code": code, "message": message, "exit_code": exit_code})
