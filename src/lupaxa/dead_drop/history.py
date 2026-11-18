"""Optional local operation history."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.config import data_directory

SENSITIVE_KEYS = {"password", "key", "secret", "share", "plaintext", "token"}


def history_path() -> Path:
    """Return the JSONL history file location."""
    return data_directory() / "history.jsonl"


def _scrub(value: object) -> object:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                cleaned[str(key)] = "[REDACTED]"
            else:
                cleaned[str(key)] = _scrub(item)
        return cleaned
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, str) and len(value) > 4096:
        return value[:4096] + "…"
    return value


def record_history(
    *,
    enabled: bool,
    command: str,
    status: str,
    started: float,
    inputs: list[str] | None = None,
    outputs: list[str] | None = None,
    warnings: list[str] | None = None,
    error_code: str | None = None,
) -> dict[str, Any] | None:
    """Append one history record when history is enabled."""
    entry: dict[str, Any] = {
        "operation_id": str(uuid.uuid4()),
        "command": command,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inputs": inputs or [],
        "outputs": outputs or [],
        "status": status,
        "duration_seconds": round(time.monotonic() - started, 6),
        "warnings": warnings or [],
        "error_code": error_code,
    }
    scrubbed = _scrub(entry)
    if not isinstance(scrubbed, dict):
        raise TypeError("History scrubber must return an object.")
    entry = scrubbed
    if not enabled:
        return entry
    path = history_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError:
        return entry
    return entry


def read_history(*, limit: int = 100) -> list[dict[str, Any]]:
    """Return the newest history records."""
    path = history_path()
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    records: list[dict[str, Any]] = []
    for line in lines[-limit:]:
        if not line.strip():
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            records.append(loaded)
    return records
