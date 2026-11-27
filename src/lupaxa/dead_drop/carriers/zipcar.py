"""ZIP container embedding.

Adding a named entry is overt container storage. It is not statistical steganography.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport
from lupaxa.dead_drop.errors import FilesystemError, IntegrityError, LimitError
from lupaxa.dead_drop.limits import Limits

ALG_ZIP = 13
DEFAULT_ENTRY = "dead-drop/payload.bin"


def _unsafe(name: str) -> bool:
    path = Path(name)
    return name.startswith(("/", "\\")) or ".." in path.parts or "\\" in name


def inspect_zip(path: Path, limits: Limits) -> dict[str, Any]:
    """Inspect a ZIP without extracting it, and refuse bomb-like members."""
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise IntegrityError(f"Invalid ZIP file: {exc}") from exc
    with archive:
        if len(archive.infolist()) > limits.max_zip_entries:
            raise LimitError("ZIP entry count exceeds the configured limit.")
        total = 0
        names = []
        for info in archive.infolist():
            if _unsafe(info.filename):
                raise FilesystemError(f"ZIP member {info.filename!r} has an unsafe path.")
            if info.compress_size and info.file_size / info.compress_size > limits.max_compression_ratio and info.file_size > 1024 * 1024:
                raise LimitError(f"ZIP member {info.filename!r} looks like a decompression bomb.")
            total += info.file_size
            limits.check_expansion(total)
            names.append(info.filename)
        bad = archive.testzip()
        if bad is not None:
            raise IntegrityError(f"ZIP member {bad!r} failed its CRC.")
    return {"format": "zip", "entries": names, "declared_size": total, "concealment_class": "container"}


def embed(source: Path, destination: Path, payload: bytes, options: EmbedOptions, limits: Limits) -> EmbedReport:
    """Copy an archive and add an explicitly named payload entry."""
    info = inspect_zip(source, limits)
    entry = options.entry_name or DEFAULT_ENTRY
    if _unsafe(entry):
        raise FilesystemError(f"Refusing payload entry name {entry!r}.")
    if entry in info["entries"] and not options.force:
        raise FilesystemError(f"ZIP already contains {entry}. Choose another slot name or pass --force via the entry option.")
    with zipfile.ZipFile(source) as incoming, zipfile.ZipFile(destination, "w") as outgoing:
        for member in incoming.infolist():
            if member.filename == entry:
                continue
            outgoing.writestr(member, incoming.read(member))
        outgoing.writestr(entry, payload)
    inspect_zip(destination, limits)
    extracted = extract(destination, entry, limits)
    if extracted != payload:
        destination.unlink(missing_ok=True)
        raise IntegrityError("ZIP embedding failed its recovery check.")
    warnings = [
        "ZIP embedding is container-based concealment, not statistically covert steganography.",
        *options.warnings,
    ]
    return EmbedReport("zip-entry", "container", len(payload), limits.max_container_payload_bytes, 1, {"mse": None}, warnings, str(destination))


def extract(path: Path, entry: str, limits: Limits) -> bytes:
    """Read one named payload entry."""
    inspect_zip(path, limits)
    with zipfile.ZipFile(path) as archive:
        matches = [info for info in archive.infolist() if info.filename == entry]
        if len(matches) != 1:
            raise IntegrityError(f"ZIP payload entry {entry!r} is missing or ambiguous.")
        if matches[0].file_size > limits.max_container_payload_bytes:
            raise LimitError("ZIP payload exceeds the configured limit.")
        return archive.read(matches[0])
