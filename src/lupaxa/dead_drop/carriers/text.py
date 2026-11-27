"""Text and Markdown concealment.

These methods are fragile. Editors, copiers, and Unicode normalisation can
destroy them. They are included for experimentation and puzzles, not as a
durable store.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport
from lupaxa.dead_drop.errors import CapacityError, IntegrityError, UnsupportedError

WARNING = "Text concealment is vulnerable to formatting, Unicode normalisation, copying, and editor transformations. It is not a durable store."
ZW0 = "\u200b"
ZW1 = "\u200c"
MARKER = "\u2060\u2060\u2063"

ALGORITHMS = {
    "txt-whitespace": 6,
    "txt-space-tab": 7,
    "txt-zero-width": 8,
    "md-whitespace": 9,
    "md-space-tab": 10,
    "md-zero-width": 11,
}


def _read(path: Path) -> str:
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedError(f"{path} is not valid UTF-8.") from exc


def _family(algorithm: str) -> str:
    if algorithm.endswith("whitespace"):
        return "whitespace"
    if algorithm.endswith("space-tab"):
        return "space-tab"
    if algorithm.endswith("zero-width"):
        return "zero-width"
    raise UnsupportedError(f"Unknown text algorithm {algorithm}.")


def capacity_bytes(path: Path, algorithm: str, *, limit: int) -> int:
    """Return how many payload bytes this text method can hold."""
    text = _read(path)
    family = _family(algorithm)
    if family == "whitespace":
        return max(0, len(text.splitlines()) - 1)
    return limit


def embed(source: Path, destination: Path, payload: bytes, options: EmbedOptions, *, algorithm: str) -> EmbedReport:
    """Embed into a new text file. The source file is not modified."""
    text = _read(source)
    family = _family(algorithm)
    if family == "whitespace":
        updated = _embed_whitespace(text, payload)
        capacity = max(0, len(text.splitlines()) - 1)
    elif family == "space-tab":
        updated = text + ("\n" if text and not text.endswith("\n") else "") + _space_tab(payload) + "\n"
        capacity = options.max_bytes or len(payload)
    else:
        updated = text + MARKER + _zero_width(len(payload), 4) + _zero_width_bytes(payload)
        capacity = options.max_bytes or len(payload)
    if not updated.endswith("\n"):
        updated += "\n"
    encoded = updated.encode("utf-8")
    destination.write_bytes(encoded)
    # Round-trip the bytes we just wrote before reporting success.
    extracted = extract(destination, len(payload), algorithm)
    if extracted != payload:
        destination.unlink(missing_ok=True)
        raise IntegrityError("Text embedding failed its recovery check.")
    return EmbedReport(
        algorithm,
        "covert",
        len(payload),
        capacity,
        abs(len(encoded) - source.stat().st_size),
        {"mse": None, "psnr": None, "note": "distortion metrics do not apply to text"},
        [WARNING, *options.warnings],
        str(destination),
    )


def extract(path: Path, size: int, algorithm: str) -> bytes:
    """Extract a text payload of ``size`` bytes."""
    text = _read(path)
    family = _family(algorithm)
    if family == "whitespace":
        return _extract_whitespace(text, size)
    if family == "space-tab":
        return _extract_space_tab(text, size)
    return _extract_zero_width(text, size)


def analyse_text(path: Path) -> dict[str, Any]:
    """Report invisible characters, trailing whitespace, and encoding facts."""
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = data.decode("utf-8", "replace")
        encoding = "invalid-utf-8"
    invisible = sum(1 for char in text if char in {ZW0, ZW1, "\u200d", "\ufeff", "\u2060", "\u2063"})
    trailing = sum(1 for line in text.splitlines() if line.endswith((" ", "\t")))
    normalised = text != __import__("unicodedata").normalize("NFC", text)
    return {
        "encoding": encoding,
        "lines": len(text.splitlines()),
        "invisible_characters": invisible,
        "trailing_whitespace_lines": trailing,
        "normalisation_changes_text": normalised,
        "tab_count": text.count("\t"),
        "warning": WARNING,
    }


def _embed_whitespace(text: str, payload: bytes) -> str:
    lines = text.splitlines()
    if len(lines) < len(payload) + 1:
        raise CapacityError(f"Trailing whitespace needs {len(payload) + 1} lines and this file has {len(lines)}.")
    lines[0] = lines[0].rstrip(" \t") + (" " * (len(payload) + 1))
    for index, byte in enumerate(payload, start=1):
        lines[index] = lines[index].rstrip(" \t") + (" " * (byte + 1))
    return "\n".join(lines) + "\n"


def _extract_whitespace(text: str, size: int) -> bytes:
    lines = text.splitlines()
    if not lines:
        raise IntegrityError("Text carrier is empty.")
    declared = len(lines[0]) - len(lines[0].rstrip(" "))
    if declared != size + 1:
        raise IntegrityError("Trailing whitespace length header does not match the requested size.")
    output = bytearray()
    for line in lines[1 : size + 1]:
        count = len(line) - len(line.rstrip(" "))
        if count < 1 or count > 256:
            raise IntegrityError("A trailing-whitespace byte is missing or out of range.")
        output.append(count - 1)
    return bytes(output)


def _space_tab(payload: bytes) -> str:
    bits = []
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append(" " if ((byte >> shift) & 1) == 0 else "\t")
    return "\t" + "".join(bits)


def _extract_space_tab(text: str, size: int) -> bytes:
    marker = text.rfind("\n\t")
    if marker < 0 and not text.startswith("\t"):
        raise IntegrityError("Space/tab payload marker was not found.")
    block = text[marker + 1 :] if marker >= 0 else text
    block = block.splitlines()[0]
    if not block.startswith("\t"):
        raise IntegrityError("Space/tab payload marker was not found.")
    bits = block[1:]
    needed = size * 8
    if len(bits) < needed:
        raise IntegrityError("Space/tab payload is truncated.")
    output = bytearray()
    for index in range(0, needed, 8):
        value = 0
        for symbol in bits[index : index + 8]:
            if symbol not in {" ", "\t"}:
                raise IntegrityError("Space/tab payload contains an unexpected character.")
            value = (value << 1) | (0 if symbol == " " else 1)
        output.append(value)
    return bytes(output)


def _zero_width(value: int, width: int) -> str:
    return "".join(ZW1 if (value >> shift) & 1 else ZW0 for shift in range(width * 8 - 1, -1, -1))


def _zero_width_bytes(payload: bytes) -> str:
    return "".join(_zero_width(byte, 1) for byte in payload)


def _zw_bits(text: str) -> str:
    return "".join(char for char in text if char in {ZW0, ZW1})


def _extract_zero_width(text: str, size: int) -> bytes:
    start = text.find(MARKER)
    if start < 0:
        raise IntegrityError("Zero-width payload marker was not found.")
    bits = _zw_bits(text[start + len(MARKER) :])
    if len(bits) < 32 + size * 8:
        raise IntegrityError("Zero-width payload is truncated.")
    declared = _bits_to_int(bits[:32])
    if declared != size:
        raise IntegrityError("Zero-width length header does not match the requested size.")
    output = bytearray()
    for index in range(32, 32 + size * 8, 8):
        output.append(_bits_to_int(bits[index : index + 8]))
    return bytes(output)


def _bits_to_int(bits: str) -> int:
    value = 0
    for symbol in bits:
        value = (value << 1) | (0 if symbol == ZW0 else 1)
    return value
