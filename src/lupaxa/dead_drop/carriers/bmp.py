"""Uncompressed 24-bit and 32-bit BMP pixel LSB embedding."""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport, read_bits, usable_bytes, write_bits
from lupaxa.dead_drop.errors import IntegrityError, UnsupportedError

ALG_BMP_LSB = 4


class Bmp:
    """A parsed uncompressed BMP."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 54 or data[:2] != b"BM":
            raise UnsupportedError("File is not a BMP.")
        self.offset = struct.unpack_from("<I", data, 10)[0]
        dib_size, width, height, planes, bit_count, compression = struct.unpack_from("<IiiHHI", data, 14)
        if dib_size < 40 or planes != 1 or compression != 0 or bit_count not in {24, 32}:
            raise UnsupportedError("Only uncompressed 24-bit and 32-bit BMP files are supported.")
        if width <= 0 or height == 0:
            raise IntegrityError("BMP dimensions are invalid.")
        self.data = bytearray(data)
        self.width = width
        self.height = abs(height)
        self.top_down = height < 0
        self.bit_count = bit_count
        self.channels = 4 if bit_count == 32 else 3
        self.row_stride = ((width * bit_count + 31) // 32) * 4
        expected = self.offset + self.row_stride * self.height
        if expected > len(data):
            raise IntegrityError("BMP pixel array is truncated.")

    def pixel_offset(self, x: int, y: int) -> int:
        """Return the file offset of pixel ``(x, y)`` in top-to-bottom order."""
        file_row = y if self.top_down else self.height - 1 - y
        return int(self.offset + file_row * self.row_stride + x * self.channels)

    def save(self, path: Path) -> None:
        """Write the BMP bytes."""
        path.write_bytes(self.data)


def validate_bmp(path: Path) -> dict[str, Any]:
    """Re-parse a BMP and check that its pixel array fits the file."""
    bmp = Bmp(path.read_bytes())
    return {
        "format": "bmp",
        "mode": "BGRA" if bmp.bit_count == 32 else "BGR",
        "size": [bmp.width, bmp.height],
        "bit_count": bmp.bit_count,
        "compression": 0,
    }


def _bands(options: EmbedOptions) -> tuple[int, ...]:
    order = {"b": 0, "g": 1, "r": 2, "a": 3}
    selected = []
    for name in options.channels:
        if name.lower() == "a" and options.preserve_alpha:
            continue
        if name.lower() not in order:
            raise UnsupportedError(f"Unknown BMP channel {name!r}.")
        index = order[name.lower()]
        selected.append(index)
    return tuple(selected)


def capacity_bits(path: Path, options: EmbedOptions) -> int:
    """Return writable BMP pixel bits, excluding headers and row padding."""
    bmp = Bmp(path.read_bytes())
    bands = [band for band in _bands(options) if band < bmp.channels]
    if not bands:
        raise UnsupportedError("No embeddable BMP channels were selected.")
    return int(bmp.width * bmp.height * len(bands) * len(options.bit_planes))


def embed_lsb(source: Path, destination: Path, payload: bytes, options: EmbedOptions) -> EmbedReport:
    """Embed bytes in BMP pixel LSBs without touching the header or row padding."""
    before = source.read_bytes()
    bmp = Bmp(before)
    bands = tuple(band for band in _bands(options) if band < bmp.channels)
    total = bmp.width * bmp.height * len(bands) * len(options.bit_planes)
    changed = 0

    def set_bit(index: int, bit: int) -> None:
        nonlocal changed
        x, y, band_index, plane_index = _coordinate(index, bmp, bands, options)
        offset = bmp.pixel_offset(x, y) + bands[band_index]
        plane = options.bit_planes[plane_index]
        updated = (bmp.data[offset] & ~(1 << plane)) | (bit << plane)
        if updated != bmp.data[offset]:
            changed += 1
            bmp.data[offset] = updated

    write_bits(total, options, payload, set_bit)
    bmp.save(destination)
    validate_bmp(destination)
    metrics = _byte_metrics(before, destination.read_bytes())
    return EmbedReport("bmp-lsb", "covert", len(payload), usable_bytes(total, options), changed, metrics, list(options.warnings), str(destination))


def extract_lsb(path: Path, size: int, options: EmbedOptions) -> bytes:
    """Read embedded bytes from a BMP."""
    bmp = Bmp(path.read_bytes())
    bands = tuple(band for band in _bands(options) if band < bmp.channels)
    total = bmp.width * bmp.height * len(bands) * len(options.bit_planes)

    def get_bit(index: int) -> int:
        x, y, band_index, plane_index = _coordinate(index, bmp, bands, options)
        offset = bmp.pixel_offset(x, y) + bands[band_index]
        return (bmp.data[offset] >> options.bit_planes[plane_index]) & 1

    data, _resolved = read_bits(total, options, size, get_bit)
    return data


def _coordinate(index: int, bmp: Bmp, bands: tuple[int, ...], options: EmbedOptions) -> tuple[int, int, int, int]:
    plane_count = len(options.bit_planes)
    if options.placement == "distributed":
        block = bmp.width * bmp.height
        which = index // block
        pixel = index % block
        band_index = which // plane_count
        plane_index = which % plane_count
    else:
        per_pixel = len(bands) * plane_count
        pixel = index // per_pixel
        which = index % per_pixel
        band_index = which // plane_count
        plane_index = which % plane_count
    y, x = divmod(pixel, bmp.width)
    return x, y, band_index, plane_index


def _byte_metrics(before: bytes, after: bytes) -> dict[str, Any]:
    if len(before) != len(after):
        return {"mse": None, "psnr": None, "changed_bytes": None, "note": "file size changed"}
    delta = [left - right for left, right in zip(before, after, strict=True)]
    changed = sum(1 for value in delta if value)
    mse = sum(value * value for value in delta) / len(delta)
    return {"mse": mse, "psnr": None if mse == 0 else 10 * math.log10((255 * 255) / mse), "changed_bytes": changed}
