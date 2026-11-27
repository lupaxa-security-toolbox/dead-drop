"""PNG structure, LSB placement, bit planes, and ancillary chunks."""

from __future__ import annotations

import struct
import zlib
from io import BytesIO
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport, read_bits, usable_bytes, write_bits
from lupaxa.dead_drop.errors import IntegrityError, UnsupportedError

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
NONCE_CHUNK = "deNp"
PAYLOAD_CHUNK = "deDp"
ALG_LSB = 1
ALG_PLANE = 2
ALG_CHUNK = 3


def read_chunks(data: bytes) -> list[tuple[str, bytes]]:
    """Read PNG chunks and verify each CRC."""
    if not data.startswith(PNG_MAGIC):
        raise IntegrityError("File is not a PNG.")
    chunks: list[tuple[str, bytes]] = []
    offset = len(PNG_MAGIC)
    while offset < len(data):
        if offset + 8 > len(data):
            raise IntegrityError("PNG chunk header is truncated.")
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        name = data[offset : offset + 4]
        offset += 4
        if offset + length + 4 > len(data):
            raise IntegrityError("PNG chunk is truncated.")
        payload = data[offset : offset + length]
        offset += length
        (crc,) = struct.unpack_from(">I", data, offset)
        offset += 4
        expected = zlib.crc32(name + payload) & 0xFFFFFFFF
        if crc != expected:
            raise IntegrityError(f"PNG chunk {name!r} has a bad CRC.")
        try:
            label = name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise IntegrityError("PNG chunk type is not ASCII.") from exc
        chunks.append((label, payload))
        if label == "IEND":
            break
    if not chunks or chunks[-1][0] != "IEND":
        raise IntegrityError("PNG file is missing IEND.")
    return chunks


def write_chunks(chunks: list[tuple[str, bytes]]) -> bytes:
    """Serialise PNG chunks with fresh CRCs."""
    parts = [PNG_MAGIC]
    for name, payload in chunks:
        raw_name = name.encode("ascii")
        parts.append(struct.pack(">I", len(payload)))
        parts.append(raw_name)
        parts.append(payload)
        parts.append(struct.pack(">I", zlib.crc32(raw_name + payload) & 0xFFFFFFFF))
    return b"".join(parts)


def validate_png(path: Path) -> dict[str, Any]:
    """Validate a PNG with an independent chunk parser and with Pillow."""
    data = path.read_bytes()
    chunks = read_chunks(data)
    trailing = b""
    encoded = write_chunks(chunks)
    if len(data) > len(encoded) and data.startswith(encoded[: len(PNG_MAGIC)]):
        # Trailing bytes are reported; the chunk parser already stopped at IEND.
        iend = data.rfind(b"IEND")
        trailing = data[iend + 8 :] if iend >= 0 else b""
    with Image.open(path) as image:
        image.load()
        info = {
            "format": "png",
            "mode": image.mode,
            "size": list(image.size),
            "chunks": [name for name, _ in chunks],
            "trailing_bytes": len(data) - _chunk_bytes_length(data),
        }
    if info["mode"] not in {"RGB", "RGBA"}:
        raise UnsupportedError(f"PNG mode {info['mode']} is not a supported 8-bit RGB mode.")
    info["trailing_bytes"] = max(0, len(data) - _consumed(data))
    del trailing
    return info


def _consumed(data: bytes) -> int:
    offset = len(PNG_MAGIC)
    while offset + 8 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        name = data[offset + 4 : offset + 8]
        offset += 12 + length
        if name == b"IEND":
            return int(offset)
    return offset


def _chunk_bytes_length(data: bytes) -> int:
    return _consumed(data)


def _load(path: Path) -> Image.Image:
    info = validate_png(path)
    image = Image.open(path)
    image.load()
    if list(image.size) != info["size"]:
        raise IntegrityError("PNG decoder disagreed about the image size.")
    return image


def _channels(image: Image.Image, options: EmbedOptions) -> tuple[int, ...]:
    bands = image.getbands()
    selected: list[int] = []
    for name in options.channels:
        label = name.upper()
        if label == "A" and options.preserve_alpha:
            continue
        if label not in bands:
            raise UnsupportedError(f"PNG does not have channel {name!r}.")
        selected.append(bands.index(label))
    if not selected:
        raise UnsupportedError("No embeddable colour channels were selected.")
    for plane in options.bit_planes:
        if plane < 0 or plane > 7:
            raise UnsupportedError("Bit planes must be between 0 and 7.")
    return tuple(selected)


def capacity_bits(path: Path, options: EmbedOptions) -> int:
    """Return the number of writable bits for the selected channels and planes."""
    image = _load(path)
    try:
        width, height = image.size
        return width * height * len(_channels(image, options)) * len(options.bit_planes)
    finally:
        image.close()


def _slot(index: int, width: int, height: int, channel_count: int, plane_count: int, placement: str) -> tuple[int, int, int, int]:
    if placement == "distributed":
        block = width * height
        which = index // block
        pixel = index % block
        channel = which // plane_count
        plane = which % plane_count
    else:
        per_pixel = channel_count * plane_count
        pixel = index // per_pixel
        which = index % per_pixel
        channel = which // plane_count
        plane = which % plane_count
    y, x = divmod(pixel, width)
    return x, y, channel, plane


def embed_lsb(source: Path, destination: Path, payload: bytes, options: EmbedOptions, *, algorithm: str) -> EmbedReport:
    """Embed bytes in selected pixel bit planes and validate the saved PNG."""
    image = _load(source)
    channels = _channels(image, options)
    width, height = image.size
    total = width * height * len(channels) * len(options.bit_planes)
    pixels = image.load()
    if pixels is None:
        raise IntegrityError("PNG pixel buffer could not be loaded.")
    changed = 0

    def set_bit(index: int, bit: int) -> None:
        nonlocal changed
        x, y, channel, plane_index = _slot(index, width, height, len(channels), len(options.bit_planes), options.placement)
        plane = options.bit_planes[plane_index]
        raw = pixels[x, y]
        if not isinstance(raw, tuple):
            raise IntegrityError("PNG pixel value was not a colour tuple.")
        colour = [int(component) for component in raw]
        band = channels[channel]
        updated = (colour[band] & ~(1 << plane)) | (bit << plane)
        if updated != colour[band]:
            changed += 1
            colour[band] = updated
            pixels[x, y] = tuple(colour)

    write_bits(total, options, payload, set_bit)
    _save_preserving(source, image, destination, [])
    image.close()
    validate_png(destination)
    with Image.open(source) as before, Image.open(destination) as after:
        metrics = _metrics(before, after)
    return EmbedReport(algorithm, "covert", len(payload), usable_bytes(total, options), changed, metrics, list(options.warnings), str(destination))


def extract_lsb(path: Path, size: int, options: EmbedOptions) -> bytes:
    """Read ``size`` bytes from selected PNG bit planes."""
    image = _load(path)
    try:
        channels = _channels(image, options)
        width, height = image.size
        total = width * height * len(channels) * len(options.bit_planes)
        pixels = image.load()
        if pixels is None:
            raise IntegrityError("PNG pixel buffer could not be loaded.")

        def get_bit(index: int) -> int:
            x, y, channel, plane_index = _slot(index, width, height, len(channels), len(options.bit_planes), options.placement)
            plane = options.bit_planes[plane_index]
            raw = pixels[x, y]
            if not isinstance(raw, tuple):
                raise IntegrityError("PNG pixel value was not a colour tuple.")
            return (int(raw[channels[channel]]) >> plane) & 1

        data, _resolved = read_bits(total, options, size, get_bit)
        return data
    finally:
        image.close()


def read_nonce(path: Path) -> bytes:
    """Return the public placement nonce, if this PNG has one."""
    for name, payload in read_chunks(path.read_bytes()):
        if name == NONCE_CHUNK and len(payload) == 16:
            return payload
    return b""


def embed_chunk(source: Path, destination: Path, payload: bytes, options: EmbedOptions) -> EmbedReport:
    """Store a payload in an ancillary PNG chunk. This is container storage, not pixel steganography."""
    chunks = read_chunks(source.read_bytes())
    kept = [(name, data) for name, data in chunks if name != PAYLOAD_CHUNK]
    if not kept or kept[-1][0] != "IEND":
        raise IntegrityError("PNG chunk list has no IEND.")
    kept.insert(-1, (PAYLOAD_CHUNK, payload))
    destination.write_bytes(write_chunks(kept))
    validate_png(destination)
    return EmbedReport("png-chunk", "container", len(payload), 2**31, 0, {"mse": 0.0, "psnr": None, "ssim": 1.0}, ["PNG chunk embedding is overt container storage."], str(destination))


def extract_chunk(path: Path) -> bytes:
    """Read the ancillary payload chunk."""
    for name, payload in read_chunks(path.read_bytes()):
        if name == PAYLOAD_CHUNK:
            return payload
    raise IntegrityError("PNG has no dead-drop payload chunk.")


def _save_preserving(source: Path, image: Image.Image, destination: Path, extra: list[tuple[str, bytes]]) -> None:
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    new_chunks = read_chunks(buffer.getvalue())
    old_chunks = read_chunks(source.read_bytes())
    preserved = [(name, data) for name, data in old_chunks if name[:1].islower() and name not in {NONCE_CHUNK, PAYLOAD_CHUNK, "idat"} and name not in {item[0] for item in new_chunks}]
    merged: list[tuple[str, bytes]] = []
    for name, data in new_chunks:
        if name == "IEND":
            merged.extend(preserved)
            merged.extend(extra)
        merged.append((name, data))
    destination.write_bytes(write_chunks(merged))


def _metrics(before: Image.Image, after: Image.Image) -> dict[str, Any]:
    import numpy as np

    left = np.asarray(before.convert("RGB"), dtype=np.float64)
    right = np.asarray(after.convert("RGB"), dtype=np.float64)
    if left.shape != right.shape:
        return {"mse": None, "psnr": None, "ssim": None, "changed_pixels": None, "note": "dimensions differ"}
    delta = left - right
    mse = float(np.mean(delta * delta))
    psnr = None if mse == 0 else float(10 * np.log10((255.0 * 255.0) / mse))
    changed = int(np.count_nonzero(np.any(left != right, axis=2)))
    return {"mse": mse, "psnr": psnr, "ssim": _ssim(left, right), "changed_pixels": changed, "units": "pixels"}


def _ssim(left: np.ndarray, right: np.ndarray) -> float:

    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    mu_left = float(left.mean())
    mu_right = float(right.mean())
    var_left = float(left.var())
    var_right = float(right.var())
    cov = float(((left - mu_left) * (right - mu_right)).mean())
    return float(((2 * mu_left * mu_right + c1) * (2 * cov + c2)) / ((mu_left**2 + mu_right**2 + c1) * (var_left + var_right + c2)))
