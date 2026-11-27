"""Shared carrier types and bit placement."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.errors import ArgumentError, CapacityError
from lupaxa.dead_drop.placement import identity, permute


@dataclass
class EmbedOptions:
    """Options that affect how bytes are placed inside one carrier."""

    placement: str = "sequential"
    channels: tuple[str, ...] = ("r", "g", "b")
    bit_planes: tuple[int, ...] = (0,)
    key: bytes = b""
    nonce: bytes = b""
    start_byte: int = 0
    max_bytes: int | None = None
    preserve_alpha: bool = True
    entry_name: str = "dead-drop/payload.bin"
    force: bool = False
    warnings: list[str] = field(default_factory=list)

    def require_keyed_material(self) -> None:
        """Keyed placement needs a key and a carrier nonce."""
        if self.placement == "keyed" and (len(self.key) < 16 or len(self.nonce) != 16):
            raise ArgumentError("Keyed placement requires a 16-byte key prefix and a 16-byte carrier nonce.")


@dataclass
class EmbedReport:
    """What an embedding operation actually changed."""

    algorithm: str
    concealment_class: str
    bytes_embedded: int
    capacity_bytes: int
    changed_units: int
    metrics: dict[str, Any]
    warnings: list[str]
    output: str


def new_nonce() -> bytes:
    """Carrier nonce. It is not a secret."""
    return os.urandom(16)


def bits_of(data: bytes) -> list[int]:
    """Expand bytes to bits, most significant bit first."""
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bytes_of(bits: list[int]) -> bytes:
    """Pack bits back into bytes."""
    if len(bits) % 8:
        raise CapacityError("Embedded bit stream ended before a whole byte.")
    output = bytearray()
    for index in range(0, len(bits), 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | bit
        output.append(value)
    return bytes(output)


def map_index(index: int, size: int, options: EmbedOptions) -> int:
    """Translate a payload bit index into a carrier bit index."""
    if options.placement == "keyed":
        options.require_keyed_material()
        return permute(index, size, options.key, options.nonce)
    return identity(index, size, b"", b"")


def usable_bytes(capacity_bits: int, options: EmbedOptions) -> int:
    """Bytes available after the start offset and optional cap."""
    start_bits = options.start_byte * 8
    if start_bits > capacity_bits:
        raise CapacityError("The reserved region starts past the end of the carrier.")
    available = (capacity_bits - start_bits) // 8
    if options.max_bytes is not None:
        available = min(available, options.max_bytes)
    return available


def check_fit(data: bytes, capacity_bits: int, options: EmbedOptions) -> None:
    """Reject a payload that does not fit the selected region."""
    if len(data) > usable_bytes(capacity_bits, options):
        raise CapacityError(f"Need {len(data)} bytes but the selected region holds {usable_bytes(capacity_bits, options)}.")


def write_bits(capacity_bits: int, options: EmbedOptions, payload: bytes, set_bit: Callable[[int, int], None]) -> None:
    """Write payload bits, storing a sequential nonce preamble when placement is keyed."""
    if options.placement == "keyed":
        options.require_keyed_material()
        prefix = b"DDNN" + options.nonce
        sequential = EmbedOptions(placement="sequential", channels=options.channels, bit_planes=options.bit_planes, start_byte=options.start_byte, preserve_alpha=options.preserve_alpha)
        _write_one(capacity_bits, sequential, prefix, set_bit)
        keyed = EmbedOptions(
            placement="keyed",
            channels=options.channels,
            bit_planes=options.bit_planes,
            key=options.key,
            nonce=options.nonce,
            start_byte=options.start_byte + len(prefix),
            max_bytes=options.max_bytes,
            preserve_alpha=options.preserve_alpha,
        )
        _write_one(capacity_bits, keyed, payload, set_bit)
        return
    _write_one(capacity_bits, options, payload, set_bit)


def read_bits(capacity_bits: int, options: EmbedOptions, size: int, get_bit: Callable[[int], int]) -> tuple[bytes, EmbedOptions]:
    """Read a payload, discovering a keyed nonce preamble when present."""
    if options.placement == "keyed":
        sequential = EmbedOptions(placement="sequential", channels=options.channels, bit_planes=options.bit_planes, start_byte=options.start_byte)
        prefix = _read_one(capacity_bits, sequential, 20, get_bit)
        if not prefix.startswith(b"DDNN") or len(prefix) != 20:
            raise ArgumentError("Keyed carrier is missing its public nonce preamble.")
        if options.nonce and options.nonce != prefix[4:]:
            raise ArgumentError("Carrier nonce does not match the requested placement nonce.")
        options = EmbedOptions(
            placement="keyed",
            channels=options.channels,
            bit_planes=options.bit_planes,
            key=options.key,
            nonce=prefix[4:],
            start_byte=options.start_byte + 20,
            max_bytes=options.max_bytes,
            preserve_alpha=options.preserve_alpha,
        )
    return _read_one(capacity_bits, options, size, get_bit), options


def _write_one(capacity_bits: int, options: EmbedOptions, payload: bytes, set_bit: Callable[[int, int], None]) -> None:
    check_fit(payload, capacity_bits, options)
    start = options.start_byte * 8
    region = capacity_bits - start
    for bit_index, bit in enumerate(bits_of(payload)):
        set_bit(start + map_index(bit_index, region, options), bit)


def _read_one(capacity_bits: int, options: EmbedOptions, size: int, get_bit: Callable[[int], int]) -> bytes:
    check_fit(b"\x00" * size, capacity_bits, options)
    start = options.start_byte * 8
    region = capacity_bits - start
    bits = [get_bit(start + map_index(bit_index, region, options)) for bit_index in range(size * 8)]
    return bytes_of(bits)


def output_path(source: Path, destination: Path) -> None:
    """Refuse to write a carrier onto itself unless the caller already copied it."""
    if source.resolve() == destination.resolve():
        raise ArgumentError(f"Refusing to modify {source} in place. Choose a different output.")
