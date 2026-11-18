"""Carrier detection and the shared embed/extract facade."""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers import bmp, png, svg, text, wav, zipcar
from lupaxa.dead_drop.carriers.base import EmbedOptions, EmbedReport
from lupaxa.dead_drop.errors import IntegrityError, UnsupportedError
from lupaxa.dead_drop.limits import Limits

DEFAULT_ALGORITHM = {
    "png": "png-lsb",
    "bmp": "bmp-lsb",
    "wav": "wav-lsb",
    "txt": "txt-zero-width",
    "markdown": "md-zero-width",
    "svg": "svg-metadata",
    "zip": "zip-entry",
}

ALGORITHM_FORMAT = {
    "png-lsb": "png",
    "png-bitplane": "png",
    "png-chunk": "png",
    "bmp-lsb": "bmp",
    "wav-lsb": "wav",
    "txt-whitespace": "txt",
    "txt-space-tab": "txt",
    "txt-zero-width": "txt",
    "md-whitespace": "markdown",
    "md-space-tab": "markdown",
    "md-zero-width": "markdown",
    "svg-metadata": "svg",
    "zip-entry": "zip",
}

CONCEALMENT_CLASS = {
    "png-lsb": "covert",
    "png-bitplane": "covert",
    "png-chunk": "container",
    "bmp-lsb": "covert",
    "wav-lsb": "covert",
    "txt-whitespace": "covert",
    "txt-space-tab": "covert",
    "txt-zero-width": "covert",
    "md-whitespace": "covert",
    "md-space-tab": "covert",
    "md-zero-width": "covert",
    "svg-metadata": "structured",
    "zip-entry": "container",
}


@dataclass(frozen=True)
class AlgorithmInfo:
    """Declared properties for one embedding algorithm."""

    identifier: str
    version: str
    formats: tuple[str, ...]
    modes: tuple[str, ...]
    capacity_formula: str
    extraction_requires_key: bool
    extraction_requires_metadata: bool
    deterministic_placement: bool
    transformation_tolerance: str
    visualisations: tuple[str, ...]
    distortion_metrics: tuple[str, ...]
    forensic_tests: tuple[str, ...]
    concealment_class: str

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-ready properties."""
        return {
            "identifier": self.identifier,
            "version": self.version,
            "formats": list(self.formats),
            "modes": list(self.modes),
            "capacity_formula": self.capacity_formula,
            "extraction_requires_key": self.extraction_requires_key,
            "extraction_requires_metadata": self.extraction_requires_metadata,
            "deterministic_placement": self.deterministic_placement,
            "transformation_tolerance": self.transformation_tolerance,
            "visualisations": list(self.visualisations),
            "distortion_metrics": list(self.distortion_metrics),
            "forensic_tests": list(self.forensic_tests),
            "concealment_class": self.concealment_class,
        }


def algorithm_catalogue() -> dict[str, AlgorithmInfo]:
    """Return every algorithm shipped in this release."""
    items = [
        AlgorithmInfo(
            "png-lsb",
            "1",
            ("png",),
            ("RGB", "RGBA"),
            "width * height * channels * bit_planes / 8",
            False,
            False,
            True,
            "survives lossless pixel-preserving rewrites; destroyed by resize, JPEG, and most colour conversions",
            ("bit-plane", "difference", "histogram", "entropy"),
            ("mse", "psnr", "ssim"),
            ("chi-square-lsb", "bit-plane"),
            "covert",
        ),
        AlgorithmInfo(
            "png-bitplane",
            "1",
            ("png",),
            ("RGB", "RGBA"),
            "width * height * channels * selected_planes / 8",
            False,
            False,
            True,
            "same pixel constraints as png-lsb",
            ("bit-plane", "difference"),
            ("mse", "psnr", "ssim"),
            ("chi-square-lsb",),
            "covert",
        ),
        AlgorithmInfo(
            "png-chunk",
            "1",
            ("png",),
            ("RGB", "RGBA"),
            "configured container limit, independent of pixel count",
            False,
            False,
            True,
            "removed by metadata stripping; pixels are unchanged",
            ("structure",),
            (),
            ("chunk-scan",),
            "container",
        ),
        AlgorithmInfo(
            "bmp-lsb",
            "1",
            ("bmp",),
            ("BGR", "BGRA"),
            "width * height * channels * bit_planes / 8, excluding header and row padding",
            False,
            False,
            True,
            "survives lossless rewrites that preserve pixels",
            ("bit-plane", "difference"),
            ("mse", "psnr"),
            ("chi-square-lsb",),
            "covert",
        ),
        AlgorithmInfo(
            "wav-lsb",
            "1",
            ("wav",),
            ("pcm-8", "pcm-16", "pcm-24", "pcm-32"),
            "frames * selected_channels / 8",
            False,
            False,
            True,
            "destroyed by resampling, truncation, and lossy codecs",
            ("waveform", "sample-diff"),
            ("snr",),
            ("lsb-distribution",),
            "covert",
        ),
        AlgorithmInfo(
            "txt-whitespace",
            "1",
            ("txt",),
            ("utf-8",),
            "line_count - 1",
            False,
            False,
            True,
            "destroyed by whitespace trimming",
            ("whitespace",),
            (),
            ("trailing-whitespace",),
            "covert",
        ),
        AlgorithmInfo(
            "txt-space-tab",
            "1",
            ("txt",),
            ("utf-8",),
            "configured text limit",
            False,
            False,
            True,
            "destroyed by whitespace normalisation",
            ("whitespace",),
            (),
            ("space-tab",),
            "covert",
        ),
        AlgorithmInfo(
            "txt-zero-width",
            "1",
            ("txt",),
            ("utf-8",),
            "configured text limit",
            False,
            False,
            True,
            "destroyed by zero-width stripping and some normalisers",
            ("invisible-chars",),
            (),
            ("zero-width",),
            "covert",
        ),
        AlgorithmInfo(
            "md-whitespace",
            "1",
            ("markdown",),
            ("utf-8",),
            "line_count - 1",
            False,
            False,
            True,
            "destroyed by Markdown rewrapping and trimming",
            ("whitespace",),
            (),
            ("trailing-whitespace",),
            "covert",
        ),
        AlgorithmInfo(
            "md-space-tab",
            "1",
            ("markdown",),
            ("utf-8",),
            "configured text limit",
            False,
            False,
            True,
            "destroyed by Markdown rewrapping",
            ("whitespace",),
            (),
            ("space-tab",),
            "covert",
        ),
        AlgorithmInfo(
            "md-zero-width",
            "1",
            ("markdown",),
            ("utf-8",),
            "configured text limit",
            False,
            False,
            True,
            "destroyed by zero-width stripping",
            ("invisible-chars",),
            (),
            ("zero-width",),
            "covert",
        ),
        AlgorithmInfo(
            "svg-metadata",
            "1",
            ("svg",),
            ("xml",),
            "configured container limit",
            False,
            False,
            True,
            "visible in XML; removed by metadata sanitising",
            ("structure",),
            (),
            ("xml-metadata",),
            "structured",
        ),
        AlgorithmInfo(
            "zip-entry",
            "1",
            ("zip",),
            ("archive",),
            "configured container limit; archive grows",
            False,
            False,
            True,
            "visible as a named entry; survives repacking only if that entry is copied",
            ("structure",),
            (),
            ("entry-list",),
            "container",
        ),
    ]
    return {item.identifier: item for item in items}


def detect_format(path: Path) -> str:
    """Identify a carrier from its signature, then its suffix."""
    head = path.read_bytes()[:512]
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"BM"):
        return "bmp"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "wav"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    sample = head.lower()
    if b"<svg" in sample or path.suffix.lower() == ".svg":
        return "svg"
    if path.suffix.lower() == ".md":
        return "markdown"
    if path.suffix.lower() in {".txt", ".text"}:
        return "txt"
    raise UnsupportedError(f"Unsupported carrier format: {path}")


def resolve_algorithm(path: Path, algorithm: str) -> str:
    """Pick an explicit algorithm or the format default."""
    detected = detect_format(path)
    chosen = DEFAULT_ALGORITHM[detected] if algorithm in {"", "auto"} else algorithm
    expected = ALGORITHM_FORMAT.get(chosen)
    if expected is None:
        raise UnsupportedError(f"Unknown algorithm {algorithm!r}.")
    if expected != detected:
        raise UnsupportedError(f"Algorithm {chosen} does not support {detected} carriers.")
    return chosen


def capacity(path: Path, algorithm: str, options: EmbedOptions, limits: Limits) -> int:
    """Return usable payload bytes for this carrier and algorithm."""
    chosen = resolve_algorithm(path, algorithm)
    if chosen in {"png-lsb", "png-bitplane"}:
        total = png.capacity_bits(path, options)
    elif chosen == "png-chunk":
        return limits.max_container_payload_bytes
    elif chosen == "bmp-lsb":
        total = bmp.capacity_bits(path, options)
    elif chosen == "wav-lsb":
        total = wav.capacity_bits(path, options)
    elif chosen.startswith(("txt-", "md-")):
        return text.capacity_bytes(path, chosen, limit=limits.max_text_payload_bytes)
    elif chosen == "svg-metadata":
        return limits.max_container_payload_bytes
    else:
        return limits.max_container_payload_bytes
    usable = total // 8 - options.start_byte
    if options.placement == "keyed":
        usable -= 20
    return max(0, usable)


def embed(
    source: Path, destination: Path, payload: bytes, algorithm: str, options: EmbedOptions, limits: Limits
) -> EmbedReport:
    """Embed payload bytes, prefixed with their length, and return the engine report."""
    chosen = resolve_algorithm(source, algorithm)
    framed = struct.pack(">I", len(payload)) + payload
    if len(framed) > capacity(source, chosen, options, limits):
        from lupaxa.dead_drop.errors import CapacityError

        raise CapacityError(
            f"{source.name} can hold {capacity(source, chosen, options, limits)} bytes, not {len(framed)}."
        )
    if chosen in {"png-lsb", "png-bitplane"}:
        return png.embed_lsb(source, destination, framed, options, algorithm=chosen)
    if chosen == "png-chunk":
        return png.embed_chunk(source, destination, framed, options)
    if chosen == "bmp-lsb":
        return bmp.embed_lsb(source, destination, framed, options)
    if chosen == "wav-lsb":
        return wav.embed_lsb(source, destination, framed, options)
    if chosen.startswith(("txt-", "md-")):
        bounded = EmbedOptions(**{**options.__dict__, "max_bytes": limits.max_text_payload_bytes})
        return text.embed(source, destination, framed, bounded, algorithm=chosen)
    if chosen == "svg-metadata":
        bounded = EmbedOptions(**{**options.__dict__, "max_bytes": limits.max_container_payload_bytes})
        return svg.embed(source, destination, framed, bounded)
    return zipcar.embed(source, destination, framed, options, limits)


def extract(path: Path, algorithm: str, options: EmbedOptions, limits: Limits) -> bytes:
    """Extract the embedded byte string."""
    chosen = resolve_algorithm(path, algorithm)
    if chosen in {"png-lsb", "png-bitplane"}:
        raw = _extract_prefixed(path, options, limits, png.extract_lsb)
    elif chosen == "png-chunk":
        raw = png.extract_chunk(path)
    elif chosen == "bmp-lsb":
        raw = _extract_prefixed(path, options, limits, bmp.extract_lsb)
    elif chosen == "wav-lsb":
        raw = _extract_prefixed(path, options, limits, wav.extract_lsb)
    elif chosen.startswith(("txt-", "md-")):
        raw = _extract_text(path, chosen)
    elif chosen == "svg-metadata":
        raw = svg.extract(path)
    else:
        raw = zipcar.extract(path, options.entry_name, limits)
    return _strip_prefix(raw, limits)


def _extract_prefixed(
    path: Path, options: EmbedOptions, limits: Limits, reader: Callable[[Path, int, EmbedOptions], bytes]
) -> bytes:
    prefix = reader(path, 4, options)
    if len(prefix) != 4:
        raise IntegrityError("Embedded length prefix is truncated.")
    (length,) = struct.unpack(">I", prefix)
    if length > limits.max_input_bytes:
        raise IntegrityError("Embedded length exceeds the configured limit.")
    return reader(path, 4 + length, options)


def _strip_prefix(raw: bytes, limits: Limits) -> bytes:
    if len(raw) < 4:
        raise IntegrityError("Embedded payload is truncated.")
    (length,) = struct.unpack(">I", raw[:4])
    if length > limits.max_input_bytes or 4 + length > len(raw):
        raise IntegrityError("Embedded length does not match the recovered bytes.")
    return raw[4 : 4 + length]


def _extract_text(path: Path, algorithm: str) -> bytes:
    raw = path.read_text(encoding="utf-8")
    family = algorithm.split("-", 1)[1]
    if family == "whitespace":
        first = raw.splitlines()[0] if raw.splitlines() else ""
        size = len(first) - len(first.rstrip(" ")) - 1
        if size < 0:
            raise IntegrityError("Text carrier has no whitespace payload header.")
        return text.extract(path, size, algorithm)
    if family == "zero-width":
        marker = raw.find(text.MARKER)
        if marker < 0:
            raise IntegrityError("Text carrier has no zero-width payload.")
        bits = "".join(char for char in raw[marker + len(text.MARKER) :] if char in {text.ZW0, text.ZW1})
        if len(bits) < 32:
            raise IntegrityError("Zero-width payload is truncated.")
        size = text._bits_to_int(bits[:32])  # noqa: SLF001
        return text.extract(path, size, algorithm)
    # Space/tab stores no separate length. Read until a non-whitespace marker ends the block,
    # then keep whole bytes. Callers that need a length use the envelope inside the bytes.
    block_at = raw.rfind("\n\t")
    block = raw[block_at + 1 :] if block_at >= 0 else raw
    line = block.splitlines()[0] if block.splitlines() else ""
    size = max(0, (len(line) - 1) // 8)
    return text.extract(path, size, algorithm)


def validate(path: Path, limits: Limits) -> dict[str, Any]:
    """Validate a carrier for its detected format."""
    kind = detect_format(path)
    if kind == "png":
        return png.validate_png(path)
    if kind == "bmp":
        return bmp.validate_bmp(path)
    if kind == "wav":
        return wav.describe(path)
    if kind == "svg":
        return svg.validate_svg(path)
    if kind == "zip":
        return zipcar.inspect_zip(path, limits)
    info = text.analyse_text(path)
    info["format"] = kind
    return info
