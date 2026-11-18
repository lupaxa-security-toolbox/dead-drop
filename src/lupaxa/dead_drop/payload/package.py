"""Payload packages, compression, and nesting limits.

Compression always happens before encryption. The package format is the
plaintext inside an envelope, so names and file bytes are encrypted with the
envelope when encryption is enabled.
"""

from __future__ import annotations

import hashlib
import io
import lzma
import os
import struct
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from lupaxa.dead_drop.errors import FilesystemError, IntegrityError, LimitError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.paths import safe_join

PACKAGE_MAGIC = b"DDPL"
PACKAGE_VERSION = 1
KIND_BYTES = 1
KIND_FILE = 2
KIND_TREE = 3
KIND_NESTED = 4
COMPRESS_NONE = 0
COMPRESS_ZLIB = 1
COMPRESS_LZMA = 2


@dataclass
class PackageInfo:
    """Public description of a package. It does not include file contents."""

    kind: str
    name: str
    size: int
    sha256: str
    nested_depth: int
    member_count: int


def _zip_tree(paths: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in paths:
            if name.startswith("/") or ".." in Path(name).parts:
                raise FilesystemError(f"Refusing package member {name!r}.")
            archive.writestr(name, data)
    return buffer.getvalue()


def package_bytes(data: bytes, *, name: str = "payload.bin", nested_depth: int = 0) -> bytes:
    """Package an in-memory payload."""
    header = struct.pack(">4sBBHI", PACKAGE_MAGIC, PACKAGE_VERSION, KIND_BYTES, nested_depth, len(name.encode()))
    return header + name.encode("utf-8") + struct.pack(">Q", len(data)) + data


def package_path(path: Path, *, limits: Limits, nested_depth: int = 0) -> bytes:
    """Package a file or directory without loading a whole tree at once when zipping."""
    if path.is_dir():
        members: list[tuple[str, bytes]] = []
        total = 0
        for current in sorted(item for item in path.rglob("*") if item.is_file() and not item.is_symlink()):
            relative = current.relative_to(path).as_posix()
            data = current.read_bytes()
            total += len(data)
            limits.check_input(total, what=relative)
            members.append((relative, data))
        blob = _zip_tree(members)
        header = struct.pack(">4sBBHI", PACKAGE_MAGIC, PACKAGE_VERSION, KIND_TREE, nested_depth, len(b"tree"))
        return header + b"tree" + struct.pack(">Q", len(blob)) + blob
    data = path.read_bytes()
    limits.check_input(len(data), what=str(path))
    return package_bytes(data, name=path.name, nested_depth=nested_depth)


def package_info(package: bytes) -> PackageInfo:
    """Describe a package without treating it as an authenticated file."""
    kind, name, data, depth = _split_package(package)
    labels = {KIND_BYTES: "bytes", KIND_FILE: "file", KIND_TREE: "directory", KIND_NESTED: "nested"}
    members = 1
    if kind == KIND_TREE:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = len(archive.infolist())
    return PackageInfo(labels.get(kind, "unknown"), name, len(data), hashlib.sha256(data).hexdigest(), depth, members)


def unpack_package(package: bytes, destination: Path, *, limits: Limits, seen: set[bytes] | None = None) -> Path:
    """Unpack a package. Existing destination files are left in place on failure."""
    kind, name, data, depth = _split_package(package)
    limits.check_nesting(depth)
    limits.check_expansion(len(data))
    identity = hashlib.sha256(package).digest()
    seen_ids = set() if seen is None else set(seen)
    if identity in seen_ids:
        raise LimitError("Circular payload nesting was detected.")
    seen_ids.add(identity)
    destination.mkdir(parents=True, exist_ok=True)
    if kind in {KIND_BYTES, KIND_FILE, KIND_NESTED}:
        target = safe_join(destination, Path(name).name)
        if target.exists():
            raise FilesystemError(f"Refusing to overwrite {target}.")
        partial = target.with_suffix(target.suffix + ".partial")
        partial.write_bytes(data)
        partial.replace(target)
        return target
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        _guard_zip(archive, limits)
        for info in archive.infolist():
            target = safe_join(destination, info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise FilesystemError(f"Duplicate output path {target}.")
            member = archive.read(info)
            limits.check_expansion(len(member))
            target.write_bytes(member)
    return destination


def _split_package(package: bytes) -> tuple[int, str, bytes, int]:
    if len(package) < 12 or not package.startswith(PACKAGE_MAGIC):
        raise IntegrityError("Payload package header is missing.")
    magic, version, kind, depth, name_length = struct.unpack_from(">4sBBHI", package)
    if magic != PACKAGE_MAGIC or version != PACKAGE_VERSION:
        raise IntegrityError("Unsupported payload package version.")
    offset = 12
    if offset + name_length + 8 > len(package):
        raise IntegrityError("Payload package is truncated.")
    name = package[offset : offset + name_length].decode("utf-8", "strict")
    offset += name_length
    (size,) = struct.unpack_from(">Q", package, offset)
    offset += 8
    if size != len(package) - offset:
        raise IntegrityError("Payload package length does not match its header.")
    return kind, name, package[offset:], depth


def _guard_zip(archive: zipfile.ZipFile, limits: Limits) -> None:
    if len(archive.infolist()) > limits.max_zip_entries:
        raise LimitError("Archive has too many entries.")
    total = 0
    for info in archive.infolist():
        if info.filename.startswith("/") or ".." in Path(info.filename).parts or info.filename.startswith("\\"):
            raise FilesystemError(f"Archive member {info.filename!r} is unsafe.")
        total += info.file_size
        if (
            info.compress_size
            and info.file_size / max(info.compress_size, 1) > limits.max_compression_ratio
            and info.file_size > 1024 * 1024
        ):
            raise LimitError(f"Archive member {info.filename!r} looks like a decompression bomb.")
        limits.check_expansion(total)


def compress(data: bytes, method: str, *, limit: int) -> tuple[bytes, int]:
    """Compress before encryption. ``auto`` keeps the smallest useful result."""
    if method == "none":
        return data, COMPRESS_NONE
    if method == "zlib":
        return zlib.compress(data, 9), COMPRESS_ZLIB
    if method == "lzma":
        return lzma.compress(data), COMPRESS_LZMA
    if method != "auto":
        raise IntegrityError(f"Unknown compression method {method!r}.")
    candidates = [(data, COMPRESS_NONE), (zlib.compress(data, 9), COMPRESS_ZLIB), (lzma.compress(data), COMPRESS_LZMA)]
    best = min(candidates, key=lambda item: len(item[0]))
    if len(best[0]) > limit:
        raise LimitError("Compressed payload exceeds the configured limit.")
    if len(best[0]) >= len(data) - 32:
        return data, COMPRESS_NONE
    return best


def decompress(data: bytes, method: int, *, limit: int) -> bytes:
    """Reverse compression and stop past the expansion limit."""
    if method == COMPRESS_NONE:
        if len(data) > limit:
            raise LimitError("Payload exceeds the decompression limit.")
        return data
    if method == COMPRESS_ZLIB:
        decompressor = zlib.decompressobj()
        try:
            plain = decompressor.decompress(data, max_length=limit)
        except zlib.error as exc:
            raise IntegrityError("Zlib payload could not be decompressed.") from exc
        if decompressor.unconsumed_tail or not decompressor.eof:
            raise LimitError("Zlib payload exceeds the decompression limit.")
        return plain
    if method == COMPRESS_LZMA:
        lzma_decoder = lzma.LZMADecompressor()
        try:
            plain = lzma_decoder.decompress(data, max_length=limit)
        except lzma.LZMAError as exc:
            raise IntegrityError("LZMA payload could not be decompressed.") from exc
        if lzma_decoder.eof is False and not lzma_decoder.needs_input:
            raise LimitError("LZMA payload exceeds the decompression limit.")
        return plain
    raise IntegrityError("Unknown compression identifier.")


def stamp() -> str:
    """UTC timestamp used for vault metadata."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_id() -> bytes:
    """16-byte random identifier."""
    return os.urandom(16)
