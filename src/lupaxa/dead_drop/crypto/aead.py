"""Chunked authenticated encryption using maintained primitives."""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from lupaxa.dead_drop.errors import AuthenticationError, IntegrityError, UnsupportedError

AES_256_GCM = "aes-256-gcm"
CHACHA20_POLY1305 = "chacha20-poly1305"
ALGORITHMS = (AES_256_GCM, CHACHA20_POLY1305)
CHUNK_SIZE = 1024 * 1024
TAG_LENGTH = 16
_HEADER = struct.Struct(">I")
_CHUNK = struct.Struct(">BI")


def normalise_algorithm(name: str) -> str:
    """Return the canonical algorithm name."""
    cleaned = name.strip().lower().replace("_", "-")
    aliases = {
        "aes-256-gcm": AES_256_GCM,
        "aesgcm": AES_256_GCM,
        "chacha20-poly1305": CHACHA20_POLY1305,
        "chacha20": CHACHA20_POLY1305,
    }
    if cleaned not in aliases:
        raise UnsupportedError(f"Unsupported encryption algorithm {name!r}.")
    return aliases[cleaned]


def encrypted_body_length(plain_length: int, *, chunk_size: int = CHUNK_SIZE) -> int:
    """Return the ciphertext body length for a known plaintext size."""
    if plain_length < 0:
        raise IntegrityError("Plaintext length is negative.")
    chunks = 1 if plain_length == 0 else (plain_length + chunk_size - 1) // chunk_size
    remaining = plain_length
    total = _HEADER.size
    for _ in range(chunks):
        size = 0 if plain_length == 0 else min(chunk_size, remaining)
        total += _CHUNK.size + size + TAG_LENGTH
        remaining -= size
    return total


def _cipher(algorithm: str, key: bytes) -> AESGCM | ChaCha20Poly1305:
    if len(key) != 32:
        raise IntegrityError("Encryption keys must be 32 bytes.")
    name = normalise_algorithm(algorithm)
    if name == AES_256_GCM:
        return AESGCM(key)
    return ChaCha20Poly1305(key)


def chunk_nonce(prefix: bytes, index: int) -> bytes:
    """Build a 12-byte nonce from an 8-byte prefix and a chunk counter."""
    if len(prefix) != 8:
        raise IntegrityError("Nonce prefix must be 8 bytes.")
    if index < 0 or index > 0xFFFFFFFF:
        raise IntegrityError("Chunk index is outside the nonce counter range.")
    return prefix + struct.pack(">I", index)


def encrypt(key: bytes, nonce_prefix: bytes, plaintext: bytes, aad: bytes, algorithm: str) -> bytes:
    """Encrypt plaintext as a sequence of authenticated chunks."""
    cipher = _cipher(algorithm, key)
    parts = [_HEADER.pack(CHUNK_SIZE)]
    if not plaintext:
        ranges = [(0, b"")]
    else:
        ranges = []
        for index in range(0, len(plaintext), CHUNK_SIZE):
            ranges.append((index // CHUNK_SIZE, plaintext[index : index + CHUNK_SIZE]))
    for number, (index, chunk) in enumerate(ranges):
        last = number == len(ranges) - 1
        nonce = chunk_nonce(nonce_prefix, index)
        associated = aad + struct.pack(">I", index)
        ciphertext = cipher.encrypt(nonce, chunk, associated)
        parts.append(_CHUNK.pack(1 if last else 0, len(ciphertext)))
        parts.append(ciphertext)
    return b"".join(parts)


def decrypt(key: bytes, nonce_prefix: bytes, body: bytes, aad: bytes, algorithm: str, *, max_plain_bytes: int) -> bytes:
    """Decrypt a chunked body and enforce the expansion limit."""
    cipher = _cipher(algorithm, key)
    if len(body) < _HEADER.size:
        raise IntegrityError("Encrypted body is truncated.")
    (chunk_size,) = _HEADER.unpack_from(body, 0)
    if chunk_size <= 0 or chunk_size > CHUNK_SIZE:
        raise IntegrityError("Encrypted body uses an unsupported chunk size.")
    offset = _HEADER.size
    output = bytearray()
    index = 0
    seen_last = False
    while offset < len(body):
        if seen_last:
            raise IntegrityError("Data follows the final encrypted chunk.")
        if offset + _CHUNK.size > len(body):
            raise IntegrityError("Encrypted chunk header is truncated.")
        flags, length = _CHUNK.unpack_from(body, offset)
        offset += _CHUNK.size
        if length < TAG_LENGTH or offset + length > len(body):
            raise IntegrityError("Encrypted chunk is truncated.")
        ciphertext = body[offset : offset + length]
        offset += length
        nonce = chunk_nonce(nonce_prefix, index)
        associated = aad + struct.pack(">I", index)
        try:
            plain = cipher.decrypt(nonce, ciphertext, associated)
        except Exception as exc:
            raise AuthenticationError("Authentication failed.") from exc
        if len(output) + len(plain) > max_plain_bytes:
            raise IntegrityError("Decrypted payload exceeds the configured size limit.")
        output.extend(plain)
        seen_last = bool(flags & 1)
        index += 1
        if index > 0xFFFFFFFF:
            raise IntegrityError("Too many encrypted chunks.")
    if not seen_last:
        raise IntegrityError("Encrypted body is missing its final chunk.")
    return bytes(output)
