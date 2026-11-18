"""Versioned payload envelope.

All integers are big-endian. The fixed header is 50 bytes. When a password
KDF is used, a 10-byte parameter block follows. Salt and nonce follow that.
The body is either ciphertext (encryption tag included) or plaintext. An
unencrypted body is followed by SHA-256 over everything before that digest.
Authenticated encryption covers the header, KDF block, salt, and nonce as
additional data. Encryption does not conceal the payload identifier, fragment
index, or coding parameters, because recovery has to group fragments before
it can decrypt them.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from lupaxa.dead_drop.crypto.aead import decrypt, encrypt, encrypted_body_length
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.errors import IntegrityError, UnsupportedError

MAGIC = b"DDR1"
VERSION = 1
HEADER = struct.Struct(">4sBBHH16sHHBBBBBBBBQI")
KDF_BLOCK = struct.Struct(">IIBB")

TYPE_SINGLE = 1
TYPE_FRAGMENT = 2
TYPE_KEY_SHARE = 3
TYPE_VAULT_BLOCK = 4
TYPE_VAULT_METADATA = 5
TYPE_SLOT_TABLE = 6
TYPE_VAULT_POINTER = 7

FLAG_COMPRESSED = 1
FLAG_ENCRYPTED = 2
FLAG_LZMA = 4
FLAG_ERASURE = 8
FLAG_KEYED = 16
FLAG_NESTED = 32
FLAG_DECOY = 64

ENC_NONE = 0
ENC_AES = 1
ENC_CHACHA = 2
ENC_NAMES = {ENC_NONE: "none", ENC_AES: "aes-256-gcm", ENC_CHACHA: "chacha20-poly1305"}
ENC_IDS = {name: ident for ident, name in ENC_NAMES.items()}
KDF_NONE = 0
KDF_ARGON2ID = 1


@dataclass
class Envelope:
    """One decoded envelope."""

    envelope_type: int
    flags: int
    algorithm_id: int
    payload_id: bytes
    fragment_index: int
    fragment_count: int
    data_shards: int
    parity_shards: int
    compression_id: int
    kdf_id: int
    encryption_id: int
    payload_length: int
    salt: bytes
    nonce: bytes
    body: bytes
    kdf: KdfParams | None
    plaintext: bytes

    @property
    def encrypted(self) -> bool:
        """Whether the body is authenticated ciphertext."""
        return bool(self.flags & FLAG_ENCRYPTED)


def build_envelope(
    *,
    envelope_type: int,
    algorithm_id: int,
    payload_id: bytes,
    plaintext: bytes,
    fragment_index: int = 0,
    fragment_count: int = 1,
    data_shards: int = 1,
    parity_shards: int = 0,
    compression_id: int = 0,
    flags: int = 0,
    encryption: str = "none",
    key: bytes | None = None,
    kdf: KdfParams | None = None,
    salt: bytes = b"",
    nonce_prefix: bytes = b"",
    max_plain_bytes: int,
) -> bytes:
    """Serialise an envelope. ``plaintext`` is the bytes stored in the body."""
    if len(payload_id) != 16:
        raise IntegrityError("Payload identifiers must be 16 bytes.")
    if len(plaintext) > max_plain_bytes:
        raise IntegrityError("Payload exceeds the configured size limit.")
    encryption_id = ENC_IDS[encryption]
    kdf_id = KDF_ARGON2ID if kdf is not None else KDF_NONE
    if encryption_id == ENC_NONE:
        if key is not None:
            raise IntegrityError("An encryption key was supplied without an algorithm.")
        nonce = b""
        body_length = len(plaintext)
        flags = flags & ~FLAG_ENCRYPTED
    else:
        if key is None or len(nonce_prefix) != 8:
            raise IntegrityError("Encrypted envelopes require a key and an 8-byte nonce prefix.")
        flags |= FLAG_ENCRYPTED
        nonce = nonce_prefix + b"\x00\x00\x00\x00"
        body_length = encrypted_body_length(len(plaintext))
    if parity_shards:
        flags |= FLAG_ERASURE
    if compression_id == 2:
        flags |= FLAG_COMPRESSED | FLAG_LZMA
    elif compression_id == 1:
        flags |= FLAG_COMPRESSED
    header = HEADER.pack(
        MAGIC,
        VERSION,
        envelope_type,
        flags,
        algorithm_id,
        payload_id,
        fragment_index,
        fragment_count,
        data_shards,
        parity_shards,
        compression_id,
        kdf_id,
        encryption_id,
        len(nonce),
        len(salt),
        0,
        len(plaintext),
        body_length,
    )
    if HEADER.size != 50:
        raise IntegrityError("Envelope header layout drifted from the documented 50-byte size.")
    prefix = header
    if kdf is not None:
        kdf.validate()
        prefix += KDF_BLOCK.pack(kdf.time_cost, kdf.memory_kib, kdf.parallelism, kdf.hash_len)
    prefix += salt + nonce
    if encryption_id == ENC_NONE:
        digest = hashlib.sha256(prefix + plaintext).digest()
        return prefix + plaintext + digest
    body = encrypt(key, nonce_prefix, plaintext, prefix, encryption)  # type: ignore[arg-type]
    if len(body) != body_length:
        raise IntegrityError("Encrypted body length does not match the envelope header.")
    return prefix + body


def parse_envelope(blob: bytes, *, key: bytes | None, max_plain_bytes: int) -> Envelope:
    """Parse an envelope and recover plaintext only after authentication."""
    if len(blob) < HEADER.size or not blob.startswith(MAGIC):
        raise IntegrityError("Carrier data does not contain a Dead Drop envelope.")
    (
        magic,
        version,
        envelope_type,
        flags,
        algorithm_id,
        payload_id,
        fragment_index,
        fragment_count,
        data_shards,
        parity_shards,
        compression_id,
        kdf_id,
        encryption_id,
        nonce_len,
        salt_len,
        _reserved,
        payload_length,
        body_length,
    ) = HEADER.unpack_from(blob)
    if magic != MAGIC or version != VERSION:
        raise UnsupportedError("Unsupported envelope version.")
    if payload_length < 0 or body_length < 0 or payload_length > max_plain_bytes:
        raise IntegrityError("Envelope length fields are not usable.")
    offset = HEADER.size
    kdf: KdfParams | None = None
    if kdf_id == KDF_ARGON2ID:
        if offset + KDF_BLOCK.size > len(blob):
            raise IntegrityError("Envelope KDF parameters are truncated.")
        time_cost, memory_kib, parallelism, hash_len = KDF_BLOCK.unpack_from(blob, offset)
        offset += KDF_BLOCK.size
        kdf = KdfParams(time_cost, memory_kib, parallelism, hash_len)
        try:
            kdf.validate()
        except Exception as exc:
            raise IntegrityError("Envelope KDF parameters are invalid.") from exc
    elif kdf_id != KDF_NONE:
        raise UnsupportedError("Unsupported password KDF.")
    if offset + salt_len + nonce_len + body_length > len(blob):
        raise IntegrityError("Envelope body is truncated.")
    salt = blob[offset : offset + salt_len]
    offset += salt_len
    nonce = blob[offset : offset + nonce_len]
    offset += nonce_len
    prefix = blob[:offset]
    body = blob[offset : offset + body_length]
    offset += body_length
    if encryption_id == ENC_NONE:
        if flags & FLAG_ENCRYPTED:
            raise IntegrityError("Envelope encryption flag does not match the algorithm.")
        if offset + 32 > len(blob):
            raise IntegrityError("Envelope integrity digest is truncated.")
        digest = blob[offset : offset + 32]
        if not hmac.compare_digest(hashlib.sha256(prefix + body).digest(), digest):
            raise IntegrityError("Envelope integrity check failed.")
        if len(body) != payload_length:
            raise IntegrityError("Envelope payload length does not match the body.")
        plaintext = body
    else:
        if encryption_id not in ENC_NAMES or ENC_NAMES[encryption_id] == "none":
            raise UnsupportedError("Unsupported encryption algorithm identifier.")
        if key is None:
            raise IntegrityError("This envelope is encrypted and no key was provided.")
        if len(nonce) != 12:
            raise IntegrityError("Encrypted envelope nonce must be 12 bytes.")
        try:
            plaintext = decrypt(
                key,
                nonce[:8],
                body,
                prefix,
                ENC_NAMES[encryption_id],
                max_plain_bytes=max_plain_bytes,
            )
        except Exception as exc:
            from lupaxa.dead_drop.errors import AuthenticationError

            if isinstance(exc, AuthenticationError):
                raise
            raise IntegrityError("Encrypted envelope could not be read.") from exc
        if len(plaintext) != payload_length:
            raise IntegrityError("Decrypted payload length does not match the envelope.")
    return Envelope(
        envelope_type=envelope_type,
        flags=flags,
        algorithm_id=algorithm_id,
        payload_id=payload_id,
        fragment_index=fragment_index,
        fragment_count=fragment_count,
        data_shards=data_shards,
        parity_shards=parity_shards,
        compression_id=compression_id,
        kdf_id=kdf_id,
        encryption_id=encryption_id,
        payload_length=payload_length,
        salt=salt,
        nonce=nonce,
        body=body,
        kdf=kdf,
        plaintext=plaintext,
    )


def envelope_total_length(header: bytes) -> int:
    """Return the on-carrier size of an envelope from its first 50 bytes."""
    if len(header) < HEADER.size:
        raise IntegrityError("Envelope header is truncated.")
    fields = HEADER.unpack_from(header)
    kdf_id = fields[11]
    encryption_id = fields[12]
    nonce_len = fields[13]
    salt_len = fields[14]
    body_length = fields[17]
    total = HEADER.size + salt_len + nonce_len + body_length
    if kdf_id == KDF_ARGON2ID:
        total += KDF_BLOCK.size
    elif kdf_id != KDF_NONE:
        raise UnsupportedError("Unsupported password KDF.")
    if encryption_id == ENC_NONE:
        total += 32
    return int(total)


def walk_frames(blob: bytes) -> list[bytes]:
    """Split a concatenation of ``u32 length || envelope`` frames."""
    frames: list[bytes] = []
    offset = 0
    while offset < len(blob):
        if offset + 4 > len(blob):
            raise IntegrityError("Embedded frame header is truncated.")
        (length,) = struct.unpack_from(">I", blob, offset)
        offset += 4
        if length < HEADER.size or offset + length > len(blob):
            raise IntegrityError("Embedded frame is truncated.")
        frames.append(blob[offset : offset + length])
        offset += length
    return frames


def pack_frames(envelopes: list[bytes]) -> bytes:
    """Concatenate envelopes with explicit lengths."""
    parts: list[bytes] = []
    for envelope in envelopes:
        if len(envelope) > 0xFFFFFFFF:
            raise IntegrityError("Envelope is too large to frame.")
        parts.append(struct.pack(">I", len(envelope)))
        parts.append(envelope)
    return b"".join(parts)
