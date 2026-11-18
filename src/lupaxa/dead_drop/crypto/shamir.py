"""Shamir secret sharing over GF(2^8).

Shares use the AES polynomial. Reconstruction checks a SHA-256 binding that
was shared with the secret, so a wrong share set does not return key bytes.
Fewer than the threshold number of distinct shares is refused before interpolation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from lupaxa.dead_drop.errors import ArgumentError, IntegrityError

SHARE_MAGIC = b"DDSS"
SHARE_VERSION = 1
_HEADER = struct.Struct(">4sB16sBBBHH")


def _mul(left: int, right: int) -> int:
    product = 0
    for _ in range(8):
        if right & 1:
            product ^= left
        high = left & 0x80
        left = (left << 1) & 0xFF
        if high:
            left ^= 0x1B
        right >>= 1
    return product


def _pow(value: int, exponent: int) -> int:
    result = 1
    base = value
    while exponent:
        if exponent & 1:
            result = _mul(result, base)
        base = _mul(base, base)
        exponent >>= 1
    return result


def _inv(value: int) -> int:
    if value == 0:
        raise IntegrityError("Shamir interpolation divided by zero.")
    return _pow(value, 254)


def _evaluate(coefficients: list[int], x_value: int) -> int:
    result = 0
    power = 1
    for coefficient in coefficients:
        result ^= _mul(coefficient, power)
        power = _mul(power, x_value)
    return result


def _interpolate(points: list[tuple[int, int]]) -> int:
    secret = 0
    for index, (x_value, y_value) in enumerate(points):
        numerator = 1
        denominator = 1
        for other, (other_x, _) in enumerate(points):
            if index == other:
                continue
            numerator = _mul(numerator, other_x)
            denominator = _mul(denominator, x_value ^ other_x)
        secret ^= _mul(y_value, _mul(numerator, _inv(denominator)))
    return secret


@dataclass(frozen=True)
class Share:
    """One Shamir share."""

    set_id: bytes
    threshold: int
    share_count: int
    index: int
    payload_length: int
    values: bytes
    checksum: bytes

    def serialise(self) -> bytes:
        """Encode the share, including its checksum."""
        body = (
            _HEADER.pack(
                SHARE_MAGIC,
                SHARE_VERSION,
                self.set_id,
                self.threshold,
                self.share_count,
                self.index,
                self.payload_length,
                len(self.values),
            )
            + self.values
        )
        digest = hashlib.sha256(body).digest()
        return body + digest


def parse_share(blob: bytes) -> Share:
    """Parse one share and reject a bad checksum or header."""
    if len(blob) < _HEADER.size + 32:
        raise IntegrityError("Share is truncated.")
    digest = blob[-32:]
    body = blob[:-32]
    if not hmac.compare_digest(hashlib.sha256(body).digest(), digest):
        raise IntegrityError("Share checksum does not match.")
    magic, version, set_id, threshold, share_count, index, payload_length, value_length = _HEADER.unpack_from(body)
    if magic != SHARE_MAGIC or version != SHARE_VERSION:
        raise IntegrityError("Share header is not a Dead Drop share.")
    values = body[_HEADER.size :]
    if len(values) != value_length:
        raise IntegrityError("Share value length does not match the header.")
    if index < 1 or index > 255 or threshold < 1 or share_count < threshold or threshold > 255:
        raise IntegrityError("Share threshold metadata is invalid.")
    return Share(set_id, threshold, share_count, index, payload_length, values, digest)


def split_secret(secret: bytes, *, shares: int, threshold: int) -> list[Share]:
    """Split a secret into ``shares`` shares with the given threshold."""
    if not 1 <= threshold <= shares <= 255:
        raise ArgumentError("Share threshold must satisfy 1 <= threshold <= shares <= 255.")
    if not secret:
        raise ArgumentError("Refusing to split an empty secret.")
    binding = hashlib.sha256(secret).digest()
    protected = secret + binding
    set_id = os.urandom(16)
    encoded: list[list[int]] = []
    for byte in protected:
        coefficients = [byte] + [os.urandom(1)[0] for _ in range(threshold - 1)]
        encoded.append(coefficients)
    results: list[Share] = []
    for index in range(1, shares + 1):
        values = bytes(_evaluate(coefficients, index) for coefficients in encoded)
        share = Share(set_id, threshold, shares, index, len(secret), values, b"")
        results.append(parse_share(share.serialise()))
    return results


def combine_shares(shares: list[Share]) -> bytes:
    """Reconstruct a secret. The result is returned only after the binding matches."""
    if not shares:
        raise ArgumentError("No shares were provided.")
    set_ids = {share.set_id for share in shares}
    if len(set_ids) != 1:
        raise IntegrityError("Shares from different sets cannot be combined.")
    thresholds = {share.threshold for share in shares}
    counts = {share.share_count for share in shares}
    lengths = {share.payload_length for share in shares}
    widths = {len(share.values) for share in shares}
    if len(thresholds) != 1 or len(counts) != 1 or len(lengths) != 1 or len(widths) != 1:
        raise IntegrityError("Share metadata does not agree.")
    threshold = shares[0].threshold
    indexes = [share.index for share in shares]
    if len(indexes) != len(set(indexes)):
        raise IntegrityError("Duplicate shares do not count towards the threshold.")
    if len(shares) < threshold:
        raise IntegrityError("Fewer than the required shares were provided.")
    chosen = shares[:threshold]
    width = len(chosen[0].values)
    restored = bytearray()
    for position in range(width):
        points = [(share.index, share.values[position]) for share in chosen]
        restored.append(_interpolate(points))
    payload_length = chosen[0].payload_length
    if payload_length + 32 != width:
        raise IntegrityError("Share payload length does not match the binding.")
    secret = bytes(restored[:payload_length])
    binding = bytes(restored[payload_length:])
    if not hmac.compare_digest(hashlib.sha256(secret).digest(), binding):
        raise IntegrityError("Reconstructed secret failed its integrity check.")
    return secret
