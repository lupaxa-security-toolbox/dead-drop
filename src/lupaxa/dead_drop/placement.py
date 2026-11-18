"""Keyed and sequential placement.

Keyed placement is a cycle-walking affine permutation. It is a concealment
placement stream, not an encryption primitive. The carrier nonce is public.
The placement key is not.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable

from lupaxa.dead_drop.errors import ArgumentError


def _prime_after(value: int) -> int:
    candidate = max(value + 1, 2)
    if candidate % 2 == 0:
        candidate += 1
    while not _is_prime(candidate):
        candidate += 2
    return candidate


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def _affine_constants(key: bytes, nonce: bytes) -> tuple[int, int, int]:
    material = hmac.new(key, b"dead-drop-placement" + nonce, hashlib.sha256).digest()
    return int.from_bytes(material[:8], "big") | 1, int.from_bytes(material[8:16], "big"), 0


def permute(index: int, size: int, key: bytes, nonce: bytes) -> int:
    """Map ``index`` onto a unique position in ``0 .. size-1``."""
    if size <= 1:
        return 0
    if not 0 <= index < size:
        raise ArgumentError("Placement index is outside the carrier capacity.")
    prime = _prime_after(size)
    multiplier, addend, _ignored = _affine_constants(key, nonce)
    multiplier %= prime
    if multiplier == 0:
        multiplier = 1
    addend %= prime
    value = index
    for _ in range(prime):
        value = (value * multiplier + addend) % prime
        if value < size:
            return value
    raise ArgumentError("Placement permutation failed to land inside the carrier.")


def identity(index: int, size: int, key: bytes, nonce: bytes) -> int:
    """Sequential placement."""
    del key, nonce
    if not 0 <= index < size:
        raise ArgumentError("Placement index is outside the carrier capacity.")
    return index


def mapper(strategy: str) -> Callable[[int, int, bytes, bytes], int]:
    """Return the placement function for a strategy name."""
    if strategy == "keyed":
        return permute
    if strategy in {"sequential", "distributed", "capacity-weighted", "reserved"}:
        return identity
    raise ArgumentError(f"Unknown placement strategy {strategy!r}.")
