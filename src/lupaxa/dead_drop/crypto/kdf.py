"""Password-based key derivation. Argon2id is the only supported KDF."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from argon2.low_level import Type, hash_secret_raw

from lupaxa.dead_drop.errors import ArgumentError, AuthenticationError


@dataclass(frozen=True)
class KdfParams:
    """Parameters stored beside a password-derived key."""

    time_cost: int = 2
    memory_kib: int = 19456
    parallelism: int = 1
    hash_len: int = 32

    def validate(self) -> None:
        """Reject parameters Argon2id cannot run or that are absurdly large."""
        if self.time_cost < 1 or self.time_cost > 128:
            raise ArgumentError("Argon2id time cost is outside 1..128.")
        if self.memory_kib < 8 or self.memory_kib > 4 * 1024 * 1024:
            raise ArgumentError("Argon2id memory cost is outside the supported range.")
        if self.parallelism < 1 or self.parallelism > 16:
            raise ArgumentError("Argon2id parallelism is outside 1..16.")
        if self.hash_len != 32:
            raise ArgumentError("Derived keys must be 32 bytes.")
        if self.memory_kib < 8 * self.parallelism:
            raise ArgumentError("Argon2id memory cost is too small for the parallelism.")


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """Derive a 32-byte key. The same message is used for every failure."""
    params.validate()
    if not isinstance(password, str) or password == "":
        raise AuthenticationError("Authentication failed.")
    if len(salt) < 16:
        raise ArgumentError("Password salt must be at least 16 bytes.")
    try:
        return cast(
            bytes,
            hash_secret_raw(
                secret=password.encode("utf-8"),
                salt=salt,
                time_cost=params.time_cost,
                memory_cost=params.memory_kib,
                parallelism=params.parallelism,
                hash_len=params.hash_len,
                type=Type.ID,
            ),
        )
    except Exception as exc:
        raise AuthenticationError("Authentication failed.") from exc
