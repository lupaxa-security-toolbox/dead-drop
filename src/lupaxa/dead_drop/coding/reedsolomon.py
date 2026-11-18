"""Reed-Solomon erasure coding for equal-sized shards.

Any ``k`` complete shards reconstruct the encoded bytes. This is redundancy,
not authentication. Callers still have to verify an authenticated payload.
"""

from __future__ import annotations

from lupaxa.dead_drop.errors import ArgumentError, FragmentError, IntegrityError


def _codec(parity_shards: int) -> object:
    from reedsolo import RSCodec

    return RSCodec(parity_shards)


def shard_parameters(data_shards: int, parity_shards: int) -> dict[str, int]:
    """Return the public parameters for a k-of-n layout."""
    if data_shards < 1 or parity_shards < 0:
        raise ArgumentError("Shard counts must be non-negative and include at least one data shard.")
    total = data_shards + parity_shards
    if total > 255:
        raise ArgumentError("Reed-Solomon shard count cannot exceed 255.")
    return {
        "data_shards": data_shards,
        "parity_shards": parity_shards,
        "total_shards": total,
        "reconstruction_threshold": data_shards,
    }


def encode(payload: bytes, *, data_shards: int, parity_shards: int) -> list[bytes]:
    """Split ``payload`` into systematic data shards plus parity shards."""
    params = shard_parameters(data_shards, parity_shards)
    del params
    if parity_shards == 0:
        return _split_only(payload, data_shards)
    length = len(payload)
    padded = payload
    if length % data_shards:
        padded += b"\x00" * (data_shards - (length % data_shards))
    shard_length = len(padded) // data_shards
    data = [bytearray(padded[index * shard_length : (index + 1) * shard_length]) for index in range(data_shards)]
    parity = [bytearray(shard_length) for _ in range(parity_shards)]
    codec = _codec(parity_shards)
    for position in range(shard_length):
        message = bytes(piece[position] for piece in data)
        encoded = bytes(codec.encode(message))  # type: ignore[attr-defined]
        if len(encoded) != data_shards + parity_shards:
            raise IntegrityError("Reed-Solomon encoder returned an unexpected width.")
        for index in range(parity_shards):
            parity[index][position] = encoded[data_shards + index]
    return [bytes(piece) for piece in data + parity]


def decode(
    shards: list[bytes | None],
    *,
    data_shards: int,
    parity_shards: int,
    payload_length: int,
) -> bytes:
    """Reconstruct the original payload from any ``data_shards`` shards."""
    shard_parameters(data_shards, parity_shards)
    if len(shards) != data_shards + parity_shards:
        raise FragmentError("Shard list does not match the declared code.")
    present = [shard for shard in shards if shard is not None]
    if len(present) < data_shards:
        raise FragmentError(f"{len(present)} shards are available; {data_shards} are required.")
    if parity_shards == 0:
        if any(shard is None for shard in shards[:data_shards]):
            raise FragmentError("A data shard is missing and no parity was configured.")
        joined = b"".join(shard for shard in shards[:data_shards] if shard is not None)
        return joined[:payload_length]
    lengths = {len(shard) for shard in present}
    if len(lengths) != 1:
        raise IntegrityError("Shard sizes do not match.")
    shard_length = lengths.pop()
    codec = _codec(parity_shards)
    restored = [bytearray(shard_length) for _ in range(data_shards)]
    erase_pos = [index for index, shard in enumerate(shards) if shard is None]
    for position in range(shard_length):
        block = bytearray(data_shards + parity_shards)
        for index, shard in enumerate(shards):
            block[index] = 0 if shard is None else shard[position]
        try:
            decoded = codec.decode(bytes(block), erase_pos=erase_pos)[0]  # type: ignore[attr-defined]
        except Exception as exc:
            raise FragmentError("Erasure decoding failed.") from exc
        message = bytes(decoded)[:data_shards]
        for index in range(data_shards):
            restored[index][position] = message[index]
    joined = b"".join(restored)
    if payload_length > len(joined):
        raise IntegrityError("Declared payload length exceeds the reconstructed bytes.")
    return joined[:payload_length]


def _split_only(payload: bytes, data_shards: int) -> list[bytes]:
    padded = payload
    if len(payload) % data_shards:
        padded += b"\x00" * (data_shards - (len(payload) % data_shards))
    shard_length = len(padded) // data_shards
    return [padded[index * shard_length : (index + 1) * shard_length] for index in range(data_shards)]
