"""Hide, reveal, distribute, and recover payloads.

Successful embedding always includes a recovery check. A failure deletes the
output it created and leaves the source carrier untouched.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.api import capacity, embed, extract, resolve_algorithm
from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.coding.reedsolomon import decode as rs_decode
from lupaxa.dead_drop.coding.reedsolomon import encode as rs_encode
from lupaxa.dead_drop.crypto.aead import normalise_algorithm
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.crypto.keys import key_from_password, read_key_file
from lupaxa.dead_drop.crypto.shamir import Share, combine_shares, parse_share, split_secret
from lupaxa.dead_drop.errors import AuthenticationError, CapacityError, DeadDropError, FragmentError, IntegrityError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.payload.envelope import (
    TYPE_FRAGMENT,
    TYPE_KEY_SHARE,
    TYPE_SINGLE,
    Envelope,
    build_envelope,
    pack_frames,
    parse_envelope,
    walk_frames,
)
from lupaxa.dead_drop.payload.package import compress, decompress, new_id, package_bytes, package_path, unpack_package
from lupaxa.dead_drop.redact import register_secret

TEXT_WARNING = (
    "Text concealment is vulnerable to formatting, Unicode normalisation, copying, and editor transformations."
)


@dataclass
class CryptoChoices:
    """How a payload is protected. Placement keys are separate from encryption keys."""

    encrypt: bool = True
    algorithm: str = "chacha20-poly1305"
    password: str | None = None
    key: bytes | None = None
    kdf: KdfParams = field(default_factory=KdfParams)
    insecure_deterministic: bool = False
    seed: bytes = b""
    compress: str = "none"


@dataclass
class DistributionChoices:
    """How an encrypted payload is spread across carriers."""

    mode: str = "single"
    data_shards: int = 1
    parity_shards: int = 0
    shares: int = 1
    threshold: int = 1


def prepare_package(path: Path | None, raw: bytes | None, limits: Limits) -> bytes:
    """Package a file, directory, or raw bytes."""
    if raw is not None:
        limits.check_input(len(raw))
        return package_bytes(raw, name="stdin.bin")
    if path is None:
        raise IntegrityError("No payload was provided.")
    return package_path(path, limits=limits)


def _nonce_prefix(choices: CryptoChoices) -> bytes:
    if choices.insecure_deterministic:
        if not choices.seed:
            raise IntegrityError("Deterministic encryption requires a seed, and it is insecure for real secrets.")
        import hashlib
        import hmac

        return hmac.new(choices.seed, b"dead-drop-insecure-nonce", hashlib.sha256).digest()[:8]
    return os.urandom(8)


def _salt(choices: CryptoChoices) -> bytes:
    if choices.insecure_deterministic:
        import hashlib
        import hmac

        return hmac.new(choices.seed, b"dead-drop-insecure-salt", hashlib.sha256).digest()[:16]
    return os.urandom(16)


def seal(
    package: bytes, choices: CryptoChoices, limits: Limits, *, payload_id: bytes | None = None
) -> tuple[bytes, bytes]:
    """Compress and encrypt a package into one envelope. Returns envelope bytes and payload id."""
    compressed, method = compress(package, choices.compress, limit=limits.max_archive_expansion_bytes)
    identifier = payload_id or new_id()
    if not choices.encrypt:
        blob = build_envelope(
            envelope_type=TYPE_SINGLE,
            algorithm_id=0,
            payload_id=identifier,
            plaintext=compressed,
            compression_id=method,
            encryption="none",
            max_plain_bytes=limits.max_archive_expansion_bytes,
        )
        return blob, identifier
    algorithm = normalise_algorithm(choices.algorithm)
    salt = _salt(choices)
    prefix = _nonce_prefix(choices)
    if choices.key is not None:
        key = choices.key
        kdf = None
        register_secret(key.hex())
    elif choices.password:
        material = key_from_password(choices.password, salt, choices.kdf)
        key = bytes(material.key)
        kdf = choices.kdf
        material.close()
    else:
        raise AuthenticationError("Encryption was requested but no password or key was provided.")
    blob = build_envelope(
        envelope_type=TYPE_SINGLE,
        algorithm_id=0,
        payload_id=identifier,
        plaintext=compressed,
        compression_id=method,
        encryption=algorithm,
        key=key,
        kdf=kdf,
        salt=salt if kdf else b"",
        nonce_prefix=prefix,
        max_plain_bytes=limits.max_archive_expansion_bytes,
    )
    return blob, identifier


def open_envelope(blob: bytes, choices: CryptoChoices, limits: Limits) -> bytes:
    """Authenticate, decrypt, and decompress one envelope back to a package."""
    key = _key_for_open(blob, choices)
    try:
        envelope = parse_envelope(blob, key=key, max_plain_bytes=limits.max_archive_expansion_bytes)
    except AuthenticationError:
        raise
    except Exception as exc:
        raise IntegrityError("Envelope could not be authenticated.") from exc
    return decompress(envelope.plaintext, envelope.compression_id, limit=limits.decompress_limit_bytes)


def _key_for_open(blob: bytes, choices: CryptoChoices) -> bytes | None:
    if choices.key is not None:
        register_secret(choices.key.hex())
        return choices.key
    if not choices.password:
        return None
    # Salt and KDF parameters are in the header. Parse without decrypting by asking
    # parse to fail only after we derive the key. Read them from a first pass with key None
    # when the envelope is encrypted: parse requires a key. So derive using header fields.
    from lupaxa.dead_drop.payload.envelope import HEADER, KDF_ARGON2ID, KDF_BLOCK

    if len(blob) < HEADER.size:
        raise IntegrityError("Envelope header is truncated.")
    fields = HEADER.unpack_from(blob)
    kdf_id = fields[11]
    encryption_id = fields[12]
    if encryption_id == 0:
        return None
    offset = HEADER.size
    if kdf_id == KDF_ARGON2ID:
        time_cost, memory_kib, parallelism, hash_len = KDF_BLOCK.unpack_from(blob, offset)
        offset += KDF_BLOCK.size
        params = KdfParams(time_cost, memory_kib, parallelism, hash_len)
        salt_len = fields[14]
        salt = blob[offset : offset + salt_len]
        material = key_from_password(choices.password, salt, params)
        key = bytes(material.key)
        material.close()
        return key
    if choices.key is None:
        raise AuthenticationError("Authentication failed.")
    return choices.key


def fragment_blob(blob: bytes, payload_id: bytes, distribution: DistributionChoices, limits: Limits) -> list[bytes]:
    """Split an envelope into self-describing fragment envelopes."""
    if distribution.parity_shards == 0 and distribution.data_shards <= 1:
        return [blob]
    shards = rs_encode(blob, data_shards=distribution.data_shards, parity_shards=distribution.parity_shards)
    wrapped: list[bytes] = []
    for index, shard in enumerate(shards):
        wrapped.append(
            build_envelope(
                envelope_type=TYPE_FRAGMENT,
                algorithm_id=0,
                payload_id=payload_id,
                plaintext=shard,
                fragment_index=index,
                fragment_count=len(shards),
                data_shards=distribution.data_shards,
                parity_shards=distribution.parity_shards,
                encryption="none",
                max_plain_bytes=limits.max_archive_expansion_bytes,
            )
        )
    return wrapped


def reassemble(envelopes: list[Envelope], limits: Limits) -> bytes:
    """Rebuild one sealed envelope from fragment envelopes."""
    if len(envelopes) == 1 and envelopes[0].envelope_type == TYPE_SINGLE:
        return _reserialise(envelopes[0])
    fragments = [item for item in envelopes if item.envelope_type == TYPE_FRAGMENT]
    if not fragments:
        raise FragmentError("No payload fragments were found.")
    payload_ids = {item.payload_id for item in fragments}
    if len(payload_ids) != 1:
        raise FragmentError("Fragments belong to different payloads.")
    counts = {(item.data_shards, item.parity_shards, item.fragment_count) for item in fragments}
    if len(counts) != 1:
        raise FragmentError("Fragment coding parameters do not agree.")
    data_shards, parity_shards, total = counts.pop()
    shards: list[bytes | None] = [None] * total
    for item in fragments:
        if item.fragment_index >= total:
            raise IntegrityError("Fragment index is outside the declared set.")
        if shards[item.fragment_index] is not None and shards[item.fragment_index] != item.plaintext:
            raise IntegrityError("Two different fragments claim the same index.")
        shards[item.fragment_index] = item.plaintext
    present = [shard for shard in shards if shard is not None]
    if len(present) < data_shards:
        raise FragmentError(f"{len(present)} fragments are available; {data_shards} are required.")
    length = data_shards * len(present[0])
    # The original envelope length is not stored separately. Decode using the padded length
    # and trim at the first valid envelope by trying the decoded buffer.
    decoded = rs_decode(
        shards,
        data_shards=data_shards,
        parity_shards=parity_shards,
        payload_length=length,
    )
    return _trim_envelope(decoded)


def _trim_envelope(decoded: bytes) -> bytes:
    from lupaxa.dead_drop.payload.envelope import envelope_total_length

    if not decoded.startswith(b"DDR1"):
        raise IntegrityError("Reconstructed bytes are not an envelope.")
    total = envelope_total_length(decoded[:50])
    if total > len(decoded):
        raise IntegrityError("Reconstructed envelope is shorter than its header claims.")
    return decoded[:total]


def _reserialise(envelope: Envelope) -> bytes:
    """Fragments already contain plaintext shards. A single envelope is returned as originally parsed input."""
    raise FragmentError("Single envelopes must be passed through as raw bytes.")


def hide_into(
    carrier: Path,
    output: Path,
    package: bytes,
    *,
    choices: CryptoChoices,
    options: EmbedOptions,
    limits: Limits,
    algorithm: str = "auto",
) -> dict[str, Any]:
    """Embed one sealed payload and verify that it extracts."""
    blob, payload_id = seal(package, choices, limits)
    report = embed(carrier, output, blob, algorithm, options, limits)
    try:
        recovered = extract(output, algorithm, options, limits)
        opened = open_envelope(recovered, choices, limits)
    except Exception:
        output.unlink(missing_ok=True)
        raise
    if opened != package:
        output.unlink(missing_ok=True)
        raise IntegrityError("Embedded payload did not match the verified recovery.")
    warnings = list(report.warnings)
    if resolve_algorithm(carrier, algorithm).startswith(("txt-", "md-")):
        warnings.append(TEXT_WARNING)
    if not choices.encrypt:
        warnings.append("This payload is concealed but not encrypted.")
    return {
        "payload_id": payload_id.hex(),
        "algorithm": report.algorithm,
        "concealment_class": report.concealment_class,
        "bytes_embedded": report.bytes_embedded,
        "capacity_bytes": capacity(carrier, algorithm, options, limits),
        "metrics": report.metrics,
        "warnings": warnings,
        "output": str(output),
        "verified": True,
    }


def reveal_from(
    carrier: Path,
    *,
    choices: CryptoChoices,
    options: EmbedOptions,
    limits: Limits,
    algorithm: str = "auto",
    destination: Path | None = None,
) -> dict[str, Any]:
    """Extract, authenticate, and optionally unpack one carrier."""
    blob = extract(carrier, algorithm, options, limits)
    package = open_envelope(blob, choices, limits)
    result: dict[str, Any] = {"verified": True, "bytes": len(package)}
    if destination is not None:
        written = unpack_package(package, destination if destination.is_dir() else destination.parent, limits=limits)
        if not destination.is_dir() and written != destination:
            written.replace(destination)
            written = destination
        result["output"] = str(written)
    else:
        result["package_sha256"] = __import__("hashlib").sha256(package).hexdigest()
    return result


def distribute(
    carriers: list[Path],
    outputs: list[Path],
    package: bytes,
    *,
    choices: CryptoChoices,
    distribution: DistributionChoices,
    options: EmbedOptions,
    limits: Limits,
    algorithm: str = "auto",
) -> dict[str, Any]:
    """Spread a payload across carriers and verify reconstruction from the outputs."""
    if len(carriers) != len(outputs):
        raise CapacityError("Each selected carrier needs its own output path.")
    blob, payload_id = seal(package, choices, limits)
    pieces = fragment_blob(blob, payload_id, distribution, limits)
    shares: list[Share] = []
    share_blobs: list[bytes] = []
    if distribution.shares > 1:
        if choices.key is None:
            secret = os.urandom(32)
            # Re-seal with this random key so the password is not required for the data key.
            choices = CryptoChoices(
                encrypt=True,
                algorithm=choices.algorithm,
                key=secret,
                compress=choices.compress,
                kdf=choices.kdf,
            )
            blob, payload_id = seal(package, choices, limits, payload_id=payload_id)
            pieces = fragment_blob(blob, payload_id, distribution, limits)
        else:
            secret = choices.key
        shares = split_secret(secret, shares=distribution.shares, threshold=distribution.threshold)
        for share in shares:
            share_blobs.append(
                build_envelope(
                    envelope_type=TYPE_KEY_SHARE,
                    algorithm_id=0,
                    payload_id=payload_id,
                    plaintext=share.serialise(),
                    encryption="none",
                    max_plain_bytes=limits.max_input_bytes,
                )
            )
    if len(pieces) > len(carriers):
        raise CapacityError(f"Need {len(pieces)} carriers and only {len(carriers)} were selected.")
    written = []
    for index, carrier in enumerate(carriers):
        frames = []
        if index < len(pieces):
            frames.append(pieces[index])
        if index < len(share_blobs):
            frames.append(share_blobs[index])
        payload = frames[0] if len(frames) == 1 else pack_frames(frames)
        if len(payload) > capacity(carrier, algorithm, options, limits):
            raise CapacityError(f"{carrier} cannot hold its assigned fragment.")
        embed(carrier, outputs[index], payload, algorithm, options, limits)
        written.append(str(outputs[index]))
    recovered = recover_from(outputs, choices=choices, options=options, limits=limits, algorithm=algorithm)
    if recovered["package"] != package:
        for path in outputs:
            path.unlink(missing_ok=True)
        raise IntegrityError("Distributed payload failed its reconstruction check.")
    return {
        "payload_id": payload_id.hex(),
        "outputs": written,
        "data_shards": distribution.data_shards if distribution.parity_shards or distribution.data_shards > 1 else 1,
        "parity_shards": distribution.parity_shards,
        "key_shares": distribution.shares if shares else 0,
        "key_threshold": distribution.threshold if shares else 0,
        "verified": True,
        "warnings": [] if choices.encrypt else ["This payload is concealed but not encrypted."],
    }


def recover_from(
    carriers: list[Path],
    *,
    choices: CryptoChoices,
    options: EmbedOptions,
    limits: Limits,
    algorithm: str = "auto",
) -> dict[str, Any]:
    """Scan carriers, group fragments, reconstruct, and authenticate."""
    found: list[Envelope] = []
    raw_singles: list[bytes] = []
    shares: list[Share] = []
    from lupaxa.dead_drop.payload.envelope import ENC_NONE, HEADER

    for carrier in carriers:
        try:
            blob = extract(carrier, algorithm, options, limits)
        except (OSError, DeadDropError):
            continue
        blobs = walk_frames(blob) if not blob.startswith(b"DDR1") else [blob]
        for piece in blobs:
            if len(piece) < HEADER.size or not piece.startswith(b"DDR1"):
                continue
            encryption_id = HEADER.unpack_from(piece)[12]
            envelope_type = HEADER.unpack_from(piece)[2]
            if encryption_id != ENC_NONE and envelope_type == TYPE_SINGLE:
                raw_singles.append(piece)
                continue
            envelope = parse_envelope(piece, key=None, max_plain_bytes=limits.max_archive_expansion_bytes)
            if envelope.envelope_type == TYPE_KEY_SHARE:
                shares.append(parse_share(envelope.plaintext))
            elif envelope.envelope_type == TYPE_SINGLE:
                raw_singles.append(piece)
            else:
                found.append(envelope)
    if (
        shares
        and choices.key is None
        and not choices.password
        and len({share.set_id for share in shares}) == 1
        and len(shares) >= shares[0].threshold
    ):
        choices = CryptoChoices(
            encrypt=True,
            algorithm=choices.algorithm,
            key=combine_shares(shares),
            compress=choices.compress,
            kdf=choices.kdf,
        )
    if raw_singles:
        package = open_envelope(raw_singles[0], choices, limits)
        return {"package": package, "fragments": 1, "verified": True}
    if not found:
        raise FragmentError("No compatible embedded envelopes were found.")
    blob = reassemble(found, limits)
    package = open_envelope(blob, choices, limits)
    return {"package": package, "fragments": len(found), "verified": True}


def key_material_from_file(path: Path) -> bytes:
    """Load a Dead Drop key file."""
    return bytes(read_key_file(path))
