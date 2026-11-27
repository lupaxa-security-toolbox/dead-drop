"""Carrier-backed encrypted filesystem.

A vault generation is committed only after every temporary carrier has been
validated. Previous generations stay inside the rewritten carriers until
compaction, so an interrupted replace can still open the last committed
generation when the configured redundancy is intact.

Python cannot atomically replace several files as one filesystem transaction.
Recovery therefore trusts generation numbers and complete shard sets, not the
hope that a directory rename is global.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filelock import FileLock, Timeout

from lupaxa.dead_drop.carriers.api import capacity, detect_format, embed, extract
from lupaxa.dead_drop.carriers.base import EmbedOptions
from lupaxa.dead_drop.coding.reedsolomon import decode as rs_decode
from lupaxa.dead_drop.coding.reedsolomon import encode as rs_encode
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.errors import ArgumentError, AuthenticationError, CapacityError, DeadDropError, FragmentError, IntegrityError, VaultConflictError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.paths import atomic_replace
from lupaxa.dead_drop.payload.envelope import TYPE_VAULT_BLOCK, TYPE_VAULT_METADATA, TYPE_VAULT_POINTER, build_envelope, pack_frames, parse_envelope, walk_frames
from lupaxa.dead_drop.payload.package import new_id, stamp
from lupaxa.dead_drop.redact import register_secret, wipe
from lupaxa.dead_drop.services.conceal import CryptoChoices, open_envelope, seal

POINTER = TYPE_VAULT_POINTER
META = TYPE_VAULT_METADATA
BLOCK = TYPE_VAULT_BLOCK


@dataclass
class VaultSettings:
    """Durable vault parameters."""

    name: str
    redundancy: int = 1
    block_size: int = 65536
    retain_generations: int = 2
    kdf: KdfParams = field(default_factory=KdfParams)
    encryption: str = "chacha20-poly1305"


class Vault:
    """An open vault. The master key lives only in this object and the session file."""

    def __init__(self, directory: Path, settings: VaultSettings, master: bytearray, state: dict[str, Any]) -> None:
        self.directory = directory
        self.settings = settings
        self.master = master
        self.state = state
        register_secret(bytes(master).hex())

    @property
    def generation(self) -> int:
        """Committed generation number."""
        return int(self.state["generation"])

    def close(self) -> None:
        """Wipe the in-memory master key."""
        wipe(self.master)

    def usable_capacity(self, limits: Limits) -> int:
        """Bytes still available for new file contents after overhead."""
        total = 0
        for carrier in self.state["carriers"]:
            total += int(capacity(Path(str(carrier["path"])), str(carrier["algorithm"]), EmbedOptions(), limits))
        copies = self.state["data_shards"] + self.state["parity_shards"]
        overhead = 4096 * max(1, len(self.state["carriers"]))
        if copies <= 0:
            return 0
        return int(max(0, (total // copies) - overhead - self._used_bytes()))

    def _used_bytes(self) -> int:
        return sum(item["size"] for item in _files(self.state["tree"]))

    def put(self, source: Path, vault_path: str, limits: Limits, *, metadata: dict[str, str] | None = None) -> None:
        """Store a file as encrypted blocks."""
        data = source.read_bytes()
        limits.check_input(len(data), what=source.name)
        blocks: list[dict[str, Any]] = []
        for offset in range(0, max(len(data), 1), self.settings.block_size):
            chunk = data[offset : offset + self.settings.block_size]
            if not data:
                chunk = b""
            block_id = new_id()
            sealed, _payload = seal(chunk, CryptoChoices(encrypt=True, algorithm=self.settings.encryption, key=bytes(self.master), compress="none"), limits, payload_id=block_id)
            shards = rs_encode(sealed, data_shards=self.state["data_shards"], parity_shards=self.state["parity_shards"])
            blocks.append(
                {
                    "id": block_id.hex(),
                    "size": len(chunk),
                    "sha256": hashlib.sha256(chunk).hexdigest(),
                    "shards": shards,
                }
            )
            if not data:
                break
        limits.check_blocks(len(self.state["blocks"]) + len(blocks))
        node = _ensure_parent(self.state["tree"], vault_path)
        name = Path(vault_path).name
        node["entries"][name] = {
            "type": "file",
            "size": len(data),
            "ctime": stamp(),
            "mtime": stamp(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "blocks": [item["id"] for item in blocks],
            "meta": metadata or {},
        }
        for item in blocks:
            self.state["blocks"][item["id"]] = {
                "size": item["size"],
                "sha256": item["sha256"],
                "shards": [None] * len(item["shards"]),
            }
            self._place_shards(item["id"], item["shards"])
        self.state["generation"] += 1
        self.state["transaction"] = "committed"

    def get(self, vault_path: str, limits: Limits) -> bytes:
        """Read a file. Authentication failure raises rather than returning partial plaintext."""
        node = _require(self.state["tree"], vault_path, "file")
        parts = []
        for block_id in node["blocks"]:
            sealed = self._load_block(block_id)
            plain = open_envelope(sealed, CryptoChoices(encrypt=True, algorithm=self.settings.encryption, key=bytes(self.master)), limits)
            if hashlib.sha256(plain).hexdigest() != self.state["blocks"][block_id]["sha256"]:
                raise IntegrityError(f"Block {block_id} failed its content check.")
            parts.append(plain)
        data = b"".join(parts)
        if hashlib.sha256(data).hexdigest() != node["sha256"]:
            raise IntegrityError(f"{vault_path} failed its file hash.")
        return data

    def _place_shards(self, block_id: str, shards: list[bytes]) -> None:
        carriers = self.state["carriers"]
        if len(shards) > len(carriers):
            raise CapacityError("Not enough carriers for the vault redundancy.")
        for index, shard in enumerate(shards):
            carrier = carriers[index % len(carriers)]
            carrier.setdefault("shards", []).append({"block": block_id, "index": index, "bytes": shard})
            self.state["blocks"][block_id]["shards"][index] = carrier["carrier_id"]

    def _load_block(self, block_id: str) -> bytes:
        if block_id not in self.state["blocks"]:
            raise IntegrityError(f"Block {block_id} is not in this vault.")
        located: list[bytes | None] = [None] * (self.state["data_shards"] + self.state["parity_shards"])
        for carrier in self.state["carriers"]:
            for shard in carrier.get("shards", []):
                if shard["block"] == block_id:
                    located[shard["index"]] = shard["bytes"]
        return rs_decode(
            located,
            data_shards=self.state["data_shards"],
            parity_shards=self.state["parity_shards"],
            payload_length=self.state["data_shards"] * len(next(item for item in located if item is not None)),
        )

    def commit(self, limits: Limits, *, fail_after: int | None = None) -> list[str]:
        """Write a new generation to temporary carriers, validate, then replace."""
        lock = _lock(self.directory)
        try:
            meta_blob = _dump_state(self.state, bytes(self.master), self.settings, limits)
            temps: list[tuple[Path, Path]] = []
            for carrier in self.state["carriers"]:
                source = Path(carrier["path"])
                pristine = Path(str(carrier.get("pristine") or source))
                base = pristine if pristine.exists() else source
                frames = [_pointer(self.state, carrier), meta_blob, *_shard_frames(carrier, self.state, limits)]
                payload = pack_frames(frames)
                if len(payload) > capacity(base, carrier["algorithm"], EmbedOptions(), limits):
                    raise CapacityError(f"{source.name} cannot hold the new vault generation.")
                temporary = source.with_name(source.stem + ".dead-drop-tmp" + source.suffix)
                embed(base, temporary, payload, carrier["algorithm"], EmbedOptions(), limits)
                extracted = extract(temporary, carrier["algorithm"], EmbedOptions(), limits)
                if meta_blob not in walk_frames(extracted):
                    temporary.unlink(missing_ok=True)
                    raise IntegrityError(f"Temporary carrier {temporary.name} failed validation.")
                temps.append((temporary, source))
            for index, (temporary, source) in enumerate(temps):
                if fail_after is not None and index >= fail_after:
                    raise VaultConflictError("Injected commit failure before the generation was fully replaced.")
                atomic_replace(temporary, source)
            return []
        finally:
            lock.release()

    def materialise_index(self) -> dict[str, Any]:
        """Return a JSON-safe index without shard bytes or keys."""
        carriers = []
        for carrier in self.state["carriers"]:
            carriers.append({key: value for key, value in carrier.items() if key != "shards"} | {"shard_count": len(carrier.get("shards", []))})
        blocks = {key: {name: value for name, value in block.items() if name != "bytes"} for key, block in self.state["blocks"].items()}
        return {
            "vault_id": self.state["vault_id"],
            "name": self.state["name"],
            "generation": self.state["generation"],
            "data_shards": self.state["data_shards"],
            "parity_shards": self.state["parity_shards"],
            "tree": self.state["tree"],
            "carriers": carriers,
            "blocks": blocks,
            "snapshots": self.state["snapshots"],
        }


def create_vault(directory: Path, password: str, settings: VaultSettings, limits: Limits) -> Vault:
    """Initialise a vault in ``directory`` and prove that it opens again."""
    directory.mkdir(parents=True, exist_ok=True)
    files = _carrier_files(directory)
    if len(files) < 1:
        raise CapacityError("Vault creation needs at least one supported carrier.")
    data_shards, parity_shards = _layout(len(files), settings.redundancy)
    master = bytearray(os.urandom(32))
    carriers = []
    for path in files:
        pristine = directory / ".dead-drop-pristine" / path.name
        pristine.parent.mkdir(parents=True, exist_ok=True)
        if not pristine.exists():
            shutil.copy2(path, pristine)
        carriers.append(
            {
                "carrier_id": new_id().hex(),
                "path": str(path),
                "pristine": str(pristine),
                "algorithm": _default_algorithm(path),
                "shards": [],
            }
        )
    state: dict[str, Any] = {
        "vault_id": new_id().hex(),
        "name": settings.name,
        "generation": 1,
        "transaction": "committed",
        "data_shards": data_shards,
        "parity_shards": parity_shards,
        "block_size": settings.block_size,
        "carriers": carriers,
        "blocks": {},
        "tree": {"type": "dir", "entries": {}},
        "snapshots": [],
        "created": stamp(),
    }
    vault = Vault(directory, settings, master, state)
    wrapped = seal(bytes(master), CryptoChoices(encrypt=True, password=password, kdf=settings.kdf, algorithm=settings.encryption), limits)[0]
    state["wrapped_key"] = wrapped.hex()
    vault.commit(limits)
    reopened = open_vault(directory, password, settings.kdf, limits)
    if reopened.state["vault_id"] != state["vault_id"]:
        raise IntegrityError("The new vault could not be reopened.")
    reopened.close()
    return vault


def open_vault(directory: Path, password: str, kdf: KdfParams, limits: Limits) -> Vault:
    """Open the newest committed generation."""
    lock = _lock(directory)
    try:
        return _open_locked(directory, password, kdf, limits)
    finally:
        lock.release()


def _open_locked(directory: Path, password: str, kdf: KdfParams, limits: Limits) -> Vault:
    """Open a vault while the caller holds the writer lock."""
    discovered = _scan(directory, limits)
    if not discovered:
        raise FragmentError("No vault carriers were found.")
    generations = sorted({item["generation"] for item in discovered}, reverse=True)
    last_error: Exception | None = None
    for generation in generations:
        group = [item for item in discovered if item["generation"] == generation]
        sample = group[0]
        try:
            master = open_envelope(bytes.fromhex(sample["wrapped_key"]), CryptoChoices(encrypt=True, password=password, kdf=kdf), limits)
            state = json.loads(open_envelope(sample["metadata"], CryptoChoices(encrypt=True, key=master), limits))
        except AuthenticationError as exc:
            last_error = exc
            continue
        _attach_shards(state, group)
        if state.get("transaction") != "committed" or not _generation_complete(state):
            continue
        settings = VaultSettings(name=state["name"], redundancy=state["parity_shards"], block_size=state["block_size"], kdf=kdf)
        return Vault(directory, settings, bytearray(master), state)
    if last_error:
        raise AuthenticationError("Authentication failed.")
    raise FragmentError("No committed vault generation could be reconstructed.")


def _generation_complete(state: dict[str, Any]) -> bool:
    return all(all(item is not None for item in block["shards"]) for block in state["blocks"].values())


def _scan(directory: Path, limits: Limits) -> list[dict[str, Any]]:
    found = []
    for path in _carrier_files(directory):
        try:
            blob = extract(path, "auto", EmbedOptions(), limits)
            frames = walk_frames(blob)
        except (OSError, DeadDropError):
            continue
        pointer = None
        metadata = None
        shards: list[dict[str, Any]] = []
        for frame in frames:
            if len(frame) < 50 or not frame.startswith(b"DDR1"):
                continue
            from lupaxa.dead_drop.payload.envelope import HEADER

            _magic, _version, envelope_type, *_rest = HEADER.unpack_from(frame)
            if envelope_type == POINTER:
                pointer = json.loads(parse_envelope(frame, key=None, max_plain_bytes=limits.max_archive_expansion_bytes).plaintext)
            elif envelope_type == META:
                metadata = frame
            elif envelope_type == BLOCK:
                envelope = parse_envelope(frame, key=None, max_plain_bytes=limits.max_archive_expansion_bytes)
                shards.append({"block": envelope.payload_id.hex(), "index": envelope.fragment_index, "bytes": envelope.plaintext})
        if pointer and metadata:
            found.append(
                {
                    "generation": int(pointer["generation"]),
                    "wrapped_key": pointer["wrapped_key"],
                    "metadata": metadata,
                    "shards": shards,
                    "path": path,
                }
            )
    return found


def _attach_shards(state: dict[str, Any], group: list[dict[str, Any]]) -> None:
    by_carrier = {Path(item["path"]).resolve(): item["shards"] for item in group}
    for carrier in state["carriers"]:
        found = by_carrier.get(Path(carrier["path"]).resolve(), [])
        carrier["shards"] = found
        for shard in found:
            block = state["blocks"].get(shard["block"])
            if block is not None:
                block["shards"][shard["index"]] = carrier["carrier_id"]


def _dump_state(state: dict[str, Any], master: bytes, settings: VaultSettings, limits: Limits) -> bytes:
    public = json.loads(json.dumps(_public_state(state)))
    return build_envelope(
        envelope_type=META,
        algorithm_id=0,
        payload_id=bytes.fromhex(state["vault_id"]),
        plaintext=json.dumps(public).encode("utf-8"),
        encryption=settings.encryption,
        key=master,
        nonce_prefix=os.urandom(8),
        max_plain_bytes=limits.max_archive_expansion_bytes,
    )


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    """Return state that can be encrypted without embedding raw shard bytes."""
    carriers = []
    for carrier in state["carriers"]:
        carriers.append(
            {
                "carrier_id": carrier["carrier_id"],
                "path": carrier["path"],
                "pristine": carrier.get("pristine"),
                "algorithm": carrier["algorithm"],
                "shards": [
                    {
                        "block": shard["block"],
                        "index": shard["index"],
                        "sha256": hashlib.sha256(shard["bytes"]).hexdigest(),
                        "length": len(shard["bytes"]),
                    }
                    for shard in carrier.get("shards", [])
                ],
            }
        )
    return {
        "vault_id": state["vault_id"],
        "name": state["name"],
        "generation": state["generation"],
        "transaction": state["transaction"],
        "data_shards": state["data_shards"],
        "parity_shards": state["parity_shards"],
        "block_size": state["block_size"],
        "wrapped_key": state["wrapped_key"],
        "created": state.get("created"),
        "tree": state["tree"],
        "snapshots": state["snapshots"],
        "blocks": state["blocks"],
        "carriers": carriers,
    }


def _pointer(state: dict[str, Any], carrier: dict[str, Any]) -> bytes:
    payload = json.dumps(
        {
            "vault_id": state["vault_id"],
            "carrier_id": carrier["carrier_id"],
            "generation": state["generation"],
            "wrapped_key": state["wrapped_key"],
        }
    ).encode()
    return build_envelope(envelope_type=POINTER, algorithm_id=0, payload_id=bytes.fromhex(state["vault_id"]), plaintext=payload, encryption="none", max_plain_bytes=len(payload) + 64)


def _shard_frames(carrier: dict[str, Any], state: dict[str, Any], limits: Limits) -> list[bytes]:
    frames = []
    for shard in carrier.get("shards", []):
        frames.append(
            build_envelope(
                envelope_type=BLOCK,
                algorithm_id=0,
                payload_id=bytes.fromhex(shard["block"]),
                plaintext=shard["bytes"],
                fragment_index=shard["index"],
                fragment_count=state["data_shards"] + state["parity_shards"],
                data_shards=state["data_shards"],
                parity_shards=state["parity_shards"],
                encryption="none",
                max_plain_bytes=limits.max_archive_expansion_bytes,
            )
        )
    return frames


def _layout(carriers: int, redundancy: int) -> tuple[int, int]:
    parity = min(max(redundancy, 0), carriers - 1)
    data = max(1, carriers - parity)
    return data, parity


def _default_algorithm(path: Path) -> str:
    kind = detect_format(path)
    return {
        "png": "png-lsb",
        "bmp": "bmp-lsb",
        "wav": "wav-lsb",
        "txt": "txt-zero-width",
        "markdown": "md-zero-width",
        "svg": "svg-metadata",
        "zip": "zip-entry",
    }[kind]


def _carrier_files(directory: Path) -> list[Path]:
    files = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.is_symlink() or path.name.startswith("."):
            continue
        if ".dead-drop-tmp" in path.name:
            continue
        try:
            detect_format(path)
        except (OSError, DeadDropError):
            continue
        files.append(path)
    return files


def _lock(directory: Path) -> FileLock:
    target = directory / ".dead-drop" / "writer.lock"
    target.parent.mkdir(parents=True, exist_ok=True)
    lock = FileLock(str(target), timeout=0)
    try:
        lock.acquire()
    except Timeout as exc:
        raise VaultConflictError("Another Dead Drop process is writing this vault.") from exc
    return lock


def _files(tree: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
    found = []
    for name, node in tree.get("entries", {}).items():
        path = f"{prefix}{name}"
        if node["type"] == "file":
            found.append({"path": path, "size": node["size"]})
        else:
            found.extend(_files(node, prefix=path + "/"))
    return found


def _ensure_parent(tree: dict[str, Any], vault_path: str) -> dict[str, Any]:
    parts = [part for part in Path(vault_path).parts if part not in {".", ""}]
    if not parts:
        raise ArgumentError("A vault path is required.")
    node = tree
    for part in parts[:-1]:
        child = node["entries"].setdefault(part, {"type": "dir", "entries": {}})
        if child["type"] != "dir":
            raise ArgumentError(f"{part} is a file.")
        node = child
    return node


def _require(tree: dict[str, Any], vault_path: str, kind: str) -> dict[str, Any]:
    parts = [part for part in Path(vault_path).parts if part not in {".", ""}]
    node: dict[str, Any] = tree
    for part in parts:
        if node.get("type", "dir") != "dir" or part not in node.get("entries", {}):
            raise ArgumentError(f"Vault path not found: {vault_path}")
        node = node["entries"][part]
    if node["type"] != kind:
        raise ArgumentError(f"{vault_path} is not a {kind}.")
    return node
