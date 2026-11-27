"""Filesystem operations on an open vault."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from lupaxa.dead_drop.carriers.api import detect_format
from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.errors import ArgumentError, IntegrityError
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.payload.package import new_id, stamp
from lupaxa.dead_drop.services.conceal import CryptoChoices, open_envelope, seal
from lupaxa.dead_drop.vault.store import Vault, _carrier_files, _default_algorithm, _ensure_parent, _files, _require


def listing(vault: Vault, directory: str = "") -> list[dict[str, Any]]:
    """List one directory level."""
    node = vault.state["tree"] if not directory else _require(vault.state["tree"], directory, "dir")
    return [{"name": name, "type": child["type"], "size": child.get("size", 0)} for name, child in sorted(node["entries"].items())]


def tree_lines(vault: Vault) -> list[str]:
    """Render the vault tree as text lines."""
    return [item["path"] for item in _files(vault.state["tree"])]


def mkdir(vault: Vault, path: str) -> None:
    """Create a directory and its parents inside the vault."""
    parent = _ensure_parent(vault.state["tree"], path if path.endswith("/x") else str(Path(path) / "x"))
    name = Path(path).name
    parent["entries"].setdefault(name, {"type": "dir", "entries": {}})
    if parent["entries"][name]["type"] != "dir":
        raise ArgumentError(f"{path} is a file.")


def remove(vault: Vault, path: str) -> None:
    """Delete a file. The blocks stay until compaction so a crash can still be diagnosed."""
    parent_path = str(Path(path).parent)
    parent = vault.state["tree"] if parent_path in {"", "."} else _require(vault.state["tree"], parent_path, "dir")
    name = Path(path).name
    node = parent["entries"].get(name)
    if node is None or node["type"] != "file":
        raise ArgumentError(f"Vault file not found: {path}")
    del parent["entries"][name]


def move(vault: Vault, source: str, destination: str) -> None:
    """Move a file or directory inside the vault."""
    parent_path = str(Path(source).parent)
    parent = vault.state["tree"] if parent_path in {"", "."} else _require(vault.state["tree"], parent_path, "dir")
    name = Path(source).name
    if name not in parent["entries"]:
        raise ArgumentError(f"Vault path not found: {source}")
    node = parent["entries"].pop(name)
    dest_parent = _ensure_parent(vault.state["tree"], str(Path(destination) / "x"))
    dest_parent["entries"][Path(destination).name] = node


def copy_path(vault: Vault, source: str, destination: str) -> None:
    """Copy a file by referencing the same content-addressed blocks."""
    node = copy.deepcopy(_require(vault.state["tree"], source, "file"))
    node["ctime"] = stamp()
    dest_parent = _ensure_parent(vault.state["tree"], str(Path(destination) / "x"))
    dest_parent["entries"][Path(destination).name] = node


def find(vault: Vault, text: str) -> list[str]:
    """Find vault paths containing ``text``."""
    return [item["path"] for item in _files(vault.state["tree"]) if text in item["path"]]


def snapshot(vault: Vault, name: str, limits: Limits) -> dict[str, Any]:
    """Capture the current tree. Referenced blocks are kept by later compaction."""
    record = {
        "name": name,
        "generation": vault.generation,
        "created": stamp(),
        "tree": copy.deepcopy(vault.state["tree"]),
    }
    vault.state["snapshots"] = [item for item in vault.state["snapshots"] if item["name"] != name]
    vault.state["snapshots"].append(record)
    vault.state["generation"] += 1
    vault.commit(limits)
    return {"name": name, "generation": record["generation"]}


def restore_snapshot(vault: Vault, name: str, limits: Limits) -> None:
    """Point the live tree at a snapshot and commit a new generation."""
    match = next((item for item in vault.state["snapshots"] if item["name"] == name), None)
    if match is None:
        raise ArgumentError(f"Snapshot {name!r} was not found.")
    vault.state["tree"] = copy.deepcopy(match["tree"])
    vault.state["generation"] += 1
    vault.commit(limits)


def _referenced_blocks(tree: dict[str, Any]) -> set[str]:
    """Collect block ids named by a filesystem tree."""
    found: set[str] = set()
    for node in tree.get("entries", {}).values():
        if node["type"] == "file":
            found.update(node.get("blocks", []))
        else:
            found |= _referenced_blocks(node)
    return found


def compact(vault: Vault, limits: Limits) -> dict[str, int]:
    """Drop blocks that no live tree or snapshot references."""
    live = _referenced_blocks(vault.state["tree"])
    for snap in vault.state["snapshots"]:
        live |= _referenced_blocks(snap["tree"])
    before = len(vault.state["blocks"])
    vault.state["blocks"] = {key: value for key, value in vault.state["blocks"].items() if key in live}
    for carrier in vault.state["carriers"]:
        carrier["shards"] = [shard for shard in carrier.get("shards", []) if shard["block"] in live]
    vault.state["generation"] += 1
    vault.commit(limits)
    return {"removed_blocks": before - len(vault.state["blocks"]), "retained_blocks": len(vault.state["blocks"])}


def verify(vault: Vault, limits: Limits, *, deep: bool) -> dict[str, Any]:
    """Check metadata and, when deep, every stored file."""
    failures = []
    checked = 0
    if deep:
        for item in _files(vault.state["tree"]):
            checked += 1
            try:
                vault.get(item["path"], limits)
            except Exception as exc:
                failures.append({"path": item["path"], "error": str(exc)})
    return {"generation": vault.generation, "files_checked": checked, "failures": failures, "ok": not failures}


def rebalance(vault: Vault, limits: Limits) -> dict[str, Any]:
    """Adopt new carriers in the directory and spread existing shards across them."""
    known = {Path(carrier["path"]).resolve() for carrier in vault.state["carriers"]}
    for path in _carrier_files(vault.directory):
        if path.resolve() in known or ".dead-drop-tmp" in path.name:
            continue
        if ".dead-drop-pristine" in path.parts:
            continue
        pristine = vault.directory / ".dead-drop-pristine" / path.name
        pristine.parent.mkdir(parents=True, exist_ok=True)
        if not pristine.exists():
            pristine.write_bytes(path.read_bytes())
        vault.state["carriers"].append(
            {
                "carrier_id": new_id().hex(),
                "path": str(path),
                "pristine": str(pristine),
                "algorithm": _default_algorithm(path),
                "shards": [],
            }
        )
    shards = []
    for carrier in vault.state["carriers"]:
        shards.extend(carrier.get("shards", []))
        carrier["shards"] = []
    for block in vault.state["blocks"].values():
        block["shards"] = [None] * len(block["shards"])
    for index, shard in enumerate(shards):
        carrier = vault.state["carriers"][index % len(vault.state["carriers"])]
        carrier["shards"].append(shard)
        vault.state["blocks"][shard["block"]]["shards"][shard["index"]] = carrier["carrier_id"]
    vault.state["generation"] += 1
    vault.commit(limits)
    return {"carriers": len(vault.state["carriers"]), "shards": len(shards)}


def repair_plan(vault: Vault) -> dict[str, Any]:
    """Describe missing shards without modifying carriers."""
    missing = []
    for block_id, _block in vault.state["blocks"].items():
        present = []
        for carrier in vault.state["carriers"]:
            for shard in carrier.get("shards", []):
                if shard["block"] == block_id:
                    present.append(shard["index"])
        needed = vault.state["data_shards"]
        if len(set(present)) < needed:
            missing.append({"block": block_id, "present": sorted(set(present)), "required": needed})
    return {
        "missing": missing,
        "recoverable": not missing,
        "note": "Repair rewrites carriers only when you pass --apply and the coding threshold is met.",
    }


def backup(vault: Vault, destination: Path, password: str, kdf: KdfParams, limits: Limits) -> None:
    """Write a versioned encrypted backup that restores without the original carriers."""
    files = []
    for item in _files(vault.state["tree"]):
        files.append(
            {
                "path": item["path"],
                "sha256": hashlib_sha(vault.get(item["path"], limits)),
                "hex": vault.get(item["path"], limits).hex(),
            }
        )
    body = json.dumps({"format": 1, "vault_id": vault.state["vault_id"], "name": vault.state["name"], "files": files}).encode()
    blob, _ident = seal(body, CryptoChoices(encrypt=True, password=password, kdf=kdf, algorithm=vault.settings.encryption), limits)
    destination.write_bytes(b"DDBK" + blob)


def hashlib_sha(data: bytes) -> str:
    """SHA-256 hex digest."""
    import hashlib

    return hashlib.sha256(data).hexdigest()


def restore_backup(path: Path, output: Path, password: str, kdf: KdfParams, limits: Limits) -> dict[str, Any]:
    """Restore backed-up files into an ordinary directory."""
    blob = path.read_bytes()
    if not blob.startswith(b"DDBK"):
        raise IntegrityError("Backup file does not start with the DDBK marker.")
    loaded = json.loads(open_envelope(blob[4:], CryptoChoices(encrypt=True, password=password, kdf=kdf), limits))
    written = []
    for item in loaded["files"]:
        target = output / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = bytes.fromhex(item["hex"])
        if hashlib_sha(data) != item["sha256"]:
            raise IntegrityError(f"Backup entry {item['path']} failed its hash.")
        target.write_bytes(data)
        written.append(item["path"])
    return {"vault_id": loaded["vault_id"], "files": written, "output": str(output)}


def tree_files(tree: dict[str, Any]) -> list[str]:
    """List files in a stored tree."""
    return [item["path"] for item in _files(tree)]


def destroy(vault: Vault, limits: Limits) -> dict[str, str]:
    """Replace embeddings with an empty tombstone. This is not secure SSD erasure."""
    from lupaxa.dead_drop.carriers.api import embed
    from lupaxa.dead_drop.carriers.base import EmbedOptions

    for carrier in vault.state["carriers"]:
        source = Path(carrier["pristine"])
        dest = Path(carrier["path"])
        temporary = dest.with_name(dest.stem + ".dead-drop-tmp" + dest.suffix)
        embed(source, temporary, b"", carrier["algorithm"], EmbedOptions(), limits)
        temporary.replace(dest)
    return {
        "warning": ("Carrier embeddings were replaced. This does not guarantee secure deletion from SSDs, backups, or earlier copies."),
    }


def carrier_format(path: Path) -> str:
    """Detect a carrier, used by vault adoption."""
    return detect_format(path)
