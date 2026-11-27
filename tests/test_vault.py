"""Vault create, store, snapshot, and backup."""

from __future__ import annotations

from pathlib import Path

from PIL import Image

from lupaxa.dead_drop.crypto.kdf import KdfParams
from lupaxa.dead_drop.limits import Limits
from lupaxa.dead_drop.vault.ops import backup, listing, mkdir, restore_backup, snapshot, tree_lines
from lupaxa.dead_drop.vault.store import Vault, VaultSettings, create_vault, open_vault

FAST = KdfParams(time_cost=1, memory_kib=8, parallelism=1, hash_len=32)


def _vault(tmp_path: Path) -> Vault:
    for index in range(2):
        Image.new("RGB", (220, 220), (index, 20, 40)).save(tmp_path / f"{index}.png")
    source = tmp_path.parent / "hello.txt"
    source.write_text("hello vault", encoding="utf-8")
    vault = create_vault(tmp_path, "vault-password-value", VaultSettings(name="personal", redundancy=1, block_size=512, kdf=FAST), Limits())
    vault.put(source, "notes/hello.txt", Limits())
    vault.commit(Limits())
    return open_vault(tmp_path, "vault-password-value", FAST, Limits())


def test_put_get_snapshot_and_backup(tmp_path: Path) -> None:
    vault = _vault(tmp_path)
    assert vault.get("notes/hello.txt", Limits()) == b"hello vault"
    mkdir(vault, "documents")
    vault.state["generation"] += 1
    vault.commit(Limits())
    reopened = open_vault(tmp_path, "vault-password-value", FAST, Limits())
    assert "notes/hello.txt" in tree_lines(reopened)
    assert any(item["name"] == "documents" for item in listing(reopened))
    snapshot(reopened, "before-update", Limits())
    destination = tmp_path / "vault.ddbak"
    backup(reopened, destination, "vault-password-value", FAST, Limits())
    restored = tmp_path / "restored"
    report = restore_backup(destination, restored, "vault-password-value", FAST, Limits())
    assert (restored / "notes/hello.txt").read_bytes() == b"hello vault"
    assert report["files"] == ["notes/hello.txt"]
