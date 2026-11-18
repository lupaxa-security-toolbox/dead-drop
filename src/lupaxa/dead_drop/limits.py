"""Configurable safety limits."""

from __future__ import annotations

from dataclasses import dataclass

from lupaxa.dead_drop.errors import LimitError


@dataclass
class Limits:
    """Hard bounds checked before large allocations."""

    max_input_bytes: int = 1024 * 1024 * 1024
    max_carriers: int = 100_000
    max_archive_expansion_bytes: int = 4096 * 1024 * 1024
    max_nesting_depth: int = 8
    max_analysis_seconds: float = 600.0
    max_workers: int = 8
    max_temp_bytes: int = 8192 * 1024 * 1024
    max_vault_blocks: int = 1_000_000
    max_text_payload_bytes: int = 1_000_000
    max_container_payload_bytes: int = 256 * 1024 * 1024
    max_compression_ratio: int = 200
    max_zip_entries: int = 100_000
    decompress_limit_bytes: int = 4096 * 1024 * 1024

    def check_input(self, size: int, *, what: str = "input") -> None:
        """Reject an input larger than the configured maximum."""
        if size < 0:
            raise LimitError(f"{what} size is negative.")
        if size > self.max_input_bytes:
            raise LimitError(f"{what} is {size} bytes; limit is {self.max_input_bytes} bytes.")

    def check_expansion(self, size: int) -> None:
        """Reject an expanded archive or nested payload that is too large."""
        if size > self.max_archive_expansion_bytes:
            raise LimitError(f"Expanded size {size} exceeds {self.max_archive_expansion_bytes} bytes.")

    def check_nesting(self, depth: int) -> None:
        """Reject a nesting depth past the configured maximum."""
        if depth > self.max_nesting_depth:
            raise LimitError(f"Nesting depth {depth} exceeds {self.max_nesting_depth}.")

    def check_carriers(self, count: int) -> None:
        """Reject a carrier collection that is too large to scan."""
        if count > self.max_carriers:
            raise LimitError(f"Carrier count {count} exceeds {self.max_carriers}.")

    def check_blocks(self, count: int) -> None:
        """Reject a vault block map that exceeds the configured maximum."""
        if count > self.max_vault_blocks:
            raise LimitError(f"Vault block count {count} exceeds {self.max_vault_blocks}.")
