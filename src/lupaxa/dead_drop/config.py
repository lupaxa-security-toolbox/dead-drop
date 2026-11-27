"""TOML configuration, profiles, and precedence."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platformdirs import user_cache_dir, user_config_dir, user_data_dir

from lupaxa.dead_drop.errors import ArgumentError
from lupaxa.dead_drop.limits import Limits

APP_NAME = "dead-drop"
APP_AUTHOR = "Lupaxa"
INT_LIMITS = {
    "jobs": (1, 1024),
    "block_size": (4096, 16 * 1024 * 1024),
    "retain_generations": (1, 32),
    "max_file_size_mb": (1, 1024 * 1024),
    "max_nesting_depth": (1, 64),
    "max_archive_expansion_mb": (1, 1024 * 1024),
    "default_data_shards": (1, 200),
    "default_parity_shards": (0, 200),
    "max_carriers": (1, 1_000_000),
    "max_workers": (1, 256),
    "max_vault_blocks": (1, 100_000_000),
}


@dataclass
class Config:
    """Resolved runtime configuration."""

    colour: bool = True
    json_output: bool = False
    jobs: int = 4
    verify_after_write: bool = True
    default_encryption: str = "chacha20-poly1305"
    password_kdf: str = "argon2id"  # noqa: S105
    kdf_time_cost: int = 2
    kdf_memory_kib: int = 19456
    kdf_parallelism: int = 1
    require_encryption: bool = True
    default_strategy: str = "balanced"
    default_algorithm: str = "auto"
    preserve_originals: bool = True
    default_data_shards: int = 5
    default_parity_shards: int = 3
    block_size: int = 65536
    retain_generations: int = 2
    verify_on_open: bool = True
    deep_scan: bool = False
    max_file_size_mb: int = 1024
    max_nesting_depth: int = 8
    max_archive_expansion_mb: int = 4096
    history_enabled: bool = True
    max_carriers: int = 100_000
    max_workers: int = 8
    max_vault_blocks: int = 1_000_000
    profile: str | None = None
    config_path: Path | None = None

    def limits(self) -> Limits:
        """Build the safety limits implied by this configuration."""
        return Limits(
            max_input_bytes=self.max_file_size_mb * 1024 * 1024,
            max_carriers=self.max_carriers,
            max_archive_expansion_bytes=self.max_archive_expansion_mb * 1024 * 1024,
            max_nesting_depth=self.max_nesting_depth,
            max_workers=min(self.max_workers, self.jobs),
            max_vault_blocks=self.max_vault_blocks,
            decompress_limit_bytes=self.max_archive_expansion_mb * 1024 * 1024,
        )


def config_directory() -> Path:
    """Return the platform configuration directory."""
    return Path(user_config_dir(APP_NAME, APP_AUTHOR))


def cache_directory() -> Path:
    """Return the platform cache directory."""
    return Path(user_cache_dir(APP_NAME, APP_AUTHOR))


def data_directory() -> Path:
    """Return the platform application-data directory."""
    return Path(user_data_dir(APP_NAME, APP_AUTHOR))


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            loaded = tomllib.load(handle)
    except OSError as exc:
        raise ArgumentError(f"Cannot read configuration {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ArgumentError(f"Invalid TOML in {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ArgumentError(f"Configuration {path} must be a table.")
    return loaded


def _apply_table(config: Config, table: dict[str, Any]) -> None:
    general = table.get("general", {})
    security = table.get("security", {})
    embedding = table.get("embedding", {})
    distribution = table.get("distribution", {})
    vault = table.get("vault", {})
    analysis = table.get("analysis", {})
    limits = table.get("limits", {})
    history = table.get("history", {})
    mapping: dict[str, Any] = {}
    if isinstance(general, dict):
        mapping.update(
            {
                "colour": general.get("colour", general.get("color")),
                "json_output": general.get("json"),
                "jobs": general.get("jobs"),
                "verify_after_write": general.get("verify_after_write"),
            }
        )
    if isinstance(security, dict):
        mapping.update(
            {
                "default_encryption": security.get("default_encryption"),
                "password_kdf": security.get("password_kdf"),
                "require_encryption": security.get("require_encryption"),
                "kdf_time_cost": security.get("kdf_time_cost"),
                "kdf_memory_kib": security.get("kdf_memory_kib"),
                "kdf_parallelism": security.get("kdf_parallelism"),
            }
        )
    if isinstance(embedding, dict):
        mapping.update(
            {
                "default_strategy": embedding.get("default_strategy"),
                "default_algorithm": embedding.get("default_algorithm"),
                "preserve_originals": embedding.get("preserve_originals"),
            }
        )
    if isinstance(distribution, dict):
        mapping.update(
            {
                "default_data_shards": distribution.get("default_data_shards"),
                "default_parity_shards": distribution.get("default_parity_shards"),
            }
        )
    if isinstance(vault, dict):
        mapping.update(
            {
                "block_size": vault.get("block_size"),
                "retain_generations": vault.get("retain_generations"),
                "verify_on_open": vault.get("verify_on_open"),
            }
        )
    if isinstance(analysis, dict):
        mapping.update(
            {
                "deep_scan": analysis.get("deep_scan"),
                "max_file_size_mb": analysis.get("max_file_size_mb"),
            }
        )
    if isinstance(limits, dict):
        mapping.update(
            {
                "max_nesting_depth": limits.get("max_nesting_depth"),
                "max_archive_expansion_mb": limits.get("max_archive_expansion_mb"),
                "max_carriers": limits.get("max_carriers"),
                "max_workers": limits.get("max_workers"),
                "max_vault_blocks": limits.get("max_vault_blocks"),
            }
        )
    if isinstance(history, dict) and "enabled" in history:
        mapping["history_enabled"] = history.get("enabled")
    for name, value in mapping.items():
        if value is None:
            continue
        _assign(config, name, value)


def _assign(config: Config, name: str, value: object) -> None:
    current = getattr(config, name)
    if isinstance(current, bool):
        if not isinstance(value, bool):
            raise ArgumentError(f"Configuration {name} must be a boolean.")
        setattr(config, name, value)
        return
    if isinstance(current, int) and not isinstance(current, bool):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ArgumentError(f"Configuration {name} must be an integer.")
        bounds = INT_LIMITS.get(name)
        if bounds and not bounds[0] <= value <= bounds[1]:
            raise ArgumentError(f"Configuration {name}={value} is outside {bounds[0]}..{bounds[1]}.")
        setattr(config, name, value)
        return
    if isinstance(current, str):
        if not isinstance(value, str) or not value:
            raise ArgumentError(f"Configuration {name} must be a non-empty string.")
        setattr(config, name, value)
        return
    raise ArgumentError(f"Cannot apply configuration field {name}.")


def load_config(*, explicit: Path | None = None, profile: str | None = None, project_dir: Path | None = None) -> Config:
    """Load defaults, then global, profile, project, and explicit files."""
    config = Config(profile=profile)
    layers: list[Path] = []
    global_path = config_directory() / "config.toml"
    if global_path.is_file():
        layers.append(global_path)
    project = project_dir or Path.cwd()
    local = project / "dead-drop.toml"
    tables: list[dict[str, Any]] = [_read_toml(path) for path in layers]
    if profile:
        for table in tables:
            profiles = table.get("profiles", {})
            if isinstance(profiles, dict) and profile in profiles:
                chosen = profiles[profile]
                if not isinstance(chosen, dict):
                    raise ArgumentError(f"Profile {profile} must be a table.")
                _apply_table(config, chosen)
    if local.is_file():
        _apply_table(config, _read_toml(local))
    if explicit is not None:
        if not explicit.is_file():
            raise ArgumentError(f"Configuration file not found: {explicit}")
        explicit_table = _read_toml(explicit)
        if profile:
            profiles = explicit_table.get("profiles", {})
            if isinstance(profiles, dict) and profile in profiles and isinstance(profiles[profile], dict):
                _apply_table(config, profiles[profile])
        _apply_table(config, explicit_table)
        config.config_path = explicit
    if config.password_kdf != "argon2id":  # noqa: S105
        raise ArgumentError("The only supported password KDF is argon2id.")
    if config.default_encryption not in {"aes-256-gcm", "chacha20-poly1305"}:
        raise ArgumentError(f"Unsupported encryption algorithm {config.default_encryption}.")
    if "password" in os.environ.get("DEAD_DROP_CONFIG_DUMP", ""):
        raise ArgumentError("Refusing to dump configuration that requests secrets.")
    return config
