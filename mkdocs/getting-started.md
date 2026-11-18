# Getting Started

Dead Drop needs Python 3.11 or newer on macOS, Linux, or Windows. It does not download tools, models, or keys.

## Install

```bash
pip install dead-drop
```

From a checkout:

```bash
pip install -e ".[dev]"
dead-drop --version
```

## Quick Start

```bash
dead-drop hide photo.png secret.txt --output concealed.png
dead-drop reveal concealed.png --output recovered/
dead-drop plan archive.zip --carriers ./pictures --optimise balanced --save plan.json
dead-drop vault create ./carriers --name personal --encrypt --redundancy 1
```

Global options come before the command:

```bash
dead-drop --json --quiet hide photo.png secret.txt --output concealed.png
```

The password is read from a non-echoing prompt, or from `--password-file`. It is not a command-line argument.

## Configuration

Precedence, later wins:

1. Built-in defaults.
2. The global file from `platformdirs` (`dead-drop` / `Lupaxa`).
3. A named profile, `[profiles.NAME]`, selected with `--profile`.
4. `./dead-drop.toml`.
5. `--config PATH`.
6. Explicit command-line flags.

```toml
[general]
colour = true
json = false
jobs = 4
verify_after_write = true

[security]
default_encryption = "chacha20-poly1305"
password_kdf = "argon2id"
require_encryption = true

[embedding]
default_strategy = "balanced"
default_algorithm = "auto"
preserve_originals = true

[distribution]
default_data_shards = 5
default_parity_shards = 3

[vault]
block_size = 65536
retain_generations = 2
verify_on_open = true

[analysis]
deep_scan = false
max_file_size_mb = 1024

[limits]
max_nesting_depth = 8
max_archive_expansion_mb = 4096

[history]
enabled = true
```

Numeric limits are rejected when they fall outside the ranges in `config.py`. Configuration must not contain a plaintext password.

## Troubleshooting

- Exit code 2 means the arguments or the TOML file are invalid. Read the message; it names the field.
- Exit code 4 means the selected algorithm's validated capacity is too small. A large file size does not imply LSB capacity.
- Exit code 5 always says `Authentication failed.` A wrong password and a damaged tag share that message.
- Text carriers that use trailing whitespace only hold one byte per line after the first line. Use `txt-zero-width` for a short sealed payload.
- A vault image must be large enough for the encrypted metadata and the block shards. A 96 pixel square is enough for a small hide, not for a vault.
- `dead-drop --help` lists every command group. Each group has its own `--help`.
