# Formats and JSON

Integers are big-endian. Lengths are the lengths written below, in bytes.

## JSON Envelope

```json
{
  "schema_version": "1.0",
  "command": "capacity",
  "success": true,
  "data": {},
  "warnings": [],
  "errors": []
}
```

`errors` items have `code`, `message`, and `exit_code`. Field names stay stable. Units are bytes, seconds, or a named ratio. JSON output has no colour codes and no progress bars. Passwords, keys, share contents, and raw payload bytes are
not fields.

## DDR1 Envelope

Fixed header, 50 bytes, `struct` format `>4sBBHH16sHHBBBBBBBBQI`:

| Field            | Size |
| ---------------- | ---- |
| Magic `DDR1`     | 4    |
| Version `1`      | 1    |
| Type             | 1    |
| Flags            | 2    |
| Algorithm id     | 2    |
| Payload id       | 16   |
| Fragment index   | 2    |
| Fragment count   | 2    |
| Data shards      | 1    |
| Parity shards    | 1    |
| Compression id   | 1    |
| KDF id           | 1    |
| Encryption id    | 1    |
| Nonce length     | 1    |
| Salt length      | 1    |
| Reserved         | 1    |
| Plaintext length | 8    |
| Body length      | 4    |

Types: 1 single, 2 fragment, 3 key share, 4 vault block, 5 vault metadata, 6 slot table, 7 vault pointer.

Flags: 1 compressed, 2 encrypted, 4 LZMA, 8 erasure, 16 keyed placement, 32 nested, 64 decoy.

Encryption ids: 0 none, 1 AES-256-GCM, 2 ChaCha20-Poly1305. KDF id 1 is Argon2id and is followed by a 10-byte block `>IIBB` (time, memory KiB, parallelism, hash length). Salt and nonce follow. An unencrypted body is followed by 32 bytes of
SHA-256 over the prefix and body.

Frames that share a carrier are `u32 length || envelope`, repeated. The carrier embedder adds one more `u32` length in front of that blob so extractors do not have to guess.

## DDPL Package

`>4sBBHI` then the name, then `>Q` size, then the bytes. Magic `DDPL`, version 1. Kinds: 1 bytes, 2 file, 3 directory tree, 4 nested. A tree's bytes are a stored-method ZIP.

## DDSS Share

Magic `DDSS`. Header `>4sB16sBBBHH` then the share body. The body is the secret polynomial evaluation together with a binding digest of the secret. Combining shares checks that binding.

## DDK1 Key File

Magic `DDK1`, version byte, kind 1, then 32 key bytes. Write it with mode `0600` on platforms that honour that mode.

## DDNN Placement Preamble

ASCII `DDNN` plus the 16-byte public nonce. Keyed pixel and sample streams store this preamble before the payload. The nonce is not secret.

## DDBK Backup

ASCII `DDBK` plus one encrypted `DDR1` envelope. The plaintext is JSON: `format` 1, `vault_id`, `name`, and `files` (path, SHA-256, hex bytes). The hex encoding is deliberate and larger than the raw files. Restoring checks the hash before
writing.

## PNG Chunks

`deNp` holds a nonce. `deDp` holds a container payload. These chunks are ancillary and visible to a chunk walker. Pixel LSB methods do not use them.

## Vault Pointer

The pointer envelope is type 7 and is not encrypted. Its plaintext is the vault id, carrier id, generation, and the hex of the wrapped master key. The wrapped key is already ciphertext. The directory tree is only inside the type 5 metadata
envelope, which is encrypted with the master key. Block shards are type 4 and carry pieces of an already-encrypted block.
