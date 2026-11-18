# Payload, Encryption, and Sharing

Concealment, encryption, and redundancy are three different steps.

- Concealment changes a carrier so the payload bytes are stored in it.
- Encryption makes the payload unreadable without the key. It does not hide the fact that an envelope exists when the envelope is in a visible ZIP entry, SVG element, or PNG chunk.
- Redundancy lets a collection survive missing shards. It does not prove the bytes are authentic. The authentication tag does that.

## Pipeline

```text
Input
  -> package (DDPL)
  -> optional compression
  -> authenticated encryption
  -> optional fragmentation
  -> embed
  -> carrier validation
  -> recovery check
```

Extraction reverses the same steps. Compression always happens before encryption. `none`, `zlib`, `lzma`, and `auto` are supported. `auto` keeps a smaller encoding only when it saves at least 32 bytes. Decompression stops at the configured
expansion limit.

## Packages

`DDPL` packages accept a text string, a file, a directory, standard input, or an existing package. A directory becomes a stored ZIP member list inside the package. Member names cannot be absolute or contain `..`. Unpacking refuses to
replace an existing file and refuses a path that escapes the destination.

Nested packages are marked and counted. Depth and expanded size stop at `max_nesting_depth` and `max_archive_expansion_mb`.

## Envelope

Every embedded payload uses the version 1 `DDR1` envelope documented in [Formats and JSON](formats.md). The header is 50 bytes, big-endian. Fields that must be visible to group fragments (payload id, fragment index, shard counts) stay
outside the ciphertext. The password, the key, and the file bytes do not.

Unencrypted envelopes end with SHA-256 over the prefix and body. They are integrity-checked. They are not confidential.

## Encryption

AES-256-GCM and ChaCha20-Poly1305 come from the `cryptography` library. Dead Drop does not implement a cipher. Bodies are chunked at 1 MiB. Each chunk uses an 8-byte prefix plus a counter. The additional data is the envelope prefix and the
chunk index. A nonce prefix is never reused with the same key in one sealing operation.

The default password KDF is Argon2id. The envelope stores the salt, the KDF id, the parameters, the algorithm, and the nonce prefix. Production defaults are time cost 2, memory 19456 KiB, parallelism 1, and a 32-byte key. Tests and local
experiments may set lower costs in configuration. Those costs are not a recommendation for real secrets.

Passwords come from a prompt or a password file. The password file prints a warning because the password is then sitting on disk. Key files use the `DDK1` format and mode `0600` where the platform allows it. A threshold-combined share set
can become the key. A vault wraps a random 32-byte master key with the password.

Wrong passwords and bad tags both surface as `Authentication failed.` The command does not print a partial plaintext.

Deterministic nonces and salts exist only when a caller sets the insecure laboratory flag and a seed. Normal encryption uses `os.urandom`.

Python cannot promise that a key is gone from memory after `wipe`. Copies inside OpenSSL, the allocator, swap, and crash dumps are outside this process. The security page states that limit.

## Shamir Sharing

```bash
dead-drop shares create secret.key --shares 5 --threshold 3 --output shares/
dead-drop shares combine shares/ --output recovered.key
```

Shares use the `DDSS` format over GF(2^8) with the AES polynomial. Each share carries an index, a set id, and a checksum. Reconstruction also checks a SHA-256 binding that was shared with the secret. Fewer than the threshold are refused
before interpolation. Duplicate indexes and mixed set ids are refused.

For a large distributed payload the default is:

1. Generate a random data key.
2. Encrypt the payload with that key.
3. Split the data key into Shamir shares.
4. Split the ciphertext with the requested Reed-Solomon parameters.
5. Embed key shares and data shards.

The result reports both the key threshold and the data-shard threshold. They are not the same number.
