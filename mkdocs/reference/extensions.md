# Extension Interfaces

The packages under `lupaxa.dead_drop` are the supported extension surface. Import them. Do not scrape command output except the JSON envelope, which is stable.

## Add a Carrier

Implement the operations the PNG engine implements: detect, validate, capacity in bytes, embed, and extract. Register the algorithm in `carriers.api.algorithm_catalogue` and `ALGORITHM_FORMAT`. Set `concealment_class` to `covert`,
`structured`, or `container`. A container method must not be described as covert.

`embed` in `carriers.api` prefixes the payload with a 4-byte length. Extractors return the raw stored bytes. The facade strips the length. An engine that needs a keyed preamble uses `DDNN` plus a 16-byte nonce and documents that the nonce
is public.

Refuse to write when the framed payload does not fit. Write to the destination path, never to the source, unless the caller is the vault commit and has already staged a temporary file.

## Add an Algorithm Property

`AlgorithmInfo` is the declaration a command prints. Fill the capacity formula, the transformation note, the metrics, and the forensic tests with what the code measures. Do not add a field whose only purpose is a guarantee the tests do not
check.

## Crypto

Call `crypto.aead` and `crypto.kdf`. Do not add a cipher implementation. New algorithms have to be names the `cryptography` library already provides, with a new id in the envelope table and a version note in `mkdocs/reference/formats.md`.

Nonce prefixes come from `os.urandom` unless the caller set the insecure deterministic laboratory flag. Register key material with `redact.register_secret` before you log a record that might contain it.

## Envelopes

Build bytes with `payload.envelope.build_envelope`. Parse with `parse_envelope`, which requires a key for encrypted bodies and a maximum plaintext size. Add a type code only by extending the documented table. Unknown versions must fail. Do
not guess.

## Vault

A vault change goes through `Vault.commit`. Stage temps, validate the extracted metadata frame, then `atomic_replace`. Keep the previous generation recoverable when the new shard set is incomplete. Compaction may drop a block only when the
live tree and every snapshot omit it.

## Recipes

A recipe operation is a named string in the TOML schema. The runner must not `eval` or `exec` the file. New path fields that expand environment variables belong in the explicit allow-list in `automation._expand_paths`.

## Tests

A new carrier needs a round trip, a too-small carrier, a wrong password, and a check that the source bytes did not change. A new vault write needs a reopen. Version tests check the semantic-version shape only. They must not compare
`__version__` with a literal such as `0.0.0`.
