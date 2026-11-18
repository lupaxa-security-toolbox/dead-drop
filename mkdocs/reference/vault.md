# Vault

The vault is an encrypted filesystem stored across ordinary carriers. Filenames, the directory tree, and file bytes are inside authenticated ciphertext. A small pointer on each carrier is visible and holds only the vault id, the carrier id,
the generation, and the already-encrypted wrapped master key.

## Create

```bash
dead-drop vault create ./carriers --name personal --encrypt --redundancy 1
```

Creation scans supported files, copies them to `.dead-drop-pristine/`, measures capacity, generates a vault id and a random master key, wraps that key with the password, writes the first generation, and opens the vault again before it
returns. Usable capacity is reported from the algorithm capacity, not from file size.

`--redundancy N` is the number of parity shards, capped at one less than the carrier count. Data shards take the rest. One carrier has no parity.

## Files

The tree holds files and directories, names, sizes, created and modified timestamps, optional metadata, and content hashes. Symbolic links, permission bits, and a kernel mount are not part of this filesystem. Use the CLI or the terminal UI.

```bash
dead-drop vault put ./carriers ./document.pdf documents/document.pdf
dead-drop vault get ./carriers documents/document.pdf --output document.pdf
dead-drop vault ls ./carriers
dead-drop vault tree ./carriers
dead-drop vault mkdir ./carriers documents
dead-drop vault mv ./carriers document.pdf documents/document.pdf
dead-drop vault cp ./carriers documents/document.pdf copies/document.pdf
dead-drop vault rm ./carriers copies/document.pdf
dead-drop vault rmdir ./carriers empty-dir
```

File contents are split into blocks (`block_size`, default 65536). Each block is encrypted with the master key and then split into Reed-Solomon shards. A block is readable when enough shards survive.

## Transactions

A commit rewrites each carrier from its pristine original into `name.dead-drop-tmp`, checks that the temporary file still contains the metadata frame, then replaces the live file. Several files cannot be replaced as one atomic filesystem
transaction. The generation number and the completeness of the shard set decide which generation opens.

An interrupted commit leaves either the previous complete generation or, once every replacement has landed, the new one. `fail_after` exists so tests can stop between replacements. Do not treat a crash window as impossible. Treat a
generation that fails its shard check as unreadable, and keep the previous one.

A writer lock on `.dead-drop/writer.lock` rejects a second writer in the same directory. Stale generations that fail authentication or completeness are skipped in favour of the newest generation that opens.

## Verify, Repair, Rebalance, Compact

`vault verify --deep` authenticates every stored file. `vault repair` prints a plan and does not rewrite carriers while shards are missing and unrecoverable. It does not delete a file it cannot rebuild.

`vault rebalance` adopts new carrier files in the directory and spreads shards across the collection, then commits. Removing a carrier that would drop the collection under the data-shard threshold has to be a rebalance or an export first.
The repair plan says when the set is short.

`vault compact` drops blocks that the live tree and every snapshot no longer name. Snapshot blocks stay.

## Snapshots and Backup

```bash
dead-drop vault snapshot ./carriers --name before-update
dead-drop vault snapshot ./carriers --list
dead-drop vault restore ./carriers --name before-update
dead-drop vault snapshot ./carriers --delete before-update
dead-drop vault backup ./carriers --output personal.ddbak
dead-drop vault recover --backup personal.ddbak --output ./restored
```

A snapshot is a copy of the filesystem tree at one generation. It counts toward capacity because its blocks are retained.

The backup file starts with `DDBK` and then a password-sealed envelope. Inside are the file paths and bytes. Restoring it does not need the original carriers. The backup is encrypted. It is not concealed, and it is only as secret as the
password and the file permissions.

## Destroy

```bash
dead-drop vault destroy ./carriers --force
```

Destroy re-embeds an empty payload from the pristine originals over the live carriers. That removes the vault pointer from those files. It does not erase old copies, SSD wear-levelling residue, or a backup you already made.
