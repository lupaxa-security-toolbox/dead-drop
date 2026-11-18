# Security Limitations

Dead Drop is a local laboratory. Read this page before you store something you cannot afford to lose or to expose.

## Three Different Properties

| Property    | What it does                                        | What it does not do                                                      |
| ----------- | --------------------------------------------------- | ------------------------------------------------------------------------ |
| Concealment | Stores bytes in a carrier using the named method    | Encrypt them, or make every method invisible                             |
| Encryption  | Hides payload bytes from someone without the key    | Hide a ZIP entry name, an SVG metadata element, or a PNG ancillary chunk |
| Redundancy  | Rebuilds bytes from a threshold of shards or shares | Authenticate those bytes                                                 |

Pixel LSB, sample LSB, and the text methods are the covert methods. `png-chunk`, `svg-metadata`, and `zip-entry` are labelled container or structured storage in the algorithm catalogue and in command output. Do not describe them as
undetectable. The application does not claim undetectability for the covert methods either. A later editor, a recompressor, or a statistical test can still notice or destroy them.

## Passwords and Memory

Passwords are prompted or read from a file you name. They are not command-line arguments. Logs pass through a redaction filter for secrets the process registered. History records commands, paths, status, duration, and error codes. History
can be turned off with `[history] enabled = false`.

`wipe` overwrites a `bytearray` this process still holds. CPython, the `cryptography` library, and the operating system can keep other copies. Dead Drop does not promise that a key is gone from RAM, swap, a crash dump, or a hibernation
file.

## Deletion

Vault destroy and compaction stop the current carriers from serving the old generation. They do not promise secure deletion on an SSD, in a cloud backup, in a filesystem snapshot, or in a copy you made earlier.

## Atomicity

Replacing one file with `os.replace` is atomic on the same volume. Replacing a directory of carriers is not one transaction. Vault recovery trusts generation numbers and complete shard sets. An interrupted commit can leave a mix of old and
new files. The previous complete generation remains the one that opens when the new set is incomplete.

## Untrusted Input

Archives, XML, images, and paths are untrusted. Extraction refuses absolute paths, `..`, symlinks used as outputs, and expansions past the configured byte limit. XML parsing rejects doctype, entities, scripts, and event-handler attributes.
Those checks are the implemented defences. They are not a general malware scanner.

## Text and Transforms

Text and Markdown payloads can be destroyed by trimming, rewrapping, normalisation, or a change of newline. The hide command warns about that. Stress tests measure specific transforms. A pass on one transform is not a pass on the next one.

## Statistical Language

Chi-square figures, entropy, and LSB counts are numbers. A known magic string in cleartext is a detection of that string. Neither one is proof that an unknown method is present, and neither one is proof that a carrier is clean.

## Network

No command contacts a service. If a future build tried to download a codec or a model, that would be a defect. Lossy audio conversion runs only when a local codec is already installed, and the stress report says when it is not.
