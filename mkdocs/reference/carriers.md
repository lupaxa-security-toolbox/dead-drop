# Carriers and Algorithms

A carrier is an ordinary file that can hold extra bytes and still open as that format. Every engine can detect the format, validate the structure, measure capacity, plan an embed, embed, extract, and report what it changed.

Capacity is computed from the algorithm and the carrier structure. File size is not a proxy.

## Formats and Methods

| Format   | Algorithms                                          | Class                                                             |
| -------- | --------------------------------------------------- | ----------------------------------------------------------------- |
| PNG      | `png-lsb`, `png-bitplane`, `png-chunk`              | Pixel methods are covert. Ancillary chunks are container storage. |
| BMP      | `bmp-lsb`                                           | Covert pixel LSB on uncompressed 24-bit and 32-bit BMP.           |
| WAV      | `wav-lsb`                                           | Covert sample LSB on integer PCM.                                 |
| Text     | `txt-whitespace`, `txt-space-tab`, `txt-zero-width` | Covert, and fragile.                                              |
| Markdown | `md-whitespace`, `md-space-tab`, `md-zero-width`    | Covert, and fragile.                                              |
| SVG      | `svg-metadata`                                      | Structured metadata. Not statistically covert.                    |
| ZIP      | `zip-entry`                                         | A named archive entry. Container storage, not steganography.      |

`auto` selects `png-lsb`, `bmp-lsb`, `wav-lsb`, `txt-zero-width`, `md-zero-width`, `svg-metadata`, or `zip-entry`.

## PNG

8-bit RGB and RGBA only. Other modes and bit depths are rejected. Dimensions stay the same. Alpha is preserved unless a caller selects that channel. RGB channels and bit planes are selectable. Placement is sequential or a keyed permutation.

The keyed stream is deterministic for a key and a public 16-byte nonce. The output starts with the ASCII marker `DDNN` and that nonce, then the keyed payload. The nonce is not a secret. The placement key is not encryption.

`png-chunk` stores bytes in the ancillary chunks `deNp` and `deDp`. Unrelated ancillary chunks are copied when Pillow rewrites the image. The output is checked with an independent decoder. Reports include changed-pixel counts, MSE, PSNR,
and a global SSIM figure.

## BMP

Uncompressed `BI_RGB` 24-bit and 32-bit files. Row padding and the file header are not used as payload bits. Bottom-up height is preserved. Compressed BMP is rejected. The written file is parsed again before success.

## WAV

Integer PCM at 8, 16, 24, or 32 bits, mono or multichannel. The least significant byte of each selected sample carries the bits. Sample rate, duration, and channel count stay the same. Float and compressed encodings are rejected. Reports
include signal-to-noise ratio and sample-difference counts.

## Text and Markdown

Trailing whitespace encodes one payload byte per line after a length line. Space and tab patterns use a line that starts with a tab. Zero-width encoding uses U+2060 and U+2063.

The file is checked as UTF-8. The command warns that editors, copy and paste, rewrapping, and Unicode normalisation can destroy the payload. That warning is a fact about the method, not a detection claim.

## SVG

Parsing uses `defusedxml`. Doctype declarations, entities, `script`, `foreignObject`, `on*` attributes, and `javascript:` links are rejected. The payload is base64 in a metadata element in the `urn:dead-drop:1` namespace. The document stays
XML. This is structured storage. Anyone who opens the XML can see the element.

## ZIP

The payload is the entry `dead-drop/payload.bin`. Existing entries stay. Paths that escape the archive, and archives that expand past the configured limit, are rejected. `testzip` runs after the write. A duplicate payload name needs
`--force`. This is container storage. The entry name is visible.

## Placement

Strategies are sequential, keyed, distributed across channels, capacity-weighted, and reserved-region. Reserved regions are not reused by a later placement in the same plan. Distributed channel layout is applied by the carrier, not twice.

## Error Correction

Reed-Solomon shards are optional and configurable. The report states how many shards reconstruct the blob. A failed reconstruction is an error. The coding parity is not an authentication tag. Authentication is the AEAD tag, or the SHA-256
trailer on an unencrypted envelope.

## What the Application Will Not Claim

A successful embed means the bytes were written and read back by Dead Drop. It does not mean a person or another program cannot notice the change. Statistical tests in `analyse` are measurements and heuristics. They are not proof that a
payload is present or absent.
