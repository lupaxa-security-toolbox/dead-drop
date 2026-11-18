# Dead Drop

Dead Drop is an offline laboratory for concealing, encrypting, distributing, analysing, and recovering data in ordinary files. A carrier-backed encrypted filesystem is one of its central features.

It runs on macOS, Linux, and Windows. It does not use the network, an account, or a cloud service.

## Three Separate Properties

| Property    | What it does                                        |
| ----------- | --------------------------------------------------- |
| Concealment | Stores bytes in a carrier using the named method    |
| Encryption  | Hides payload bytes from someone without the key    |
| Redundancy  | Rebuilds bytes from a threshold of shards or shares |

Hiding bytes does not encrypt them. Encryption does not make a carrier look unchanged. Erasure coding and secret sharing do not authenticate a payload. Each command reports which of those properties it actually used.

## What it Does

- Hides payloads in PNG, BMP, WAV, text, Markdown, SVG, and ZIP carriers.
- Encrypts payloads with AES-256-GCM or ChaCha20-Poly1305 and Argon2id passwords.
- Splits keys with Shamir sharing and spreads ciphertext with Reed-Solomon shards.
- Plans carrier use without modifying files, then runs the plan from a recipe.
- Analyses and visualises carriers without treating statistics as proof.
- Stress-tests transformations on temporary copies.
- Stores a transactional encrypted filesystem across a carrier collection.
- Builds reproducible steganography challenges.
