<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Dead Drop</h1>

Dead Drop is an offline laboratory for concealing, encrypting, distributing, analysing, and recovering data in ordinary files. A carrier-backed encrypted filesystem is one of its central features.

Concealment, encryption, and redundancy are separate. Hiding bytes does not encrypt them. Encryption does not make a carrier look unchanged.

Erasure coding and secret sharing do not authenticate a payload. Each command reports which of those properties it used.

## Install

Python 3.11 or newer:

```bash
pip install lupaxa-dead-drop
```

From a checkout:

```bash
pip install -e ".[dev]"
```

The command is `dead-drop`. The import path is `lupaxa.dead_drop`. `lupaxa` is a namespace package — there is no `lupaxa/__init__.py`. It does not use the network.

## Quick Start

```bash
dead-drop hide photo.png secret.txt --output concealed.png
dead-drop reveal concealed.png --output secret.txt
dead-drop plan archive.zip --carriers ./pictures --optimise balanced
dead-drop vault create ./carriers --name personal --encrypt --redundancy 3
```

Passwords are prompted and are not accepted as command-line arguments. Add `--json` for a stable result envelope.

## What it Does

- Hides payloads in PNG, BMP, WAV, text, Markdown, SVG, and ZIP carriers.
- Encrypts payloads with AES-256-GCM or ChaCha20-Poly1305 and Argon2id passwords.
- Splits keys with Shamir sharing and spreads ciphertext with Reed-Solomon shards.
- Plans carrier use without modifying files, then runs the plan from a recipe.
- Analyses and visualises carriers without treating statistics as proof.
- Stress-tests transformations on temporary copies.
- Stores a transactional encrypted filesystem across a carrier collection.
- Builds reproducible steganography challenges.

## Documentation

The published guide is at <https://dead-drop.thelupaxaproject.org/>.

Site Markdown lives in `mkdocs/`.

```bash
python -m pip install -r requirements.txt
mkdocs serve
```

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
