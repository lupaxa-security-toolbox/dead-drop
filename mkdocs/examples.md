# Examples

## Challenges

```bash
dead-drop challenge create --difficulty hard --output challenge/ --seed local
dead-drop challenge inspect challenge/
dead-drop challenge solve challenge/ --answer answer.bin
```

Difficulties are `easy`, `medium`, `hard`, `expert`, and `custom`. The public `challenge.json` contains an identifier, the difficulty, the expected solution type, a SHA-256 commitment, carrier names, clues, and generation metadata. The
solution bytes and the puzzle password are written only under `challenge/.private/`. Public metadata does not contain either one.

Easy and custom puzzles are one PNG using pixel LSB. The clue states that the password is the difficulty, a hyphen, and the seed. Medium puzzles are two PNG fragments with one data shard and one parity shard, so either intact file is
enough. Hard puzzles use zero-width text and do not publish the password. Expert puzzles use SVG metadata, which is structured storage rather than pixel steganography, and do not publish the password.

Challenge encryption uses a fast Argon2id cost (time 1, 8 KiB) so a puzzle stays local and quick. That cost is not the vault default and is not appropriate for a real secret. The password is a puzzle password.

## Recipes

Recipes are TOML. They do not run Python and they do not run a shell. `${VAR}` expansion is applied only to `input.path`, `carriers.directory`, and `output.directory`.

```toml
[recipe]
name = "private-archive"
operation = "distribute"

[input]
path = "archive.zip"
compress = "auto"

[security]
encrypt = true
algorithm = "chacha20-poly1305"
key_source = "prompt"

[carriers]
directory = "./photographs"
recursive = true
formats = ["png", "bmp"]

[distribution]
strategy = "erasure-coded"
data_shards = 2
parity_shards = 1

[output]
directory = "./concealed"
verify = true
```

```bash
dead-drop recipe validate recipe.toml
dead-drop recipe plan recipe.toml
dead-drop recipe run recipe.toml
```

`plan` is a dry run. `run` prompts for the password, embeds, and verifies. `operation` may be `hide`, `distribute`, `reveal`, or `vault-create`. `hide` and `distribute` execute. The other names are accepted by the schema check and refused
at execution until you use the matching command, so a typo does not become an unexpected write.

A saved plan is JSON. `dead-drop recipe run plan.json` rechecks carrier hashes and then distributes. Batch recipes should record each payload's success or failure separately. A partial batch exits 12.
