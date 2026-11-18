# Usage

Global options work with every command. Put them before the command name.

| Option              | Meaning                                                |
| ------------------- | ------------------------------------------------------ |
| `--config PATH`     | Explicit TOML configuration                            |
| `--json`            | JSON result envelope                                   |
| `--quiet`           | Warnings and errors only                               |
| `--verbose`         | Operational detail                                     |
| `--debug`           | Diagnostic logging                                     |
| `--no-colour`       | Plain text                                             |
| `--non-interactive` | Refuse a password prompt                               |
| `--dry-run`         | Plan without writing, where the command supports it    |
| `--force`           | Permit a documented overwrite, including vault destroy |
| `--jobs N`          | Worker hint                                            |
| `--temp-dir PATH`   | Temporary directory override                           |
| `--profile NAME`    | Named configuration profile                            |
| `--version`         | Print the package version and exit                     |

Exit codes are stable: 0 success, 1 general failure, 2 arguments, 3 unsupported format, 4 capacity, 5 authentication, 6 integrity, 7 fragments, 8 filesystem, 9 vault conflict, 10 resource limit, 11 cancellation, 12 partial batch.

## Concealment

```bash
dead-drop hide photo.png secret.txt --output concealed.png --algorithm png-lsb
dead-drop reveal concealed.png --output recovered/
dead-drop capacity photo.png
dead-drop inspect photo.png
dead-drop verify concealed.png secret.txt
```

`hide` deletes its output when the recovery check fails. The source carrier is not the output.

## Distribution

```bash
dead-drop distribute archive.zip --carriers ./pictures --output ./concealed --data-shards 2 --parity-shards 1
dead-drop recover ./concealed --output recovered/
dead-drop plan archive.zip --carriers ./pictures --optimise balanced --save plan.json
dead-drop recipe run plan.json
```

`plan` never writes a carrier. `recipe run` on a saved plan refuses the plan when a carrier hash changed.

`--optimise` accepts `capacity`, `low-distortion`, `spread`, `fewest-files`, `robustness`, `balanced`, and `custom`.

## Collections, Shares, Algorithms, Payloads, and Slots

```bash
dead-drop carriers scan ./pictures
dead-drop carriers list ./pictures
dead-drop carriers inspect photo.png
dead-drop carriers validate photo.png
dead-drop shares create secret.key --shares 5 --threshold 3 --output shares/
dead-drop shares inspect shares/share-1.ddshare
dead-drop shares combine shares/ --output recovered.key
dead-drop shares verify shares/
dead-drop algorithms list
dead-drop algorithms info png-lsb
dead-drop algorithms compare --carrier photo.png --payload sample.bin --output bench.csv
dead-drop algorithms benchmark --carrier photo.png --payload sample.bin
dead-drop payload pack secret.txt --output secret.ddpl
dead-drop payload inspect secret.ddpl
dead-drop payload unpack secret.ddpl --output unpacked/
dead-drop payload verify secret.ddpl
dead-drop slots reserve photo.png --slot private --output slotted.png
dead-drop slots list slotted.png
dead-drop slots inspect slotted.png --slot private
dead-drop slots remove slotted.png --slot private --output cleared.png
```

Slot names are a management record. They are not a claim that the slot is statistically hidden.

## Laboratory

```bash
dead-drop analyse suspicious.png --deep
dead-drop compare before.png after.png
dead-drop visualise image.png --type bit-plane --channel red --bit 0 --output plane.png
dead-drop stress-test image.png
dead-drop audit recovery plan.json --mode analytical
dead-drop audit integrity suspicious.png
dead-drop audit report plan.json --output report.md
```

## Vault

```bash
dead-drop vault create ./carriers --name personal --encrypt --redundancy 1
dead-drop vault open ./carriers
dead-drop vault status ./carriers
dead-drop vault put ./carriers ./document.pdf documents/document.pdf
dead-drop vault ls ./carriers
dead-drop vault tree ./carriers
dead-drop vault get ./carriers documents/document.pdf --output document.pdf
dead-drop vault cat ./carriers documents/document.pdf
dead-drop vault mkdir ./carriers documents
dead-drop vault rmdir ./carriers documents
dead-drop vault mv ./carriers documents/document.pdf notes/document.pdf
dead-drop vault cp ./carriers notes/document.pdf copies/document.pdf
dead-drop vault rm ./carriers copies/document.pdf
dead-drop vault find ./carriers document
dead-drop vault info ./carriers notes/document.pdf
dead-drop vault capacity ./carriers
dead-drop vault verify ./carriers --deep
dead-drop vault repair ./carriers
dead-drop vault rebalance ./carriers
dead-drop vault compact ./carriers
dead-drop vault snapshot ./carriers --name before-update
dead-drop vault snapshot ./carriers --list
dead-drop vault restore ./carriers --name before-update
dead-drop vault backup ./carriers --output personal.ddbak
dead-drop vault recover --backup personal.ddbak --output ./restored
dead-drop vault recover ./carriers
dead-drop vault close
dead-drop vault destroy ./carriers --force
```

`destroy` replaces embeddings. It does not promise that an SSD, a backup, or an earlier copy forgot the previous bytes.

## Challenges, Recipes, and the Terminal

```bash
dead-drop challenge create --difficulty hard --output challenge/ --seed local
dead-drop challenge generate --difficulty medium --output challenge/ --seed local
dead-drop challenge inspect challenge/
dead-drop challenge solve challenge/ --answer answer.bin
dead-drop challenge verify challenge/ --answer answer.bin
dead-drop recipe validate recipe.toml
dead-drop recipe plan recipe.toml
dead-drop recipe run recipe.toml
dead-drop interactive
dead-drop history
```

`interactive` opens the Textual application. It uses the same detection code as the CLI and does not modify a carrier from the path preview.
