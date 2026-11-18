# Distribution and Recovery

## Modes

- One carrier.
- Sequential fragments.
- Balanced and capacity-weighted plans.
- Replicated placement when the plan selects more carriers than shards.
- Reed-Solomon data and parity shards.
- Shamir on the data key, with Reed-Solomon on the ciphertext.

`reedsolo` provides the code. A `k-of-n` code reconstructs from any `k` intact shards of that set. Dead Drop does not promise that losing an arbitrary carrier is safe when that carrier held more than one essential shard, or when the carrier
was too small and the shard was never written. The plan's blocking errors say so before a write.

## Planning

```bash
dead-drop plan secret.zip --carriers ./pictures --optimise balanced --save plan.json
```

The planner reads capacity from the selected algorithm. It includes package size, a fixed allowance for encryption overhead, and the requested shard counts. It does not modify a carrier.

The saved JSON includes payload size, packaged size, an encrypted-size estimate, required capacity, available capacity, the chosen paths, algorithms, shard parameters, the recovery threshold, a distortion note, warnings, blocking errors,
and SHA-256 of each chosen carrier.

```bash
dead-drop recipe run plan.json
```

Execution hashes the carriers again. A mismatch is a stale plan and the command stops. There is no separate manifest. Each fragment envelope carries the payload id, the shard index, and the code parameters.

## Recovery

```bash
dead-drop recover ./concealed --output recovered/
```

Recovery scans the directory, extracts envelopes, groups them by payload id, rejects a mix of sets, names the gap when too few shards exist, reconstructs, then authenticates. An unauthenticated partial file is not written as a success.

A placement key, when the embed used keyed placement, is required again at extract time. Ordinary sequential embeds do not need a placement key. They still need the encryption password.

## Audits

`dead-drop audit recovery plan.json` reports the analytical threshold: any `data_shards` intact shards reconstruct, and `parity_shards` losses are tolerated when each shard is on its own carrier. Sampled and exhaustive carrier-loss runs are
labelled as samples. An analytical line is not a sample, and a sample is not a guarantee.

Reports include format versions and carrier hashes. They do not include passwords or keys.
