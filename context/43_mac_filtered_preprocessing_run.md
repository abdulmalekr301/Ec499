# MAC-Filtered Preprocessing Run

Generated: `2026-07-04`

## Purpose

This run regenerated the preprocessing outputs after adding the attacker MAC address list in `context/attacker_macs.txt`. The goal was to keep attack flows that involve known attacker devices, remove attacker-involved flows from benign traffic, and rebuild the graph training inputs from that filtered compact reservoir.

## Commands Used

```bash
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_BENIGN_ONLY_ENFORCE=1 \
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
PYTHONUNBUFFERED=1 \
.venv/bin/python -m secureedge.data.preprocess
```

```bash
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
PYTHONUNBUFFERED=1 \
.venv/bin/python -m secureedge.data.build_graphs
```

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
PYTHONUNBUFFERED=1 \
.venv/bin/python -m secureedge.data.create_shards --overwrite
```

## Results

- Attacker-MAC filtering was enabled.
- Loaded attacker MAC count: `9`.
- Compact reservoir total after balanced split construction: `192000`.
- Train split: `160000` graphs, `20000` per canonical class.
- Test split: `32000` graphs, `4000` per canonical class.
- Graph feature dimensions:
  - flow node: `92`
  - packet node: `1500`
  - containment edge: `4`
  - packet-link edge: `1`
- Shards:
  - train: `160` shard files
  - test: `32` shard files

## Important Observations

The MAC filter reduced several raw subtype pools before oversampling. This is expected because background traffic not involving the known attacker MACs is now excluded from attack classes.

Notable filtered subtype counts:

- `MITM-ArpSpoofing`: `2151`
- `Recon-PingSweep`: `743`
- `SqlInjection`: `2830`
- `XSS`: `222`
- `BrowserHijacking`: `972`
- `CommandInjection`: `275`
- `Uploading_Attack`: `84`
- `Backdoor_Malware`: `244`
- `DictionaryBruteForce`: `2184`

The final class-balanced train/test outputs were still produced through the existing XG-NID balanced-pool oversampling path.

## Validation

Validation loaded `artifacts/compact_reservoir_manifest.json`, `artifacts/graph_dataset_manifest.json`, and `artifacts/graph_shard_manifest.json`.

Confirmed:

- `mac_filter_enabled=True`
- `attacker_mac_count=9`
- train/test class counts match `20000/4000` per class
- sample shard length is `1000`
- sample flow tensor shape is `(1, 92)`
- sample packet tensor shape is `(20, 1500)`
- expected edge types are present:
  - `flow -> contains -> packet`
  - `packet -> rev_contains -> flow`
  - `packet -> linked_to -> packet`

## Memory Safety

The full preprocessing, graph construction, and sharding steps were run with allocator/thread limits:

- `MALLOC_ARENA_MAX=2`
- `OMP_NUM_THREADS=1`
- `OPENBLAS_NUM_THREADS=1`
- `MKL_NUM_THREADS=1`

Available memory stayed above the configured guardrail during the run. Swap was already partially used before the graph/shard phases, but did not show runaway growth during these phases.
