# Validation Split Added

Generated: `2026-07-04`

## Purpose

Added a dedicated validation split so training behavior can be observed during training without using the final test split every epoch.

Before this change, `secureedge.models.train` evaluated every epoch on the `test` split. That made test performance visible during training and could bias model-selection decisions. The training loop now evaluates each epoch on `val`, saves best checkpoints by validation macro F1, and leaves `test` for final evaluation through `secureedge.models.evaluate`.

## Code Changes

- Added `SECUREEDGE_VAL_SAMPLES_PER_CLASS`, default `4000`.
- Added validation graph directories:
  - `data/graphs/val/`
  - `data/graphs/val_shards/`
- Updated preprocessing to build three splits:
  - `train`: `20000` per class
  - `val`: `4000` per class
  - `test`: `4000` per class
- Updated compact reservoir manifest generation to include `val`.
- Updated graph construction to materialize validation graphs using scalers fitted on train only.
- Updated graph sharding to produce validation shards.
- Updated dataset loading to accept `split="val"`.
- Updated training to:
  - read validation shards for per-epoch evaluation
  - use validation macro F1 for best-checkpoint selection
  - write validation accuracy, macro F1, false positive rates, and false negative rates into `logs-n.md`
  - reserve test graphs for final evaluation only

## Data Regeneration

The PCAP/NFStream extraction phase was not rerun. Instead, the existing MAC-filtered compact reservoir was resplit:

```bash
SECUREEDGE_RESPLIT_EXISTING_RESERVOIR=1 \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_BENIGN_ONLY_ENFORCE=1 \
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
PYTHONUNBUFFERED=1 \
.venv/bin/python -m secureedge.data.preprocess
```

Then graph files and shards were regenerated:

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

## Final Counts

```json
{
  "compact_total": 224000,
  "compact_splits": {
    "train": 160000,
    "val": 32000,
    "test": 32000
  },
  "graph_counts": {
    "train": 160000,
    "val": 32000,
    "test": 32000
  },
  "shards": {
    "train": 160,
    "val": 32,
    "test": 32
  },
  "val_per_class": {
    "Benign": 4000,
    "DDoS": 4000,
    "DoS": 4000,
    "Mirai": 4000,
    "Recon": 4000,
    "Spoofing": 4000,
    "WebBased": 4000,
    "BruteForce": 4000
  }
}
```

## Validation

Checks completed successfully:

- `python -m compileall secureedge tests`
- `python tests/smoke_checks.py`
- Loaded `artifacts/compact_reservoir_manifest.json`
- Loaded `artifacts/graph_dataset_manifest.json`
- Loaded `artifacts/graph_shard_manifest.json`
- Loaded one validation shard and confirmed graph tensors are readable.

## Training Impact

New training runs will use:

- `train` for gradient updates
- `val` for per-epoch behavior tracking and best-checkpoint selection
- `test` only for final reporting through `python -m secureedge.models.evaluate`

Existing checkpoints from earlier runs remain valid only if their model signature matches, but their reported per-epoch metrics came from the old test-each-epoch behavior.
