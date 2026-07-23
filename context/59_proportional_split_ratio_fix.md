# Proportional Split Ratio Fix

## Purpose

This update implements the split correction requested in `context/proportional-split-ratio-fix.md`.
The previous split logic protected fixed validation/test targets before training received the remaining
real samples. That was acceptable for abundant classes, but it severely starved scarce classes:

| Class | Previous Train Unique | New Train Unique | Previous Val | New Val | Previous Test | New Test |
|---|---:|---:|---:|---:|---:|---:|
| Recon | 19143 | 19286 | 2000 | 1929 | 2000 | 1928 |
| Spoofing | 12151 | 13459 | 2000 | 1346 | 2000 | 1346 |
| WebBased | 627 | 3856 | 2000 | 386 | 2000 | 385 |
| BruteForce | 184 | 1820 | 1000 | 182 | 1000 | 182 |

The main improvement is that WebBased now gets roughly 6.1x more real training samples and
BruteForce gets roughly 9.9x more real training samples before train-only oversampling fills each
class to 20000 training graphs.

## Code Changes

- Changed the default validation/test targets in `secureedge/config.py` from 4000 to 2000 per class.
- Added `PROPORTIONAL_SPLIT_THRESHOLD`, derived from train + validation + test targets. With the current
  defaults, this is `20000 + 2000 + 2000 = 24000`.
- Removed the stale BruteForce-only validation/test config knobs. BruteForce now follows the same
  proportional split rule as every other scarce class.
- Added `split_targets_for_class()` in `secureedge/data/preprocess.py`.
- Updated `split_without_cross_split_duplicates()` to choose split targets from the proportional rule
  before balancing the train split.
- Extended split metadata with:
  - `split_target_mode`
  - `proportional_split_threshold`
  - `requested_train_real_count`
  - `requested_val_count`
  - `requested_test_count`

## Split Rule

For each canonical class:

```text
if pool_size >= 24000:
    val = 2000
    test = 2000
    train_real = pool_size - val - test
else:
    train_real = round(pool_size * 20000 / 24000)
    val = round(pool_size * 2000 / 24000)
    test = pool_size - train_real - val
```

After this split, only the train split is oversampled to 20000 graphs per class. Validation and test
remain real, non-oversampled records.

## Regeneration Performed

The existing compact reservoir was re-split without re-extracting PCAPs, then graphs and shards were
rebuilt from the corrected split manifest.

Commands run:

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_RESPLIT_EXISTING_RESERVOIR=1 \
SECUREEDGE_VAL_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor \
SECUREEDGE_WEBBASED_SUBTYPE_FLOOR_FRACTION=0.10 \
SECUREEDGE_WEBBASED_SUBTYPE_CEILING_FRACTION=0.30 \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.preprocess
```

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor \
.venv/bin/python -m secureedge.data.build_graphs
```

```bash
MALLOC_ARENA_MAX=2 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python -m secureedge.data.create_shards --overwrite
```

## Regenerated Dataset Counts

| Split | Graph Count | Shards |
|---|---:|---:|
| train | 160000 | 160 |
| val | 11843 | 12 |
| test | 11841 | 12 |

| Class | Pool Before Split | Split Mode | Train Sampled | Train Unique | Val | Test |
|---|---:|---|---:|---:|---:|---:|
| Benign | 28000 | fixed_targets | 20000 | 20000 | 2000 | 2000 |
| DDoS | 28008 | fixed_targets | 20000 | 20000 | 2000 | 2000 |
| DoS | 28000 | fixed_targets | 20000 | 20000 | 2000 | 2000 |
| Mirai | 28002 | fixed_targets | 20000 | 20000 | 2000 | 2000 |
| Recon | 23143 | proportional_targets | 20000 | 19286 | 1929 | 1928 |
| Spoofing | 16151 | proportional_targets | 20000 | 13459 | 1346 | 1346 |
| WebBased | 4627 | proportional_targets | 20000 | 3856 | 386 | 385 |
| BruteForce | 2184 | proportional_targets | 20000 | 1820 | 182 | 182 |

Full class and subtype details were written to `context/58_proportional_split_class_distribution_report.md`.
A JSON copy was written to `artifacts/class_distribution_report_proportional_split.json`.

## Leakage Audit

The leakage audit passed after graph and shard regeneration.

Audit report: `artifacts/training_runs/run_21_proportional_split_leakage_audit.md`

Summary:

```json
{
  "duplicate_compact_rows": {
    "train_val": 0,
    "train_test": 0,
    "val_test": 0
  },
  "duplicate_graph_hashes": {
    "train_val": 0,
    "train_test": 0,
    "val_test": 0
  },
  "near_duplicate_graph_fingerprints": {
    "train_val": 0,
    "train_test": 0,
    "val_test": 0
  },
  "leaked_identity_features": [],
  "graph_value_mode": "raw",
  "scalers_fit_on_train_only": true
}
```

## Verification

- `python -m compileall secureedge tests` passed.
- `tests/smoke_checks.py` passed with attacker-MAC filtering enabled and raw/log1p graph mode.

## Training Command

Use a fresh run id and remove or avoid resuming from an older checkpoint because the split distribution
changed.

```bash
SECUREEDGE_RUN_ID=21 \
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=256 \
SECUREEDGE_GRAD_ACCUM_STEPS=2 \
SECUREEDGE_USE_AMP=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_MAX_EPOCHS=300 \
SECUREEDGE_EARLY_STOP=75 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p \
.venv/bin/python -m secureedge.models.train
```
