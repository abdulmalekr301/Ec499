# Run 14 Checks and Fixes Verification

Generated: `2026-07-04`

## Source Instructions

Implemented and verified the checks from:

```text
context/run-14-checks&fixes.md
```

The main objective was to validate that the high Run 13 result after attacker-MAC filtering was not caused by train/test leakage, duplicate graph tensors, identity features, or scaler leakage.

## Fixes Applied

### 1. Split Order Fixed

Previous behavior:

```text
balance/oversample full class pool -> split train/val/test
```

This could place oversampled duplicate records into multiple splits for underrepresented classes.

New behavior:

```text
load compact records
group by exact compact tensor-content hash
assign each hash group to exactly one split
oversample train only
leave validation/test as held-out unique records
```

The active manifest now reports:

```text
split_strategy = split_first_then_oversample_train_only
```

### 2. Content-Hash Groups Kept Atomic

The splitter now hashes compact graph content before splitting:

- flow node vector
- packet payload matrix
- containment edge attributes
- packet-link edge attributes
- label

All records with the same content hash are assigned to only one split. This prevents exact tensor duplicates from crossing train/validation/test even when the source file paths are different.

### 3. Validation/Test Counts Made Leakage-Safe

Because some MAC-filtered classes have fewer than 8,000 unique records, validation/test cannot both stay at 4,000 per class without duplication.

Final split counts:

```json
{
  "train": 160000,
  "val": 27404,
  "test": 27405
}
```

Final per-class counts:

```json
{
  "train": {
    "Benign": 20000,
    "DDoS": 20000,
    "DoS": 20000,
    "Mirai": 20000,
    "Recon": 20000,
    "Spoofing": 20000,
    "WebBased": 20000,
    "BruteForce": 20000
  },
  "val": {
    "Benign": 4000,
    "DDoS": 4000,
    "DoS": 4000,
    "Mirai": 4000,
    "Recon": 4000,
    "Spoofing": 4000,
    "WebBased": 2313,
    "BruteForce": 1091
  },
  "test": {
    "Benign": 4000,
    "DDoS": 4000,
    "DoS": 4000,
    "Mirai": 4000,
    "Recon": 4000,
    "Spoofing": 4000,
    "WebBased": 2313,
    "BruteForce": 1092
  }
}
```

### 4. Scaler Provenance Added

`artifacts/graph_dataset_manifest.json` now records:

```json
{
  "flow_scaler_fit_split": "train",
  "contain_edge_scaler_fit_split": "train",
  "link_delta_normalizer_fit_split": "train"
}
```

### 5. Per-Graph Audit Metadata Added

Each materialized graph now stores audit metadata outside model tensors:

- `graph_id`
- `split`
- `used_attacker_mac_filter`
- `num_packets`
- `flow_id_hash`

Raw MAC/IP values are not stored in tensors.

### 6. Leakage Audit Script Added

Created:

```text
secureedge/data/leakage_audit.py
```

Command used:

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
PYTHONUNBUFFERED=1 \
.venv/bin/python -m secureedge.data.leakage_audit \
  --report artifacts/training_runs/run_14_leakage_audit.md
```

Report written to:

```text
artifacts/training_runs/run_14_leakage_audit.md
```

## Audit Results

```json
{
  "split_strategy": "split_first_then_oversample_train_only",
  "compact_counts": {
    "train": 160000,
    "val": 27404,
    "test": 27405
  },
  "graph_counts": {
    "train": 160000,
    "val": 27404,
    "test": 27405
  },
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
    "train_val": 196,
    "train_test": 182,
    "val_test": 59
  },
  "leaked_identity_features": [],
  "scalers_fit_on_train_only": true
}
```

## Interpretation

Hard leakage checks passed:

- exact compact-row overlap across splits: `0`
- exact graph-hash overlap across splits: `0`
- MAC/IP/file identity columns in model features: none
- scalers fit on train only: yes

Near-duplicate fingerprints are still present:

- train/val: `196`
- train/test: `182`
- val/test: `59`

These are not exact duplicate tensors and did not trigger the hard leakage assertions, but they remain a generalization risk. A future PCAP-held-out split is still recommended to measure capture-independent performance.

## Regenerated Artifacts

Regenerated after the fixes:

- `artifacts/compact_reservoir_manifest.json`
- `artifacts/graph_dataset_manifest.json`
- `artifacts/graph_shard_manifest.json`
- `data/graphs/train/`
- `data/graphs/val/`
- `data/graphs/test/`
- `data/graphs/train_shards/`
- `data/graphs/val_shards/`
- `data/graphs/test_shards/`

Final shard counts:

```json
{
  "train_shards": 160,
  "val_shards": 28,
  "test_shards": 28
}
```

## Verification Commands

Completed successfully:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
.venv/bin/python -m secureedge.data.leakage_audit --report artifacts/training_runs/run_14_leakage_audit.md
```

## Remaining Work

The hard leakage checks are now clean. The remaining recommended check from `run-14-checks&fixes.md` is a harder evaluation split, preferably PCAP-held-out or time-based. That has not been implemented in this pass.
