# Run 16b NaN Diagnosis Fix

## Source

Implemented `context/run-16b-nan-diagnosis.md`.

## Diagnosis

The raw flow-feature diagnostic was run on the sampled training split and saved to:

```text
artifacts/raw_flow_feature_diagnostic_run16b.json
```

The diagnostic found no literal `inf` or `nan` values, but confirmed extreme
derived byte-rate values:

| Feature | Max | Values with abs(value) > 1e6 |
|---|---:|---:|
| `bidirectional_bytes_per_second` | 30,280,000 | 19,606 |
| `src2dst_bytes_per_second` | 30,280,000 | 19,453 |
| `dst2src_bytes_per_second` | 28,766,000 | 2,692 |

The largest non-derived extreme was:

| Feature | Max | Values with abs(value) > 1e6 |
|---|---:|---:|
| `Rolling_Average_Duration` | 341,547,008 | 86,775 |

The immediate fix follows the plan: transform only the 8 derived flow features.
`Rolling_Average_Duration` is documented as a remaining watch item if instability
persists.

## Code Changes

- Added `SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM`.
- Default is `log1p`.
- Supported values:
  - `log1p`
  - `off`
- In raw graph mode only, the 8 `DERIVED_FLOW_FEATURES` are transformed as:

```python
np.log1p(np.clip(values, a_min=0.0, a_max=None))
```

- Scaled graph mode is unchanged.
- Added fail-fast training guards:
  - non-finite logits raise `FloatingPointError`
  - non-finite loss raises `FloatingPointError`

## Transform Verification

Sampled check on 20,000 compact train records:

| Feature | Raw max | Transformed max | Raw extreme count | Transformed extreme count |
|---|---:|---:|---:|---:|
| `bidirectional_bytes_per_second` | 30,280,000 | 17.226 | 2,482 | 0 |
| `src2dst_bytes_per_second` | 30,280,000 | 17.226 | 2,444 | 0 |
| `dst2src_bytes_per_second` | 23,630,000 | 16.979 | 330 | 0 |

Actual graph-shard check on 10,000 train graphs:

```text
nonfinite_flow_graphs=0
max transformed derived feature <= 17.226
```

## Rebuilt Artifacts

Rebuilt with:

```bash
SECUREEDGE_GRAPH_VALUE_MODE=raw
SECUREEDGE_RAW_DERIVED_FLOW_TRANSFORM=log1p
```

Completed:

- graph materialization
- shard creation
- leakage audit

The graph manifest now records:

```json
{
  "graph_value_mode": "raw",
  "raw_derived_flow_transform": "log1p"
}
```

## Leakage Audit

Report:

```text
artifacts/training_runs/run_16b_log_derived_leakage_audit.md
```

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

## Forward-Pass Smoke Check

A real training shard batch of 64 graphs was passed through the HGNN on CPU:

```text
logits_finite=True
loss_finite=True
loss=2.094508171081543
logits_minmax=-0.39216816425323486, 0.33931395411491394
```

This does not guarantee full training stability, but it confirms the rebuilt
graph tensors and initial model forward pass are finite before GPU training.
