# BruteForce Scarce-Class Correction

## Reason

The previous split reserved too many held-out records for `BruteForce`, leaving
only one unique real `DictionaryBruteForce` record in training:

```text
train unique real: 1
validation real: 1091
test real: 1092
```

This made the 20,000 BruteForce training slots effectively a single duplicated
record, which is not usable for learning.

## Change

Added class-specific held-out targets for `BruteForce`:

```text
SECUREEDGE_BRUTEFORCE_VAL_SAMPLES=1000
SECUREEDGE_BRUTEFORCE_TEST_SAMPLES=1000
```

This keeps WebBased at 2,000/2,000 while reducing BruteForce held-out allocation
to 1,000/1,000 and moving the freed records into the BruteForce training seed.

## Resulting BruteForce Counts

| Split | Sampled Count | Unique Real Count | Subtype |
|---|---:|---:|---|
| Train | 20,000 | 184 | DictionaryBruteForce |
| Validation | 1,000 | 1,000 | DictionaryBruteForce |
| Test | 1,000 | 1,000 | DictionaryBruteForce |

Total real BruteForce pool:

```text
2184 records
```

Oversampling summary:

```json
{
  "real_available": 184,
  "target_total": 20000,
  "unique_in_balanced_pool": 184,
  "oversampled_count": 19816,
  "oversampled_fraction": 0.9908,
  "requested_val_count": 1000,
  "requested_test_count": 1000,
  "val_shortfall": 0,
  "test_shortfall": 0
}
```

## Rebuilt Artifacts

Completed:

- compact manifest resplit
- raw graph rebuild
- shard rebuild
- leakage audit

Final graph counts:

```json
{
  "train": 160000,
  "val": 15000,
  "test": 15000
}
```

Leakage audit report:

```text
artifacts/training_runs/run_16b_bruteforce_balanced_leakage_audit.md
```

Audit summary:

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
