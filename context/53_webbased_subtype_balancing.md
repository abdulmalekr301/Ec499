# WebBased Subtype-Balanced Resplit

## Source

Implemented `context/webbased-subtype-balancing.md`.

## Code Changes

- Added `SECUREEDGE_WEBBASED_SUBTYPE_BALANCING`.
- Added `SECUREEDGE_WEBBASED_SUBTYPE_FLOOR_FRACTION`.
- Added `SECUREEDGE_WEBBASED_SUBTYPE_CEILING_FRACTION`.
- Implemented train-only WebBased subtype balancing in `secureedge/data/preprocess.py`.
- Validation and test are not subtype-balanced; they keep natural held-out subtype distribution.
- Other classes still use the existing class-level train-only oversampling logic.

## Active Parameters

```text
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor
SECUREEDGE_WEBBASED_SUBTYPE_FLOOR_FRACTION=0.10
SECUREEDGE_WEBBASED_SUBTYPE_CEILING_FRACTION=0.30
SECUREEDGE_VAL_SAMPLES_PER_CLASS=2000
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2000
```

## WebBased Training Allocation

| Subtype | Unique Real Train Records | Training Slots |
|---|---:|---:|
| Backdoor_Malware | 33 | 2,577 |
| BrowserHijacking | 132 | 4,305 |
| CommandInjection | 27 | 2,472 |
| SqlInjection | 398 | 6,000 |
| Uploading_Attack | 15 | 2,262 |
| XSS | 22 | 2,384 |

Total WebBased train slots: 20,000.

## Held-Out WebBased Distribution

Validation remains natural and unique:

| Subtype | Validation Records |
|---|---:|
| Backdoor_Malware | 116 |
| BrowserHijacking | 401 |
| CommandInjection | 111 |
| SqlInjection | 1,239 |
| Uploading_Attack | 31 |
| XSS | 102 |

Test remains natural and unique:

| Subtype | Test Records |
|---|---:|
| Backdoor_Malware | 95 |
| BrowserHijacking | 439 |
| CommandInjection | 137 |
| SqlInjection | 1,193 |
| Uploading_Attack | 38 |
| XSS | 98 |

## Rebuild Steps Completed

```bash
SECUREEDGE_RESPLIT_EXISTING_RESERVOIR=1 \
SECUREEDGE_VAL_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_WEBBASED_SUBTYPE_BALANCING=capped_floor \
SECUREEDGE_WEBBASED_SUBTYPE_FLOOR_FRACTION=0.10 \
SECUREEDGE_WEBBASED_SUBTYPE_CEILING_FRACTION=0.30 \
.venv/bin/python -m secureedge.data.preprocess

SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.build_graphs

SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.create_shards --overwrite

SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.leakage_audit \
  --report artifacts/training_runs/run_16b_webbased_balanced_leakage_audit.md
```

## Audit Result

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
