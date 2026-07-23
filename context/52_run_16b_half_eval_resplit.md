# Run 16b Half-Evaluation Resplit

## Reason

The first Run 16b split left only one unique real `WebBased` compact record in
the training seed because validation and test each tried to reserve 4,000 samples
from a class with only 4,627 real records after uniform attacker-MAC filtering.

## Change

Validation and test targets were reduced from 4,000 to 2,000 per class:

```bash
SECUREEDGE_VAL_SAMPLES_PER_CLASS=2000
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2000
```

This moves the freed real records into the training seed before train-only
oversampling.

## Commands Run

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_RESPLIT_EXISTING_RESERVOIR=1 \
SECUREEDGE_VAL_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.preprocess

MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_VAL_SAMPLES_PER_CLASS=2000 \
SECUREEDGE_TEST_SAMPLES_PER_CLASS=2000 \
.venv/bin/python -m secureedge.data.build_graphs

MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.create_shards --overwrite

MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.leakage_audit \
  --report artifacts/training_runs/run_16b_half_eval_leakage_audit.md
```

## Resulting Counts

| Class | Train sampled | Train unique real | Val real | Test real | Total unique real |
|---|---:|---:|---:|---:|---:|
| WebBased | 20,000 | 627 | 2,000 | 2,000 | 4,627 |
| Recon | 20,000 | 19,143 | 2,000 | 2,000 | 23,143 |

## WebBased Train Unique Subtypes

```text
Backdoor_Malware       33
BrowserHijacking      132
CommandInjection       27
SqlInjection          398
Uploading_Attack       15
XSS                    22
```

## Recon Train Unique Subtypes

```text
Recon-HostDiscovery  4660
Recon-OSScan         4619
Recon-PingSweep       605
Recon-PortScan       4595
VulnerabilityScan    4664
```

## Leakage Audit

The adjusted split passed:

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
