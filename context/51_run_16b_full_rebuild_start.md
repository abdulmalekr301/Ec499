# Run 16b Full Rebuild and Start

## Objective

Run 16b tests the XG-NID repo-comparison hypothesis:

- `BatchNorm1d(eps=1.0)`
- raw graph values
- no flow-node `StandardScaler`
- no packet-byte `/255`
- no contain-edge scaler
- no link-edge p99 normalization
- uniform attacker-MAC filtering for every non-benign attack class

## Commands Run

### Full compact preprocessing rebuild

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_USE_SPLIT_PCAP_CHUNKS=1 \
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4.0 \
SECUREEDGE_MAX_PROCESS_RSS_GB=2.0 \
.venv/bin/python -m secureedge.data.preprocess
```

Result:

- Compact reservoir rebuilt under `data/graphs/_reservoir`.
- Compact manifest written to `artifacts/compact_reservoir_manifest.json`.

Notable retained counts under uniform attacker-MAC filtering:

- `Backdoor_Malware`: 244
- `BrowserHijacking`: 972
- `CommandInjection`: 275
- `DictionaryBruteForce`: 2,184
- `MITM-ArpSpoofing`: 2,151
- `SqlInjection`: 2,830
- `Uploading_Attack`: 84
- `XSS`: 222

### Raw graph materialization

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_ALLOW_FULL_PREPROCESS=1 \
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
SECUREEDGE_MIN_AVAILABLE_MEMORY_GB=4.0 \
SECUREEDGE_MAX_PROCESS_RSS_GB=2.0 \
.venv/bin/python -m secureedge.data.build_graphs
```

Result:

```json
{
  "n_train": 160000,
  "n_val": 27404,
  "n_test": 27405,
  "graph_value_mode": "raw"
}
```

### Shard creation

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.create_shards --overwrite
```

Result:

- Train shards: 160
- Validation shards: 28
- Test shards: 28

## Pre-Training Checks

### Smoke checks

```bash
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python tests/smoke_checks.py
```

Result:

```text
smoke checks passed
```

### Leakage audit

```bash
MALLOC_ARENA_MAX=2 \
OMP_NUM_THREADS=1 \
MKL_NUM_THREADS=1 \
OPENBLAS_NUM_THREADS=1 \
SECUREEDGE_GRAPH_VALUE_MODE=raw \
.venv/bin/python -m secureedge.data.leakage_audit \
  --report artifacts/training_runs/run_16b_leakage_audit.md
```

Result:

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

## Class Counts

Training is balanced by train-only oversampling:

```json
{
  "Benign": 20000,
  "DDoS": 20000,
  "DoS": 20000,
  "Mirai": 20000,
  "Recon": 20000,
  "Spoofing": 20000,
  "WebBased": 20000,
  "BruteForce": 20000
}
```

Validation and test use available real records after uniform MAC filtering:

```json
{
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

## Status

Run 16b graph data is ready for training.
