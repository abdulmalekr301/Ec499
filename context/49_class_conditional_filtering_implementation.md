# Class-Conditional Filtering Implementation

Generated: `2026-07-04`

## Source Instructions

Implemented the specification from:

```text
context/class-conditional-filtering-implementation.md
```

The decision was to stop using one universal attacker-MAC filter for all attack classes. The audit showed that this filter works for DDoS but discards most WebBased and BruteForce traffic.

## Code Changes

### Config

Added:

```python
MAC_FILTERED_CLASSES = {"DDoS", "DoS", "Mirai", "Recon", "Spoofing"}
```

### Filter Routing

Updated `secureedge/data/extract_worker.py`:

- `Benign`: still strict; drops flows involving known attacker MACs.
- `DDoS`, `DoS`, `Mirai`, `Recon`, `Spoofing`: still require attacker MAC involvement.
- `WebBased`, `BruteForce`: bypass attacker-MAC filtering and use filename/subtype labels.

New decision reason:

```text
class_conditional_unfiltered
```

### Partial Regeneration

Added `SECUREEDGE_REGENERATE_SUBTYPES` support in `secureedge/data/preprocess.py`.

This lets the pipeline regenerate only selected subtype reservoirs without rerunning all PCAP extraction.

## Regenerated Subtypes

```text
Backdoor_Malware
BrowserHijacking
CommandInjection
SqlInjection
Uploading_Attack
XSS
DictionaryBruteForce
```

Command used:

```bash
SECUREEDGE_REGENERATE_SUBTYPES=Backdoor_Malware,BrowserHijacking,CommandInjection,SqlInjection,Uploading_Attack,XSS,DictionaryBruteForce \
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

## Restored Pool Sizes

```json
{
  "Benign": 24000,
  "DDoS": 24000,
  "DoS": 24000,
  "Mirai": 24000,
  "Recon": 19943,
  "Spoofing": 14151,
  "WebBased": 23126,
  "BruteForce": 11043
}
```

WebBased increased from the universal-MAC-filtered `4627` pool to `23126`.

BruteForce increased from the universal-MAC-filtered `2184` pool to `11043`.

## Final Split Counts

```json
{
  "train": 160000,
  "val": 32000,
  "test": 32000
}
```

Each split is class-balanced:

```text
train: 20000 per class
val:    4000 per class
test:   4000 per class
```

## WebBased Subtype Diversity

WebBased training subtype counts:

```json
{
  "Backdoor_Malware": 2732,
  "BrowserHijacking": 4090,
  "CommandInjection": 4004,
  "SqlInjection": 4040,
  "Uploading_Attack": 1443,
  "XSS": 3691
}
```

All six WebBased subtypes are represented.

## Rebuilt Artifacts

Rebuilt:

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
  "val_shards": 32,
  "test_shards": 32
}
```

## Verification

### Routing Check

```text
WebBased  -> kept as class_conditional_unfiltered
BruteForce -> kept as class_conditional_unfiltered
DDoS background -> dropped as attack_background_dropped
DDoS attacker -> kept as attack_attacker_kept
Benign attacker -> dropped as benign_attacker_dropped
```

### Class-Conditional MAC Audit

Report:

```text
artifacts/mac_filter_audit_class_conditional.json
```

Summary:

```json
{
  "BruteForce": {
    "flows_examined": 11043,
    "kept": 11043,
    "dropped": 0,
    "kept_fraction": 1.0
  },
  "DDoS": {
    "flows_examined": 36000,
    "kept": 35099,
    "dropped": 901,
    "kept_fraction": 0.9749722222222222
  },
  "WebBased": {
    "flows_examined": 25601,
    "kept": 25601,
    "dropped": 0,
    "kept_fraction": 1.0
  }
}
```

### Leakage Audit

Report:

```text
artifacts/training_runs/run_15_leakage_audit.md
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
  "leaked_identity_features": [],
  "scalers_fit_on_train_only": true
}
```

Near-duplicate fingerprints remain:

```json
{
  "train_val": 205,
  "train_test": 190,
  "val_test": 60
}
```

These are not exact duplicate tensors, but should still be mentioned as a residual generalization risk.

## Training Readiness

The dataset is ready for Run 15 under the same training configuration as Run 14.

Use a fresh checkpoint for Run 15 because the upstream data changed for WebBased and BruteForce.
