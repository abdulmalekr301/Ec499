# Class Imbalance Fixes Applied

> Generated: 2026-06-16
> Source instruction: `context/class-imbalance-fixes.md`

## Summary

Applied the no-new-PCAP class imbalance strategy. The original training shards
are preserved, and a new duplicate-free training shard set is now available for
round-4 training.

Training was not started from this turn. The per-class payload gate found that
WebBased and BruteForce payload means are below the `0.10` threshold from the
imbalance plan, so round-4 training should be treated as risky until PacketCapture
payload quality is accepted or fixed.

## Changes Applied

### 1. Deduped training shard support

Added `secureedge/data/deduplicate_shards.py`.

The script streams original training shards one at a time, removes duplicate graph
identities, and writes new shards under:

```text
data/graphs/train_shards_deduped/
```

The stable dedupe identity is:

```text
class_name + subtype_label + source_file + source_order
```

This avoids relying on `.pt` filenames, because oversampled duplicates were saved
as separate graph files.

### 2. Deduped manifest and class weights

Generated:

```text
artifacts/deduped_manifest.json
context/28_class_imbalance_deduped_shards.md
```

Deduplication result:

```json
{
  "total_original_train_graphs": 160000,
  "total_deduped_train_graphs": 130242,
  "removed_duplicate_graphs": 29758,
  "duplicate_fraction_removed": 0.1859875,
  "class_counts": {
    "Benign": 20000,
    "DDoS": 20000,
    "DoS": 20000,
    "Mirai": 20000,
    "Recon": 11882,
    "Spoofing": 20000,
    "WebBased": 11691,
    "BruteForce": 6669
  },
  "class_weights": {
    "Benign": 1.0,
    "DDoS": 1.0,
    "DoS": 1.0,
    "Mirai": 1.0,
    "Recon": 1.6832183134152499,
    "Spoofing": 1.0,
    "WebBased": 1.710717646052519,
    "BruteForce": 2.99895036737142
  },
  "shard_count": 131
}
```

### 3. Config switches for round-4 imbalance training

Updated `secureedge/config.py` with:

```python
USE_DEDUPED_SHARDS = True
CLASS_WEIGHTS = (1.0, 1.0, 1.0, 1.0, 1.68, 1.0, 1.71, 3.0)
FOCAL_GAMMA = 2.0
AUGMENT_FLOW_NOISE = 0.02
AUGMENT_PACKET_MASK = 0.15
```

All values can still be overridden with environment variables.

### 4. Weighted focal loss

Added `secureedge/models/focal_loss.py`.

Updated `secureedge/models/train.py` so round-4 training uses:

```python
FocalLoss(gamma=FOCAL_GAMMA, weight=class_weights)
```

The class weights are loaded from `artifacts/deduped_manifest.json` when deduped
shards are enabled.

### 5. Online training augmentation

Updated `secureedge/models/train.py` with `augment_batch()`.

Training batches now receive augmentation after device transfer and before the
forward pass:

- flow node Gaussian noise scaled by `AUGMENT_FLOW_NOISE`
- packet byte masking controlled by `AUGMENT_PACKET_MASK`

Evaluation is unchanged and receives no augmentation.

### 6. Per-class payload diagnostic

Updated `secureedge/data/payload_diagnostic.py` with `--per-class`.

Command run:

```bash
.venv/bin/python -m secureedge.data.payload_diagnostic --source shards --split train --limit 3 --per-class
```

Important result:

| Class | Mean Packet Value | Payload Gate |
|---|---:|---|
| WebBased | 0.0448 | below 0.10 gate |
| BruteForce | 0.0394 | below 0.10 gate |

This means payload features are not fully all-zero, but the two payload-heavy
classes are below the gate defined in `class-imbalance-fixes.md`.

## Validation

Passed:

```bash
.venv/bin/python -m compileall secureedge tests
.venv/bin/python tests/smoke_checks.py
```

Bounded forward-pass check also passed on one small deduped batch:

```text
logits_shape = [4, 8]
weighted_focal_loss = 2.572192668914795
```

The forward-pass check loaded deduped shards, applied augmentation, ran HGNN
inference, and computed weighted focal loss. It did not run an epoch.

## Round-4 Command

Use this when you are ready to train:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=512 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_MAX_EPOCHS=300 \
SECUREEDGE_EARLY_STOP=50 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
SECUREEDGE_USE_DEDUPED_SHARDS=1 \
SECUREEDGE_FOCAL_GAMMA=2.0 \
.venv/bin/python -m secureedge.models.train
```

## Remaining Risk

The imbalance fixes are implemented, but the payload gate did not pass for
WebBased and BruteForce. If round-4 training does not improve past the old 0.87
plateau, the next likely cause is not class imbalance; it is insufficient HTTP
payload extraction for the two classes that need application-layer content most.
