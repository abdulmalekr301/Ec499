# SecureEdge — Class Imbalance Fixes

> **Generated:** 2026-06-16
> **Context:** No additional PCAPs are available for underrepresented classes.
> All available CIC-IoT2023 samples have been downloaded. This document describes
> how to reach the 0.97 macro F1 target without removing any class and without
> acquiring new raw data.

---

## 0. Current Problem Summary

The oversampling audit confirmed three classes have severe duplicate fractions:

| Class | Real unique train flows | Duplicates | Duplicate fraction |
|---|---|---|---|
| BruteForce | 6,669 | 13,331 | **66.7%** |
| WebBased | 11,691 | 8,309 | **41.6%** |
| Recon | 11,882 | 8,118 | **40.6%** |
| All others | 20,000 | 0 | 0.0% |

This caused the training loss to reach 0.116 (near-zero, model memorised
duplicates) while test F1 stalled at 0.87. No hyperparameter change can fix
memorisation — only data-level changes matter now.

Three fixes are applied in combination. They do not require downloading new data
or regenerating the 192,000-graph dataset from scratch.

---

## 1. Fix 1 — De-duplicate Training Shards

### What changes

Remove all oversampled duplicate entries from the training shards. Only real,
unique graph instances remain in training. The test set is unchanged — it was
already built from real unique flows before oversampling was applied.

### New training set sizes

| Class | Training samples (was 20,000) | Class weight |
|---|---|---|
| Benign | 20,000 | 1.00 |
| DDoS | 20,000 | 1.00 |
| DoS | 20,000 | 1.00 |
| Mirai | 20,000 | 1.00 |
| Recon | **11,882** | 1.68 |
| Spoofing | 20,000 | 1.00 |
| WebBased | **11,691** | 1.71 |
| BruteForce | **6,669** | 3.00 |
| **Total** | **~130,000** (was 160,000) | |

Class weights are computed as: `weight_c = 20000 / real_unique_count_c`

Benign through DDoS all have 20,000 real flows and keep weight 1.00. Every
BruteForce sample now counts three times as much in the loss as a DDoS sample,
compensating the smaller class size without introducing memorisation of duplicates.

### Implementation

Add `secureedge/data/deduplicate_shards.py`. This script:

1. Loads the oversampling audit from `artifacts/oversampling_audit.json` to
   identify which compact record paths are duplicates.
2. Loads each existing training shard from `data/graphs/train_shards/`.
3. For each graph in the shard, checks whether its source compact record path
   is marked as a duplicate in the audit.
4. Writes a new de-duplicated shard to `data/graphs/train_shards_deduped/`
   containing only unique graphs.
5. Writes a manifest recording new per-class counts and class weights.

```
PROCEDURE deduplicate_shards():

    audit = load_json("artifacts/oversampling_audit.json")
    duplicate_paths = SET of all record paths flagged as duplicates

    all_shards = sorted(glob("data/graphs/train_shards/*.pt"))
    deduped_graphs = []

    FOR each shard_path in all_shards:
        graphs = torch.load(shard_path)

        FOR each graph in graphs:
            source_path = graph.source_compact_record_path
            IF source_path NOT in duplicate_paths:
                deduped_graphs.append(graph)

    shuffle(deduped_graphs)

    WRITE deduped_graphs in chunks of 1,000 to data/graphs/train_shards_deduped/
    WRITE per-class counts and class weights to artifacts/deduped_manifest.json
```

If `graph.source_compact_record_path` is not stored on the graph object, add it
during `build_graphs.py` when constructing each `HeteroData` object:

```python
graph.source_compact_record_path = record["source_path"]
```

And store it in the compact record during preprocessing:

```python
compact_record["source_path"] = str(pcap_path) + f"::flow_{flow_index}"
```

### Expected effect on training dynamics

With duplicates removed, the model can no longer reach training loss 0.116 by
memorising repeated instances. The expected training loss floor rises to
approximately 0.30–0.50 for a well-generalising model — this is the correct
behaviour. A training loss that bottoms out at 0.116 indicates memorisation,
not learning.

---

## 2. Fix 2 — Class-Weighted Loss Function

### What changes

Replace plain `CrossEntropyLoss()` with a class-weighted version using the
weights computed in Fix 1:

```python
class_weights = torch.tensor([
    1.00,   # 0 Benign
    1.00,   # 1 DDoS
    1.00,   # 2 DoS
    1.00,   # 3 Mirai
    1.68,   # 4 Recon       (20000 / 11882)
    1.00,   # 5 Spoofing
    1.71,   # 6 WebBased    (20000 / 11691)
    3.00,   # 7 BruteForce  (20000 / 6669)
], dtype=torch.float32).to(device)

loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)
```

Store the computed weights in `config.py` as `CLASS_WEIGHTS` so they are
loaded consistently between training, evaluation, and any future runs.

### Why class weights and not just accepting unbalanced batches

With BruteForce at 5.1% of the training set (6,669 / 130,000), an unweighted
loss would allocate only 5% of its gradient budget to BruteForce. With weight
3.00, each BruteForce sample contributes as much gradient as three Benign samples,
restoring the effective balance without duplicating data.

---

## 3. Fix 3 — Focal Loss for Duplicate Resistance

### What changes

Switch from `CrossEntropyLoss` to `FocalLoss` with `γ=2`, combined with the
class weights from Fix 2.

Focal loss adds a modulating factor `(1 - p_correct)^γ` to standard
cross-entropy. When the model is highly confident about a sample (`p_correct → 1`),
this factor approaches zero and that sample contributes almost nothing to the
gradient. For any remaining duplicates that survive the de-duplication step, focal
loss ensures their over-confident predictions are down-weighted automatically.

Implement in `secureedge/models/focal_loss.py`:

```
CLASS FocalLoss (extends nn.Module):

    INIT(gamma=2.0, weight=None, reduction='mean'):
        self.gamma = gamma
        self.weight = weight    # class weights tensor
        self.reduction = reduction

    FORWARD(logits, targets):
        # Standard cross-entropy per sample, without reduction
        ce_per_sample = cross_entropy(logits, targets,
                                      weight=self.weight,
                                      reduction='none')

        # p_correct = probability assigned to the correct class
        p_correct = torch.exp(-ce_per_sample)

        # Modulating factor: down-weights easy/confident samples
        focal_weight = (1.0 - p_correct) ** self.gamma

        focal_loss = focal_weight * ce_per_sample

        IF self.reduction == 'mean':
            RETURN focal_loss.mean()
        ELSE:
            RETURN focal_loss.sum()
```

Usage in `train.py`:

```python
loss_fn = FocalLoss(gamma=2.0, weight=class_weights.to(device))
```

### When focal loss matters most

For classes with heavy oversampling, the model sees the same graph instances
repeatedly across epochs. After a few epochs, those duplicates are classified
with very high confidence. Focal loss ensures those confident duplicate predictions
contribute near-zero gradient, redirecting the model's learning capacity toward
harder and more novel examples.

---

## 4. Fix 4 — Online Feature Augmentation During Training

### What changes

Apply lightweight stochastic augmentation to every training graph on each forward
pass. Each time a graph is seen, it is slightly different — preventing exact
memorisation of any instance, including duplicates.

Implement in `secureedge/models/train.py` as an `augment_batch` function called
immediately after `batch.to(device)` and before the forward pass:

```
FUNCTION augment_batch(batch, flow_noise_scale=0.02, packet_mask_rate=0.15):

    # --- Flow node augmentation ---
    # Add Gaussian noise proportional to each feature's standard deviation.
    # The noise is small enough not to change the class-level meaning of features
    # but large enough that duplicates no longer have identical feature vectors.
    flow_std = batch['flow'].x.std(dim=0, keepdim=True).clamp(min=1e-6)
    noise = torch.randn_like(batch['flow'].x) * flow_noise_scale * flow_std
    batch['flow'].x = batch['flow'].x + noise

    # --- Packet node augmentation ---
    # Randomly zero packet_mask_rate fraction of payload bytes.
    # This forces the model to classify using partial payload context,
    # which prevents overfitting to specific byte patterns in duplicates.
    mask = (torch.rand_like(batch['packet'].x) > packet_mask_rate).float()
    batch['packet'].x = batch['packet'].x * mask

    RETURN batch
```

Apply augmentation ONLY during training, never during evaluation or export:

```
FOR each batch in train_loader:
    batch = batch.to(device, non_blocking=True)
    batch = augment_batch(batch)      # augment on GPU, after device transfer
    logits = model(batch.x_dict, batch.edge_index_dict,
                   batch.edge_attr_dict, batch.batch_dict)
    loss = loss_fn(logits, batch.y)
    ...
```

### Augmentation parameter guidance

`flow_noise_scale=0.02` adds noise with standard deviation equal to 2% of each
feature's own standard deviation. This is small enough that the semantics of the
features are preserved (a high Rolling_SYN_Sum stays high) but large enough that
no two passes over the same graph produce identical inputs.

`packet_mask_rate=0.15` zeros 15% of payload bytes randomly. For WebBased attacks,
the distinctive SQL injection or XSS patterns span many bytes, so masking 15% still
leaves the pattern detectable. For SYN flood attacks with zero-payload graphs, the
masking has no effect (zeros remain zeros).

---

## 5. Per-Class Payload Diagnostic Before Training

The overall payload diagnostic showed a non-zero fraction of 0.15–0.22, which is
below the expected 0.80+ for real data. Before starting round 4 training, verify
that WebBased and BruteForce specifically — the classes where payload content is
the primary discriminating signal — have adequate payload density.

Run this per-class breakdown:

```python
import torch, glob, numpy as np
from collections import defaultdict

paths = sorted(glob.glob("data/graphs/train/*.pt"))
class_means = defaultdict(list)

FOR path in paths[:2000]:
    g = torch.load(path)
    class_idx = g.y.item()
    class_name = CANONICAL_CLASS_NAMES[class_idx]
    class_means[class_name].append(g['packet'].x.mean().item())

FOR class_name, means in sorted(class_means.items()):
    print(f"{class_name:15s}: mean={np.mean(means):.4f}  n={len(means)}")
```

Expected values by class:

| Class | Expected mean payload value | Reason |
|---|---|---|
| DDoS (SYN, RST) | 0.01–0.05 | TCP flood — no application payload |
| DDoS (HTTP) | 0.05–0.15 | HTTP headers only |
| DoS | 0.01–0.10 | Varies by sub-type |
| Mirai | 0.01–0.05 | Scanning probes — minimal payload |
| Recon | 0.01–0.08 | Port scan probes — minimal payload |
| Spoofing | 0.02–0.10 | DNS/ARP — small payloads |
| **WebBased** | **0.15–0.35** | HTTP bodies with SQL/XSS/upload content |
| **BruteForce** | **0.10–0.25** | HTTP POST login attempts |
| Benign | 0.05–0.20 | Mixed application traffic |

If WebBased and BruteForce show means near 0.01–0.03 (similar to Mirai), the
PacketCapture plugin is not extracting HTTP payload content for those classes.
This would indicate the raw payload attribute used by the plugin does not capture
application-layer bytes for TCP connections that go through HTTP.

If this check fails, update `PacketCapture.on_update` to use the correct NFStream
attribute that exposes HTTP body content. See `preprocessing-find-missing.md`
section 2 for the attribute-finding approach.

---

## 6. Implementation Order

Apply in this sequence. Steps 1–3 must complete before training starts.
Steps 4–5 are training-loop changes requiring no data regeneration.

### Step 1 — Run the per-class payload diagnostic

Confirm that WebBased and BruteForce have payload means ≥ 0.10. If they do not,
fix PacketCapture and regenerate graphs before proceeding. This check gates
everything else because augmentation and focal loss cannot substitute for missing
payload signal.

### Step 2 — Run `deduplicate_shards.py`

Output: `data/graphs/train_shards_deduped/` containing ~130,000 unique training
graphs and `artifacts/deduped_manifest.json` with per-class counts and weights.

### Step 3 — Update `config.py`

```python
CLASS_WEIGHTS = [1.00, 1.00, 1.00, 1.00, 1.68, 1.00, 1.71, 3.00]
USE_DEDUPED_SHARDS = True
FOCAL_GAMMA = 2.0
AUGMENT_FLOW_NOISE = 0.02
AUGMENT_PACKET_MASK = 0.15
```

### Step 4 — Implement `FocalLoss` in `secureedge/models/focal_loss.py`

### Step 5 — Update `train.py`

- Point the shard loader to `train_shards_deduped/` when `USE_DEDUPED_SHARDS=True`
- Replace `CrossEntropyLoss` with `FocalLoss(gamma=FOCAL_GAMMA, weight=CLASS_WEIGHTS)`
- Add `augment_batch()` call in the training loop after device transfer

---

## 7. Round 4 Training Command

Use the round 3 baseline settings — they are the best confirmed configuration.
The only changes are in the data and loss function:

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
python -m secureedge.models.train
```

---

## 8. Verification Checkpoints

### Check 1 — Training loss floor

With duplicates removed and focal loss, the training loss should no longer reach
0.116. By epoch 100, training loss should be in the range 0.25–0.45. A loss
below 0.15 at epoch 100 indicates remaining duplicates are still being memorised
— verify the de-duplication ran correctly.

### Check 2 — Per-class F1 at epoch 50

Print per-class F1 at each 10-epoch interval. By epoch 50 (end of first cosine
cycle), BruteForce F1 should exceed 0.83 (was 0.82 in round 1 with duplicates).
If BruteForce is still below 0.80, the class weight of 3.00 may need to be
increased or the per-class payload diagnostic revealed missing HTTP payload
content that needs to be fixed first.

### Check 3 — Macro F1 progression

| Milestone | Expected macro F1 |
|---|---|
| Epoch 50 | > 0.870 |
| Epoch 100 | > 0.890 |
| Epoch 200 | > 0.910 |
| Best checkpoint | > 0.930 |

If macro F1 at epoch 100 is below 0.88 — worse than round 3 — something went
wrong with the de-duplication or the shard loading is still using the old
oversampled shards.

---

## 9. Expected Outcomes

| Contribution | Source | Expected macro F1 lift |
|---|---|---|
| De-duplication removes memorisation | Fix 1 | +0.02–0.04 |
| Class weights restore BruteForce gradient | Fix 2 | +0.02–0.04 |
| Focal loss down-weights any residual duplicates | Fix 3 | +0.01–0.02 |
| Augmentation prevents overfit on hard classes | Fix 4 | +0.01–0.02 |
| **Combined** | | **+0.06–0.12** |

Starting from round 3 best (0.873), combined expected result: **0.930–0.990**

Reaching exactly 0.97 additionally depends on whether WebBased and BruteForce
payload content is correctly extracted — those classes need application-layer
bytes to achieve 0.90+ F1 individually. If the per-class payload diagnostic
confirms real HTTP payload content, the combined fixes should reach 0.97.
If payloads are still near-zero for those classes, expect 0.92–0.95, which
would require a separate PacketCapture fix pass.
