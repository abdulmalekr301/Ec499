# SecureEdge — Training Round 2 Plan

> **Generated:** 2026-06-15
> **Applies to:** HGNN training after the 92-feature graph dataset.
> **Baseline:** Round 1 achieved macro F1 = 0.873 (target ≥ 0.97).
> **Root causes addressed:** Oversized learning rate for batch size, ReduceLROnPlateau
> over-firing, missing label smoothing, GPU data pipeline starvation.

---

## 0. Prerequisites — Complete Before Retraining

Two prerequisites must be done before starting round 2. Skipping either will
result in a slow or suboptimal run.

### 0.1 Graph sharding (mandatory)

The round 1 training ran at 1–5% GPU utilization because the DataLoader was
opening 160,000 individual `.pt` files per epoch. At that throughput, each epoch
takes many minutes. Round 2 must use graph shards (1,000 graphs per `.pt` file)
so the DataLoader performs 160 file reads per epoch instead of 160,000.

Implement and run `secureedge/data/create_shards.py` before training:

```
PROCEDURE create_shards(source_dir, output_dir, shard_size=1000):

    all_files = sorted(glob(source_dir / "*.pt"))
    shuffle(all_files)

    FOR i in range(0, len(all_files), shard_size):
        chunk = all_files[i : i + shard_size]
        graphs = [torch.load(f) for f in chunk]
        shard_index = i // shard_size
        torch.save(graphs, output_dir / f"shard_{shard_index:04d}.pt")

    WRITE manifest JSON: shard count, shard size, total graphs
```

Output directories:
```
data/graphs/train_shards/shard_0000.pt  ... shard_0159.pt   (160 shards × 1,000)
data/graphs/test_shards/shard_0000.pt   ... shard_0031.pt   (32 shards × 1,000)
```

The training loop must be updated to load one shard at a time and create a
per-shard DataLoader over the in-memory list. Use `num_workers=0` for shard
loaders — the graphs are already in RAM and spawning workers adds overhead:

```
FOR each epoch:

    shard_paths = shuffled list of train_shards/*.pt

    FOR each shard_path in shard_paths:
        graphs = torch.load(shard_path)   # 1,000 graphs into RAM (~120 MB)
        shuffle(graphs)

        loader = PyG DataLoader(
            graphs,
            batch_size  = BATCH_SIZE,
            shuffle     = False,
            num_workers = 0,
            pin_memory  = True,
        )

        FOR each batch in loader:
            batch = batch.to(device, non_blocking=True)
            ... forward, loss, backward, step, scheduler.step() ...

    eval_f1 = evaluate on test_shards
    checkpoint if best
    early stop if stale
```

Expected GPU utilization after sharding: 15–35% at batch_size=512, which is
acceptable for this architecture. Do not chase 80%+ — the model is small and
GPU utilization is inherently limited by the graph processing time.

### 0.2 Payload quality diagnostic (mandatory)

Round 1 showed the HGNN improved WebBased by only 0.07 F1 over the flow-only
MLP. If packet payload nodes were carrying real application-layer bytes
(SQL injection patterns, XSS tags, HTTP POST bodies), the improvement should
be much larger. Before spending another multi-hour training run, confirm that
the packet node features are non-zero.

Run this diagnostic after importing torch:

```python
import torch, glob, numpy as np

paths = sorted(glob.glob("data/graphs/train/*.pt"))[:200]
means = []
for p in paths:
    g = torch.load(p)
    means.append(g['packet'].x.mean().item())

overall_mean = np.mean(means)
print(f"Mean packet node feature value: {overall_mean:.4f}")
print(f"Min: {np.min(means):.4f}  Max: {np.max(means):.4f}")
```

**Interpretation:**
- `mean ≈ 0.0` → payloads are all zeros. PacketCapture is not capturing raw
  bytes. Training with payload zeros is equivalent to having no packet nodes.
  Fix the plugin before retraining.
- `mean ≈ 0.3–0.5` → payloads contain real data. Proceed with training.
- `mean ≈ 0.5` is the expected value for random byte content.

If payloads are zero, the fix is to confirm which NFStream 6.6.0 packet
attribute carries raw IP payload bytes. Candidates to try in `on_update`:

```
packet.ip_payload_bytes      # preferred
packet.payload               # fallback
packet.raw_packet[offset:]   # last resort — requires computing IP header offset
```

Print `dir(packet)` inside `on_update` during one short extraction run to see
all available attributes. Do not proceed to round 2 training until this check
passes.

---

## 1. Config Changes

Update `secureedge/config.py` with the following values. Every changed value
includes a rationale.

```python
# ── Learning rate ────────────────────────────────────────────────
LR_START          = 3e-4      # warmup start  (was 1e-3)
                               # proportionally scaled with new LR_TARGET
LR_TARGET         = 3e-3      # warmup end    (was 1e-2)
                               # REASON: linear-scaling rule for BATCH_SIZE=512
                               # XG-NID used lr=0.01 at batch~32
                               # equivalent for batch=512: 0.01 × sqrt(32/512)
                               # ≈ 0.0025; round to 0.003 for slight conservatism
LR_MIN            = 1e-5      # floor for all schedulers (was 1e-6)
                               # REASON: 1e-6 allows ReduceLROnPlateau to fire
                               # 11+ times and trap the model. 1e-5 stops decay
                               # earlier and keeps the model in a usable range.

# ── Scheduler ────────────────────────────────────────────────────
LR_SCHEDULER      = "cosine"  # was "plateau"
                               # REASON: ReduceLROnPlateau reduced LR 11 times
                               # in 121 epochs, trapping the model. Cosine annealing
                               # with warm restarts periodically raises LR back up,
                               # escaping local minima — especially important for
                               # the WebBased/Recon/Spoofing confusion cluster.
COSINE_T0         = 50        # first cosine cycle length in epochs
COSINE_T_MULT     = 2         # second cycle = 100 epochs, third = 200 epochs

# ── Training duration ────────────────────────────────────────────
WARMUP_EPOCHS     = 5         # unchanged
MAX_EPOCHS        = 300       # was 200 — gives second cosine cycle room to run
EARLY_STOP_PAT    = 50        # was 20
                               # REASON: cosine annealing raises LR at cycle
                               # boundaries, so F1 may temporarily dip before
                               # improving. Patience=20 would fire mid-cycle.
                               # Patience=50 ensures at least one full second
                               # cycle completes before stopping.

# ── Batch size ───────────────────────────────────────────────────
BATCH_SIZE        = 512       # was 256
                               # REASON: sharding eliminates the data bottleneck;
                               # larger batch utilises GPU better and amortises
                               # the per-batch PyG collation cost.
                               # RTX 4060 VRAM estimate: 512 graphs × 120 KB ×
                               # 4-6x for activations ≈ 250-370 MB — well within 8 GB.

# ── Loss function ────────────────────────────────────────────────
LABEL_SMOOTHING   = 0.1       # was 0.0 (plain CrossEntropyLoss)
                               # REASON: the confusion matrix shows the model
                               # over-commits to WebBased when uncertain. Hard
                               # labels (smoothing=0) force 100% confidence on
                               # ambiguous samples. Smoothing=0.1 replaces the
                               # target one-hot with 0.9 for the true class and
                               # 0.1/7 ≈ 0.014 for others, preventing overconfidence
                               # on the four overlapping application-layer classes.

# ── Gradient clipping ────────────────────────────────────────────
GRAD_CLIP_NORM    = 1.0       # unchanged — keep
```

---

## 2. Training Loop Changes

### 2.1 Loss function

Replace the existing `CrossEntropyLoss()` with:

```python
loss_fn = torch.nn.CrossEntropyLoss(label_smoothing=LABEL_SMOOTHING)
```

No other changes to the forward pass or backward pass are needed. Label
smoothing is applied internally by PyTorch.

### 2.2 Scheduler replacement

Remove the `ReduceLROnPlateau` scheduler entirely. Replace with:

```python
scheduler = torch.optim.lr_scheduler.CosineAnnealingWarmRestarts(
    optimizer,
    T_0    = COSINE_T0,      # 50 epochs
    T_mult = COSINE_T_MULT,  # 2
    eta_min = LR_MIN,        # 1e-5
)
```

`CosineAnnealingWarmRestarts` is called **once per step** (once per batch),
not once per epoch. In the training loop:

```
FOR each shard:
    FOR each batch in shard_loader:
        ... forward, loss, backward, clip ...
        optimizer.step()
        scheduler.step(epoch + batch_index / n_batches_per_epoch)
        # The fractional epoch argument advances the cosine schedule smoothly
        # across all batches within an epoch.
```

The step argument computes the current epoch as a float that advances with
each batch. This gives a smooth cosine curve rather than a stepped one.

### 2.3 Warmup behaviour change

With `CosineAnnealingWarmRestarts`, the warmup phase must be handled manually
for the first 5 epochs. After warmup, hand off to the cosine scheduler:

```
FOR epoch = 1 TO MAX_EPOCHS:

    IF epoch <= WARMUP_EPOCHS:
        # Linear warmup: LR_START → LR_TARGET over 5 epochs
        current_lr = LR_START + (LR_TARGET - LR_START) * (epoch / WARMUP_EPOCHS)
        set_lr(optimizer, current_lr)
        # Do NOT call scheduler.step() during warmup
    ELSE:
        # Cosine annealing handles LR from here
        # scheduler.step() called per batch (as above)
```

### 2.4 Early stopping change

Early stopping now triggers after `EARLY_STOP_PAT = 50` stale epochs. The
counter resets whenever the best macro F1 improves. A stale epoch is one where
the end-of-epoch macro F1 does not exceed the historical best.

Do not reset the stale counter when LR changes — with cosine annealing, LR
changes every batch automatically, so there is no discrete "LR reduction event"
to reset around.

### 2.5 Checkpoint behaviour (unchanged)

Save `artifacts/best_hgnn.pt` whenever macro F1 exceeds the historical best.
Include in the checkpoint:

```python
{
    "model_state_dict":   model.state_dict(),
    "optimizer_state":    optimizer.state_dict(),
    "scheduler_state":    scheduler.state_dict(),
    "epoch":              epoch,
    "macro_f1":           val_f1,
    "config": {
        "flow_node":    N_FLOW_NODE_FEATURES,
        "packet_node":  N_PACKET_FEATURES,
        "contain_edge": N_CONTAIN_EDGE_FEATS,
        "link_edge":    N_LINK_EDGE_FEATS,
        "label_smoothing": LABEL_SMOOTHING,
        "lr_target":    LR_TARGET,
        "batch_size":   BATCH_SIZE,
    }
}
```

Saving scheduler state allows training to be resumed without resetting the
cosine cycle.

---

## 3. Per-Epoch Logging (required for round 2)

Round 1 lost all per-epoch data because nothing was written to disk. Round 2
must write a training history file so each epoch is traceable.

Add this to `train.py` — append one row per epoch to a CSV and JSON file:

```python
history_row = {
    "epoch":                   epoch,
    "train_loss":              avg_train_loss,
    "macro_f1":                val_macro_f1,
    "learning_rate":           get_current_lr(optimizer),
    "stale_epochs":            stale_counter,
    "best_f1_so_far":          best_f1,
    "is_best":                 val_macro_f1 > prev_best,
    "epoch_duration_seconds":  epoch_end_time - epoch_start_time,
    "cosine_cycle":            current_cosine_cycle_number,
}
```

Write to:
```
artifacts/training_history.csv    (append one row per epoch)
artifacts/training_history.json   (full list, overwritten each epoch)
```

This allows plotting the loss and F1 curve after training and identifying
exactly which epoch produced the best checkpoint.

Also print a one-line summary per epoch to stdout:

```
Epoch 047/300 | Loss: 0.3214 | F1: 0.9102 | LR: 2.84e-3 | Stale: 3 | BEST
```

---

## 4. Additional Diagnostic During Training

At the end of every 10th epoch, print a per-class F1 breakdown alongside the
macro F1. This is the only way to see whether the WebBased/Recon/Spoofing
confusion is improving without waiting for training to finish:

```
Epoch 050/300 | Loss: 0.2847 | Macro F1: 0.9124
  Benign:     0.898   DDoS:       0.961
  DoS:        0.987   Mirai:      0.991
  Recon:      0.871   Spoofing:   0.855
  WebBased:   0.823   BruteForce: 0.858
```

If WebBased is still stuck below 0.80 after 50 epochs AND the payload quality
diagnostic confirmed real bytes are present, the confusion is genuine
flow-level ambiguity between these four classes and the sub-classifier
architecture will be needed to resolve it. Do not keep training indefinitely
if no improvement is observed in the confused cluster.

---

## 5. Training Command

After both prerequisites (sharding and payload quality check) are confirmed:

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
SECUREEDGE_LABEL_SMOOTHING=0.1 \
python -m secureedge.models.train
```

Do not increase `NUM_WORKERS` above 0. With in-memory shard loading, workers
only add subprocess overhead. Pinned memory and non-blocking transfers (already
implemented) provide the transfer optimisation.

---

## 6. What to Watch During Training

### 6.1 The cosine cycle signature

With `CosineAnnealingWarmRestarts(T_0=50, T_mult=2)`, the LR follows this
schedule:

```
Epoch   1–5:    Linear warmup 3e-4 → 3e-3
Epoch   6–55:   Cosine cycle 1: 3e-3 → 1e-5  (50 epochs)
Epoch  56–155:  Cosine cycle 2: 3e-3 → 1e-5  (100 epochs)
Epoch 156–355:  Cosine cycle 3: 3e-3 → 1e-5  (200 epochs, if MAX_EPOCHS=300 allows)
```

At epoch 6 and epoch 56, the LR jumps back up to 3e-3. Macro F1 will
typically dip slightly when LR rises at cycle start, then recover and often
surpass the previous best. This is expected and is NOT a reason to stop
training early. The early stopping counter should NOT be reset at cycle
boundaries — only when F1 actually improves.

### 6.2 Signs of a healthy training run

By epoch 30 (end of first cosine half-cycle):
- WebBased F1 should be above 0.78
- Macro F1 should be above 0.88

By epoch 55 (end of first full cycle):
- WebBased F1 should be above 0.82
- Macro F1 should be above 0.91

By epoch 100 (midpoint of second cycle):
- All classes should be above 0.87
- Macro F1 should be above 0.93

### 6.3 Signs of a problem

If any of these are true at epoch 55, stop and diagnose:
- WebBased F1 < 0.75: payloads are likely zeros despite the diagnostic passing.
  Run the diagnostic again on the SHARD files (not individual `.pt` files) to
  confirm the sharding step preserved the packet features correctly.
- Macro F1 < 0.87: the LR might still be too high. Reduce `LR_TARGET` to 0.001
  and restart.
- Training loss is not decreasing: gradient accumulation might be needed
  (see Section 7 fallback options).

### 6.4 GPU memory check at start

At the first batch, confirm VRAM usage is reasonable:

```bash
nvidia-smi --query-gpu=memory.used,memory.free --format=csv
```

Expected for batch_size=512: roughly 500–800 MB used. If it exceeds 6 GB,
reduce `BATCH_SIZE` to 256.

---

## 7. Expected Results After Round 2

Based on the confusion matrix analysis and the specific failure modes addressed:

| Class | Round 1 F1 | Round 2 target | Why |
|---|---|---|---|
| DoS | 0.980 | 0.985 | Already strong; minor gains |
| Mirai | 0.976 | 0.992 | Cosine annealing unlocks last few % |
| DDoS | 0.931 | 0.965 | LR fix stops noisy updates hurting this class |
| Benign | 0.863 | 0.910 | Label smoothing reduces false WebBased predictions |
| BruteForce | 0.822 | 0.880 | Payload features + label smoothing |
| Recon | 0.834 | 0.890 | Label smoothing reduces absorption into WebBased |
| Spoofing | 0.822 | 0.880 | Same as Recon |
| WebBased | 0.756 | 0.855 | LR fix + label smoothing + cosine warm restart |
| **Macro F1** | **0.873** | **≥ 0.92** | |

Reaching 0.97 in round 2 is optimistic but possible if the payload diagnostic
confirms real bytes are present and the cosine warm restarts escape the local
minimum. A result of 0.92–0.95 in round 2 is the more conservative expectation.
If round 2 reaches 0.95, round 3 can focus on architecture-level changes.

---

## 8. Fallback Options if Round 2 Underperforms

If round 2 macro F1 is still below 0.90, investigate in this order:

**Check 1 — Payload bytes in shards:**
Run the payload diagnostic on files in `data/graphs/train_shards/` (not the
original individual `.pt` files). Confirm that `torch.load(shard_path)` returns
a list where each element has non-zero `g['packet'].x`.

**Check 2 — Reduce LR further:**
If training loss is oscillating (not monotonically decreasing within each cosine
cycle), set `LR_TARGET=0.001` and restart. Loss oscillation means the LR is
still too high.

**Check 3 — Add dropout to HGNN:**
If the model is overfitting (train loss significantly lower than test F1 would
suggest), add `Dropout(p=0.3)` after each GATConv + BatchNorm + activation
block in `secureedge/models/hgnn.py`. XG-NID does not mention dropout but it
helps regularise GNNs on small-to-medium datasets.

**Check 4 — Class-weighted loss for WebBased:**
If WebBased F1 is still below 0.80 despite non-zero payloads and correct LR,
apply a class weight to make WebBased errors more costly:

```python
class_weights = torch.ones(8)
class_weights[6] = 2.0    # class index 6 = WebBased
class_weights[7] = 1.5    # class index 7 = BruteForce
loss_fn = CrossEntropyLoss(
    weight         = class_weights.to(device),
    label_smoothing = LABEL_SMOOTHING,
)
```

This does not improve the underlying confusion but forces the model to trade
false negatives on easier classes for fewer WebBased misses.

**Check 5 — Increase hidden size:**
If all other checks pass and F1 plateaus at 0.92–0.94, try `hidden_size=128`
(doubling the current 64). This doubles model parameters but the model is
still tiny (~500 KB → ~1 MB) so VRAM is not a concern.
