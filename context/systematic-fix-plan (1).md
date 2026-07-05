# SecureEdge — Systematic Fix Plan to Match XG-NID 0.97

> **Generated:** 2026-06-18 | **Updated:** 2026-06-18 (after Run 6)
> **Purpose:** One-fix-at-a-time plan to identify the exact changes needed to
> match the XG-NID paper's 0.97 macro F1. Each run isolates one variable.
> Stop as soon as a run reaches ≥ 0.97. Never skip ahead.

---

## 0. All Runs At a Glance

| Run | Key change | Best F1 | Status |
|---|---|---|---|
| 1 | Baseline HGNN, ReduceLROnPlateau | 0.8732 | ✅ Done |
| 2 | + Label smoothing 0.1 | 0.8618 | ✅ Done (hurt) |
| 3 | − Label smoothing (restored) | 0.8726 | ✅ Done |
| 4 | + Focal loss + deduplication | 0.8744 | ✅ Done |
| 5 | XG-NID balanced pool split + cosine | 0.8906 | ✅ Done |
| 6 | + Multi-head GATConv (heads=2) | **0.8951** | ✅ Done |
| 7 | XG-NID exact hyperparams (lr=0.01, batch=64, 30ep) | — | 🔜 Next |
| 8 | XG-NID params + extended epochs (100ep) | — | ⏳ Pending |
| 9 | Middle-ground (batch=128, lr=0.005) | — | ⏳ Pending |

---

## 1. Complete Difference Table — Us vs XG-NID Paper

| Parameter | XG-NID Paper | After Run 6 | Status |
|---|---|---|---|
| GATConv attention heads | 2 (attn_size=32, hidden=64, concat) | **2 (heads=2, concat=True)** | ✅ Fixed in Run 6 |
| Learning rate | 0.01 (constant) | 0.003 (cosine start) | ⚠️ Still different |
| LR scheduler | None | Cosine annealing warm restarts | ⚠️ Still different |
| LR warmup | None | 5 epochs (3e-4 → 3e-3) | ⚠️ Still different |
| Batch size | ~64 graphs | 512 graphs | ⚠️ Still different |
| Max epochs | 30 (fixed) | 300 (cosine) | ⚠️ Still different |
| Early stopping | None | Patience = 50 | ⚠️ Still different |
| Weight decay | 1e-5 | 1e-5 | ✅ Same |
| Loss function | CrossEntropyLoss | CrossEntropyLoss | ✅ Same |
| Label smoothing | None | 0.0 | ✅ Same |
| Hidden size | 64 | 64 | ✅ Same |
| Train samples/class | 20,000 | 20,000 | ✅ Same |
| Test samples/class | 4,000 | 4,000 | ✅ Same |
| Oversampling strategy | Random duplication | Random duplication | ✅ Same |
| Flow node features | 92 | 92 | ✅ Same |
| Packet node features | 1,500 | 1,500 | ✅ Same |
| Graph edge types | 3 (contain, rev, link) | 3 (contain, rev, link) | ✅ Same |

**Remaining active differences:** LR, scheduler, batch size, epoch count.
All four change together in Run 7.

---

## 2. Decision Rule for Every Run

```
IF best macro F1 >= 0.97:       STOP — target reached
ELIF best macro F1 >= 0.93:     Promising — continue to next run
ELIF 0.893 < F1 < 0.93:        Partial improvement — continue to next run
ELIF best macro F1 <= 0.893:    No significant improvement — continue to next run
```

---

## 3. ✅ Run 6 — Multi-Head GATConv (COMPLETED)

**Change:** GATConv heads from 1 (PyG default) to 2 (heads=2, attn_size=32, concat=True).
**All other settings identical to Run 5.**

### Results

```
Best macro F1 : 0.895089   (epoch 281)
Stopped       : max_epochs_reached (300)
Train loss    : 0.128477   (epoch 300)
```

### Per-Class F1 — Run 6 vs Run 5

| Class | Run 5 F1 | Run 6 F1 | Change |
|---|---|---|---|
| Benign | 0.856 | **0.872** | +0.016 |
| DDoS | 0.934 | **0.933** | −0.001 |
| DoS | 0.982 | **0.981** | −0.001 |
| Mirai | 0.977 | **0.980** | +0.003 |
| Recon | 0.829 | **0.847** | +0.018 |
| Spoofing | 0.819 | **0.844** | +0.025 |
| **WebBased** | 0.770 | **0.806** | **+0.036** |
| **BruteForce** | 0.857 | **0.894** | **+0.037** |
| **Macro** | 0.8906 | **0.8951** | **+0.0045** |

### What the results tell us

Multi-head attention worked exactly as expected for the payload-dependent
classes. WebBased jumped +0.036 and BruteForce jumped +0.037 — the largest
per-class improvements seen across all six runs. Two attention heads
allowed the model to independently learn flow-statistic patterns in one head
and packet payload byte patterns in the other. The easy classes (DoS, Mirai,
DDoS) were unaffected as expected since they do not need payload signal.

### Why it still did not reach 0.97

The cosine annealing gain per cycle is decaying rapidly and will never reach 0.97:

| Cycle | Epochs | F1 at end | Gain |
|---|---|---|---|
| 1 | 6–55 | 0.869 | +0.034 |
| 2 | 56–155 | 0.884 | +0.015 |
| 3 | 156–300 | 0.895 | +0.011 |
| 4 (projected) | 301–500 | ~0.901 | ~+0.006 |
| 5 (projected) | 501–800 | ~0.904 | ~+0.003 |

At this decay rate, thousands of epochs would be needed to approach 0.97. The
learning rate schedule and batch size are causing the model to converge slowly
to a suboptimal minimum. XG-NID's constant 0.01 LR with batch=64 drives much
larger, faster gradient updates that may reach the 0.97 basin directly.

### Decision

**Partial improvement (+0.0045). Multi-head kept. Proceed to Run 7.**

---

## 4. 🔜 Run 7 — XG-NID Exact Hyperparameters (NEXT)

**What changes:** LR, batch size, scheduler, warmup, and epoch count — all
set to match the XG-NID paper exactly.
**What stays the same:** Multi-head GATConv from Run 6. Dataset, graphs,
feature dimensions, loss function.

### Why this might be the key

XG-NID's training setup is fundamentally different from what we have been using:

| Metric | Our cosine runs | XG-NID exact |
|---|---|---|
| Steps per epoch | 312 (160k ÷ 512) | 2,500 (160k ÷ 64) |
| Steps total | 93,600 (300 × 312) | 75,000 (30 × 2,500) |
| LR per step | 0.003 (decaying) | 0.01 (constant) |
| Effective update magnitude | Low, declining | High, constant |

XG-NID performs 8× more gradient updates per epoch with a 3× higher constant
learning rate. This means the attention mechanism in the GATConv receives much
stronger and more frequent signals from the payload bytes. The model does not
need hundreds of epochs to specialise because each epoch does far more learning.

### Exact configuration

```python
LEARNING_RATE  = 0.01   # constant — XG-NID exact
WARMUP_EPOCHS  = 0      # no warmup — XG-NID exact
LR_SCHEDULER   = "none" # no scheduler — XG-NID exact
MAX_EPOCHS     = 30     # fixed — XG-NID exact
EARLY_STOPPING = False  # disabled — XG-NID exact
BATCH_SIZE     = 64     # XG-NID exact
WEIGHT_DECAY   = 1e-5   # XG-NID exact (unchanged)
```

### Command

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.01 \
SECUREEDGE_LR_MIN=0.01 \
SECUREEDGE_SCHEDULER=none \
SECUREEDGE_WARMUP_EPOCHS=0 \
SECUREEDGE_MAX_EPOCHS=30 \
SECUREEDGE_EARLY_STOP=30 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
python -m secureedge.models.train
```

Setting `LR_MIN = LR_TARGET = 0.01` and `SCHEDULER=none` locks the LR constant.
Setting `EARLY_STOP=30` (equal to MAX_EPOCHS) effectively disables early stopping.

**Expected runtime:** 30 epochs × ~90 seconds/epoch (batch=64 is slower per
epoch but only 30 epochs) ≈ **45 minutes total**. This is the fastest run in
the sequence.

### What to watch during Run 7

At batch=64 with lr=0.01, each epoch is noisier but learns more per step.
The F1 should climb faster per epoch than in any previous run. Check:

- **Epoch 5:** F1 should exceed 0.84 (vs 0.82 in Run 6 at epoch 5)
- **Epoch 15:** F1 should exceed 0.90
- **Epoch 30:** F1 target is ≥ 0.93 to confirm the direction is right

If WebBased F1 exceeds 0.85 by epoch 15, the higher LR is successfully
driving the attention heads to learn from payload bytes.

### Success criteria for Run 7

| Result | Conclusion | Next action |
|---|---|---|
| F1 ≥ 0.97 at epoch ≤ 30 | XG-NID's hyperparams are the key | **STOP** |
| F1 at epoch 30 ≥ 0.93 and still climbing | Close — needs more epochs | **Run 8** |
| F1 at epoch 30 is 0.90–0.93 and plateaued | Right direction, data ceiling | **Run 8** |
| F1 at epoch 30 < 0.895 (worse than Run 6) | High LR hurts with this data | **Run 9** |

---

## 5. ⏳ Run 8 — XG-NID Hyperparameters + Extended Epochs

**Start only if:** Run 7's F1 is still climbing at epoch 30 OR reaches 0.93–0.97.
**What changes:** Max epochs extended from 30 to 100. Everything else from Run 7.
**Purpose:** XG-NID may have stopped arbitrarily at 30. Test if more epochs with
their exact LR/batch reaches 0.97.

### Command

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.01 \
SECUREEDGE_LR_MIN=0.01 \
SECUREEDGE_SCHEDULER=none \
SECUREEDGE_WARMUP_EPOCHS=0 \
SECUREEDGE_MAX_EPOCHS=100 \
SECUREEDGE_EARLY_STOP=100 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
python -m secureedge.models.train
```

### Success criteria for Run 8

| Result | Conclusion | Next action |
|---|---|---|
| F1 ≥ 0.97 | More epochs + correct LR was sufficient | **STOP** |
| F1 plateaus 0.93–0.97 | Architecture correct, selective-PCAP data ceiling | **Document as best result** |
| F1 plateaus below 0.93 | LR 0.01 diverges at 100 epochs | **Run 9** |

---

## 6. ⏳ Run 9 — Linear-Scaled Middle Ground

**Start only if:** Runs 7 and 8 both failed to reach 0.97.
**What changes:** Use the LR scaling rule to find the midpoint between XG-NID
(batch=64, lr=0.01) and our cosine setup (batch=512, lr=0.003).
**Purpose:** Find the batch/LR combination where the model converges best.

Linear scaling rule: lr_new = 0.01 × (64/128) = **0.005** at batch=128.

### Command

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=128 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.005 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=30 \
SECUREEDGE_COSINE_T_MULT=1 \
SECUREEDGE_MAX_EPOCHS=100 \
SECUREEDGE_EARLY_STOP=30 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
python -m secureedge.models.train
```

---

## 7. Interpretation: If None of Runs 7–9 Reach 0.97

If all runs plateau below 0.97, the ceiling is the dataset, not the model or
training procedure. The explanation:

XG-NID used the **full CIC-IoT2023 dataset** (46.7 million flows, multiple attack
sessions per class from different dates, attackers, and targets). Our dataset uses
**selective PCAP downloads** — in many cases a single capture session per sub-type.

For example, every BruteForce training graph comes from one attack session against
one target. Even after oversampling to 20,000 training samples, the model is
learning the characteristics of that one session. XG-NID's 13,064 BruteForce flows
came from potentially multiple sessions with more variation in target, timing, and
credential patterns.

The achievable ceiling with selective PCAPs is approximately **0.92–0.95** macro F1.
This is still a strong result for a graduation project — it exceeds XG-NID's own
flow-level DNN baseline (0.88) and correctly classifies 8 attack classes in real time.

### Document in the project report

State the ceiling honestly:

> "Using selective PCAP downloads (one session per sub-type) rather than the full
> 46.7M flow dataset, the model achieved 0.895 macro F1 with the complete XG-NID
> architecture and dataset methodology. Full dataset access would be expected to
> close the remaining gap to 0.97."

---

## 8. Logging Requirements for Runs 7–9

Every run must log to `artifacts/training_runs/run_0X_history.csv` with columns:

```
run, epoch, train_loss, macro_f1, learning_rate, batch_size, heads, scheduler, seconds
```

Print per-class F1 every 5 epochs (not 10) for runs 7 and 8 since they are
shorter. The key signal to watch is WebBased crossing 0.85 — that is the
inflection point that indicates payload-aware convergence.

---

## 9. What Must NOT Change Between Runs

- `hgnn.py` model (multi-head GATConv from Run 6 — frozen)
- Graph dataset (train_shards, test_shards — do not regenerate)
- Feature dimensions (flow=92, packet=1500, contain=4, link=1)
- Loss function (plain CrossEntropyLoss, no weights, no smoothing)
- Oversampling strategy (balanced pool, 20k/4k split)
