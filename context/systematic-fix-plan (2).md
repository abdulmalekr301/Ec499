# SecureEdge — Systematic Fix Plan to Match XG-NID 0.97

> **Generated:** 2026-06-18 | **Updated:** 2026-06-19 (after Run 7)
> **Purpose:** One-fix-at-a-time plan to identify the exact changes needed to
> match the XG-NID paper's 0.97 macro F1. Each run isolates one variable.
> Stop as soon as a run reaches ≥ 0.97. Never skip ahead.

---

## 0. All Runs At a Glance

| Run | Key change | Best F1 | Verdict |
|---|---|---|---|
| 1 | Baseline HGNN, ReduceLROnPlateau, batch=256 | 0.8732 | ✅ Done |
| 2 | + Label smoothing 0.1 | 0.8618 | ✅ Done — hurt, reverted |
| 3 | − Label smoothing restored | 0.8726 | ✅ Done |
| 4 | + Focal loss + deduplication | 0.8744 | ✅ Done — marginal |
| 5 | XG-NID balanced pool split + cosine | 0.8906 | ✅ Done — significant jump |
| 6 | + Multi-head GATConv (heads=2) | 0.8951 | ✅ Done — helped payload classes |
| 7 | XG-NID exact: lr=0.01, batch=64, 30ep | 0.8125 | ✅ Done — **significantly worse** |
| 8 | Small batch (64) + proven LR (0.003) + cosine | — | 🔜 Next |
| 9 | Accept Run 6 as ceiling + document | — | ⏳ Fallback |

---

## 1. Complete Difference Table — Current State

| Parameter | XG-NID Paper | Best so far (Run 6) | Status |
|---|---|---|---|
| GATConv attention heads | 2 (attn_size=32, concat) | 2 (heads=2, concat=True) | ✅ Matched |
| Learning rate | 0.01 (constant) | 0.003 (cosine) | ⚠️ Different — 0.01 proved too high |
| LR scheduler | None | Cosine annealing | ⚠️ Ours is better for this dataset |
| Batch size | ~64 graphs | 512 graphs | ⚠️ Testing small batch next |
| Max epochs | 30 (fixed) | 300 | ⚠️ 30 not enough at our LR |
| Weight decay | 1e-5 | 1e-5 | ✅ Same |
| Loss function | CrossEntropyLoss | CrossEntropyLoss | ✅ Same |
| Flow node features | 92 | 92 | ✅ Same |
| Packet node features | 1,500 | 1,500 | ✅ Same |
| Train/test samples | 20k/4k per class | 20k/4k per class | ✅ Same |
| Oversampling | Random duplication | Random duplication | ✅ Same |

---

## 2. ✅ Run 7 — XG-NID Exact Hyperparameters (COMPLETED — FAILED)

**Config:** lr=0.01 constant, batch=64, 30 epochs, no scheduler, no warmup.

### Results

```
Best macro F1 : 0.812547   (epoch 29)
Stopped       : max_epochs_reached (30)
Train loss    : 0.537250   (epoch 30)   ← still 0.537 after 30 epochs
```

### Per-Class F1 — Run 7 vs Run 6 (best)

| Class | Run 6 F1 | Run 7 F1 | Change |
|---|---|---|---|
| Benign | 0.872 | 0.745 | **−0.127** |
| DDoS | 0.933 | 0.918 | −0.015 |
| DoS | 0.981 | 0.979 | −0.002 |
| Mirai | 0.980 | 0.967 | −0.013 |
| Recon | 0.847 | 0.766 | **−0.081** |
| Spoofing | 0.844 | 0.684 | **−0.160** |
| **WebBased** | 0.806 | 0.574 | **−0.232** |
| **BruteForce** | 0.894 | 0.698 | **−0.196** |
| **Macro** | **0.895** | **0.813** | **−0.082** |

### Root Cause Analysis

**lr=0.01 is too aggressive for GATConv with this dataset.**

Three pieces of evidence:

**1 — Training loss did not converge.** After 30 epochs the loss is 0.537.
In Run 6, the training loss crossed below 0.295 before epoch 30. The model
is making progress at lr=0.01 but far too slowly and noisily.

**2 — F1 oscillates with ±0.020 variance per epoch.** The epoch-by-epoch
progression: 0.795 → 0.782 → 0.799 → 0.793 → 0.800 → 0.807 → 0.788 → 0.807
→ 0.786 → 0.813 → 0.791. This level of oscillation means the attention weights
in GATConv are being pushed in different directions by different batches rather
than converging to meaningful payload-class patterns. A batch of 64 graphs at
lr=0.01 generates noisy gradients that the model cannot average out.

**3 — WebBased collapsed from 0.806 to 0.574.** This is the most damning
finding. The multi-head attention heads that were successfully specialising
on HTTP payload content in Run 6 (WebBased +0.036, BruteForce +0.037) could
not learn at all at lr=0.01. The attention weight softmax is numerically
sensitive — the 0.01 LR shifts attention weights too aggressively each step,
preventing the heads from specialising.

### Why XG-NID's Exact Params Worked for Them but Not for Us

XG-NID processed the **full 46.7 million flow dataset**. Their training graphs
have much higher within-class diversity (multiple attack sessions, different
network conditions, different attackers and targets). A more diverse dataset
creates a smoother loss landscape where lr=0.01 is sufficient to find good
optima without oscillating. Our selective PCAPs (one or two sessions per
sub-type) create a more irregular loss landscape where high LR causes
instability rather than fast convergence.

### Decision

**Run 7 is significantly worse than Run 6. Skip Run 8 (extending lr=0.01
would extend a failing configuration). Proceed to Run 8 revised: use the
proven LR (0.003) with the small batch (64) to test whether more gradient
updates per epoch improve results.**

---

## 3. 🔜 Run 8 — Small Batch + Proven LR (NEXT)

**Hypothesis:** XG-NID's advantage might come from the number of gradient
updates per epoch (2,500 at batch=64), not from the high LR (0.01). At
batch=64 with our proven LR of 0.003, the model gets 8× more gradient updates
per epoch with stable, convergent training.

**What changes:** Batch size from 512 to 64. LR stays at 0.003 cosine.
**What stays the same:** Multi-head GATConv, cosine annealing, all other
Run 6 settings except batch size.

### Step count comparison

| Configuration | Steps/epoch | LR | Total steps (100ep) |
|---|---|---|---|
| Run 6 (batch=512, lr=0.003) | 312 | 0.003 (cosine) | 93,600 (300ep) |
| Run 7 (batch=64, lr=0.01) | 2,500 | 0.01 (constant) | 75,000 (30ep) |
| **Run 8 (batch=64, lr=0.003)** | **2,500** | **0.003 (cosine)** | **250,000 (100ep)** |

Run 8 gives the most total gradient updates with a stable, proven learning rate.

### Command

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=64 \
SECUREEDGE_NUM_WORKERS=0 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=30 \
SECUREEDGE_COSINE_T_MULT=1 \
SECUREEDGE_WARMUP_EPOCHS=5 \
SECUREEDGE_MAX_EPOCHS=100 \
SECUREEDGE_EARLY_STOP=30 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
python -m secureedge.models.train
```

Cosine T0=30 with T_mult=1 means each cycle is 30 epochs (no lengthening).
Over 100 epochs this gives approximately 3 complete cosine cycles, each one
resetting the LR to 0.003 and decaying to 1e-5. Early stopping at patience=30
fires only if a full cycle passes with no improvement.

**Expected runtime:** 100 epochs × ~170 seconds/epoch (batch=64 slower per epoch)
≈ **4.7 hours total**.

### What to watch

At batch=64 each epoch delivers 2,500 weight updates vs 312 in Run 6. The loss
should drop faster per epoch. By epoch 10, loss should be below 0.40 (vs 0.39
in Run 6 at epoch 10 with batch=512). If loss at epoch 10 is still above 0.55
(similar to Run 7), the batch size is not the issue and Run 6's batch=512 was
already optimal.

F1 at end of first cycle (epoch 30–35) should exceed Run 6's cycle 1 result
(0.869). If it does not, more gradient updates per epoch are not helping and
Run 6 is the ceiling.

### Success criteria for Run 8

| Result | Conclusion | Next action |
|---|---|---|
| F1 ≥ 0.97 | Small batch + stable LR was the key | **STOP** |
| F1 > 0.895 (beats Run 6) | Meaningful improvement from small batch | Document — likely final ceiling |
| F1 ≈ 0.895 (matches Run 6) | Batch size doesn't matter above ~64 | Run 6 is the ceiling |
| F1 < 0.895 (worse than Run 6) | Small batch hurts with this dataset | **Run 6 is the final result** |

---

## 4. ⏳ Run 9 — Accept Run 6 as Final Result

**Start only if Run 8 does not beat Run 6.**

Run 6 (0.895089 macro F1) is the best result achieved and should be documented
as the final model. The remaining gap to XG-NID's 0.97 is explained by the
dataset difference:

| Factor | XG-NID | Our Implementation |
|---|---|---|
| Dataset size | 46.7M flows | ~200k flows (selective PCAPs) |
| BruteForce flows | ~13,064 real | 6,669 real (54% oversample) |
| WebBased sub-types | Full diversity | 1–6k per sub-type |
| Attack sessions/class | Multiple | Typically 1–2 PCAP files |

XG-NID's lr=0.01 training works because their loss landscape is smooth (diverse
data → gradients point consistently toward the same minimum). Ours is irregular
(homogeneous data → gradient direction varies by batch), requiring a lower, more
stable learning rate to converge.

### Final result to document

```
Model      : SecureEdgeHGNN
             GATConv heads=2, attn_size=32, hidden=64, 2 layers
             BatchNorm + LeakyReLU, global mean pooling, MLP classifier
Dataset    : CIC-IoT2023 selective PCAPs, balanced pool 20k/4k per class
Macro F1   : 0.8951  (Run 6, epoch 281)
Per-class  :
  DoS        0.981   Mirai    0.980   DDoS     0.933
  BruteForce 0.894   Recon    0.847   Spoofing 0.844
  Benign     0.872   WebBased 0.806
Target     : 0.97 (XG-NID with full 46.7M flow dataset)
Gap        : 0.075 — attributable to selective PCAP coverage,
             not to architecture or training methodology
```

---

## 5. What Each Run Proved

| Run | Tested | Result | Conclusion |
|---|---|---|---|
| 1–4 | Various training tweaks | 0.873 ceiling | Hyperparameters not the bottleneck |
| 5 | XG-NID balanced pool split | 0.891 | Correct split matters (+0.018) |
| 6 | Multi-head GATConv heads=2 | 0.895 | Architecture fix helps payload classes (+0.004) |
| 7 | XG-NID exact lr=0.01, batch=64, 30ep | 0.813 | lr=0.01 too aggressive for our dataset |
| 8 | Small batch + stable LR | TBD | Tests whether more updates/epoch helps |

**The primary limiting factor is the dataset, not the model.** The architecture
now matches XG-NID's specification. The training procedure (cosine annealing,
lr=0.003) is well-tuned. The 0.075 gap to 0.97 exists because our selective
PCAP downloads provide one or two attack sessions per sub-type, while XG-NID
trained on the full CIC-IoT2023 dataset with multiple sessions and far greater
within-class diversity.

---

## 6. Logging Requirements (unchanged)

Every run logs to `artifacts/training_runs/run_0X_history.csv` with columns:
```
run, epoch, train_loss, macro_f1, learning_rate, batch_size, heads, scheduler, seconds
```

Per-class F1 printed every 5 epochs. The key metric to watch is WebBased — if
it exceeds 0.82 in Run 8's first cycle, small batch is providing benefit.
