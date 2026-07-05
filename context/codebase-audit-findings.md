# SecureEdge — Full Codebase Audit vs XG-NID Methodology

> **Generated:** 2026-06-24
> **Trigger:** 10 training runs all plateau at macro F1 ≈ 0.89 (best: 0.8966,
> Run 10). Goal: audit every component against XG-NID to locate the structural
> cause of the gap to 0.97.
> **Method:** Direct read of `hgnn.py`, `graph_builder.py`, `config.py`,
> `train.py`, and the methodology document, cross-checked against the per-class
> result pattern from all runs.

---

## 0. Headline Verdict

The implementation faithfully matches the team's written methodology. There is
**no training-loop bug, no learning-rate bug, no data-leakage bug, and the
multi-head GAT fix is correctly applied.** The plateau is **structural**: the
packet-payload modality is contributing almost nothing, so the model behaves like
a flow-statistics-only classifier — which is exactly the ~0.88 score XG-NID's own
flow-only DNN baseline reached.

The single clearest piece of evidence is the per-class signature, identical across
all 10 runs:

| Class type | Classes | F1 | What separates them |
|---|---|---|---|
| Volumetric (flow stats) | DoS 0.98, Mirai 0.98, DDoS 0.94 | **high** | packet rates, byte counts, flags |
| Application-layer (payload) | WebBased 0.80, Spoofing 0.85, Recon 0.86, Benign 0.87, BruteForce 0.89 | **plateau** | payload byte content |

If the 1,500-byte payload nodes were contributing, WebBased and BruteForce would
not be the worst classes — payload content (SQL injection strings, HTTP POST
bodies) is the *most* discriminative signal for them. Their being the weakest is
the fingerprint of a payload modality that the model cannot read.

---

## 1. Component-by-Component Audit

| Component | XG-NID / sound practice | Our code (verified) | Status |
|---|---|---|---|
| Flow node features | 92 (76 flow + 16 temporal) | 92, StandardScaler | ✅ Correct |
| Packet node features | 1,500 payload bytes | uint8 / 255 → [0,1], no scaler | ⚠️ See Finding A/B |
| Contain edges | 4 features | 4, StandardScaler | ✅ Correct |
| Reverse contain edges | for bidirectional msg passing | present, attrs cloned | ✅ Correct |
| Link edges | Δt between packets | 1 feature, / p99 | ✅ Correct |
| GATConv heads | 2 (attn 32 → 64) | heads=2, concat=True, 32→64 | ✅ Correct (fixed Run 6) |
| Conv layers | 2 | 2 (HeteroConv) | ✅ Correct |
| Activation | ReLU/LeakyReLU | LeakyReLU(0.01) | ✅ Correct (NOT 1.0 — see Finding E) |
| BatchNorm | per node type | bn_flow, bn_packet ×2 | ✅ Correct |
| **conv2 edge attributes** | edges inform every layer | **conv2 drops edge_attr** | ⚠️ Finding D |
| **Graph readout** | combine node-type embeddings | **(flow + packet) / 2** | ⚠️ Finding C |
| **Payload encoding** | sequence/locality model | **raw bytes → linear GAT proj** | ❌ Finding A (primary) |
| Classifier | FC head | 64→32→16→8 | ✅ Correct |
| Loss | CrossEntropyLoss | plain CE, no weights | ✅ Correct |
| Optimizer | Adam, wd 1e-5 | Adam, wd 1e-5 | ✅ Correct |
| Training loop | standard | zero_grad/backward/clip/step, eval, checkpoint | ✅ Correct |
| Train/test split | 20k / 4k per class | 20k / 4k balanced pool | ✅ Correct |
| Oversampling | random duplication | random duplication | ✅ Correct |

Three components are flagged. One is the primary cause; the other two are
contributing factors. All three are in the **packet/readout path** — consistent
with the per-class evidence.

---

## 2. Finding A (PRIMARY) — Payloads Enter the GNN as Raw Bytes Through a Single Linear Projection

### What the code does

Each packet node is a 1,500-dimensional vector of `byte / 255` values. The first
GATConv applies a single linear weight matrix (1,500 → 32 per head) to this vector.
That is the entire payload feature extractor — one position-wise linear map.

### Why this cannot learn payload signatures

A position-wise linear projection treats each of the 1,500 byte offsets as an
independent feature with its own weight. It has no weight sharing across positions
and no notion of locality. Consequently:

- The token `' OR 1=1` appearing at byte offset 40 produces a completely different
  activation than the same token at offset 80. The model would have to independently
  learn the pattern at every possible offset.
- There is no mechanism to detect a contiguous n-gram of bytes as a unit. SQL
  injection, XSS (`<script>`), and HTTP POST credential patterns are exactly such
  contiguous byte sequences.

The byte patterns that define WebBased and BruteForce are sequential and
position-invariant. A linear layer is the wrong tool for sequential,
position-invariant patterns. This is the core reason the payload modality is inert.

### Evidence

- We reproduce XG-NID's flow-only DNN baseline (~0.88), not their dual-modality
  result (0.97). Adding 1,500-dim payload nodes moved macro F1 by only ~0.02 over a
  flow-only model across the project's history.
- The multi-head GAT fix (Run 6) helped WebBased/BruteForce by ~0.04 — real, but
  small — because better attention over an uninformative packet embedding still has
  little to attend to.

### Honest caveat

I cannot fully verify XG-NID's exact internal payload module from the materials in
this project. The team's own methodology document specifies raw bytes, so this may
be a gap between the team's interpretation and the actual XG-NID implementation.
Regardless of what XG-NID did, the raw-byte-into-linear-projection approach is
insufficient on machine-learning grounds, and replacing it with a sequence encoder
is the highest-value change available.

---

## 3. Finding B — Extreme Payload Sparsity Compounds Finding A

Measured payload density (from the project's own diagnostics): mean packet feature
value ≈ 0.07, non-zero fraction ≈ 0.15–0.22. Payloads are padded to 1,500 bytes, so
roughly 85–92% of every packet vector is zero.

The linear projection therefore sees mostly zeros, and the small amount of real
signal is spread across 1,500 input dimensions. Even if a linear map *could* capture
the pattern (it cannot — Finding A), the signal-to-padding ratio is very low.

A sequence encoder with pooling (Finding A's fix) naturally concentrates on the
informative region. Alternatively, truncating the payload to the first ~256 bytes
(where HTTP request lines, methods, and injection payloads live) would raise density
several-fold.

---

## 4. Finding C — The (flow + packet)/2 Readout Dilutes the Working Modality

### What the code does

```
flow_pooled   = mean of flow node embeddings    (1 flow node per graph)
packet_pooled = mean of packet node embeddings  (≤20 packet nodes)
graph_embedding = (flow_pooled + packet_pooled) / 2
```

The graph embedding is a fixed 50/50 average of the two modalities.

### Why this hurts

The flow branch carries the discriminative signal. The packet branch is currently
near-noise (Findings A, B). Averaging forces the clean flow signal down to 50% weight
and injects 50% noise into every graph embedding. This can actively *lower* the
ceiling that a flow-only model would reach — and indeed the gap between our HGNN and
a pure flow model is tiny, consistent with the packet branch adding noise rather than
signal.

### The alternative

Concatenate instead of average: `graph_embedding = [flow_pooled ‖ packet_pooled]`
(128-dim), then `classifier(128 → 64 → 32 → 8)`. Concatenation lets the classifier
*learn* how much weight to give each modality instead of hard-coding 50/50, and it
preserves the full flow signal. This is small and reversible.

Note: the methodology document explicitly says to average, so the code matches the
methodology. This is still a likely contributor and is worth testing once the payload
encoder (Finding A) is in place — concatenation only helps if the packet branch
carries signal.

---

## 5. Finding D — conv2 Ignores Edge Attributes

`conv1` is built with `edge_dim=...` and receives `edge_attr_dict`. `conv2` is built
without `edge_dim` and is called without edge attributes. So the second message-
passing layer ignores all edge features: contain-edge direction and packet sizes, and
critically the **link-edge inter-packet time deltas**.

Impact is medium-low, but the link-edge Δt is the signal for timing-based attacks
(notably DDoS-SlowLoris, whose whole signature is slow, irregular inter-packet
timing). Letting both layers see edge attributes is a cheap correctness improvement.

---

## 6. Finding E — eps=1.0 Activation Trap (Correctly Avoided — Do Not "Fix")

The methodology document states the XG-NID `eps: 1.0` config value should be set as
`LeakyReLU(negative_slope=1.0)`. That would make the activation the identity function
`f(x) = x`, collapsing both GAT layers into an effectively linear model and destroying
all non-linear learning.

The actual code uses `HGNN_LEAKY_RELU_SLOPE = 0.01`, which is correct. **This finding
is a warning, not a fix:** if anyone later "aligns" the code to the methodology's
`eps=1.0` instruction, the model will break. The `eps` value in a GNN config almost
certainly refers to a GIN-style epsilon (unused by GATConv), not an activation slope.
Leave the slope at 0.01.

---

## 7. Finding F — Data Diversity Ceiling (Already Established, Still Real)

Independent of architecture, the dataset limits the achievable ceiling:

| Class | Real unique flows | Oversample rate |
|---|---|---|
| BruteForce | 11,043 (one session) | 54% |
| WebBased | 20,855 | 13% |
| Recon | 21,426 | 11% |

BruteForce flows come from essentially one capture session against one target. Even a
perfect payload encoder learns the characteristics of that one session. XG-NID trained
on the full 46.7M-flow corpus with many sessions per class. This ceiling cannot be
removed by architecture changes — only by more diverse data — and it means even the
Finding A fix may only partially close the gap.

---

## 8. Priority Summary

| Finding | Severity | Fix effort | Expected lever |
|---|---|---|---|
| A — raw-byte linear payload encoding | **Critical** | Medium (new encoder module) | Largest — unlocks payload modality |
| C — averaged readout dilutes signal | High | Small (concat) | Medium, only after A |
| D — conv2 drops edge attrs | Medium-low | Small | Small, helps timing attacks |
| B — payload sparsity | Compounds A | Small (truncate) | Helps A |
| E — eps=1.0 trap | N/A | Do nothing | Already correct |
| F — data diversity | Hard limit | Out of scope | Caps final result |

The detailed, ordered experiment plan to test these is in
`payload-encoder-fix-plan.md`.

---

## 9. What This Audit Rules OUT

To be explicit about what is *not* the problem, so no more time is spent there:

- **Not the learning rate / scheduler** — Runs 1–10 swept LR (0.01, 0.005, 0.003),
  schedulers (plateau, cosine, none), and batch sizes (64, 128, 256, 512). All
  plateau at 0.89.
- **Not label smoothing / focal loss / class weights** — tested in Runs 2, 4. Neutral
  or harmful.
- **Not a train/eval bug** — the training loop is correct.
- **Not the GAT head count** — fixed in Run 6, helped slightly.
- **Not the flow features** — flow-stat classes already score 0.94–0.98.

The problem is the payload path. That is where the next work must go.
