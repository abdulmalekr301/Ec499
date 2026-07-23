# SecureEdge vs GNN4ID — Source Code Comparison Findings

> **Generated:** 2026-07-05
> **Source:** Direct read of the actual GNN4ID repository code
> (https://github.com/Yasir-ali-farrukh/GNN4ID) — `Utility/Model.py`,
> `Utility/Training.py`, `Utility/Functions.py`,
> `Utility/Feature_extractor_flow_packet_combined.py`,
> `GNN4ID_Model.ipynb`, `GNN4ID.ipynb`, `Data_preprocessing_CIC-IoT2023.ipynb`
> **Context:** Current best result is 0.94. This document supersedes parts of
> `codebase-audit-findings.md` and `class-conditional-filtering-implementation.md`
> where the actual repo contradicts assumptions made from the paper text alone.

---

## 0. Corrections to Prior Guidance (read first)

Reading the actual code overturned three things I told you earlier. Stating them
plainly:

1. **`eps: 1.0` is BatchNorm1d's epsilon, not a LeakyReLU slope.** My earlier
   "Finding E" (never set eps=1.0, it would collapse LeakyReLU to identity) was
   based on a wrong guess about which layer the methodology doc's `eps` referred
   to. It's real XG-NID code, deliberately used, and it's now the top candidate
   fix — see Section 1.
2. **`attn_size` and multi-head GAT attention are not part of XG-NID's actual
   model.** The Run 6 fix (heads=2, attn_size=32) was based on a misreading of
   the methodology. It happened to help empirically, but it isn't a parity
   target — see Section 3.
3. **MAC filtering is applied uniformly to every attack class in XG-NID's own
   code — there is no class-conditional exception.** The class-conditional
   filtering fix I recommended last time is a deviation from faithful
   reproduction, not an alignment with it. More importantly, new evidence shows
   the BruteForce data scarcity isn't a SecureEdge bug at all — see Section 4.

None of this means earlier work was wasted — Run 6's multi-head fix genuinely
improved results, and the Run 14 split fix is independently confirmed correct
by this same source-code read (Section 6). But three specific pieces of guidance
need to be corrected now that the actual code is in hand.

---

## 1. BatchNorm eps=1.0 Paired With Zero Feature Scaling (Primary New Hypothesis)

### What XG-NID's code actually does

```python
# Utility/Model.py
self.bns1[node_type] = torch.nn.BatchNorm1d(self.hidden_size, eps=args['eps'])  # eps=1.0
self.relus1[node_type] = nn.LeakyReLU()  # default negative_slope=0.01, unrelated to eps
```

And separately, in `Utility/Functions.py`, **no feature scaling exists anywhere**:

```python
# Flow features — straight to tensor, no StandardScaler
all_flow_node_feats = np.asarray(flow_data, dtype=float)
all_flow_node_feats = torch.tensor(all_flow_node_feats, dtype=torch.float32)

# Packet payload — raw 0-255 byte values, NOT divided by 255
byte_array = bytes.fromhex(flow['udps.payload_data'][index_value])
packet_feat = np.abs(np.uint8(packet_feat))
packet_feats_combined.extend(packet_feat.tolist())

# Contain edge / link edge — raw ints, no normalization
contain_edge_all_feats = torch.tensor(np.asarray(..., dtype=int), dtype=torch.float32)
link_edge_feats = torch.tensor(np.asarray(flow['udps.delta_time'][1:], dtype=int), dtype=torch.float32)
```

SecureEdge, by contrast, fits a StandardScaler on flow features, divides payload
bytes by 255, and applies p99 normalization to link-edge deltas — then feeds
that into BatchNorm with PyTorch's default `eps=1e-5`.

### Why this combination is mechanistically significant, not just a stylistic difference

BatchNorm normalizes by `(x - mean) / sqrt(var + eps)`. For a feature dimension
with genuinely tiny variance — which is exactly what you get in a packet-payload
channel that's 85-92% zero-padding, especially after scaling those already-sparse
bytes down to a 0-1 range — `sqrt(var + eps)` becomes very sensitive to `eps`:

- **SecureEdge's setup** (scaled inputs, `eps=1e-5`): if a payload byte-position
  has variance ~1e-6 across a batch (extremely plausible for a mostly-zero,
  0-1-scaled column), the denominator is `sqrt(1e-6 + 1e-5) ≈ 0.0033`. Any small
  deviation from the mean gets divided by 0.0033 — amplified roughly 300x. This
  turns padding noise into large, unstable normalized outputs.
- **XG-NID's setup** (raw 0-255 inputs, `eps=1.0`): the same low-variance column
  now has denominator `sqrt(var + 1.0) ≈ 1.0` regardless of how small the real
  variance is. The large, fixed `eps` deliberately *dampens* the normalization's
  sensitivity to near-zero-variance columns instead of amplifying it.

This lines up with a finding that has persisted across the entire project: the
packet-payload modality behaving like noise the model can't use. That symptom is
consistent with SecureEdge's scaling + tiny-eps combination amplifying padding
noise into the payload channel, while XG-NID's raw-values + large-eps combination
does the opposite — actively suppressing it.

**This is a strong, mechanistically-grounded hypothesis, not a certainty.** It
needs to be tested, not assumed. But it is the most concrete, novel, and
cheaply-testable lead to come out of this comparison.

### Recommended test (Run 16)

Two isolated variables, tested separately so the result is interpretable:

**Run 16a — BatchNorm eps only:**
Set every `BatchNorm1d(hidden_size)` in `hgnn.py` to `eps=1.0`. Keep all current
feature scaling (StandardScaler, /255, p99) exactly as is. This isolates whether
`eps=1.0` alone helps even with scaled inputs.

**Run 16b — Full match (eps=1.0 + remove feature scaling):**
Set `eps=1.0` AND remove the StandardScaler on flow features, the /255 division
on payload bytes, and the p99 normalization on link-edge deltas — feed raw
values, exactly like XG-NID. This is the faithful reproduction test.

Run both. If 16b clearly beats 16a and the Run 14 baseline, the eps/scaling
*combination* is the mechanism, not eps alone. If neither helps, this hypothesis
is falsified and can be set aside with confidence — the audit will have been
worth doing either way.

**No graph regeneration needed for 16a. For 16b, feature values change (unscaled),
so graphs must be rebuilt** — though this only means skipping the scaler-fit step,
not re-extracting from PCAPs.

---

## 2. Exact Scheduler: ReduceLROnPlateau on Training Accuracy (Not What Run 7 Tested)

### What XG-NID's code actually does

```python
# Utility/Training.py
optimizer = torch.optim.Adam(model.parameters(), lr=args['lr'])  # lr=0.01
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, mode='max', factor=0.5, patience=5, threshold=0.01, min_lr=0.00001
)
for epoch in range(args['epochs']):  # epochs=30
    ... train one epoch ...
    train_acc = test(train_loader, model, device)   # evaluated on TRAINING data
    scheduler.step(train_acc)                          # stepped on TRAINING accuracy
```

**This is not what Run 7 tested.** Run 7 used a constant lr=0.01 with no scheduler
at all for 30 epochs, and it failed badly (0.813, oscillating ±0.02 per epoch).
XG-NID's actual recipe starts at the same lr=0.01 and batch=64, but *halves the
LR whenever training accuracy plateaus for 5 epochs* (down to a floor of 1e-5).
That could very plausibly be the difference between Run 7's instability and
XG-NID's reported stability — the aggressive initial LR only needs to survive a
handful of early epochs before the scheduler starts taming it.

Note also: the scheduler steps on *training* accuracy, not a held-out set. XG-NID
never uses a validation split anywhere in this pipeline — consistent with what
was established earlier in this project.

### Recommended test (Run 17)

```python
LEARNING_RATE = 0.01
BATCH_SIZE = 64          # see note below on the standing batch-512 constraint
MAX_EPOCHS = 30
SCHEDULER = ReduceLROnPlateau(mode='max', factor=0.5, patience=5, threshold=0.01, min_lr=1e-5)
# stepped on training-set accuracy each epoch, exactly as above
```

**Note on the batch-size constraint:** this project's standing rule is batch=512
because batch=64 was "already proven worse" in Runs 7-8. That conclusion is true
for the two schedules actually tested at batch=64 (constant lr=0.01, and cosine
lr=0.003) — neither of which is XG-NID's actual recipe. This run would be a
one-off, clearly-labeled diagnostic to test the *real* XG-NID recipe, not a
reversion of the standing default. I'd recommend running it once for comparison
and then returning to batch=512 for everything else unless it changes the
picture substantially.

---

## 3. `attn_size` / Multi-Head Attention Is Dead Code in XG-NID's Actual Model

### What the code shows

`args['attn_size'] = 32` is referenced in exactly one place:

```python
# Utility/Model.py, inside HeteroGNNWrapperConv (a custom class)
if self.aggr == "attn":
    self.attn_proj = nn.Sequential(
        nn.Linear(args['hidden_size'], args['attn_size']), nn.Tanh(),
        nn.Linear(args['attn_size'], 1, bias=False)
    )
```

But the model actually instantiated and trained in the notebook —
`HeteroGNN(data_model, args, aggr="mean")` — never calls `HeteroGNNWrapperConv`
at all. It uses PyTorch Geometric's built-in `HeteroConv` directly with
`SAGEConv` layers. `HeteroGNNWrapperConv` and its sibling `HeteroGNNConv` appear
to be unused scaffolding (structurally similar to a well-known GNN course
template), never wired into the active training path. `attn_size` has zero
effect on the actual reported results.

Separately, the GAT-with-edge-attributes variant (`HeteroGNN_Edge`, commented
out in the notebook — not the model actually trained) builds `GATConv` layers
with no `heads` argument at all:

```python
GATConv((-1, -1), 64, edge_dim=-1, add_self_loops=False)  # heads defaults to 1
```

### What this means for SecureEdge

Run 6's multi-head fix (heads=2, attn_size=32) was implemented based on a
misreading of the methodology document — this project treated `attn_size: 32`
as a GATConv attention-head-size parameter, but in the actual code it's an
unused artifact of dead scaffolding. **This doesn't mean Run 6 was a mistake** —
it produced a real, measured improvement (WebBased +0.036, BruteForce +0.037) —
but it means continuing to chase "attn_size/heads alignment" as a reproduction
target is chasing something that was never real. No further action needed here
beyond updating the mental model: multi-head attention is a SecureEdge-original
enhancement over XG-NID's actual architecture, not a parity fix.

---

## 4. XG-NID's Own BruteForce Data Is Almost As Scarce As Ours

### What the preprocessing notebook says, directly

> *"we first identified the class with the least number of samples, which in
> our scenario was the BruteForce Attack class, with 2,336 samples... We applied
> an oversampling factor of 10x to the minority class for the training data...
> to 20,000 samples."*

XG-NID's own real, MAC-filtered BruteForce pool was **2,336 samples total**
(≈1,869 for the 80% train share), oversampled roughly 10.7x to reach 20,000.
SecureEdge's own MAC filter audit found 2,184 kept BruteForce flows out of
11,043 examined — the same order of magnitude, arguably comparable.

### Why this overturns the class-conditional-filtering recommendation

I previously recommended bypassing MAC filtering for BruteForce/WebBased,
reasoning that the resulting data scarcity was an artifact of a filtering bug.
This new evidence says otherwise: **XG-NID worked with almost exactly this same
scarcity for BruteForce and still reported strong aggregate results.** That
means BruteForce being data-starved after MAC filtering is not a SecureEdge-
specific problem to engineer around — it's an inherent property of this dataset
that XG-NID's own pipeline also has to contend with.

**This redirects the whole investigation.** If XG-NID gets usable results from a
similarly tiny, heavily-duplicated real BruteForce pool, the reason SecureEdge's
Run 14 collapsed to BruteForce F1=0.151 with a comparable pool size is much more
likely to be the model/normalization pipeline (Section 1) than the data volume
itself.

### Recommendation

- **Revert the class-conditional filtering exception** — apply attacker-MAC
  filtering uniformly to all attack classes, matching XG-NID exactly (Section 5
  has the literal MAC list to use).
- **Prioritize the eps/scaling fix (Section 1) over any further data-sourcing
  discussion.** The evidence now points at *how* the model processes the scarce-
  but-real data, not at needing more of it.
- WebBased's situation may differ in degree — its real pool is larger than
  BruteForce's even after filtering — but the same underlying mechanism
  (Section 1) should be tested there too before assuming a data-volume ceiling.

---

## 5. Exact Attacker MAC List (Directly Actionable)

From `Utility/Functions.py`, `split_csv()`:

```
dc:a6:32:dc:27:d5
e4:5f:01:55:90:c4
dc:a6:32:c9:e4:ab
ac:17:02:05:34:27
dc:a6:32:c9:e5:a4
dc:a6:32:c9:e4:d5
dc:a6:32:c9:e5:ef
dc:a6:32:c9:e4:90
b0:09:da:3e:82:6c
```

Applied uniformly: for any non-Benign class, keep a flow if `src_mac` OR
`dst_mac` matches this list; for Benign, exclude any flow where either matches.

**Immediate action:** diff this exact list against whatever is currently in
SecureEdge's `ATTACKER_MACS`. If they differ at all, that's a direct, verifiable
bug — fix it first, before any of the other experiments in this document, since
it's nearly free to check and could independently improve the WebBased keep-rate
data from Section 4 of the prior MAC-filter audit.

---

## 6. Confirmed Correct — No Action Needed

Two things this project already implemented were independently confirmed
correct by reading the actual source:

**Split-before-oversample (Run 14 fix).** XG-NID's `split_csv()` filters by MAC,
then splits into test/train pools, and only *afterward* does `Combining_classes()`
oversample the train portion via `duplicate_rows()`. Test sets are **not** padded
with duplicates if real data is scarce — `Combining_classes()` only downsamples
if over 4,000, never oversamples test. This is functionally identical to Run 14's
`split_first_then_oversample_train_only` methodology, including the detail that
scarce classes end up with smaller-than-4,000 test sets. Run 14's approach is a
faithful reproduction of XG-NID's actual method, not a deviation from it.

**20-packet flow/packet consistency.** XG-NID's `Feature_extractor_flow_packet_combined.py`
forces flow expiration the instant the 20th packet arrives
(`if self.limit == flow.bidirectional_packets: flow.expiration_id = -1`), in the
same NFStream pass that computes flow statistics. There is no full-flow-stats-
vs-truncated-packets mismatch in XG-NID's own code. Bottleneck 2 from the earlier
`XGNID-mine.md` comparison is very likely a non-issue for SecureEdge too, provided
`FlowCapper` mirrors this same expiration trigger — which prior project
documentation indicates it does. No further action needed unless direct
verification shows otherwise.

---

## 7. Confirmed Architecture Choice — SAGEConv Is XG-NID's Actual Default

The model instantiated and trained in `GNN4ID_Model.ipynb` is `HeteroGNN`
(SAGEConv-based, mean aggregation across edge types via the standard PyG
`HeteroConv`). The GAT-with-edge-attributes variant (`HeteroGNN_Edge`) exists in
the code but is commented out — not the model whose results are reported. This
confirms `XGNID-mine.md`'s Bottleneck 3 directly from source. SecureEdge's choice
to use GAT with edge attributes is a deliberate, reasonable enhancement over
XG-NID's actual reported architecture — worth keeping, but worth knowing it's an
enhancement rather than a reproduction gap to close.

**Optional diagnostic (lower priority than Section 1):** build the literal
SAGEConv `HeteroGNN` architecture (2 layers, mean aggregation, concat pooling,
128→64→16→8 classifier, `F.log_softmax` + `nll_loss`, no edge attributes) as a
side-by-side comparison arm. This isolates whether the edge-aware GAT is helping,
hurting, or neutral relative to the literal paper architecture.

---

## 8. Loss Function — Confirmed Equivalent, No Action Needed

XG-NID uses `F.log_softmax(logits)` + `F.nll_loss(...)`. This is mathematically
identical to `CrossEntropyLoss()` applied to raw logits. SecureEdge's current
loss function is already equivalent; no change needed here.

---

## 9. Updated Ordered Experiment Plan

One variable at a time, as always. Baseline to beat: 0.94.

| Run | Change | Batch | Regen? |
|---|---|---|---|
| 16a | BatchNorm eps=1.0, keep current feature scaling | 512 | No |
| 16b | BatchNorm eps=1.0 + remove all feature scaling (raw values, matching XG-NID) | 512 | Yes (rescale step only) |
| 17 | One-off diagnostic: batch=64, lr=0.01, ReduceLROnPlateau(mode='max', factor=0.5, patience=5, threshold=0.01, min_lr=1e-5) stepped on train accuracy, 30 epochs, using whichever of 16a/16b won | 64 (one-off) | No |
| 18 | Revert class-conditional MAC filtering; apply the verified attacker MAC list (Section 5) uniformly to all attack classes | 512 | Yes |
| 19 (optional) | SAGEConv comparison arm (Section 7) | 512 | No |

Decision rule unchanged from prior documents: ≥0.97 stops the search; ≥+0.005
over the running best keeps the change; smaller or negative deltas revert it.

---

## 10. What Must Not Change

- 92 flow features — the person's explicit standing decision; this comparison
  doesn't argue for reverting to 82, it argues about *scaling*, not feature count.
- Batch size 512 as the standing default — Run 17 is an explicitly-labeled
  one-off diagnostic, not a proposal to change the default.
- The Run 14 split methodology — independently confirmed correct in Section 6.
