# SecureEdge — Run 16b NaN Collapse: Diagnosis and Refined Fix

> **Generated:** 2026-07-05
> **Trigger:** Run 16b (BatchNorm eps=1.0 + full removal of feature scaling)
> frozen at Loss=nan, Acc=0.1325, F1=0.0293, every attack class F1=0.000, for
> 6+ consecutive epochs by epoch 36.
> **Action: kill this run now.** Frozen identical values across multiple
> epochs is the signature of NaN weights that will never recover on their own.

---

## 0. What the Screenshot Shows

```
Epoch 030 | Loss: nan | Acc: 0.1325 | F1: 0.0293 | ... Stale: 29
Epoch 031 | Loss: nan | Acc: 0.1325 | F1: 0.0293 | ... Stale: 30
...identical every epoch through 036...
```

Every attack class F1 = 0.000, Benign = 0.234. Bit-for-bit identical metrics
across six consecutive printed epochs is not a model struggling to learn — it
is a dead model. Once weights become NaN, every forward pass outputs NaN
regardless of input, `argmax` of a NaN tensor returns a fixed index every time,
and the resulting "prediction" is constant. The fixed 0.234 accuracy is just
whatever fraction of the eval set happens to share that one constant predicted
label. The collapse itself almost certainly happened in the first several
epochs, long before epoch 30 — the run has just been grinding uselessly since.

---

## 1. Leading Hypothesis: SecureEdge's Own Rate Features, Not the Core 82

XG-NID's 82 features never include this project's 8 added rate-derived
features (bytes/s, packets/s per direction, byte/packet ratio, average size).
Those features divide by flow duration. With the 20-packet cutoff in place,
very short flows — sub-millisecond in the extreme case — are entirely
possible, and `bytes / duration` for such a flow can produce an enormous, or
literally near-infinite, value.

This has never surfaced before because the StandardScaler these features
normally pass through converts any such outlier into a bounded z-score before
it reaches the network. Run 16b removed that scaler entirely (by design, to
match XG-NID's raw-feature approach) — which also removed the only thing
protecting the network from this SecureEdge-specific numerical hazard. XG-NID
never encounters this failure mode because they never computed these features
in the first place.

**Gradient clipping (already active at 1.0) is consistent with, not against,
this diagnosis.** Clipping bounds gradients, not the forward pass. If ordinary
large-but-finite unscaled values were the whole story, clipping likely would
have kept training stable, as it does for the other 82 base features. Getting
NaN despite active clipping points at an actual Inf (or a value large enough
to overflow float32 during matrix multiplication) already present in the
input data before any gradient is even computed.

---

## 2. Immediate Diagnostic (before any further training)

Before restarting anything, confirm this directly:

```python
# For each of the 92 raw flow feature columns, across the full training pool:
for i, feature_name in enumerate(FLOW_FEATURE_NAMES):
    col = raw_flow_features[:, i]
    print(f"{feature_name}: min={col.min()}, max={col.max()}, "
          f"mean={col.mean()}, n_inf={np.isinf(col).sum()}, "
          f"n_nan={np.isnan(col).sum()}, n_extreme={np.sum(np.abs(col) > 1e6)}")
```

Focus specifically on the 8 rate-derived columns (bytes/s, packets/s per
direction, ratio, avg size). Expect to find either literal `inf` values (from
true divide-by-zero) or extreme finite values (e.g., 1e8+) concentrated in
very-short-duration flows. This takes minutes to run and will confirm or rule
out the hypothesis before any more GPU time is spent.

---

## 3. Refined Fix (not "add the scaler back")

Reverting to full StandardScaler would defeat the purpose of testing raw
features against XG-NID's approach. The more surgical fix: **keep the core
76-82 XG-NID-style features raw and unscaled (they should behave fine
unscaled — XG-NID trains on them this way), and apply a light, targeted
transform only to the 8 rate-derived features that are structurally prone to
the near-zero-duration blowup.**

Two reasonable options for that targeted transform, in order of preference:

**Option A — log1p transform on the 8 rate features only:**
```python
rate_features = np.log1p(np.clip(rate_features, a_min=0, a_max=None))
```
Compresses large values into a manageable range while preserving relative
ordering, and is a standard, well-understood technique for heavy-tailed rate/
count features. Does not require fitting anything on the data (no train/test
leakage risk), unlike StandardScaler.

**Option B — hard clip on the 8 rate features only:**
```python
rate_features = np.clip(rate_features, a_min=0, a_max=some_reasonable_ceiling)
```
Simpler, but requires choosing a ceiling value, which is more arbitrary than
the log transform. Use only if Option A doesn't fully resolve the instability.

Everything else about Run 16b's design stays the same: BatchNorm eps=1.0, no
scaling on the other 84-ish features, no scaling on payload bytes or edge
attributes (revisit those too if NaN persists after fixing the rate features —
same near-zero-denominator logic could theoretically apply to link-edge delta
features if two packets arrive with near-simultaneous timestamps, though this
is a secondary concern to check only if the primary fix doesn't resolve it).

---

## 4. What To Do Right Now

1. **Kill the current Run 16b process.** It will not recover — NaN weights are
   permanent for the remainder of that run.
2. **Run the diagnostic in Section 2** on the raw flow feature pool. This is
   fast and doesn't require touching the model or retraining anything.
3. **If confirmed:** apply Option A (log1p on the 8 rate features) and restart
   Run 16b with that one change added. Everything else (eps=1.0, no scaling on
   the rest) stays as originally planned.
4. **In parallel, consider running Run 16a instead** (eps=1.0 with all current
   scaling kept in place) while the 16b fix is being sorted out. 16a has no
   raw-value exposure at all, so it isn't at risk of this specific failure
   mode, and it still tests the core eps hypothesis in isolation — which is
   the part of this experiment most worth getting a clean answer on quickly.

---

## 5. Why This Is Still a Useful Result, Not a Wasted Run

This is exactly the value of testing one variable at a time. Removing scaling
alone (without the eps change) would have hit this same NaN wall — the failure
is about the *scaling removal*, not about eps=1.0. Because 16a and 16b were
planned as separate, isolated tests, this result cleanly narrows the problem
down to the raw-feature-exposure side of the experiment, specifically flagged
now to a plausible, checkable mechanism (the 8 rate-derived features) rather
than leaving "removing scaling doesn't work" as an unexplained dead end.
