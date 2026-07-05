# SecureEdge — Class-Conditional MAC Filtering (Implementation Spec)

> **Generated:** 2026-07-04
> **Based on:** `46_data_strategy_mac_filter_audit.md`, `47_data_strategy_decision_checks.md`
> **Decision:** Implement class-conditional filtering (Option 2). Do not source
> external data. Do not increase oversampling. Do not attempt to find a single
> corrected attacker MAC for WebBased — the subtype-level evidence argues against
> a single-MAC fix (see Section 1).

---

## 0. Audit Confirms the Diagnosis

| Class | Kept fraction | Verdict |
|---|---|---|
| DDoS (control) | 97.5% | Filter works as intended |
| WebBased | 18.1% | Filter discards most real flows |
| BruteForce | 19.8% | Filter discards most real flows |

The prior hypothesis (`run-14-diagnosis-mac-filter-attrition.md`) is confirmed: the
WebBased/BruteForce scarcity seen in Run 14 was substantially filter-induced, not a
true limit of the source PCAPs.

---

## 1. Why Class-Conditional Filtering, Not a Corrected MAC List

The WebBased subtype-level keep rates rule out a simple "wrong MAC" explanation:

```
SqlInjection:      45.3% kept
BrowserHijacking:  20.4% kept
Backdoor_Malware:   7.5% kept
XSS:                5.2% kept
Uploading_Attack:   5.2% kept
CommandInjection:   5.0% kept
```

A single missing/incorrect attacker MAC would produce roughly uniform failure across
all six subtypes. The 9x spread (45.3% vs 5.0%) instead suggests some WebBased attack
techniques structurally do not preserve the attacker's original MAC in the flows NFStream
sees — e.g., traffic reflecting an already-compromised device's own outbound calls, or
a path through a hop that rewrites L2 addressing for some techniques but not others.
Chasing a corrected MAC list would require separate per-subtype investigation with
uncertain payoff. Class-conditional filtering sidesteps this entirely and is
implementable immediately.

---

## 2. The Trade-off (state this explicitly, don't treat it as free)

Reverting WebBased/BruteForce to filename-based labeling restores real attacker flows
but also restores whatever background/benign noise those flows contained — the
original reason MAC filtering was added. This is an accepted trade: recovering to
~20,000/~11,000 real flows with some label noise is better than ~4,600/~2,184 real
flows with clean labels, because the latter starves the model of enough diversity to
generalize at all (as Run 14 demonstrated — WebBased F1 = 0.000).

Historical precedent supports this trade being net-positive: Run 10, using pure
filename labeling with the *older* architecture, already reached WebBased 0.806 /
BruteForce 0.894. The current architecture (concat pooling, edge_attr in conv2) is
stronger, so applying it to filename-labeled WebBased/BruteForce data should plausibly
match or exceed those numbers.

---

## 3. Implementation

### 3.1 Config change

```python
# config.py

MAC_FILTERED_CLASSES = {"DDoS", "DoS", "Mirai", "Recon", "Spoofing"}
# WebBased and BruteForce: filename/subtype-based labeling, no attacker-MAC filter.
# Benign: keep existing strict behavior (exclude any flow involving an attacker MAC,
#         regardless of which list — this protects against WebBased/BruteForce
#         attacker devices' traffic leaking into the Benign pool).
```

### 3.2 Routing logic (wherever the filter is currently applied — likely `extract_worker.py`)

```
FUNCTION should_keep_flow(flow, class_name, src_mac, dst_mac):

    IF class_name == "Benign":
        # unchanged — exclude any flow touching any known attacker MAC
        RETURN src_mac NOT IN ALL_ATTACKER_MACS AND dst_mac NOT IN ALL_ATTACKER_MACS

    IF class_name IN MAC_FILTERED_CLASSES:
        # unchanged — existing validated behavior for DDoS/DoS/Mirai/Recon/Spoofing
        RETURN src_mac IN ATTACKER_MACS OR dst_mac IN ATTACKER_MACS

    # WebBased, BruteForce — no MAC filter, revert to filename/subtype labeling only
    RETURN True
```

`ALL_ATTACKER_MACS` for the Benign exclusion should include any attacker MAC known
from any class's testbed session, not just the ones validated for the flood/recon/
spoof classes — this keeps Benign filtering strict regardless of which devices were
used for WebBased/BruteForce.

### 3.3 What does NOT change

- MAC filtering for DDoS, DoS, Mirai, Recon, Spoofing — validated at 97.5%+ keep rate,
  leave untouched.
- Benign filtering — keep strict, unchanged.
- The Run 14 split methodology (`split_first_then_oversample_train_only`, content-hash
  grouping, train-only oversampling). Whatever real pool results from this change
  still goes through that same leak-free pipeline.
- 92 flow features, batch size 512, cosine schedule (lr 0.003, T0=50, T_mult=2) — all
  fixed decisions from prior rounds, unrelated to this fix.
- Architecture (concat pooling, edge_attr in conv2) — keep as is.

---

## 4. Regeneration and Verification Steps

1. Regenerate reservoirs for WebBased and BruteForce PCAPs only, using filename-based
   labeling (no MAC filter). DDoS/DoS/Mirai/Recon/Spoofing/Benign reservoirs are
   unaffected and do not need regeneration.
2. Rebuild the balanced pool, graphs, and shards using the Run 14 split pipeline
   (content-hash split-before-oversample).
3. Confirm real pool sizes for WebBased and BruteForce return close to historical
   levels (~20,000–24,000 for WebBased, ~11,000 for BruteForce) rather than the
   MAC-filtered ~4,600 / ~2,184.
4. Confirm val/test counts for WebBased and BruteForce return to the full 4,000/class
   target (or close to it), matching the other six classes.
5. Re-run `leakage_audit.py`. Confirm exact-duplicate counts remain 0 across all
   splits for all classes — this must stay true regardless of the labeling change.
6. Spot-check `subtype_label` diversity within the WebBased training pool — confirm
   all 6 sub-types (SqlInjection, XSS, BrowserHijacking, CommandInjection,
   Uploading_Attack, Backdoor_Malware) are represented, not just the higher-yield ones.

---

## 5. Run 15 — Training Command

Same configuration as Run 14 (only the labeling source for two classes changed
upstream in the data; nothing about training changes):

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
python -m secureedge.models.train
```

Delete `artifacts/best_hgnn.pt` before starting (fresh data for two classes;
avoid any confusion with the Run 14 checkpoint).

---

## 6. Success Criteria

| Result | Interpretation |
|---|---|
| WebBased ≥ 0.80, BruteForce ≥ 0.89 (meets/beats Run 10) | Fix worked as expected; architecture improvements plus restored data compound |
| WebBased/BruteForce improve but stay below Run 10 | Some benefit, but background noise cost may be higher than Run 10's older data cut; inspect confusion matrix for these two classes |
| WebBased/BruteForce still near-zero | Something else is wrong — check the routing logic actually bypassed the filter for these two classes; verify with the audit script |
| Other six classes regress from Run 14 | Unexpected — the change should not touch their pipeline at all; investigate for an implementation error in the routing logic |

Log per-class F1 every 10 epochs, matching Run 14's format. Watch WebBased and
BruteForce specifically for the first 50 epochs — recovery should be visible early
if the fix is working, since these classes previously converged reasonably by
epoch 50 in Run 6 (heads=2 architecture, filename labeling).

---

## 7. Deferred, Not Abandoned

If time permits after this fix is validated, the SqlInjection anomaly (45.3% keep
rate vs. 5–20% for other WebBased subtypes) is worth a short follow-up: confirm
whether SqlInjection's higher match rate reflects a genuinely different attack
delivery mechanism, or a data artifact worth understanding for the project report.
This is not a blocker for Run 15.
