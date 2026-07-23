# SecureEdge — WebBased Subtype-Balanced Oversampling (Implementation Spec)

> **Generated:** 2026-07-05
> **Proposal source:** Equalize WebBased's 6 sub-attack-types via targeted
> duplication before the existing train/val/test split, rather than pooling
> and oversampling the class as one undifferentiated group.
> **Verdict: worth testing as an isolated experiment, with two guardrails.**
> It diverges from XG-NID's stated methodology (which preserves natural subtype
> proportions, not equal ones) and needs a fuller audit before committing to an
> exact scheme. Both are addressed below.

---

## 0. What Problem This Targets

WebBased is one class made of six structurally different attack techniques:
SqlInjection, XSS, BrowserHijacking, CommandInjection, Uploading_Attack, and
Backdoor_Malware. Pooling all six and oversampling the class as a unit means
whichever subtype survived MAC filtering in the largest numbers dominates the
resulting training signal. From the (sampled) MAC filter audit:

```
SqlInjection:      2,830 kept  (~61% of surviving pool)
BrowserHijacking:    972 kept  (~21%)
Backdoor_Malware:    244 kept  (~5%)
CommandInjection:    275 kept  (~6%)
Uploading_Attack:     84 kept  (~2%)
XSS:                 222 kept  (~5%)
```

If oversampling to 20,000 draws from this pool proportionally (as simple
random-with-replacement duplication would), the resulting training set is
dominated by SqlInjection-like patterns, with several subtypes contributing a
few hundred duplicated slots each. A model trained this way risks becoming a
strong SqlInjection detector wearing a "WebBased" label, generalizing poorly to
val/test examples of the rarer subtypes — which could contribute to (though not
fully explain, see Section 4 below) Run 14's WebBased collapse.

---

## 1. Important Counter-Evidence: XG-NID Did the Opposite

From the XG-NID paper directly:

> *"Since each main attack class in the CIC-IoT2023 dataset contains several
> subclasses, we ensured that the sampling process maintained **proportional**
> representation across these subclasses."*

XG-NID deliberately preserved natural, skewed subtype ratios rather than
equalizing them. Implementing equal-subtype balancing is a genuine deviation
from their methodology, not a reproduction of it. This doesn't disqualify the
idea — it may be a real improvement over what they did — but it should be
tested and compared against a proportional (XG-NID-faithful) baseline, not
adopted as an assumed fix.

---

## 2. The Trade-off: Diversity vs. Duplication Ratio

Equalizing to a 1/6 share per subtype means the rarest subtype needs *more*
duplication than its natural share would require, not less:

| Subtype | Real (sampled) | Natural share of 20,000 | Natural oversample factor | Equal 1/6 share of 20,000 | Equal oversample factor |
|---|---|---|---|---|---|
| SqlInjection | 2,830 | ~12,200 | ~4.3x | ~3,333 | ~1.2x (undersampled) |
| BrowserHijacking | 972 | ~4,200 | ~4.3x | ~3,333 | ~3.4x |
| CommandInjection | 275 | ~1,190 | ~4.3x | ~3,333 | ~12.1x |
| Backdoor_Malware | 244 | ~1,050 | ~4.3x | ~3,333 | ~13.7x |
| XSS | 222 | ~960 | ~4.3x | ~3,333 | ~15.0x |
| Uploading_Attack | 84 | ~360 | ~4.3x | ~3,333 | ~39.7x |

(Using the sampled-audit counts as a stand-in for illustration — see Section 3
on why the real full-file counts need to be measured before finalizing a
scheme.) Equal balancing means the rarest subtype (Uploading_Attack) would be
duplicated roughly 40x instead of ~4x, while the most common subtype
(SqlInjection) would actually be *undersampled* relative to its available real
diversity. This is a genuine trade: more balanced exposure across subtypes,
paid for with heavier memorization risk on the rarest ones. It is not free, and
it is not obviously a net win — that's why this should be tested, not assumed.

**A middle-ground worth considering instead of strict equality:** cap the
maximum subtype share (e.g., no subtype exceeds 35-40% of the class pool) and
set a floor for the minimum share (e.g., no subtype falls below 8-10%), rather
than forcing exact 1/6 each. This captures most of the diversity benefit
without pushing Uploading_Attack to a ~40x duplication ratio. Worth testing as
a third variant alongside strict-equal and natural-proportional.

---

## 3. Prerequisite: Run the Full, Uncapped Subtype Audit First

The subtype counts used above come from `mac_filter_audit.py` run with
`--max-flows-per-subtype 12000 --max-files-per-subtype 3` — a capped sample,
not an exhaustive count. Before implementing any specific balancing scheme,
re-run the audit without those caps, across every available file per subtype:

```bash
SECUREEDGE_ENABLE_ATTACKER_MAC_FILTER=1 \
SECUREEDGE_ATTACKER_MACS_FILE=context/attacker_macs.txt \
.venv/bin/python -m secureedge.data.mac_filter_audit \
  --report artifacts/mac_filter_audit_full.json
  # no --max-flows-per-subtype or --max-files-per-subtype caps
```

The true relative skew across the full file set may differ from the sampled
numbers above, especially for subtypes with more than 3 source files. Use the
full counts to decide between strict-equal, capped-floor, or proportional
balancing — don't commit to a specific scheme from the sampled numbers.

---

## 4. Honest Caveat: This May Not Fully Explain Run 14's WebBased Collapse

Run 14's WebBased result was total (TP=0, not partial degradation), which
points to something more categorical than "the model is biased toward
SqlInjection but still detects some WebBased traffic." Subtype imbalance within
the class is a real, additive concern worth fixing, but it sits alongside —
not instead of — the higher-priority hypotheses from `xgnid-repo-comparison-findings.md`
(BatchNorm eps/feature-scaling mismatch, Section 1 of that document). Test this
subtype-balancing change as its own isolated experiment; don't expect it alone
to resolve a complete collapse if the more fundamental model/normalization
issue is still present.

---

## 5. Implementation

### 5.1 Scope the equalization to training only

This is the critical guardrail. Val and test must keep the natural, unweighted
real subtype distribution:

```
PROCEDURE build_webbased_pool(real_records_by_subtype, split_assignment):
    # split_assignment already determined by Run 14's content-hash
    # split-before-oversample logic — this does NOT change.

    FOR each real WebBased record:
        it is already assigned to train, val, or test (content-hash based,
        unchanged from Run 14)

    # Val and test: leave exactly as Run 14 produces them.
    # No subtype-level rebalancing applied here — natural distribution stands.

    # Train only: apply subtype-balanced oversampling
    train_records_by_subtype = {subtype: [real records assigned to train]
                                 for each of the 6 subtypes}

    target_per_subtype = TRAIN_TARGET_FOR_CLASS / 6   # strict-equal variant
    # OR apply capped-floor logic (Section 2) as an alternative variant

    FOR each subtype:
        oversample (duplicate with replacement) train_records_by_subtype[subtype]
        up to target_per_subtype

    train_pool_for_webbased = concatenate all 6 oversampled subtype pools
    shuffle(train_pool_for_webbased)
```

### 5.2 What does NOT change

- The Run 14 content-hash split-before-oversample methodology for determining
  which real records go to train/val/test — unchanged.
- Val/test composition — natural subtype distribution, no rebalancing.
- Every other class's oversampling logic — this change is scoped to WebBased
  only (and could be extended to other multi-subtype classes later if it helps,
  but should be tested on WebBased alone first).
- 92 flow features, batch size 512, the leak-free split methodology, the
  uniform attacker-MAC list (Section 5 of `xgnid-repo-comparison-findings.md`).

---

## 6. Recommended Approach (Decision, Not Just Options)

**Capped-floor rebalancing, not strict equal.** Concrete parameters:

```
Floor:   10% minimum per subtype  (2,000 of the 20,000 training slots)
Ceiling: 30% maximum per subtype  (6,000 of the 20,000 training slots)

Algorithm:
  1. Allocate every subtype its floor of 2,000 slots first (6 x 2,000 = 12,000).
  2. Distribute the remaining 8,000 slots proportionally to each subtype's
     real-data availability, capping any single subtype's total at 6,000.
```

Applied to the current (sampled) audit proportions, this lands approximately at:

```
SqlInjection:      6,000  (capped down from its natural ~12,200 share)
BrowserHijacking:  ~4,500
Backdoor_Malware:  ~2,500
CommandInjection:  ~2,500
XSS:               ~2,500
Uploading_Attack:  2,000  (floor only)
```

**Why not strict equal:** forcing exact 1/6 shares would push Uploading_Attack
from ~84 real examples to a 3,333-slot share — roughly 40x duplication of a
tiny handful of captures, which is very likely pure memorization with no
generalization benefit. The floor/ceiling scheme guarantees every subtype a
meaningful training presence without pushing the rarest ones to that extreme,
and it incidentally *reduces* SqlInjection's oversample factor (from a natural
~4.3x to ~2.1x under the cap), giving the model less repetition and more
effective diversity per epoch on the subtype that actually has real diversity
to offer.

**Sequencing — test this second, not first.** Run 14's WebBased result was
total non-detection (0 of 2,313), not degraded or biased detection. Subtype
dominance predicts the latter (a model good at SqlInjection, weak on the other
five) — not the former. Total collapse points more strongly at the BatchNorm
eps/feature-scaling mismatch in `xgnid-repo-comparison-findings.md` (Section 1)
actively destroying the payload channel's signal before the model gets a
chance to learn any subtype at all. Run the eps/scaling test (16a/16b) first,
in isolation. Apply this capped-floor rebalancing afterward, as its own
isolated run, only if WebBased still underperforms once the eps/scaling fix is
in place. Running both changes in the same experiment is possible if time
pressure demands it, but if WebBased recovers, there will be no way to
attribute the recovery to either fix specifically — which matters for what
gets written in the final report as the identified cause.

| Run | Change | Depends on |
|---|---|---|
| 16a/16b | BatchNorm eps=1.0 (+/- feature scaling removal) | Run first, isolated |
| 20 | Capped-floor subtype rebalancing (numbers above), train-only scoped | After 16a/16b, only if WebBased still weak |

Use the same training config throughout (batch 512, cosine, lr 0.003) so the
only variable in Run 20 is WebBased's internal subtype composition. Decision
rule unchanged from prior documents: >=0.005 improvement over the Run 16
result keeps the change; smaller or negative deltas revert it.

Track per-subtype recall within WebBased at evaluation time (not just overall
WebBased F1) — this is the only way to tell whether Run 20 actually improved
coverage of the rarer subtypes or just reshuffled which ones the model favors.
