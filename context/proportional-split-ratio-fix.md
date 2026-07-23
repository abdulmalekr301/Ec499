# SecureEdge — Proportional Split-Ratio Fix (Implementation Spec)

> **Generated:** 2026-07-06
> **Source:** `57_class_distribution_report.md`
> **Finding:** The current split logic gives val/test a fixed absolute target
> (2,000 normally, 1,000 as an ad-hoc BruteForce fallback) before train gets
> whatever real data remains. For scarce classes, this starves training of the
> overwhelming majority of available real data. Fix: scale val/test
> proportionally instead of protecting a fixed count.

---

## 0. Per-Class Review Verdict

| Class | Verdict | Detail |
|---|---|---|
| Benign | Proceed, no change | 0% train oversampling, full real diversity |
| DDoS | Proceed, no change | 0% train oversampling, full real diversity |
| DoS | Proceed, no change | 0% train oversampling, full real diversity |
| Mirai | Proceed, no change | 0% train oversampling, full real diversity |
| Recon | Proceed, no change | 4.3% train oversampling — mild, harmless |
| Spoofing | Proceed, minor watch item | 39% train oversampling; MITM-ArpSpoofing (1,626 real) thinner than DNS_Spoofing (10,525 real) — not urgent, revisit later if Spoofing F1 stalls |
| **WebBased** | **Fix before training** | Only 627 of 4,627 real records (13.6%) reach training |
| **BruteForce** | **Fix before training** | Only 184 of 2,184 real records (8.4%) reach training |

---

## 1. The Core Finding

Confirmed directly from the report's own numbers — every class's `train_real`
equals `pool − val_target − test_target`:

```
Recon:      23143 - 2000 - 2000 = 19143  (matches "Train seed real available: 19143")
Spoofing:   16151 - 2000 - 2000 = 12151  (matches exactly)
WebBased:    4627 - 2000 - 2000 =   627  (matches exactly)
BruteForce:  2184 - 1000 - 1000 =   184  (matches exactly, using a reduced 1000 fallback)
```

Val and test are being treated as fixed-size requirements that must be filled
first, with train receiving only the leftover. This is backwards for classes
where real data is scarce: train is where the model needs real diversity to
learn anything at all; val/test only need to be large enough to measure
performance with reasonable precision, which does not require 2,000 examples
per class.

**Fraction of each class's total real data that currently reaches training:**

```
Benign/DDoS/DoS/Mirai:  71.4%  (fine — 28,000 pool comfortably covers all splits)
Recon:                  82.7%  (fine)
Spoofing:               75.2%  (acceptable)
WebBased:               13.6%  (severe — fix)
BruteForce:              8.4%  (severe — fix)
```

---

## 2. This Matches XG-NID's Own Approach, Not a Deviation From It

From the actual GNN4ID repo, `Utility/Functions.py`, `split_csv()`:

```python
if df.shape[0] > 35000:
    df_test = df.sample(n=test_sample, random_state=42)   # fixed count
else:
    df_test = df.sample(frac=0.2, random_state=42)          # proportional
```

XG-NID only uses a fixed test count for classes with abundant data (>35,000
rows). Below that threshold, they switch to a proportional split. SecureEdge's
current logic uses a fixed val/test target regardless of class size — applying
a proportional split for scarce classes is a correction toward XG-NID's actual
method, not a departure from it.

---

## 3. The Fix

### 3.1 Rule

```
COMFORTABLE_THRESHOLD = 24000   # 20000 train + 2000 val + 2000 test

FOR each class:
    IF pool_size >= COMFORTABLE_THRESHOLD:
        # unchanged — current fixed-target logic, already working correctly
        val_target = 2000
        test_target = 2000
        train_real = pool_size - val_target - test_target   # capped/oversampled to 20000 as today

    ELSE:
        # new — proportional split matching the 20000:2000:2000 ratio (83.33% : 8.33% : 8.33%)
        train_real = round(pool_size * 20000 / 24000)
        val_target = round(pool_size * 2000 / 24000)
        test_target = pool_size - train_real - val_target   # remainder, avoids rounding drift

    # train_real is then oversampled up to 20000 exactly as the current pipeline
    # already does for Recon/Spoofing — no change to the oversampling step itself,
    # only to how much real data feeds into it before oversampling.
```

### 3.2 Recomputed splits for the affected classes

| Class | Pool | New train_real | New val | New test | Old train_real |
|---|---|---|---|---|---|
| Recon | 23,143 | 19,286 | 1,929 | 1,928 | 19,143 |
| Spoofing | 16,151 | 13,459 | 1,346 | 1,346 | 12,151 |
| **WebBased** | 4,627 | **3,856** | 386 | 385 | 627 |
| **BruteForce** | 2,184 | **1,820** | 182 | 182 | 184 |

WebBased's real training diversity increases roughly 6.1x. BruteForce's
increases roughly 9.9x. Recon and Spoofing see small additional gains as a
side effect of applying one consistent rule rather than a class-by-class
patch.

### 3.3 What does NOT change

- Benign, DDoS, DoS, Mirai — pool comfortably exceeds 24,000, so the rule's
  `IF` branch keeps them exactly as they are today. No effect.
- The oversampling step itself (duplicating train_real up to 20,000) —
  unchanged mechanism, just fed a larger real pool for WebBased/BruteForce.
- WebBased's within-train capped-floor subtype balancing (Backdoor_Malware,
  BrowserHijacking, CommandInjection, SqlInjection, Uploading_Attack, XSS) —
  keep this exactly as implemented. It was working correctly; the problem was
  never the subtype-allocation scheme, it was the total real pool it had to
  work with. Re-run it against the new, larger real pool (3,856 instead of
  627) — the same floor/ceiling logic should now produce dramatically less
  extreme duplication ratios per subtype.
- The Run 14 content-hash split-before-oversample methodology, the uniform
  attacker-MAC filtering, the log1p transform on rate features, and BatchNorm
  eps=1.0 — all unrelated to this fix, all stay as they are.

---

## 4. Honest Trade-off, Stated Explicitly

Shrinking WebBased's val/test from 2,000 to ~386/385 each, and BruteForce's
from 1,000 to ~182 each, means slightly less precise evaluation metrics for
these two classes specifically — a few hundred examples gives a noisier F1
estimate than a couple thousand. This is a deliberate, favorable trade: the
alternative was spending 86-92% of all available real data purely on
measurement while starving the model of the diversity it needs to have
anything worth measuring accurately in the first place. A model trained on
3,856 real WebBased examples and evaluated on 386 will be a better and more
informatively-evaluated model than one trained on 627 and evaluated on 2,000.

---

## 5. Regeneration and Verification Steps

1. Implement the threshold rule in the split-construction code (wherever
   `57_class_distribution_report.md`'s numbers are currently produced).
2. Regenerate reservoirs/splits for Recon, Spoofing, WebBased, and BruteForce
   (Benign/DDoS/DoS/Mirai untouched, no need to regenerate).
3. Re-run the WebBased capped-floor subtype balancing against the new, larger
   real training pool (3,856 instead of 627) — expect substantially lower
   per-subtype duplication ratios as a direct consequence.
4. Re-run `leakage_audit.py`. Confirm exact-duplicate counts remain 0 across
   all splits — this must stay true regardless of the new split ratios.
5. Regenerate a new class distribution report (same format as
   `57_class_distribution_report.md`) and confirm the new train/val/test
   counts match Section 3.2's expected numbers before starting training.

---

## 6. Training Command (unchanged)

Same configuration as the most recent run — eps=1.0, log1p on rate features,
capped-floor WebBased subtype balancing, uniform MAC filtering:

```bash
SECUREEDGE_DEVICE=cuda \
SECUREEDGE_BATCH_SIZE=256 \
SECUREEDGE_GRAD_ACCUM_STEPS=2 \
SECUREEDGE_LR_TARGET=0.003 \
SECUREEDGE_LR_MIN=1e-5 \
SECUREEDGE_SCHEDULER=cosine \
SECUREEDGE_COSINE_T0=50 \
SECUREEDGE_COSINE_T_MULT=2 \
SECUREEDGE_MAX_EPOCHS=300 \
SECUREEDGE_EARLY_STOP=75 \
SECUREEDGE_LABEL_SMOOTHING=0.0 \
python -m secureedge.models.train
```

Delete the previous checkpoint before starting — the underlying data pool for
four classes has changed.

---

## 7. Expectations

WebBased should benefit substantially — 6x more real training diversity is a
much larger lever than any within-class duplicate-allocation scheme could
provide on its own. BruteForce should also improve, though it's worth staying
realistic: even at ~1,820 real training examples, BruteForce remains by far
the scarcest class (matching XG-NID's own comparably tiny real BruteForce
pool), so meaningful improvement is plausible but it will likely remain the
hardest class to fully solve. Track per-class F1 at the same checkpoints as
before, and specifically watch whether BruteForce's earlier failure pattern
(TP near zero, FP near zero — the model refusing to predict the class at all)
changes shape, even if the absolute F1 doesn't yet reach the other classes'
level.
