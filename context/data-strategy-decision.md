# SecureEdge — Data Strategy Decision: WebBased/BruteForce Underrepresentation

> **Generated:** 2026-07-04
> **Question raised:** Should we source WebBased/BruteForce data from other datasets,
> or accept XG-NID-style duplication of existing data?
> **Answer: Neither, yet.** Run the MAC filter audit first (Fix 1 from
> `run-14-diagnosis-mac-filter-attrition.md`). The evidence strongly suggests this is
> artificial scarcity from a filtering bug, not genuine data scarcity.

---

## 0. The Question Behind the Question

Both proposed options assume the current WebBased/BruteForce pool sizes (2,313 and
~1,091 real records) reflect how much data actually exists. The project's own history
says otherwise:

| Class | Documented real pool BEFORE MAC filtering | Real pool AFTER MAC filtering (Run 14) |
|---|---|---|
| WebBased | ~20,000–24,000 (multiple prior docs) | ~16,000 or less, implied by val=test=2,313 |
| BruteForce | ~11,000 (prior docs) | far smaller, implied by val=test=~1,091 |

Both pools came from the *same* CIC-IoT2023 PCAPs already on disk. Nothing about the
underlying dataset changed between "before" and "after" — only the MAC filter was
added. A large drop after adding a filter, with no change to the source PCAPs, is the
signature of a filtering bug discarding valid data, not evidence that the data was
never there.

**Do not decide between the two proposed options until this is confirmed or ruled
out.** The audit is cheap; both proposed options are expensive and carry real risk.

---

## 1. Why "Duplicate More" (Option: XG-NID-style oversampling) Doesn't Help Here

This is not a new option — it is the status quo. Random oversampling to 20,000/class
has been the standing methodology since Run 5. It is already documented
(`class-imbalance-fixes.md`) to have caused:

```
BruteForce: 66.7% duplicate fraction in training data
WebBased:   41.6% duplicate fraction in training data
```

...which produced the exact symptom now reappearing: near-zero training loss
(memorization) with stalled real-world F1. Applying more of the same oversampling
to an even smaller post-MAC-filter real pool (2,313 unique WebBased records instead
of ~20,000) would increase the duplicate fraction further, not resolve it. This
option cannot fix a problem it already caused historically.

---

## 2. Why Sourcing External Data Is Risky as a First Move

**The core risk: dataset-of-origin becomes a shortcut feature.**

If WebBased/BruteForce examples come from a different capture setup than the other
six classes, the model can learn to distinguish flows by testbed artifacts — packet
timing precision, MTU, background traffic statistics, capture card quirks — rather
than by genuine attack signatures. This would inflate validation metrics in a way
that looks like Run 13's leakage (suspiciously good numbers) but is harder to catch,
because a duplicate-content-hash audit (like `leakage_audit.py`) would not detect it
— the records would be genuinely unique, just distinguishable for the wrong reason.

**Secondary concerns:**
- Breaks the CIC-IoT2023/XG-NID faithful-reproduction framing that has anchored every
  decision in this project so far.
- New acquisition, label-taxonomy alignment, and feature-extraction validation is
  substantial new scope for a graduation project already deep into its timeline.
- Any conclusions drawn from a mixed-dataset result are harder to defend to a
  supervisor, since "why does the model do well on WebBased now" would have two
  competing explanations (genuine learning vs. dataset-shift shortcut) that are hard
  to separate without careful domain-adaptation-style validation.

**This is not a permanent "no."** If, after the MAC-filter audit, genuine scarcity
is confirmed (i.e., CIC-IoT2023 itself only contains this much real WebBased/
BruteForce traffic even with correct MAC matching), external data becomes a
legitimate option to revisit — but only with explicit validation that the model
isn't exploiting dataset-of-origin (e.g., check per-dataset-source F1 and confusion
patterns, not just overall class F1).

---

## 3. Recommended Path

```
Step 1 (near-zero cost, no new data): Run the MAC filter audit script.
        Compare actual MAC pairs in WebBased/BruteForce PCAPs against
        ATTACKER_MACS and against a working class (e.g., DDoS).

Step 2a (if audit shows valid flows were wrongly dropped — likely):
        Fix the MAC list, or apply class-conditional labeling
        (MAC filtering for DDoS/DoS/Mirai/Recon/Spoofing only;
        filename-based labeling for WebBased/BruteForce/Benign).
        Regenerate only the affected classes.
        Expected outcome: real pools return close to historical
        ~20,000 (WebBased) / ~11,000 (BruteForce) levels, restoring
        an oversampling ratio the pipeline has already handled
        reasonably well before (Run 10: WebBased 0.806, BruteForce 0.894).

Step 2b (only if audit shows genuine scarcity persists even with
        correct MAC matching):
        Accept XG-NID's own oversampling approach as the documented
        ceiling for this specific class, OR cautiously evaluate
        external same-format data with explicit dataset-shift
        validation (per-source confusion analysis) before trusting
        any resulting metric.
```

Step 1 must happen before choosing between 2a and 2b. Nothing about the current
evidence supports skipping straight to either of the two options originally proposed.

---

## 4. What This Means for the Report

If Step 2a resolves the issue, the report can honestly state that a MAC-filtering
implementation gap was identified, diagnosed via count-shortfall evidence, and
corrected — a normal part of adapting a paper's methodology to a from-scratch PCAP
pipeline. If genuine scarcity is confirmed instead, the report should state the
CIC-IoT2023 real-data ceiling for these classes plainly, per this project's
established practice of honest, evidence-grounded reporting over optimistic
projections.
