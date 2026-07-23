# CIC-IDS2018 Thursday-22-02-2018 WebBased Verification Plan

> **Generated:** 2026-07-13
> **Context:** A second official CIC-IDS2018 web-attack day was found — not
> part of the original 6-day selection. This is same-testbed, same-lab,
> zero-domain-shift data, and should be prioritized over further CICIDS2017
> augmentation work if it holds up under verification.
> **Do not add the raw counts from the source document directly to the pool.**
> One of its numbers is already demonstrably inconsistent with this project's
> own validated pipeline — verify before trusting, exactly as every other
> ground-truth table in this project has been treated.

---

## 0. The Discrepancy That Needs Resolving First

The source document states `Friday-23-02-2018 WebBased: 566`. Four
independent runs of the coding agent's own validated pipeline (candidate
manifest, IP/time cross-check, pretraining-checklist implementation, and the
payload-retention audit) consistently show Friday at **230 raw rows, 221
after audit** — not 566. That's a 2.5x gap with no stated explanation.

This does not necessarily mean the source document is wrong about Thursday's
data existing — it likely reflects a different counting methodology (e.g.
raw ground-truth-window matches before deduplication, or a bidirectional
double-count) than the validated pipeline uses. But it does mean **Thursday's
stated counts (249 / 79 / 34 / 362) cannot be trusted at face value** until
they're independently confirmed the same way Friday's were.

**Before anything else: figure out why the Friday number differs by 2.5x.**
If it turns out to be a simple methodology difference (e.g., before-dedup vs.
after-dedup counts), that's useful to know and likely means Thursday's real
number is smaller than 362 too, proportionally. If it turns out to be a data
source error, that needs to be understood before using this document for
anything.

---

## 1. Apply the Exact Same Pipeline Already Built for Friday

Nothing new needs to be invented here — Thursday should go through the
identical process, not a shortcut:

- [ ] **Confirm PCAP structure** — is Thursday-22-02-2018 also captured as
      ~443 per-host files, matching every other CIC-IDS2018 day? Don't assume;
      check, the same way every prior day's structure was verified rather
      than assumed.
- [ ] **Triple-source labeling gate**: original CSV label + corrected/
      improved CSV label + IP/time-window ground truth. Use the times in the
      source document (10:17-11:24, 13:50-14:29, 16:15-16:29) as a starting
      hypothesis only — **verify against the actual PCAP's own timestamps**
      before trusting them, exactly as was necessary for CICIDS2017's
      morning/afternoon mix-up two messages ago. A hand-compiled reference
      table has now been wrong twice in this project (the CICIDS2017 time
      window, and very possibly this document's Friday count) — treat every
      new one as a claim to verify, not a given.
- [ ] **Re-verify the 4-hour timestamp offset** applies here too. It was
      confirmed for the original 6 days; don't assume it automatically holds
      for a day that wasn't part of that original verification pass.
- [ ] **Apply the payload-retention audit** to any `Attempted`-equivalent
      exclusions on Thursday, exactly as done for Friday — check actual
      forward-payload bytes and content-match against subtype-appropriate
      attack syntax before excluding or recovering any row.
- [ ] **Source-tag every Thursday-derived graph** distinctly from Friday's
      (e.g. `source: CIC-IDS2018-Thursday` vs `source: CIC-IDS2018-Friday`)
      even though both are native CIC-IDS2018 data — this costs nothing and
      preserves the ability to check for day-specific artifacts later if
      needed, consistent with the day-of-origin tracking already used for
      pooled Benign sampling.

---

## 2. Projected Impact (explicitly labeled as a projection, not a result)

If Thursday's actual audited loss rate resembles Friday's low rate (3.9%)
rather than CICIDS2017's much higher rate (~95%) — plausible, since Thursday
and Friday share the same testbed and almost certainly the same attacker
tooling, unlike CICIDS2017's separate infrastructure:

```
Friday-23-02-2018 (validated):        221
CICIDS2017 augmentation (validated):  167
Thursday-22-02-2018 (projected):     ~348   <- pending actual audit
---------------------------------------------
Projected combined total:            ~736

Resulting oversample ratio to reach 20,000: ~27x
(compare: proven-successful ~11x, proven-failed ~109x)
```

This is still above the range this project has seen succeed, but a real
improvement over the 57x figure from the CICIDS2017-only combined total. It
does not, on its own, fully justify returning to a 20,000 target — but it
meaningfully changes the target-selection math from the last plan revision,
which was based on ~351 total, not ~736.

---

## 3. Sequencing

```
1. Resolve the Friday-566-vs-221 discrepancy — understand its source before
   trusting Thursday's numbers at all.
2. Run Thursday-22-02-2018 through the identical validated pipeline
   (Section 1) — structure check, triple-source labeling, timestamp/IP
   verification against real packets, payload-retention audit.
3. Report Thursday's actual audited count.
4. Recompute the combined total (Friday + CICIDS2017 + Thursday) using real
   numbers, not the Section 2 projection.
5. Only then finalize WebBased's target — this may land somewhere between
   the ~3,500-5,000 range recommended off the ~351 figure and a higher range
   if Thursday contributes close to its projected ~348, using the same
   oversample-ratio reasoning (aim for something in the 10-15x range based on
   the BruteForce precedent, not a fixed 20,000).
```

---

## 4. What Must Not Happen

- Adding the source document's raw counts (249/79/34/362, or the 566 Friday
  figure) directly into any manifest without running them through the
  validated pipeline first.
- Trusting the stated Thursday time windows without verifying against actual
  PCAP timestamps — this project has now seen a hand-compiled reference table
  be wrong once already (CICIDS2017) and has an unexplained 2.5x discrepancy
  in this exact document's other stated number.
- Continuing further CICIDS2017 augmentation work (e.g. reconsidering SQL
  Injection, or expanding the recovery criteria) before this same-testbed,
  zero-domain-shift source is fully verified and exploited — it's strictly
  better data if it holds up, so it should be resolved first.
- Finalizing WebBased's target number before Thursday's real contribution is
  known.
