# CICIDS2017 WebBased Augmentation Plan

> **Generated:** 2026-07-13
> **Context:** CIC-IDS2018's native WebBased pool now stands at 221 real
> samples (157 original + 64 recovered via the payload-retention audit).
> Still far short of the other six classes, but a meaningfully better
> starting point than the original 157/158 estimate. This plan governs how
> CICIDS2017 gets folded in on top of that.

---

## 0. Target Recalibration (updated from the earlier "might not reach 1,000" concern)

The blanket 31.3% loss-rate assumption used in the earlier projection has
been replaced by the actual observed rate: **3.9%** (9 of 230 raw CIC-IDS2018
rows genuinely lost). Applying a comparable rate to CICIDS2017's raw 2,180
web-attack instances projects a combined total in the **~2,000-2,300 range**,
not under 1,000 — *provided* the same careful, mechanism-aware audit gets
applied there too (Section 2), not a blanket exclusion.

**This changes the target conversation.** On the IoT model, BruteForce
recovered from 184 real training examples to ~1,820 via the proportional
split-ratio fix (~11x oversample to reach 20,000) and achieved F1=0.970. A
combined WebBased total of ~2,000-2,300 real examples, oversampled to 20,000,
is a ~9-10x ratio — not meaningfully more aggressive than BruteForce's own
proven-successful playbook. **Keeping the 20,000 target may be defensible
after all**, conditional on CICIDS2017's own audit actually confirming a
total in this range. If it lands lower, fall back to explicitly documenting
a reduced target rather than forcing the number through, exactly as this
project has handled WebBased/BruteForce scarcity honestly before.

---

## 1. PCAP Structure — Confirmed Single File (significant simplification)

**Confirmed: CICIDS2017's Thursday web-attack day is a single PCAP file**,
unlike CIC-IDS2018's per-host structure (443 files/day). This is good news —
it removes an entire category of complexity that CIC-IDS2018 needed:

- **No IP → filename lookup table needed.** A single centralized capture
  sees every flow from one vantage point, closer to CIC-IoT2023's original
  per-subtype-file model than to CIC-IDS2018's per-host one.
- **No double-capture risk for internal flows.** That risk existed
  specifically because CIC-IDS2018 captured the same flow independently on
  both the attacker's and victim's local machine. A single file has no
  equivalent — every flow appears exactly once.
- **No endpoint-file-resolution bug risk** (the `part1`/`part2` filename
  parsing issue that initially zeroed out DoS/DDoS/Infiltration on
  CIC-IDS2018 doesn't have an analog here — there's only one file to stream).

**What still needs confirming, not assumed:**
- [ ] Does this single file cover the **entire Thursday** (benign background
      traffic plus all three attack windows), or is it a pre-trimmed extract
      containing only attack-relevant traffic? This doesn't change the
      extraction plan much either way (CICIDS2017's Benign traffic isn't
      being used — CIC-IDS2018's six days already comfortably cover the
      pooled Benign target), but it's worth knowing for the labeling step
      below, since a full-day file needs the same time-window carving CIC-IDS2018
      needed, while a pre-trimmed file may already be scoped to just the
      attacks.
- [ ] Confirm file size is manageable for direct NFStream streaming (CICIDS2017's
      testbed was much smaller than CIC-IDS2018's, so this is expected to be
      fine, but worth a quick check before assuming).

The labeling approach itself is unchanged — a single file still needs the
same triple-source cross-check (Section 2) to correctly identify which flows
within it are genuine attacks versus benign background traffic versus
`Attempted`-style contamination. What's simplified is purely the mechanical
step of getting from "here's a labeled flow" to "here are its packets" — one
stream instead of a 443-file lookup.

---

## 2. Apply the Same Triple-Source Labeling Discipline to CICIDS2017

CICIDS2017 has its own documented labeling-error corrections — Liu et al.
(2022), "Error Prevalence in NIDS datasets," covers **both** CIC-IDS-2017 and
CSE-CIC-IDS-2018 in the same paper. Do not treat CICIDS2017 as cleaner than
CIC-IDS2018 by default.

**Correction to this section's original attack windows.** This document
originally cited Brute Force/XSS/SQL Injection as afternoon attacks
(12:20 PM–1:42 PM), sourced from earlier research in this project. A
directly-provided official IP/time map places these attacks in the
**morning** instead (09:20–10:42), with the explicit note that Thursday
*afternoon* in CICIDS2017 is Infiltration, not WebBased. The morning/afternoon
split matches CICIDS2017's well-documented file structure (Thursday is
captured as two separate files — a morning Web Attacks file and an afternoon
Infiltration file), which makes the new times more likely correct than what
was cited here originally. **Verify directly against the actual file's
embedded timestamps or filename before finalizing** — if the file itself
confirms morning, that settles it; don't take either external source's word
over what the file actually contains.

**Updated official time windows (pending file verification):**

| Attack | Window |
|---|---|
| Web Attack - Brute Force | 09:20–10:00 |
| Web Attack - XSS | 10:15–10:35 |
| Web Attack - SQL Injection | 10:40–10:42 |

- [ ] Obtain the corrected/improved CICIDS2017 labels (same Kaggle source,
      `ernie55ernie/improved-cicids2017-and-csecicids2018`, already
      identified for the CIC-IDS2018 side).
- [ ] Confirm the corrected morning time windows above against the actual
      PCAP's own timestamps before relying on them for labeling.
- [ ] Apply the identical three-way cross-check used for CIC-IDS2018
      (original CSV label + corrected CSV label + IP/time-window match) before
      accepting any CICIDS2017 flow as a candidate.
- [ ] **Check for the same timestamp-offset trap that was found in
      CIC-IDS2018** (the 4-hour shift between the CSV and the official
      schedule table). Don't assume CICIDS2017's CSVs use the same timezone
      convention as CIC-IDS2018's — verify independently, the same way the
      original offset was discovered rather than assumed.

**New consideration: a NAT/firewall path with three address representations,
not two.** Unlike CIC-IDS2018's simpler private/public IP duality, this
attack path runs through a firewall performing NAT translation:

```
Attacker (Kali, 205.174.165.73, external)
  -> Firewall public side (205.174.165.80)
  -> Firewall internal side (172.16.0.1)
  -> Victim local IP (192.168.10.50), also reachable at public IP 205.174.165.68
```

Depending on where in this path the single PCAP was actually captured, the
addresses that appear on the wire could be the external pair
(`205.174.165.73` / `205.174.165.68`), the internal pair
(`172.16.0.1` / `192.168.10.50`), or — less likely but worth ruling out — a
mix if the capture point sits at the NAT boundary itself. **Apply the same
"verify empirically on a real packet sample" discipline used for CIC-IDS2018's
private/public IP question** (Section 1.6 of the pretraining checklist) before
building any IP-matching logic — pull a handful of packets from a known attack
window and check which specific addresses actually appear as src/dst, rather
than assume either the external or internal pair is correct.

**One piece of good news from this new information:** CICIDS2017's addressing
(`192.168.10.0/24` for the victim LAN, `205.174.165.x` externally) doesn't
overlap at all with CIC-IDS2018's `172.31.x.x` addressing — no risk of IP-space
collision or confusion when the two datasets' data gets combined later.

---

## 3. Apply the Payload-Retention Audit to CICIDS2017's Own Excluded Rows

This is the step that just recovered 64 real CIC-IDS2018 samples, and it
needs to happen here too, **not a blanket `Attempted` exclusion**:

- [ ] For every CICIDS2017 row excluded by the corrected-label filter, check
      actual forward-payload byte count from the matched packet capture.
- [ ] Split into zero-payload (keep excluded) vs. non-zero-payload
      (candidate for recovery) groups, exactly as done in
      `webbased-attempted-payload-check.md`.
- [ ] For non-zero-payload rows, confirm the payload contains subtype-
      appropriate attack syntax before recovering — same content check, not
      byte-count alone.
- [ ] Expect the same subtype-dependent pattern seen in CIC-IDS2018: brute-
      force-style web attacks (full HTTP POST required) likely recover at a
      high rate; single-shot injection attempts may not.

---

## 4. Subtype-Targeted Allocation — Not Uniform Augmentation

**Before deciding how much CICIDS2017 data to pull in for each sub-type, get
the current per-subtype breakdown of CIC-IDS2018's 221 real samples.** The
recovery exercise almost certainly changed the balance between Brute
Force-Web, XSS, and SQL Injection (60 of the 64 recovered rows were
Brute-Force-Web specifically) — augmenting uniformly across all three
sub-types without checking this first risks recreating the exact kind of
single-subtype dominance that caused problems on the IoT model's WebBased
class originally.

- [ ] **Skip or minimize SQL Injection augmentation from CICIDS2017.**
      CICIDS2017's entire raw SQL Injection count is only 21 instances total —
      smaller than what CIC-IDS2018 alone likely already provides for that
      specific subtype. This isn't worth the integration effort or the
      domain-shift risk for a source that adds so little.
- [ ] Prioritize CICIDS2017 augmentation toward whichever of Brute Force-Web
      and XSS is thinnest in the current 221-sample CIC-IDS2018 pool once
      that breakdown is reported.
- [ ] Apply the same capped-floor subtype balancing logic already established
      for the IoT model's WebBased class — a floor and ceiling per sub-type
      within the final training allocation, not letting one sub-type (likely
      Brute Force-Web, given its high recovery rate) dominate the pool simply
      because it happened to survive the audit better.

---

## 5. Feature Engineering Consistency

- [ ] Same NFStream configuration as the rest of this pipeline
      (`idle_timeout=120`, `active_timeout=1800`, `statistical_analysis=True`,
      `splt_analysis=0`, `n_dissections=0`, the same plugin set with the
      20-packet expiration trigger).
- [ ] **Recompute all 92-ish features fresh from CICIDS2017's own packets via
      NFStream — do not reuse CICFlowMeter's CSV feature columns**, for the
      same reason established earlier: the CSV is a labeling source, not a
      feature source, to avoid mixing two flow-extraction tools' feature
      definitions inconsistently within the same graph dataset.
- [ ] Run the same numerical safety diagnostic (min/max/inf check on rate-
      derived features) on CICIDS2017's data before it touches training —
      this is a different capture with potentially different flow-duration
      characteristics, so don't assume the CIC-IDS2018 safety check
      automatically covers it.

---

## 6. Source Tagging and Train-Only Integration (non-negotiable)

- [ ] Tag every CICIDS2017-derived graph with `source: CICIDS2017` metadata,
      carried through the entire pipeline — every graph object, every
      manifest entry.
- [ ] **CICIDS2017 data may only ever contribute to WebBased's training
      pool.** Confirm zero CICIDS2017-sourced graphs end up in val or test —
      this must remain built entirely from CIC-IDS2018-native data, so the
      reported evaluation metric measures performance on this project's
      actual target environment, not partly on a different dataset.
- [ ] Run the leakage audit after combining both sources — confirm 0 exact
      duplicates, and additionally confirm the val/test split contains only
      `source: CIC-IDS2018` tagged records for WebBased specifically.

---

## 7. Post-Training Verification (catches domain-shift/shortcut-learning)

Once the model is trained, before trusting WebBased's overall F1 at face
value:

- [ ] Evaluate WebBased performance **broken down by source tag** — does the
      model do comparably well on CIC-IDS2018-native WebBased test examples
      specifically, not just on the pooled average? A model that performs
      well only because it learned to distinguish "this looks like
      CICIDS2017's 2017-era traffic" rather than "this looks like a web
      attack" would show a gap here.
- [ ] If a large gap exists between native and augmented performance,
      that's a genuine finding to report, not something to average away.

---

## 8. Content-Hash Deduplication Across Combined Pool

- [ ] Run content-hash deduplication across the full combined WebBased pool
      (CIC-IDS2018-native + CICIDS2017-augmented) before finalizing. Exact
      duplicates across two genuinely different captures are unlikely, but
      this is a cheap, mechanical check worth doing as a formality rather
      than assuming it's unnecessary.

---

## 9. Decision Sequence

```
1. Get the current per-subtype breakdown of CIC-IDS2018's 221 real samples.
2. Confirm whether the single CICIDS2017 file is full-day or pre-trimmed
   (Section 1) — quick check, doesn't block anything else.
3. Apply the triple-source labeling gate to CICIDS2017 (Section 2).
4. Apply the payload-retention audit to CICIDS2017's excluded rows (Section 3).
5. Report CICIDS2017's real, audited usable count (not the raw 2,180 estimate).
6. Combine with CIC-IDS2018's 221, applying subtype-targeted allocation
   (Section 4) — skip/minimize SQL Injection from this source.
7. Decide the final WebBased target:
   - If combined total lands near or above ~2,000: keep the 20,000 target,
     justified by BruteForce's own successful ~10-11x oversample precedent.
   - If it lands meaningfully lower: explicitly document a reduced target,
     the same honest approach used for BruteForce/WebBased scarcity on the
     IoT model.
8. Apply the proportional split-ratio rule regardless of the final target —
   training gets the large majority of whatever real pool results.
9. Train, then run the per-source evaluation check (Section 7) before
   trusting the result.
```

---

## 10. What Must Not Happen

- Assuming the single CICIDS2017 file is pre-trimmed to attacks only without
  checking — if it's actually full-day, the same time-window carving logic
  from Section 2 is needed, not a simpler "just extract everything in the
  file" approach.
- Treating CICIDS2017's labels as error-free when the same research paper
  documents issues in both datasets.
- Blanket-excluding CICIDS2017's `Attempted`-equivalent rows instead of
  running the same payload-retention audit that just recovered 64 real
  CIC-IDS2018 samples.
- Uniformly augmenting all three WebBased sub-types without checking which
  ones actually need it after the recovery exercise.
- Spending integration effort on CICIDS2017's SQL Injection data (21 raw
  instances — not worth it).
- Letting any CICIDS2017-sourced graph reach val or test.
- Trusting a single pooled WebBased F1 without checking the per-source
  breakdown first.
