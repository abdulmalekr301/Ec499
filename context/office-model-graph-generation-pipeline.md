# Office-Network Model — Full Graph Generation Pipeline (Airtight Plan)

> **Generated:** 2026-07-11
> **Supersedes/extends:** `office-model-pretraining-checklist.md`,
> `cross-domain-generalization-test.md`, and the attacker IP/MAC mapping notes.
> This document is the authoritative, end-to-end architectural plan for going
> from raw per-host PCAPs to a training-ready graph dataset, built to hit
> exact quotas on the first attempt.

---

## 0. Target Specification (exact numbers, resolved naming)

```
Per attack class:  20,000 graphs
Benign:            20,000 graphs TOTAL, pooled across all 6 days combined
                   (NOT 20,000 per day)
```

**Resolved class taxonomy** (see Section 7 for why this needed resolving):

| Class | Source day(s) | Sub-attacks |
|---|---|---|
| BruteForce | Wed-14-02-2018 | FTP-BruteForce, SSH-Bruteforce |
| DoS | Fri-16-02-2018 | DoS-Hulk, DoS-SlowHTTPTest |
| DDoS | Wed-21-02-2018 | DDOS-HOIC, DDOS-LOIC-UDP |
| WebBased | Fri-23-02-2018 + CICIDS2017 augmentation (train-only) | Brute Force-Web, Brute Force-XSS, SQL Injection |
| Bot | Fri-02-03-2018 | Bot (Ares) |
| Infiltration | Thu-01-03-2018 | Infiltration |
| Benign | **all 6 days, pooled** | BenignTraffic (no subtypes) |

Seven classes total: six attack classes at 20,000 each (120,000 attack graphs)
plus one pooled Benign class at 20,000 — 140,000 graphs overall.

---

## 1. Research Findings: Documented CIC-IDS2018 Labeling Errors (critical new input)

Before writing any extraction code, these need to be accounted for. This
isn't hypothetical caution — these are specific, published, quantified
problems in the exact official CSVs already downloaded.

**Overall error rate.** Published audits found **up to 7.5% of flows
mislabeled** in the original CIC-IDS2018 release (Cantone et al., 2024), plus
systemic feature miscalculations (duplicated features, erroneous
directionality, inconsistent flow terminations) inherited from CICIDS2017's
own known issues (Engelen et al., 2021; Liu et al., 2022).

**Two specific, documented errors sit directly in data already in hand:**

1. **Wednesday-14-02-2018 (BruteForce day) — both attacks have a
   contamination issue**, per the corrected-documentation project
   (distrinet-research.be, CNS 2022):
   - **FTP-BruteForce flows from `18.221.219.4` → `172.31.69.25`**: the target
     port was closed (SYN packets received only `[RST, ACK]` responses), so
     the attacker never had the opportunity to actually attempt credentials.
     These should be excluded or flagged as `FTP-BruteForce - Attempted
     (Category 1 — Port/System closed)`, not treated as genuine successful
     brute-force examples.
   - **SSH-Bruteforce flows from `13.58.98.64` → `172.31.69.25:22`**: a
     specific, exactly-bounded set of flows (`Total length of Fwd Packets ==
     0`, time window `2018-02-14 18:01:50` to `19:32:30 UTC`) carry **zero
     payload bytes from the attacker** — no actual attack content was ever
     sent. These are documented as `SSH-BruteForce - Attempted (Category 0 —
     No payload sent by attacker)`. There is also a separate, documented
     contamination where some flows during this window went to **port 21**
     (FTP) rather than port 22 (SSH) — the researchers suspect the attack
     operator started the wrong tool by mistake before correcting it.
   - **Why this matters for a graph-based model specifically:** these
     "Attempted" flows have empty or near-empty payloads by definition. Packet
     nodes built from them would be uninformative padding, and training on
     them as if they were successful, characteristic BruteForce examples
     would teach the model the wrong signature — "a rejected connection
     attempt" rather than "an actual credential-guessing exchange." This is
     the exact same category of problem as the IoT model's near-zero-duration
     rate-feature issue, just manifesting as a labeling/content problem
     instead of a numerical one.

2. **Friday-02-03-2018 (Bot day) — 4 specific flows were reclassified.** The
   corrected documentation moved 4 Botnet-Ares flows from a genuine attack
   label to `Attempted (Category 2 — Attack Startup/Teardown Artefact)`. Small
   in count, but worth excluding for the same reason as above — this is the
   day already extracted and in progress.

3. **Friday-16-02-2018 (DoS day) — DoS Hulk has a known implementation
   artifact.** The corrected documentation states DoS-Hulk in CSE-CIC-IDS2018
   "suffers from the same problem" as CICIDS2017's own documented DoS-Hulk
   issue (the attack tool's traffic pattern is described elsewhere in the
   literature as unrealistically simple/repetitive compared to a genuine Hulk
   attack, which can make detection artificially easy or introduce a
   non-representative signature). No specific flow-level filter is available
   from the search results for this one — flag it as a known caveat for the
   final report rather than something to mechanically filter out, since no
   concrete correction criterion was found.

**Available correction resources (use as a third ground-truth layer):**

- **Kaggle: `ernie55ernie/improved-cicids2017-and-csecicids2018`** — corrected
  label CSVs based on Liu et al. (2022), "Error Prevalence in NIDS datasets."
  Small download (CSVs, not PCAPs), no storage-constraint conflict.
- **GitHub: `GintsEngelen/CNS2022_Code`** — contains the actual labelling
  notebooks (`CICIDS2018_labelling_fixed_CICFlowMeter.ipynb`) used to produce
  the correction, useful as a reference for the exact logic even if not run
  directly (it expects a modified CICFlowMeter run with specific timeout
  parameters — Flow Timeout 120,000,000 µs / Activity Timeout 5,000,000 µs —
  which may differ slightly from whatever generated the already-downloaded
  original CSVs, so treat it as a reference for *which flows to exclude*,
  not as a drop-in replacement feature source).
- **BCCC-CSE-CIC-IDS2018** (Shafi, Lashkari, Haghighian Roudsari, 2025) — a
  more substantial re-engineering using an entirely new traffic analyzer
  (NTLFlowLyzer, 300+ features), which specifically re-aligned DoS labels to
  attacker IPs instead of timestamps. This is a heavier adoption (different
  extraction tool entirely) — treat as a validation reference for the DoS/DDoS
  days' IP-based labeling approach (which independently confirms Section 1.6's
  IP+time-window approach is the right call), not as a data source to
  integrate directly.

**Action:** download the Kaggle corrected-label CSVs (small, no storage
conflict) and use them as a **third label source** alongside the original CSV
and the IP+time-window table (Section 1.6 of the checklist). Any flow flagged
`Attempted` or moved to a startup/teardown/closed-port category in the
corrected labels is **excluded from the training pool entirely** — not
relabeled as Benign, not kept as a weak positive, simply excluded, since it
represents neither a successful attack nor genuine benign behavior.

---

## 2. Pre-Flight Decisions (resolve before writing extraction code)

- [ ] **Class taxonomy strings finalized** — use exactly the names in
      Section 0's table (`BruteForce`, `DoS`, `DDoS`, `WebBased`, `Bot`,
      `Infiltration`, `Benign`). This resolves the `Bot`/`Botnet` and
      `Infiltration`/`Infiltration-Recon` naming inconsistency flagged
      earlier — pick one string, use it everywhere, including in file paths,
      manifests, and config.
- [ ] **Private vs. public IP resolution** (from the checklist's Section 1.6)
      — confirm empirically, using Friday-02-03-2018 (already extracted) as
      the pilot day, which IP address actually appears in victim-side
      captured packets. This gates the entire 5-tuple matching logic below.
- [ ] **Feature engineering recipe locked**: same NFStream configuration as
      the IoT model (`idle_timeout=120`, `active_timeout=1800`,
      `statistical_analysis=True`, `splt_analysis=0`, `n_dissections=0`,
      `ActiveIdlePlugin`/`PacketCapture`/`FlowCapper` with 20-packet
      expiration), same 92-feature-style computation (76 flow stats + 16
      temporal, or whatever this project's finalized feature count is),
      recomputed fresh from matched packets — **not** reused from CICFlowMeter's
      CSV feature columns. Reasoning: the CSV is used for labeling only; using
      it for feature values too would mix two different flow-extraction
      tools' feature definitions (NFStream vs. CICFlowMeter) inconsistently
      between the flow-level and packet-level halves of each graph.
- [ ] **Architecture decisions locked** (carried from the pretraining
      checklist's Section 2.4): BatchNorm eps=1.0, concat pooling, edge_attr
      through both conv layers, and an explicit decision (not a default) on
      whether multi-head GATConv is carried over or re-tested as a hypothesis
      on this dataset.
- [ ] **Benign sampling strategy across days decided** (see Section 5) —
      stratified, not naive pooled-random, to avoid one day's specific
      network conditions dominating what "Benign" means to the model.

---

## 3. Pipeline Architecture

### Stage A — Global Setup (once, before any day is processed)

1. Build the persistent cross-day manifest system. Because different classes
   only exist on specific days (BruteForce only from Wed-14-02, DDoS only
   from Wed-21-02, etc.) while Benign accumulates from every day, the manifest
   must track running per-class real-graph counts **across the whole
   multi-day workflow**, not per-day in isolation. This is the mechanism that
   makes the storage-constrained one-day-at-a-time workflow compatible with
   needing a combined 20,000-per-class target.
2. Download the corrected-label CSVs (Section 1) once, store alongside the
   original CSVs — small, no storage impact.
3. Resolve the private/public IP question (Section 2) using the already-
   extracted Friday-02-03-2018 day as the pilot.
4. Set up the IP + time-window ground truth table (from the previous
   mapping document) as machine-readable data (not just prose), for the
   automated cross-check in Stage B.

### Stage B — Per-Day Processing Loop (repeated once per day, per the
storage-constrained workflow: extract → process → save compact output →
delete raw PCAPs → move to next day)

For each day currently extracted:

1. **Build the IP → filename lookup table** for that day's ~443 host files,
   keyed on whichever IP variant was confirmed in Stage A step 3.
2. **Triple-source labeling for every candidate flow:**
   - Original CSV label (primary source of which flows exist and their
     nominal label)
   - Corrected-label CSV (Section 1) — exclude anything flagged `Attempted`
     or equivalent non-successful category
   - IP + time-window table cross-check — flag disagreement between this and
     the CSV for manual review (do not silently trust either source alone)
3. **For flows surviving all three checks and matching this day's target
   class:** extract packets via the 5-tuple → single-endpoint-file lookup
   (Section 1.5 of the checklist — never glob all 443 files and extract every
   flow independently, which double-counts internal host-to-host flows).
4. **For flows outside all attack windows and not involving any attacker IP
   (from either the CSV or the mapping table):** extract as Benign candidates
   — this happens on **every** day, not just contributing to that day's
   specific attack class.
5. **Build graphs** (flow node + up to 20 packet nodes + contain/rev_contain/
   link edges) using the locked feature recipe.
6. **Run the per-day safety checks** (NFStream sanity, payload sanity,
   rate-feature numerical safety, label accounting — all from the
   pretraining checklist's Phase 1) on this day's newly-built graphs.
7. **Save to a persistent compact reservoir** (small graph-tensor files, not
   raw packets) — append to that class's running cross-day reservoir, and
   append this day's Benign extraction to the running cross-day Benign
   reservoir. This compact output is what survives after deletion; it is
   orders of magnitude smaller than the raw per-host PCAPs.
8. **Only after checks pass:** delete this day's extracted PCAP files. Move
   to the next day.

### Stage C — Cross-Day Combination (once all 6 days have been through
Stage B)

1. **Combine each class's cross-day reservoir** into one pool per class.
   Five of the six attack classes only ever received contributions from a
   single day (BruteForce from Wed-14-02, DoS from Fri-16-02, etc.) — this
   step is mostly just consolidating that day's already-complete pool.
   WebBased is the exception: combine Fri-23-02's native pool with the
   CICIDS2017 augmentation (kept as a separate, source-tagged input — see
   Section 6).
2. **Combine the Benign reservoir** across all 6 days. This is the pool that
   genuinely needs cross-day merging.
3. **Apply content-hash deduplication** across the combined pool for every
   class — catches exact duplicates; does not catch the internal-flow
   double-capture risk (already handled structurally in Stage B step 3) or
   near-duplicate CICIDS2017 augmentation flows (handled separately, Section 6).

### Stage D — Final Split, Balance, and Graph Dataset Finalization

1. **Split-before-oversample with content-hash deduplication**
   (`split_first_then_oversample_train_only`, the IoT model's Run 14
   methodology) — applied identically here.
2. **Proportional split-ratio rule** — for any class whose combined real pool
   falls short of the comfortable threshold, scale val/test down
   proportionally rather than fixing their size and starving train (the IoT
   model's single biggest lever, per `proportional-split-ratio-fix.md`).
   Given CIC-IDS2018's per-attack real counts are generally much larger than
   CIC-IoT2023's scarcest classes, this may not bind for most classes here —
   check anyway rather than assume.
3. **Capped-floor subtype balancing** within any multi-subtype class showing
   internal skew (BruteForce: FTP vs. SSH; DoS: Hulk vs. SlowHTTPTest; DDoS:
   HOIC vs. LOIC-UDP; WebBased: Brute Force-Web vs. XSS vs. SQL Injection vs.
   CICIDS2017 additions).
4. **Oversample train only, up to 20,000 per class** (and up to 20,000 pooled
   for Benign) using whatever real pool resulted from steps 1-3.
5. **Produce the full class-distribution report** (matching
   `57_class_distribution_report.md`'s format) before considering the dataset
   final.
6. **Run the leakage audit** — confirm 0 exact duplicate compact-tensor
   hashes across train/val/test, for every class including the pooled Benign.

---

## 4. Per-Class Quota Mechanics (why Benign is architecturally different)

```
BruteForce, DoS, DDoS, Bot, Infiltration:
    single source day → single-day pool → split/balance/oversample to 20,000
    (standard case, same mechanics as the IoT model's per-subtype classes)

WebBased:
    Fri-23-02-2018 pool + CICIDS2017 augmentation (train-only, source-tagged)
    → combined pool → split/balance/oversample to 20,000
    (two-source case, needs the source-tracking discipline from Section 6)

Benign:
    Day 1 Benign extraction + Day 2 Benign extraction + ... + Day 6 Benign
    extraction → combined cross-day pool → deduplicate → split/balance/
    oversample to 20,000 TOTAL (not per day)
    (cross-day pooling case — the only class requiring the Stage A manifest
    to track a running total across the entire multi-day workflow)
```

**Benign sampling strategy across days — stratified, not naive pooling.**
Six days of background office traffic will almost certainly produce far more
than 20,000 candidate Benign flows combined, so the real risk is which 20,000
get kept, not whether there are enough. Naive random sampling from the pooled
total risks overweighting whichever day happened to produce the most candidate
flows (e.g., if Wed-21-02's DDoS day, being the most disruptive, has unusually
low benign traffic volume while a quieter day contributes disproportionately
more). Sample **roughly equally per day** (or proportionally to each day's
genuine benign volume, decided explicitly rather than defaulting to whichever
happens by accident), and **track day-of-origin as metadata** on every kept
Benign graph — this is the same discipline as the CICIDS2017 source-tagging in
Section 6, applied to an in-dataset axis (day) instead of a cross-dataset one.

---

## 5. Comprehensive Safety Checks (consolidated + new)

This section pulls together every check from the referenced documents plus
the new research findings, organized as a single pass/fail gate list.

**Structural / extraction integrity:**
- [ ] IP → filename lookup built and validated (Section 2, pre-flight)
- [ ] No flow extracted by globbing all 443 files independently — single-
      endpoint-file extraction only (Stage B, step 3)
- [ ] File-type verification — confirm no stray non-PCAP files in a day's
      folder before batch processing (flagged from the screenshot review)
- [ ] Attacker VM capture-file fallback resolved — confirm whether attacker
      IPs have their own local capture file or need victim-side extraction
      exclusively (checklist Section 1.5)

**Labeling integrity:**
- [ ] Triple-source cross-check (original CSV + corrected CSV + IP/time-window
      table) applied to every flow, not just the primary CSV
- [ ] All `Attempted`/startup-teardown/closed-port flows excluded per the
      corrected-label source (Section 1) — explicitly verify this catches the
      documented Wed-14-02 FTP/SSH contamination and the Fri-02-03 4-flow
      Botnet-Ares correction
- [ ] Disagreement rate between CSV and IP/time-window table logged and
      reviewed, not silently ignored, even for flows not caught by the
      corrected-label source
- [ ] Benign labeling rule applied strictly: outside attack windows AND not
      involving any known attacker IP AND not an attack-only victim-service
      tuple

**Numerical / feature safety:**
- [ ] Min/max/inf diagnostic on every day's raw flow features before any
      training touches the data (the Run 16b NaN lesson, applied proactively)
- [ ] Payload extraction sanity-checked per day against that day's dominant
      protocols
- [ ] log1p (or equivalent) applied to rate-derived features if the model
      starts in the raw-feature regime

**Cross-source / cross-day integrity:**
- [ ] CICIDS2017 WebBased augmentation source-tagged and confirmed train-only
      (never leaking into val/test) — re-verify the count after content-hash
      dedup, and break it down by specific subtype, not just the pooled total
      (both already flagged in the pretraining checklist)
- [ ] Benign day-of-origin tagged and stratified sampling applied (Section 4)
- [ ] Content-hash deduplication run on the final combined pool for every
      class, including pooled Benign

**Split / balance integrity:**
- [ ] Split-before-oversample with content-hash dedup confirmed to produce
      the expected per-class counts (not just assumed implemented correctly)
- [ ] Proportional split-ratio rule checked for every class, even ones
      expected to have abundant data
- [ ] Capped-floor subtype balancing applied within every multi-subtype class

**Final gate:**
- [ ] Full class-distribution report produced and matches expectations before
      training starts
- [ ] Leakage audit run, 0 exact duplicates confirmed across all splits for
      all 7 classes

---

## 6. CICIDS2017 Augmentation — Integration Point

The CICIDS2017 WebBased data is a separate dataset, not one of the 6
CIC-IDS2018 days, so it needs its own ingestion path feeding only into
WebBased's reservoir:

1. Apply the same feature-engineering recipe (Section 2) independently to its
   raw PCAPs — this is a different capture entirely, so payload-sanity and
   rate-feature-safety checks apply fresh here too, same as any new day.
2. Tag every resulting graph with `source: CICIDS2017` metadata, carried
   through the entire pipeline.
3. This source-tagged data **only ever contributes to WebBased's training
   pool** — confirm none of it ends up in val/test (Section 5, already
   flagged in the pretraining checklist, repeated here because it's easy to
   get wrong when combining two datasets' pipelines).
4. Evaluate WebBased's final performance **broken down by source tag**
   (CIC-IDS2018-native vs. CICIDS2017-augmented) at least once, to check for
   the domain-shift/shortcut-learning risk flagged throughout this project's
   discussion of external data sources.

---

## 7. What Must Not Happen (anti-patterns, stated explicitly)

- Globbing all 443 per-host files and extracting every flow independently
  (double-counts internal flows).
- Trusting the original CSV's label as sole ground truth without the
  corrected-label cross-check (misses the documented `Attempted`/contamination
  issues in data already downloaded).
- Reusing CICFlowMeter's CSV feature values directly instead of recomputing
  via NFStream (introduces a flow-tool feature-definition mismatch between
  the flow node and the packet nodes of the same graph).
- Sampling Benign by naive pooled-random selection across days without
  stratification or day-of-origin tracking.
- Letting CICIDS2017-augmented WebBased graphs leak into val/test.
- Assuming the proportional split-ratio rule or capped-floor subtype
  balancing "won't be needed here because CIC-IDS2018 has more data than
  CIC-IoT2023" — check, don't assume, for every class.
- Treating this document's numeric targets (20,000/class, 20,000 pooled
  Benign) as fixed if Stage C reveals a class's real pool can't support that
  target at a reasonable oversampling ratio — surface that as a finding
  (matching how BruteForce's and WebBased's scarcity were handled on the IoT
  model) rather than force the number through regardless of what the
  oversampling ratio ends up being.
