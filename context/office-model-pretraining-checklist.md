# Office-Network Model — Pre-Training Checks & Audits Checklist

> **Generated:** 2026-07-07 | **Updated:** 2026-07-10 (per-host capture
> structure discovered; IP/time-window attacker-victim ground truth added)
> **Context:** New XG-NID-architecture model for office/PC/server/router
> network security, trained on CIC-IDS2018 (+ CIC-IDS2017 WebBased
> augmentation). Storage-constrained workflow: PCAPs extracted one day-zip at
> a time, then deleted after processing.
> **First extracted:** Friday-02-03-2018 (Bot day — no direct overlap with
> SecureEdge's IoT taxonomy, but is one of this new model's own target
> classes. No issue, just orientation.)
> **Critical structural finding:** each day's zip contains ~443 **per-host**
> PCAP files (`cap<hostname>-<IP>`, one file per machine — matching CIC-IDS2018's
> documented ~420 PCs + ~30 servers), not one consolidated capture like
> CIC-IoT2023's per-subtype files. This changes both labeling (Section 1.4) and
> flow extraction (new Section 1.5) — see below. Labeled CSVs for every day
> have been downloaded, which resolves the labeling side of this; the
> extraction side still needs the strategy in Section 1.5. An official
> attacker/victim IP + time-window ground-truth table (Section 1.6) is now
> available as a cross-check against the CSV labels.

---

## 0. How to Use This Document

Checks are organized into three phases matching the actual workflow:

- **Phase 1 — Per-day, immediately after extraction, before deleting the zip.**
  If something looks wrong here, you still have the raw PCAP on the external
  drive and can re-extract without a full re-download cycle. Once a zip is
  deleted, fixing a discovered problem means pulling it back from the external
  drive — annoying but recoverable, so still worth catching early rather than
  discovering it after all 6 zips are gone.
- **Phase 2 — Final gate, once all days are extracted and combined**, before
  the first training run starts.
- **Phase 3 — Post-training**, before treating any result as final or moving
  toward deployment integration.

Every check below traces back to a specific, real problem this project hit on
the IoT model. Re-verifying rather than assuming is the point — the recipe is
proven, but proven *for a different dataset*.

---

## 1. Phase 1 — Per-Day Checks (run on each extracted day before deleting its zip)

### 1.1 NFStream extraction sanity
- [ ] Same NFStream configuration as the proven IoT recipe: `idle_timeout=120`,
      `active_timeout=1800`, `statistical_analysis=True`, `splt_analysis=0`,
      `n_dissections=0`, plugins (`ActiveIdlePlugin`, `PacketCapture`,
      `FlowCapper` with the 20-packet expiration trigger).
- [ ] **Check `accounting_mode`** — this was flagged during the XG-NID source
      comparison as an unresolved open question (affects byte/size feature
      computation) and never fully confirmed either way. Worth settling now
      rather than carrying the same unknown into a second model.
- [ ] Confirm the 20-packet flow/packet-node consistency (`expiration_id=-1`
      trigger) actually fires correctly on this dataset's traffic patterns.
      CIC-IDS2018 has long-lived sessions (SMB file transfers, RDP sessions)
      that behave very differently from IoT's short bursts — don't assume the
      same trigger logic behaves identically on fundamentally different flow
      durations without checking a sample.

### 1.2 Payload extraction sanity (per day, since protocol mix differs by attack type)
- [ ] Verify payload bytes extracted for this day's flows are sensible,
      non-garbage content for whatever protocols dominate that day (HTTP/S,
      FTP, SSH, RDP, SMB, SMTP, DNS — all different from IoT's MQTT/CoAP).
      This is a fresh version of the same check performed for the IoT model's
      packet payloads (previously confirmed working via direct verification)
      — do not assume the same extraction logic produces sensible bytes for
      an entirely different protocol mix without checking a sample.
- [ ] Spot-check non-zero fraction and mean payload byte value for this day's
      flows — flag anything wildly different from the IoT baseline (was
      0.15-0.22 non-zero fraction, mean ~0.07) for follow-up, not necessarily
      alarming on its own, but worth knowing.

### 1.3 Rate-feature numerical safety (the NaN lesson)
- [ ] Run the min/max/inf diagnostic on this day's raw flow features
      (especially any rate-derived features: bytes/s, packets/s, ratios)
      **before** any training touches this data. This is the exact check that
      would have caught the Run 16b NaN collapse before it happened — do it
      proactively this time instead of after a wasted run.
- [ ] Confirm the log1p transform (or equivalent) is applied to rate-derived
      features from day one if the new model uses raw/unscaled features —
      decide this explicitly (see Phase 2, Section 2.4) rather than
      discovering a NaN collapse partway through Day 3's processing.

### 1.4 Per-day label/subtype accounting
- [ ] Record real (pre-oversampling) flow counts for every label/subtype
      present in that day, matching the granularity of
      `57_class_distribution_report.md` — this builds incrementally as each
      day is processed, rather than trying to reconstruct it after all zips
      are deleted.
- [ ] Cross-check this day's actual label distribution (from CIC-IDS2018's own
      provided `Label` column in the accompanying CSV) against the expected
      attack-schedule mapping from `cross-domain-generalization-test.md`,
      Section 1 — confirms the day-to-attack mapping used for planning is
      actually correct for this specific file, not just well-documented in
      general.
- [ ] **Label source is the CSV, not the filename or folder.** Unlike
      CIC-IoT2023 (where the PCAP filename directly gave the label), each
      day's PCAP zip contains ~443 per-host files, and any single host's
      capture can mix benign and attack traffic together depending on whether
      that machine was targeted. There is no shortcut here — every flow's
      label comes from matching it against the day's labeled CSV (see 1.5),
      never inferred from which file it came from.

### 1.5 Per-host PCAP structure — flow extraction strategy (new, CIC-IDS2018-specific)

CIC-IDS2018 captures traffic **locally on each host** (`cap<hostname>-<IP>`,
one file per machine, ~443 files/day matching the ~420 PC + ~30 server
testbed), not centrally at a switch like CIC-IoT2023's per-subtype files.
This creates two problems that don't have a CIC-IoT2023 precedent:

- [ ] **Double-capture risk for internal flows.** A flow between two internal
      hosts can be captured independently in *both* machines' own PCAP files
      — the same real event seen from two vantage points, with slightly
      different packet timing/framing on each side, not byte-identical. This
      means the existing content-hash deduplication (which catches exact
      duplicates) will **not** catch this — it's a distinct kind of duplication
      risk that needs its own handling.
- [ ] **Fix: use the day's labeled CSV as the sole source of truth for which
      flows exist**, not the raw PCAPs. Concretely:
  1. Build an IP → filename lookup table for the day's ~443 host files.
  2. Iterate the CSV's rows (each row is one already-deduplicated flow per
     CIC's own methodology) rather than iterating PCAP files directly.
  3. For each row's 5-tuple (src IP, dst IP, src port, dst port, protocol),
     extract the actual packets/payload from **exactly one** endpoint's PCAP
     file — pick whichever of the two IPs has a local capture file available.
     For internal-to-internal flows either side works (both saw the same
     bytes). For flows involving an external IP (e.g., an attacker VM) with
     no local capture file, pull from the internal victim-side host's file —
     the victim's capture still sees the full packet content the attacker
     sent, consistent with how CIC-IoT2023's single-vantage-point captures
     already worked.
  4. Never process a flow by globbing all 443 files and extracting every flow
     each one contains independently — that's exactly the path that
     double-counts internal flows.
- [ ] **Confirm whether the 50 dedicated attacker VMs have their own capture
      files among the ~443**, or are exclusively visible from the victim
      side. This determines whether the lookup in step 3 ever needs a
      fallback case where *neither* IP in a CSV row has a corresponding local
      file. Check this once, early, rather than discovering a gap mid-extraction.
- [ ] **Verify file types before batch processing.** At least two files in the
      first extracted day showed a different icon (spreadsheet-style, not a
      plain document) compared to every other file — worth opening and
      confirming these are genuine packet captures before a batch NFStream job
      globs the whole directory assuming uniform file type. A stray non-PCAP
      file in the batch can crash the job or silently produce garbage output.

### 1.6 Attacker/victim IP + time-window ground truth (new — official ground truth for cross-checking the CSV)

The UNB CIC-IDS2018 page (Table 2) provides an independent, official
attacker/victim IP-and-time-window map for every attack across all 6 selected
days. This is not a replacement for the CSV-based labeling in Section 1.5 —
the CSV remains the primary, per-flow label source — but it's a valuable
**independent cross-check**: if a flow's CSV label and its IP/time-window
match disagree, that's worth investigating before trusting either blindly.

**Full reference table (attack, IPs, time window, per day):**

| Day | Attack | Attacker private IP | Attacker public IP | Victim private IP | Victim public IP | Start | Finish |
|---|---|---|---|---|---|---|---|
| Wed-14-02 | FTP-BruteForce | 172.31.70.4 | 18.221.219.4 | 172.31.69.25 | 18.217.21.148 | 10:32 | 12:09 |
| Wed-14-02 | SSH-Bruteforce | 172.31.70.6 | 13.58.98.64 | 172.31.69.25 | 18.217.21.148 | 14:01 | 15:31 |
| Fri-16-02 | DoS-SlowHTTPTest | 172.31.70.23 | 13.59.126.31 | 172.31.69.25 | 18.217.21.148 | 10:12 | 11:08 |
| Fri-16-02 | DoS-Hulk | 172.31.70.16 | 18.219.193.20 | 172.31.69.25 | 18.217.21.148 | 13:45 | 14:19 |
| Wed-21-02 | DDOS-LOIC-UDP | (10 rotating attacker IPs — see below) | — | 172.31.69.28 | 18.218.83.150 | 10:09 | 10:43 |
| Wed-21-02 | DDOS-HOIC | (same 10 rotating attacker IPs) | — | 172.31.69.28 | 18.218.83.150 | 14:05 | 15:05 |
| Fri-02-03 | Bot | — | 18.219.211.138 | 172.31.69.{6,8,10,12,14,17,23,26,29,30} | (10 distinct public IPs) | 10:11 / 14:24 | 11:34 / 15:55 |
| Thu-01-03 | Infiltration | — | 13.58.225.34 | 172.31.69.13 | 18.216.254.154 | 09:57 / 14:00 | 10:55 / 15:37 |
| Fri-23-02 | Brute Force-Web | — | 18.218.115.60 | 172.31.69.28 | 18.218.83.150 | 10:03 | 11:03 |
| Fri-23-02 | Brute Force-XSS | — | 18.218.115.60 | 172.31.69.28 | 18.218.83.150 | 13:00 | 14:10 |
| Fri-23-02 | SQL Injection | — | 18.218.115.60 | 172.31.69.28 | 18.218.83.150 | 15:05 | 15:18 |

Wednesday's DDoS rotating attacker IPs: `18.218.115.60, 18.219.9.1, 18.219.32.43,
18.218.55.126, 52.14.136.135, 18.219.5.43, 18.216.200.189, 18.218.229.235,
18.218.11.51, 18.216.24.42`.

- [ ] **Critical: resolve the private/public IP duality before building the
      IP → filename lookup table from Section 1.5.** The per-host PCAP
      filenames observed so far use **private IPs** (e.g.
      `capDESKTOP-AN3U28N-172.31.64.17`). This table gives both private and
      public IPs for most attacker/victim pairs, because CIC-IDS2018 was
      hosted on AWS — the same physical host is reachable by either address
      depending on capture vantage point and whether NAT/an AWS gateway sits
      between attacker and victim. **Before finalizing the 5-tuple matching
      logic, check empirically which IP actually appears in a sample of
      victim-side captured packets for one known attack window** (e.g. pull a
      few packets from `172.31.69.25`'s file during the Wed-14-02
      `10:32-12:09` window and check whether the source address on the wire is
      `172.31.70.4` or `18.221.219.4`). Do not assume — build the lookup table
      to match on whichever IP is empirically confirmed to appear, and prefer
      matching by private IP first since that's what the filenames use.
- [ ] **MAC addresses are a secondary validation layer here, not the primary
      filter** — this is a deliberate, important difference from the IoT
      model. CIC-IoT2023's labeling used a literal attacker-MAC allowlist as
      the primary filtering mechanism (Section 5 of `xgnid-parity-fix-plan.md`).
      CIC-IDS2018's official metadata does not provide MAC addresses at all —
      the primary ground truth here is IP + time-window (matching Section
      1.5's CSV-driven approach). MACs can be extracted locally per day via
      `tshark` for extra confidence, but should never become the primary
      filter the way it was for the IoT model, since there's no official
      attacker MAC reference to validate against here.
  - [ ] Local MAC extraction command (per PCAP): `tshark -r "$pcap" -Y "ip" -T fields -e eth.src -e ip.src -e eth.dst -e ip.dst`, aggregated into an IP→MAC frequency table per day (see full script in the source mapping notes).
- [ ] **Formal labeling rule to implement** (combines the CSV and the
      IP+time-window table as two agreeing sources rather than one):
  ```
  attack time window + attacker/victim IP match (private or confirmed-empirical) → mapped attack class
  outside attack windows AND not involving attacker IPs AND not an attack-only victim-service tuple → Benign
  ```
- [ ] **Reconcile a naming discrepancy before it propagates into the class
      taxonomy.** This mapping table labels Fri-02-03 as `Botnet` and
      Thu-01-03 as `Infiltration/Recon`; earlier planning in this project
      (`cross-domain-generalization-test.md`, sourced via direct citation)
      used `Bot` and `Infiltration` respectively, with no reconnaissance
      component mentioned for Thu-01-03. This may just be descriptive
      phrasing rather than a real difference, but confirm which exact string
      becomes the actual class label in the new model's taxonomy before
      training — an inconsistent label name across documents is an easy way
      to introduce a silent bug later (e.g. two effectively-identical classes
      that don't get merged because their label strings don't match exactly).

---

## 2. Phase 2 — Final Gate Before First Training Run

### 2.1 Class distribution audit (matching the IoT model's own format)
- [ ] Produce a full class-distribution report (same format as
      `57_class_distribution_report.md`) across **all combined days** —
      pool-before-split, train/val/test real counts, oversampling fractions,
      per-subtype breakdowns — for every class: FTP-BruteForce/SSH-Bruteforce,
      DoS-Hulk/SlowHTTPTest, DDOS-HOIC/LOIC-UDP, Brute Force-Web/XSS/SQL
      Injection, Infiltration, Bot, Benign.
- [ ] **Specifically verify the CICIDS2017 WebBased augmentation claim.**
      "More than 6,000 samples" needs to be checked, not assumed:
  - [ ] Confirm the count **after** content-hash deduplication, not before —
        a raw combined count can hide near-duplicate flows from a single
        continuous capture session (this was flagged specifically for
        CICIDS2017's XSS attack, executed in one 20-minute window).
  - [ ] Break the 6,000+ figure down **by specific subtype** (Brute Force-Web,
        XSS, SQL Injection) — a pooled total can still hide the same kind of
        single-subtype dominance that WebBased's SqlInjection/Uploading_Attack
        skew caused on the IoT model. Don't assume "6,000 total" means each
        subtype individually has enough diversity.

### 2.2 Split-ratio and oversampling methodology (apply proactively, verify it landed)
- [ ] Confirm split-before-oversample with content-hash deduplication
      (Run 14's `split_first_then_oversample_train_only` methodology) is
      implemented from the start — then **confirm it actually produced the
      expected per-class counts** in the Section 2.1 report, rather than
      trusting that "we implemented it" means "it worked correctly."
- [ ] Confirm the proportional split-ratio rule (scale val/test down when a
      class's total real pool falls short of the comfortable threshold,
      rather than fixing val/test size and starving train) is applied from
      day one — this was the single biggest lever for the IoT model's
      BruteForce recovery, and there's no reason to expect CIC-IDS2018's
      scarcer classes (Infiltration, Heartbleed if present, certain Web Attack
      subtypes) won't need it too.
- [ ] Apply capped-floor subtype balancing (or the equivalent proportional
      check) within any multi-subtype class showing internal skew — Web
      Attack (3 subtypes), DoS (2 subtypes), DDoS (2 subtypes) all need this
      checked, not just assumed fine because the class-level count looks
      large.

### 2.3 Leakage and cross-source integrity
- [ ] Run the leakage audit (same tool/methodology as `leakage_audit.py`) once
      graphs are built — confirm 0 exact duplicate compact-tensor hashes
      across train/val/test.
- [ ] **New check specific to this model, because of the two-source mixing:**
      tag every record with its source dataset (CIC-IDS2018-native vs.
      CIC-IDS2017-augmented) as metadata carried through the pipeline.
      Confirm none of the CIC-IDS2017-sourced WebBased records ended up in
      val or test — they should only ever inflate train's pool, matching the
      "oversample train only" principle. If any leaked into val/test, that's
      a real bug: it would mean evaluation is partly against a different
      source's data, which quietly changes what the reported metric means.
- [ ] Confirm any scaler/transform in use is fit on train only, with
      provenance recorded (matching `flow_scaler_fit_split: train` style
      tracking from the IoT model's manifest).

### 2.4 Architecture decisions — confirm each explicitly, don't inherit by default
- [ ] **BatchNorm eps=1.0** — carry over; this is now a confirmed, literal
      XG-NID setting, not a methodology-doc misreading.
- [ ] **Concat pooling** (flow ‖ packet), not average — matches the actual
      XG-NID default architecture, confirmed via source code.
- [ ] **Multi-head GATConv (heads=2)** — decide explicitly whether to carry
      this into the new model or test it as an isolated experiment on this
      dataset too. This was a SecureEdge-original enhancement over XG-NID's
      actual SAGEConv default, and it helped on IoT data — but "helped on IoT"
      is not the same as "will help on office-network data." Treat as a
      hypothesis to re-verify here, consistent with this project's repeated
      lesson that findings don't automatically transfer across datasets.
- [ ] **edge_attr passed through conv2**, not just conv1 — carry over.
- [ ] **Feature set** — decide explicitly whether this model uses the same
      92-feature recipe (76 NFStream + 16 temporal) or a different set suited
      to office-network characteristics. Don't let this default silently by
      copy-pasting config without a deliberate decision.
- [ ] **Raw features vs. scaled features** — decide explicitly which regime
      this model starts with, given the eps=1.0/raw-feature combination was
      the single biggest unlock for the IoT model's WebBased recovery. If
      starting raw, the Phase 1.3 rate-feature safety check is mandatory, not
      optional.

### 2.5 Training configuration
- [ ] Batch size 512, cosine annealing (T0=50, T_mult=2), lr warmup to 0.003,
      gradient clipping at 1.0 — apply as the proven starting point.
- [ ] Confirm checkpoint selection and early stopping are keyed to a genuine
      held-out validation split, not test — re-verify this is correctly wired
      in the new codebase rather than assuming it's handled because the
      project now understands the Run 13 leakage-via-training-decisions
      mistake conceptually. Understanding the mistake and having correctly
      implemented its fix in a new codebase are not the same thing until
      checked.

---

## 3. Phase 3 — Post-Training, Pre-Deployment

- [ ] Once the new model reaches a stable result, run the same kind of
      per-class F1/accuracy/FP/FN tabulation used throughout the IoT model's
      development, and apply the same skepticism to suspiciously high early
      results as was applied to Run 13 — verify before trusting.
- [ ] Design the routing mechanism between the IoT model and this new office
      model for mixed-network deployment (MAC-OUI-based device fingerprinting,
      protocol heuristics such as MQTT/CoAP presence vs. RDP/SMB/Kerberos
      presence, or a lightweight upstream gating classifier). This is a real,
      undesigned component of the "use both models together" goal, not an
      afterthought to handle later.
- [ ] Consider running the already-designed frozen-IoT-model cross-domain test
      (`cross-domain-generalization-test.md`) as a baseline comparison point
      once the dedicated office model exists — even though the project is now
      building a dedicated model rather than reusing the IoT backbone, this
      still tells you how much better the dedicated model is versus naively
      applying the IoT model out of domain, which is useful evidence for the
      thesis and for justifying the two-model approach.

---

## 4. Why This List Is Long

Every item above maps to a specific, real cost this project already paid once
on the IoT model — the NaN collapse, the split-ratio bug that silently starved
two classes for months, the Run 13 leakage that produced a fake 0.987, the
misread methodology doc that nearly caused a bad eps setting, the
misattributed "multi-head attention matches XG-NID" belief. None of these were
hypothetical risks — they each cost real time. The point of this checklist
isn't caution for its own sake; it's making sure the same lessons that were
expensive to learn once aren't quietly un-learned by assuming they don't apply
to a new dataset.

The per-host PCAP structure (Section 1.5) and the IP/time-window ground truth
(Section 1.6) are a different kind of entry on this list — not repeated
IoT-model lessons, but genuinely new problems and new resources this dataset
introduces that the IoT pipeline never had to deal with. They're included here
specifically because they were caught or found by inspecting the actual
extracted files and the official dataset documentation before building any
extraction or labeling code around an untested assumption. That's the same
discipline the rest of this checklist is asking for, just applied one step
earlier than usual.
