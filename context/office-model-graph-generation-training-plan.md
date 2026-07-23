# Office Model — Graph Generation & Training Plan (Final, Execution-Ready)

> **Generated:** 2026-07-13
> **Status:** Consolidates every decision made across the preceding planning
> documents into one execution-ready spec. Where a decision has a longer
> justification trail, this document states the final number/rule and points
> to the source document rather than re-deriving it.
> **Source documents:** `office-model-pretraining-checklist.md`,
> `office-model-graph-generation-pipeline.md`, `xgnid-parity-fix-plan.md`,
> `cicids2017-webbased-augmentation-plan.md`,
> `thursday-22-02-2018-verification-plan.md`,
> `webbased-attempted-payload-check.md`, `webbased-final-split-decision.md`.

---

## 1. Final Class Taxonomy and Targets

Seven classes. Six follow one methodology; WebBased is the sole exception.

| Class | Train | Val | Test | Sources |
|---|---:|---:|---:|---|
| Benign | 20,000 (real) | 2,000 (real) | 2,000 (real) | CIC-IDS2018, all 6 days, stratified |
| BruteForce | 20,000 (real) | 2,000 (real) | 2,000 (real) | CIC-IDS2018, Wed-14-02 |
| DoS | 20,000 (real) | 2,000 (real) | 2,000 (real) | CIC-IDS2018, Fri-16-02 |
| DDoS | 20,000 (real) | 2,000 (real) | 2,000 (real) | CIC-IDS2018, Wed-21-02 |
| Bot | 20,000 (real) | 2,000 (real) | 2,000 (real) | CIC-IDS2018, Fri-02-03 |
| Infiltration | 20,000 (real) | 2,000 (real) | 2,000 (real) | CIC-IDS2018, Thu-01-03 |
| **WebBased** | **6,000 (373 real, 16.1x oversampled)** | **103 (real)** | **103 (real)** | CIC-IDS2018 Thu-22-02 + Fri-23-02 (206 native train share) + CICIDS2017 (167, train-only) |

None of the six standard classes require oversampling — each has a real pool
far exceeding the 24,000 comfortable threshold. The proportional split-ratio
rule (scale val/test down if real data ever falls short) remains implemented
as a fallback but isn't currently triggered for any of them.

---

## 2. Graph Generation Pipeline

### Stage A — Pre-Flight (verify before generating anything)

- [ ] Class taxonomy strings locked exactly as in Section 1 — no `Bot`/`Botnet`
      or `Infiltration`/`Infiltration-Recon` inconsistency across code,
      manifests, or file paths.
- [ ] NFStream configuration locked: `idle_timeout=120`, `active_timeout=1800`,
      `statistical_analysis=True`, `splt_analysis=0`, `n_dissections=0`,
      `ActiveIdlePlugin`/`PacketCapture`/`FlowCapper` with the 20-packet
      expiration trigger — same recipe proven on the IoT model.
- [ ] Feature recipe locked: 92 features (76 flow statistics + 16 temporal),
      recomputed fresh via NFStream from matched packets for every flow —
      **never** reused from CICFlowMeter's CSV feature columns, for either
      CIC-IDS2018 or CICIDS2017 data. The CSV is a labeling source only.
- [ ] Confirmed ground-truth artifacts in place for every source:
  - CIC-IDS2018: original CSVs + improved/corrected CSVs + IP/time-window
    table for all 6 days, with the confirmed 4-hour timestamp offset applied.
  - CIC-IDS2018 per-host structure: IP → filename lookup built per day, using
    the confirmed **private-IP-on-wire** convention.
  - CICIDS2017: single-file structure confirmed, on-wire path confirmed as
    `172.16.0.1 → 192.168.10.50`, attack windows confirmed as the *original*
    afternoon citation (12:15–13:42), not the erroneous morning table.
- [ ] Architecture settings locked (Section 3) before any graph is built,
      since the raw-feature/log1p decision affects what "safe" feature values
      look like during the extraction safety checks below.

### Stage B — Per-Class Candidate Finalization

- [ ] Six standard classes: candidate manifests already at 20,000 each
      (confirmed in the latest candidate flow manifest run) — no further
      action needed here.
- [ ] WebBased: regenerate the candidate manifest to reflect the finalized
      50/25/25 native split before oversampling:
  ```
  Native pool (Thu-22-02 191 + Fri-23-02 221 = 412):
    train_native = 206
    val          = 103
    test         = 103
  CICIDS2017 (167) tagged train-only, added to train_native only.
  Final pre-oversample train real pool: 373.
  ```
- [ ] Every CICIDS2017-derived candidate carries `source: CICIDS2017` and
      `split_scope: train_only` metadata, carried through graph
      materialization — already implemented per the augmentation work; verify
      it survives into the final candidate set used for graph generation.

### Stage C — Graph Materialization (not yet started as of the last progress report — this is the next major step)

- [ ] For every retained candidate: locate the correct endpoint PCAP via the
      IP → filename lookup (never glob all per-host files), extract via
      5-tuple + timestamp-tolerance matching (3.0s tolerance, matching the
      pilot extraction's proven approach).
- [ ] Build the heterogeneous graph: flow node (92 features) + up to 20 packet
      nodes (1,500-byte payload each) + contain/rev_contain/link edges.
- [ ] **Per-graph safety checks, applied as each graph is built, not after the
      fact:**
  - `flow_finite`, `contain_finite`, `link_finite` all confirmed true (no
    NaN/Inf) — the Run 16b lesson, applied proactively.
  - Payload non-zero fraction and mean logged per graph, compared against the
    established reference range (0.10–0.33 non-zero fraction seen in the
    WebBased pilot, 0.15–0.22 on the IoT model) — flag outliers for review,
    don't silently accept them.
  - `flow_max` and similar extreme-value fields checked against expectation
    given the raw-feature + log1p regime — a value in the tens of millions
    should only appear on non-rate features (duration/byte-count scale
    values), not on anything that should have been log1p-compressed.

### Stage D — Assembly, Deduplication, Sharding

- [ ] Combine per-class graphs using the exact split counts in Section 1.
- [ ] Content-hash deduplication across the full combined pool for every
      class, including WebBased's combined native + CICIDS2017 pool.
- [ ] **Leakage audit — non-negotiable before training starts:**
  - 0 exact duplicate compact-tensor hashes across train/val/test, all 7
    classes.
  - 0 CICIDS2017-sourced graphs in WebBased's val or test — verify this
    explicitly by source tag, not just by exact-duplicate absence, since
    CICIDS2017 graphs are unique flows and won't show up as hash duplicates
    even if they leaked into the wrong split.
- [ ] Produce the full class-distribution report (matching the established
      format) — confirm actual counts match Section 1's targets before
      proceeding. Any mismatch gets investigated, not silently accepted.
- [ ] Shard the final graphs for training, matching the IoT model's sharding
      approach.

---

## 3. Model Architecture (inherited from the IoT model, stated explicitly)

```
BatchNorm eps:        1.0
Feature regime:       raw values, log1p transform on rate-derived features only
Pooling:              concatenation (flow || packet), not average
Edge attributes:      passed through both conv layers, not just the first
Attention:            multi-head GATConv (heads=2) — inherited as a
                       SecureEdge enhancement over XG-NID's literal SAGEConv
                       default; re-verify it still helps on this dataset
                       rather than assuming the IoT-model finding transfers
                       automatically
Feature count:        92 (76 flow statistics + 16 temporal)
```

---

## 4. Training Configuration (inherited starting point, re-verify rather than assume)

```
Batch size:        512 (or 256 with grad_accum_steps=2 for effective 512)
Scheduler:         cosine annealing, T0=50, T_mult=2
LR:                warmup to 0.003, decay to lr_min=1e-5
Gradient clipping: 1.0
Label smoothing:   0.0
Loss:              plain CrossEntropyLoss, no class weighting
Max epochs:        300
Early stop:        patience 50-75
Checkpoint select: val macro F1 — re-verify this is genuinely wired to the
                   val split, not test, in this codebase. Understanding the
                   Run 13 mistake conceptually is not the same as having
                   correctly implemented its fix here — check, don't assume.
```

This is the IoT model's proven configuration, used as a validated starting
point given this is a new dataset with different flow-duration and protocol
characteristics — not assumed to be optimal without verification. Run the
Stage C numerical safety checks specifically before trusting this
configuration doesn't reproduce the Run 16b NaN failure on office-network
traffic.

---

## 5. Post-Training Verification

- [ ] Standard per-class accuracy/F1/FP/FN tabulation, all 7 classes.
- [ ] **WebBased per-source breakdown** — evaluate performance separately on
      CIC-IDS2018-native test examples vs. any diagnostic check involving
      CICIDS2017 characteristics, to catch domain-shift/shortcut-learning
      before trusting a single pooled F1.
- [ ] Apply the same skepticism to unexpectedly high early results that this
      project has learned to apply — a suspiciously good result (especially
      on WebBased, given how much oversampling it involves) should trigger a
      leakage-audit re-check before being trusted, not immediate celebration.
- [ ] WebBased's F1 should be reported with explicit acknowledgment of its
      smaller val/test sample size (103) relative to the other six classes
      (2,000) — wider error bars are expected and should be stated plainly,
      not glossed over.

---

## 6. What Must Not Happen

- Oversampling before splitting, for any class, under any circumstance —
  this is the Run 13 mechanism and applies regardless of how small a class's
  real pool is.
- Reusing CICFlowMeter's CSV feature values instead of recomputing via
  NFStream.
- Globbing all per-host CIC-IDS2018 PCAP files instead of using the IP →
  filename lookup for single-endpoint extraction.
- Letting any CICIDS2017-sourced graph reach WebBased's val or test.
- Trusting the six standard classes' 20,000 target as fixed if a future
  audit reveals a real-data shortfall — apply the proportional split-ratio
  fallback rule instead of forcing the number through.
- Treating this document's inherited architecture/training configuration as
  guaranteed to work without the numerical safety checks in Stage C — a new
  dataset can surprise a proven recipe, as this project has seen before.
