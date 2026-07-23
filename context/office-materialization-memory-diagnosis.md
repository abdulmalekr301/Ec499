# Office Materialization — Memory Scaling Diagnosis and Next Steps

> **Generated:** 2026-07-14
> **Context:** The memory-safety subprocess/RLIMIT_AS fix worked — the
> process now stops cleanly instead of crashing the desktop. This document
> addresses the underlying cause of *why* memory keeps climbing during
> single-PCAP scans, which the safety fix correctly contains but doesn't fix.

---

## 0. Confirmed: The Split/Candidate Manifest Is Correct

Verified independently against the finalized plan
(`office-model-graph-generation-training-plan.md`, Section 1):

```
train:                  126,000  ✓
val:                     12,103  ✓
test:                    12,103  ✓
train_real:             120,373  ✓
materialization_unique: 144,579  ✓
cicids2017_in_val:            0  ✓
cicids2017_in_test:           0  ✓
```

All five numeric fields match exactly, and the CICIDS2017 train-only
discipline held with zero leakage into val/test. No action needed here —
this stage is done correctly.

---

## 1. The Memory-Safety Fix Worked As Intended

Subprocess isolation, the `RLIMIT_AS` hard ceiling, dual-level checks (parent
RSS + system-available memory, checked every N scanned flows), and the
full-run lock requiring explicit opt-in are all sound, and directly reuse the
proven pattern from CIC-IoT2023's own memory-safety work. The critical
evidence it worked: post-run memory state showed 9.9GB available with no
lingering worker process — the run stopped cleanly instead of repeating the
original crash. This part of the fix is complete and validated.

---

## 2. What the Escalating-Floor Pattern Reveals

The same PCAP (`capDESKTOP-AN3U28N-172.31.64.115`) was scanned three times
at progressively lower memory floors:

```
8.0 GiB floor -> stopped at 1,080 flows scanned
7.5 GiB floor -> stopped at 2,210 flows scanned
6.5 GiB floor -> stopped at 3,340 flows scanned
```

This is roughly linear growth in flows-scanned-before-ceiling as the floor
drops — consistent with memory climbing steadily with flow count, not
spiking. That pattern points at NFStream holding a large number of flows
**simultaneously open** in its internal flow table, rather than processing
and releasing them quickly.

**Working hypothesis: the NFStream timeout settings, tuned and validated on
IoT traffic, may not suit enterprise traffic's flow-duration
characteristics.** `active_timeout=1800` (30 minutes) and `idle_timeout=120`
were established and proven on CIC-IoT2023, where traffic tends toward short,
bursty flows (sensor telemetry, quick command/response exchanges). Enterprise
workstation traffic is plausibly very different — persistent file-server
connections, background sync processes, long browsing sessions — meaning far
more flows could remain open for the full 30-minute active timeout before
NFStream ever expires and releases them from memory. If so, the per-PCAP
memory cost isn't primarily about candidate density (though that's a real,
separate problem too) — it's that NFStream needs to track an unusually large
number of concurrently-open flows for this traffic type specifically.

**This needs to be checked, not assumed.** Recommended check: for the
problem PCAP, log the number of simultaneously-open (not-yet-expired) flows
NFStream is tracking at intervals during the scan. If this count grows large
and stays large (rather than cycling low as flows open and close quickly),
that confirms the timeout hypothesis. If it stays small and memory still
climbs, the cause is something else (e.g., a memory leak in the graph
construction path itself, or payload accumulation) and needs separate
investigation.

---

## 3. Two Fixes to Pursue, Not Just One

### 3.1 Density-aware batching (the coding agent's own proposed fix — sound, pursue it)

Many endpoint PCAPs currently have only one selected candidate, meaning
NFStream scans tens of thousands of flows to extract a single useful graph.
Prioritizing PCAPs with more pending candidates per scan amortizes the
expensive full-file scan across many useful extractions instead of one. This
is good, correct reasoning and should be implemented regardless of what the
timeout investigation finds.

### 3.2 If the timeout hypothesis is confirmed: reconsider NFStream's timeout settings for office data specifically

If simultaneously-open flow count is confirmed as the driver, consider:

- **Shorter `active_timeout` for office-data extraction specifically** —
  this would need its own validation (does a shorter timeout change flow
  statistics meaningfully for genuinely long-lived enterprise flows in a way
  that matters for the 92-feature recipe?), not applied blindly. This is a
  real trade-off: a shorter timeout reduces memory pressure but could split a
  genuinely long-lived flow into multiple shorter "flows," changing its
  feature profile.
- **Time-windowed chunked scanning** as an alternative that doesn't change
  feature computation: process each PCAP in bounded time windows (e.g., scan
  packets from a bounded chronological slice, extract/release, advance the
  window) rather than one continuous NFStream pass over the entire file. This
  bounds how many flows can be concurrently open at once without changing
  the timeout values themselves.

**Do not change `active_timeout`/`idle_timeout` without first confirming the
hypothesis in Section 2** — changing these values also changes computed flow
features (duration, rate-derived features, active/idle statistics), and an
unvalidated change here risks introducing a new inconsistency between how
office-data features and IoT-data features were computed, undermining the
"same feature engineering recipe throughout" discipline this project has
maintained.

### 3.3 Fallback safety net: skip/defer worst-case PCAPs

Even with density-aware batching, some PCAPs may combine low candidate
density with genuinely high memory cost (the worst-case combination). Add an
explicit skip/defer path: if a PCAP's scan exceeds a flows-scanned threshold
without finding its remaining candidates, stop and defer that PCAP rather
than let the memory floor be the only thing standing between "slow" and
"crash." This is a cheap addition given the bounded-run infrastructure
(`--office-max-flows-per-pcap`) already exists — it just needs a defer/retry
queue instead of only a hard stop.

---

## 4. Recommended Sequencing

```
1. Run the simultaneously-open-flow-count diagnostic (Section 2) on the
   problem PCAP to confirm or rule out the timeout hypothesis.
2. Implement density-aware batching (Section 3.1) regardless of the
   diagnostic's outcome — it's a correct fix either way.
3. If the timeout hypothesis is confirmed, evaluate time-windowed chunked
   scanning (Section 3.2) before touching NFStream's timeout values directly.
4. Add the skip/defer fallback (Section 3.3) as a safety net for whatever
   worst-case PCAPs remain after 1-3.
5. Re-run the bounded pilot (same `--office-limit-unique 200
   --office-max-pcaps 5` shape) to confirm the fixes actually improve
   graphs-materialized-per-memory-budget before scaling to a larger batch.
```

---

## 5. What Must Not Happen

- Continuing to lower the memory floor as the primary fix — the floor is a
  safety net, not a solution to why memory climbs in the first place.
- Changing NFStream's `active_timeout`/`idle_timeout` without first
  confirming the simultaneously-open-flow-count hypothesis, given the risk
  of silently changing computed flow features.
- Scaling to the full run before the bounded pilot demonstrates improved
  throughput under the fixes above — the full-run lock exists precisely to
  prevent this, and should stay in place until there's real evidence the
  underlying issue (not just the crash) is addressed.
